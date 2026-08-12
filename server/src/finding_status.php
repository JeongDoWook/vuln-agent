<?php
declare(strict_types=1);

/**
 * finding_status.php — 탐지 결과의 **조치 상태**(tb_finding_status) 저장·조회.
 *
 *   상태 4개(OPEN·IN_PROGRESS·DONE·EXCEPTED)와 메모 한 줄이 전부다. 담당자·결재선·기한은
 *   두지 않는다 — 20260730120000_drop_remediation_workflow.sql 이 걷어낸 워크플로를 다시
 *   들이지 않는다는 결정이다(마이그레이션 20260812190614_finding_status.sql 머리주석).
 *
 *   키는 tb_remediation_note 와 같은 자연키다: (host_id, 컨테이너 이름, cve_id, 패키지명).
 *   스캔마다 새로 발급되는 surrogate PK 로는 스캔 간 비교가 안 되기 때문이다.
 *
 *   ※ 라벨은 여기 없다 — server/src/format.php 의 vg_finding_status_labels() 가 정본이다.
 */

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/format.php';   // vg_finding_status_labels — 유효값 판정의 정본

/** 메모 입력 상한(글자수). 컬럼이 VARCHAR(1000) 이라 저장 전에 같은 길이로 자른다. */
const VG_FINDING_STATUS_NOTE_MAX = 1000;

/** 컨테이너 이름 정규화 — 호스트 자신은 '' 로 통일(NULL 은 UNIQUE 에서 중복을 못 막는다). */
function vg_finding_status_ref(?string $cid): string {
    return trim((string) $cid);
}

/** 목록에서 행↔상태를 맞추는 키. vg_finding_statuses_map() 의 반환 키와 같은 규칙. */
function vg_finding_status_key(int $hostId, ?string $cid, string $cveId, string $package): string {
    return $hostId . "\x1f" . vg_finding_status_ref($cid) . "\x1f" . $cveId . "\x1f" . $package;
}

/** 화면·POST 가 받은 값이 상태 4종에 드는가. 라벨 표가 값 목록의 정본이다(DRY). */
function vg_finding_status_valid(string $status): bool {
    return isset(vg_finding_status_labels()[$status]);
}

/**
 * 목록 한 페이지분 상태를 한 번에 읽는다(N+1 방지).
 *   findings.php 는 목록 쿼리에서 LEFT JOIN 으로 직접 가져오고, 이 함수는 조인을 걸 수 없는
 *   화면(host.php 의 탭 표처럼 이미 조립된 행 배열)이 쓴다.
 *   $keys = [[host_id, cid, cve_id, package], …] → vg_finding_status_key() 키의 맵.
 */
function vg_finding_statuses_map(PDO $pdo, array $keys): array {
    if (!$keys) { return []; }

    $hostIds = []; $cves = []; $packages = [];
    foreach ($keys as $k) {
        $hostIds[(int) $k[0]] = true;
        $cves[(string) $k[2]] = true;
        $packages[(string) $k[3]] = true;
    }
    $hostIds = array_keys($hostIds); $cves = array_keys($cves); $packages = array_keys($packages);

    // 세 축을 IN 으로 좁혀 한 번에 읽고, 정확한 조합 대조는 아래 키 맵으로 한다
    //   (곱집합은 실제 조합보다 넓지만 한 페이지분이라 건수가 작다 — remediation_note.php 와 같은 방식).
    $st = $pdo->prepare(
        'SELECT s.host_id, s.container_ref, s.cve_id, s.package_name, s.status, s.note, s.updated_at,
                u.username AS updated_by_name
           FROM tb_finding_status s
           LEFT JOIN tb_user u ON u.user_id = s.updated_user_id
          WHERE s.host_id IN (' . implode(',', array_fill(0, count($hostIds), '?')) . ')
            AND s.cve_id IN (' . implode(',', array_fill(0, count($cves), '?')) . ')
            AND s.package_name IN (' . implode(',', array_fill(0, count($packages), '?')) . ')'
    );
    $st->execute(array_merge($hostIds, $cves, $packages));

    $map = [];
    foreach ($st->fetchAll() as $r) {
        $map[vg_finding_status_key((int) $r['host_id'], (string) $r['container_ref'],
                                   (string) $r['cve_id'], (string) $r['package_name'])] = $r;
    }

    // 요청하지 않은 조합(곱집합에 딸려온 것)은 버린다.
    $wanted = [];
    foreach ($keys as $k) {
        $key = vg_finding_status_key((int) $k[0], $k[1], (string) $k[2], (string) $k[3]);
        if (isset($map[$key])) { $wanted[$key] = $map[$key]; }
    }
    return $wanted;
}

/**
 * 저장(신규/수정). 갱신자·갱신시각은 사용자가 고르는 값이 아니라 저장 행위에서 자동 기록된다.
 *   유효하지 않은 상태값은 예외 — 호출부(POST 분기)가 사용자에게 메시지로 되돌린다.
 */
function vg_finding_status_save(
    PDO $pdo, int $hostId, ?string $cid, string $cveId, string $package,
    string $status, string $note, ?int $userId
): void {
    if (!vg_finding_status_valid($status)) {
        throw new RuntimeException('알 수 없는 조치 상태입니다.');
    }
    $note = mb_substr(trim($note), 0, VG_FINDING_STATUS_NOTE_MAX);
    $pdo->prepare(
        'INSERT INTO tb_finding_status
                (host_id, container_ref, cve_id, package_name, status, note, updated_user_id)
              VALUES (?,?,?,?,?,?,?)
         ON DUPLICATE KEY UPDATE
              status = VALUES(status), note = VALUES(note),
              updated_user_id = VALUES(updated_user_id)'
    )->execute([$hostId, vg_finding_status_ref($cid), $cveId, $package, $status,
                $note === '' ? null : $note, $userId]);
}
