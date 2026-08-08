<?php
declare(strict_types=1);

/**
 * remediation_note.php — "미조치 사유 + 승인자" 최소 필드 저장·조회.
 *
 *   억제(tb_suppressed_findings)는 매처의 **자동 판정**이고, 이건 사람이 남기는 **메모**다.
 *   둘은 별개로 둔다 — 이 파일은 억제 로직을 건드리지 않는다.
 *
 *   키는 스캔이 바뀌어도 유지되는 자연키다: (host_id, 컨테이너 이름, cve_id, 패키지명).
 *   tb_container.container_id 는 스캔마다 새로 발급되는 surrogate PK 라 스캔 간 비교가 안 된다
 *   (server/public/finding_history.php 머리주석). 그래서 이름으로만 정규화한다.
 */

require_once __DIR__ . '/db.php';

/** 사유 입력 상한(글자수). DB 는 TEXT 지만 화면·감사로그가 감당할 길이로 잘라 받는다. */
const VG_REMEDIATION_REASON_MAX = 1000;

/** 컨테이너 이름 정규화 — 호스트 자신은 '' 로 통일한다(NULL 은 UNIQUE 에서 중복을 못 막는다). */
function vg_remediation_note_cid(?string $cid): string {
    return trim((string) $cid);
}

/** 목록에서 행↔메모를 맞추는 키. vg_remediation_notes_map() 의 반환 키와 같은 규칙. */
function vg_remediation_note_key(int $hostId, ?string $cid, string $cveId, string $package): string {
    return $hostId . "\x1f" . vg_remediation_note_cid($cid) . "\x1f" . $cveId . "\x1f" . $package;
}

/** 메모 1건. 없으면 null. 승인자는 사용자명까지 함께 준다(화면·export 가 id 로는 못 쓴다). */
function vg_remediation_note_get(PDO $pdo, int $hostId, ?string $cid, string $cveId, string $package): ?array {
    $st = $pdo->prepare(
        'SELECT n.remediation_note_id, n.reason, n.approved_by, n.approved_at, u.username AS approved_by_name
           FROM tb_remediation_note n
           LEFT JOIN tb_user u ON u.user_id = n.approved_by
          WHERE n.host_id = ? AND n.cid = ? AND n.cve_id = ? AND n.package = ? AND n.is_deleted = 0'
    );
    $st->execute([$hostId, vg_remediation_note_cid($cid), $cveId, $package]);
    $row = $st->fetch();
    return $row ?: null;
}

/**
 * 목록 한 페이지분 메모를 한 번에 읽는다(N+1 방지).
 *   $keys = [[host_id, cid, cve_id, package], …] → vg_remediation_note_key() 키의 맵.
 */
function vg_remediation_notes_map(PDO $pdo, array $keys): array {
    if (!$keys) { return []; }

    $hostIds = []; $cves = []; $packages = [];
    foreach ($keys as $k) {
        $hostIds[(int) $k[0]] = true;
        $cves[(string) $k[2]] = true;
        $packages[(string) $k[3]] = true;
    }
    $hostIds = array_keys($hostIds); $cves = array_keys($cves); $packages = array_keys($packages);

    // 세 축을 IN 으로 좁혀 한 번에 읽고, 정확한 조합 대조는 아래 키 맵으로 한다
    // (IN 3개의 곱집합은 실제 조합보다 넓지만, 한 페이지분이라 건수가 작다).
    $sql = 'SELECT n.host_id, n.cid, n.cve_id, n.package, n.reason, n.approved_by, n.approved_at,
                   u.username AS approved_by_name
              FROM tb_remediation_note n
              LEFT JOIN tb_user u ON u.user_id = n.approved_by
             WHERE n.is_deleted = 0
               AND n.host_id IN (' . implode(',', array_fill(0, count($hostIds), '?')) . ')
               AND n.cve_id IN (' . implode(',', array_fill(0, count($cves), '?')) . ')
               AND n.package IN (' . implode(',', array_fill(0, count($packages), '?')) . ')';
    $st = $pdo->prepare($sql);
    $st->execute(array_merge($hostIds, $cves, $packages));

    $map = [];
    foreach ($st->fetchAll() as $r) {
        $map[vg_remediation_note_key((int) $r['host_id'], (string) $r['cid'], (string) $r['cve_id'], (string) $r['package'])] = $r;
    }

    // 요청하지 않은 조합(곱집합에 딸려온 것)은 버린다.
    $wanted = [];
    foreach ($keys as $k) {
        $key = vg_remediation_note_key((int) $k[0], $k[1], (string) $k[2], (string) $k[3]);
        if (isset($map[$key])) { $wanted[$key] = $map[$key]; }
    }
    return $wanted;
}

/**
 * 저장(신규/수정). 승인자·승인일시는 사용자가 고르는 값이 아니라 **저장 행위에서 자동 기록**된다.
 *   철회(소프트삭제)된 같은 조합은 되살린다 — UNIQUE 가 조합당 한 행만 허용하기 때문이다.
 */
function vg_remediation_note_save(
    PDO $pdo, int $hostId, ?string $cid, string $cveId, string $package, string $reason, ?int $userId
): void {
    $pdo->prepare(
        'INSERT INTO tb_remediation_note (host_id, cid, cve_id, package, reason, approved_by, approved_at)
              VALUES (?,?,?,?,?,?,NOW())
         ON DUPLICATE KEY UPDATE
              reason = VALUES(reason), approved_by = VALUES(approved_by), approved_at = NOW(),
              is_deleted = 0, deleted_at = NULL'
    )->execute([$hostId, vg_remediation_note_cid($cid), $cveId, $package, $reason, $userId]);
}

/** 철회 — 소프트삭제. 누가 언제 썼던 메모인지는 감사로그에 남는다. */
function vg_remediation_note_revoke(PDO $pdo, int $hostId, ?string $cid, string $cveId, string $package): void {
    $pdo->prepare(
        'UPDATE tb_remediation_note SET is_deleted = 1, deleted_at = NOW()
          WHERE host_id = ? AND cid = ? AND cve_id = ? AND package = ? AND is_deleted = 0'
    )->execute([$hostId, vg_remediation_note_cid($cid), $cveId, $package]);
}
