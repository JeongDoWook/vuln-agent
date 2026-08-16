<?php
declare(strict_types=1);

/**
 * host/summary.php — 자산 상세의 **히어로/KPI 집계**와 화면 머리 경고의 근거 조회.
 *   심각도 분포(+KEV·외부노출) · 값싼 COUNT 묶음 · 판정 불가 컨테이너 · 미수집 단계 ·
 *   패키지 무결성 미리보기.
 *
 *   여기 있는 것은 **탭과 무관하게** 항상 필요한 값이다(탭 배지 숫자가 이것들로 만들어진다).
 *   탭별 목록 조회는 queries.php 가 갖고, 그쪽은 여전히 **활성 탭 것만** 불린다(PR #579).
 *   무결성 미리보기만 예외로 여기 있는데, 설치 패키지 탭에서만 호출한다 — 조회 위치가 아니라
 *   호출 위치가 지연 로딩을 정한다.
 */

// 무결성 목록은 "상태를 알리는 미리보기"다. 전체 목록 화면은 만들지 않는다(YAGNI).
const VG_HOST_INTEGRITY_TOP = 20;

/**
 * 취약점 0건이 "판정 불가"인 컨테이너 — 피드 미지원 배포판 + **패키지 DB 없는 이미지**.
 *   후자는 rhel 처럼 피드가 지원하는 배포판이라 미지원 경고에 안 걸린다 → 따로 잡아야 한다.
 *   반환: [['cid' => …, 'reason' => …], …]
 */
function vg_host_load_unsupported_containers(PDO $pdo, int $sid): array {
    $st = $pdo->prepare(
        'SELECT c.cid, c.os_id, c.os_version, c.manager,
                CASE WHEN EXISTS (
                    SELECT 1 FROM tb_package p
                     WHERE p.scan_id = c.scan_id AND p.container_id = c.container_id
                ) THEN 1 ELSE c.pkg_count END AS pkg_count
           FROM tb_container c WHERE c.scan_id = ?'
    );
    $st->execute([$sid]);
    $out = [];
    foreach ($st->fetchAll() as $c) {
        $reason = vg_container_unjudgeable(
            $c['os_id'] ?? null, $c['os_version'] ?? null,
            $c['manager'] ?? null, (int) ($c['pkg_count'] ?? 0)
        );
        if ($reason !== null) {
            $out[] = ['cid' => (string) $c['cid'], 'reason' => $reason];
        }
    }
    return $out;
}

/**
 * 수집 단계 누락 — 배포판도 알고 이미지도 멀쩡한데 **에이전트가 그 항목을 아예 못 걷은** 경우.
 *   MISSING 만 모은다. EMPTY 는 "정상적으로 없음"(컨테이너를 안 쓰는 호스트, 언어 패키지가
 *   없는 호스트)이라 같이 경고하면 정상 호스트마다 경고가 떠서 아무도 안 보게 된다.
 *   item_count 는 안 읽는다 — MISSING 은 정의상 0건이라(ingest.php 생산자) 볼 값이 없다.
 *   반환: ['codes' => 원본 코드, 'labels' => 한글 라벨] — 화면은 라벨을, "이 항목이 미수집인가"를
 *   묻는 탭은 코드를 쓴다.
 */
function vg_host_load_missing_stages(PDO $pdo, int $sid): array {
    $st = $pdo->prepare("SELECT stage_code FROM tb_collection_stage
                          WHERE scan_id = ? AND status = 'MISSING' ORDER BY stage_code");
    $st->execute([$sid]);
    $codes = []; $labels = [];
    foreach ($st->fetchAll() as $r) {
        $code = (string) $r['stage_code'];
        $codes[] = $code;
        $labels[] = VG_COLLECTION_STAGE_LABEL[$code] ?? $code;   // 모르는 코드는 원문 그대로
    }
    return ['codes' => $codes, 'labels' => $labels];
}

/**
 * 심각도 분포 + 위험 요약.
 *   KEV(알려진 악용)·외부노출 건수는 심각도 분포와 같은 성격의 "위험 요약" 이라
 *   쿼리를 늘리지 않고 같은 GROUP BY 에 집계를 얹어 가져온다.
 *   반환: ['counts' => [등급 => n], 'kev' => n, 'external' => n]
 */
function vg_host_load_severity_summary(PDO $pdo, int $sid): array {
    $counts = ['CRITICAL' => 0, 'HIGH' => 0, 'MEDIUM' => 0, 'LOW' => 0];
    $kev = 0; $external = 0;
    $st = $pdo->prepare("SELECT severity, COUNT(*) c,
                                SUM(in_kev = 1) kev, SUM(runtime_status = 'EXTERNAL') ext
                           FROM tb_finding WHERE scan_id = ? GROUP BY severity");
    $st->execute([$sid]);
    foreach ($st->fetchAll() as $r) {
        if (isset($counts[$r['severity']])) { $counts[$r['severity']] = (int) $r['c']; }
        $kev += (int) $r['kev'];
        $external += (int) $r['ext'];
    }
    return ['counts' => $counts, 'kev' => $kev, 'external' => $external];
}

/**
 * 히어로/KPI 와 탭 배지가 읽는 값싼 COUNT 묶음(탭과 무관하게 항상 필요하다).
 *   전부 (scan_id …) 인덱스를 타는 단건 COUNT 라 한 함수에 모아도 화면이 무거워지지 않는다 —
 *   무거운 목록 조회(queries.php)와 섞지 않는 것이 이 파일의 경계다.
 */
function vg_host_load_kpi_counts(PDO $pdo, int $sid, int $hostId): array {
    $st = $pdo->prepare('SELECT COUNT(*) FROM tb_exposure WHERE scan_id = ?');
    $st->execute([$sid]); $exposureCount = (int) $st->fetchColumn();

    $st = $pdo->prepare("SELECT COUNT(*) FROM tb_cce_finding WHERE scan_id = ? AND result = 'FAIL'");
    $st->execute([$sid]); $cceFail = (int) $st->fetchColumn();

    $st = $pdo->prepare('SELECT COUNT(*) FROM tb_suppressed_finding WHERE scan_id = ?');
    $st->execute([$sid]); $suppressedCount = (int) $st->fetchColumn();

    // 우선순위 취약점 = CRITICAL·HIGH + 재시작 필요(등급이 낮아도 숨기지 않는다).
    //   탭 배지는 둘의 합, 화면은 두 표로 나눠 보여준다(vuln 탭 참고).
    $st = $pdo->prepare("SELECT COUNT(*) FROM tb_finding
                          WHERE scan_id = ? AND (severity IN ('CRITICAL','HIGH') OR needs_restart = 1)");
    $st->execute([$sid]); $vulnTotal = (int) $st->fetchColumn();

    $st = $pdo->prepare("SELECT COUNT(*) FROM tb_finding
                          WHERE scan_id = ? AND severity IN ('CRITICAL','HIGH')");
    $st->execute([$sid]); $critHighTotal = (int) $st->fetchColumn();

    $st = $pdo->prepare('SELECT COUNT(*) FROM tb_finding WHERE scan_id = ? AND needs_restart = 1');
    $st->execute([$sid]); $restartTotal = (int) $st->fetchColumn();

    $st = $pdo->prepare('SELECT COUNT(*) FROM tb_scan_run WHERE host_id = ?');
    $st->execute([$hostId]); $scanTotal = (int) $st->fetchColumn();

    $st = $pdo->prepare('SELECT COUNT(*) FROM tb_process WHERE scan_id = ?');
    $st->execute([$sid]); $processCount = (int) $st->fetchColumn();

    $st = $pdo->prepare("SELECT COUNT(*) FROM tb_package
                          WHERE scan_id = ? AND container_id = 0 AND manager IN ('dpkg','rpm','apk')");
    $st->execute([$sid]); $packageTotal = (int) $st->fetchColumn();

    // 의존성 그래프(depgraph.php) 진입 여부 — 엣지가 있는 자산에만 링크를 건다.
    //   uk_pkg_dep_edge 좌측 접두가 (scan_id, container_id)라 scan_id 만으로도 인덱스 레인지다.
    $st = $pdo->prepare('SELECT COUNT(*) FROM tb_package_dependency WHERE scan_id = ?');
    $st->execute([$sid]); $depEdgeTotal = (int) $st->fetchColumn();

    $st = $pdo->prepare('SELECT COUNT(*) FROM tb_host_account WHERE scan_id = ? AND is_deleted = 0');
    $st->execute([$sid]); $accountTotal = (int) $st->fetchColumn();

    $st = $pdo->prepare('SELECT COUNT(*) FROM tb_container WHERE scan_id = ? AND is_deleted = 0');
    $st->execute([$sid]); $containerTotal = (int) $st->fetchColumn();

    return [
        'exposureCount' => $exposureCount, 'cceFail' => $cceFail, 'suppressedCount' => $suppressedCount,
        'vulnTotal' => $vulnTotal, 'critHighTotal' => $critHighTotal, 'restartTotal' => $restartTotal,
        'scanTotal' => $scanTotal, 'processCount' => $processCount, 'packageTotal' => $packageTotal,
        'depEdgeTotal' => $depEdgeTotal, 'accountTotal' => $accountTotal, 'containerTotal' => $containerTotal,
    ];
}

/**
 * 패키지 무결성 — 상태 한 줄 + 상위 목록만(전체 표는 만들지 않는다). 설치 패키지 탭에서만 부른다.
 *   digest 불일치(5)를 먼저 보여준다 — 권한·소유자 차이보다 무거운 관측이다.
 */
function vg_host_load_integrity_rows(PDO $pdo, int $sid): array {
    $st = $pdo->prepare('SELECT package_name, flags, file_path FROM tb_package_integrity
                          WHERE scan_id = ? ORDER BY INSTR(flags, \'5\') = 0, package_integrity_id
                          LIMIT ' . VG_HOST_INTEGRITY_TOP);
    $st->execute([$sid]);
    return $st->fetchAll();
}
