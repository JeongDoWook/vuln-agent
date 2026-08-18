<?php
declare(strict_types=1);

/**
 * findings/queries/exposure.php — 노출 탭의 조회 하나.
 *   범위 분포 · 목록 · 행별 CVE 건수(이 페이지에 보이는 행들만 한 번의 GROUP BY 로 — N+1 방지).
 */

/**
 * 노출 탭 — 범위 분포 + 목록 + 행별 CVE 건수.
 *   $f: q scope page perPage
 *   반환: scopeCounts total page rows cveCounts
 */
function vg_findings_load_exposure(PDO $pdo, array $scanIds, array $f): array {
    $q = (string) $f['q']; $scope = (string) $f['scope'];
    $page = (int) $f['page']; $perPage = (int) $f['perPage'];

    $in = implode(',', array_fill(0, count($scanIds), '?'));
    $scopeCounts = [];
    $expCveCounts = [];

    // 범위 분포 — EXTERNAL 이 몇 건인지가 이 탭의 첫 질문이다. idx_exp_scan(scan_id) 범위 집계.
    //   scope 는 NULL 을 허용하는 컬럼이라 '-'(범위 미상)로 접어 센다 — 접지 않으면 카드
    //   어디에도 없는 행이 표에만 남아 합계가 안 맞는 것처럼 보인다. 아래 필터도 같은 식이다.
    $stmt = $pdo->prepare("SELECT COALESCE(scope, '-') sc, COUNT(*) c FROM tb_exposure WHERE scan_id IN ($in) GROUP BY sc");
    $stmt->execute($scanIds);
    foreach ($stmt->fetchAll() as $r) {
        $scopeCounts[(string) $r['sc']] = (int) $r['c'];
    }

    $where  = "e.scan_id IN ($in)";
    $params = $scanIds;
    if ($scope !== '') {
        $where .= " AND COALESCE(e.scope, '-') = ?";
        $params[] = $scope;
    }
    if ($q !== '') {
        $where .= ' AND (e.proc LIKE ? OR e.exe_pkg LIKE ?)';
        $like = '%' . addcslashes($q, '%_\\') . '%';
        $params[] = $like; $params[] = $like;
    }

    $stmt = $pdo->prepare("SELECT COUNT(*) FROM tb_exposure e WHERE $where");
    $stmt->execute($params);
    $total = (int) $stmt->fetchColumn();
    if ($total > 0) { $page = min($page, (int) ceil($total / $perPage)); }
    $offset = ($page - 1) * $perPage;

    // 정렬은 host.php 의 노출 표와 같은 FIELD 순서 — EXTERNAL 이 맨 위다.
    $stmt = $pdo->prepare(
        "SELECT e.scan_id, e.container_id, e.proc, e.proto, e.bind_addr, e.port, e.scope,
                e.exe_pkg, e.loaded_pkgs, h.host_id, h.fqdn, IFNULL(c.cid, '') AS ctr
           FROM tb_exposure e
           JOIN tb_scan s ON s.scan_id = e.scan_id
           JOIN tb_host h ON h.host_id = s.host_id
           LEFT JOIN tb_container c ON c.container_id = e.container_id
          WHERE $where
          ORDER BY FIELD(e.scope,'EXTERNAL','LAN','BOUND','FILTERED','LOCAL','-'), h.fqdn, e.port
          LIMIT $perPage OFFSET $offset"
    );
    $stmt->execute($params);
    $rows = $stmt->fetchAll();

    // "이 리스너에 걸린 CVE 건수" — 노출과 취약점을 잇는 게 이 제품의 축이다.
    //   행마다 세면 N+1 이라, **이 페이지에 보이는 행들**의 (스캔·컨테이너·실행패키지)만
    //   한 번의 GROUP BY 로 읽는다. 인덱스는 uq_find(scan_id, container_id, …) 의 앞 두 컬럼까지
    //   타고 package_name 은 그 범위 안에서 걸러진다 — 대상 스캔이 이미 CVE 탭 COUNT 와
    //   같은 범위라 비용이 그 이상으로 커지지 않는다.
    $expScans = []; $expCtrs = []; $expPkgs = [];
    foreach ($rows as $r) {
        if (($r['exe_pkg'] ?? '') === '') { continue; }
        $expScans[] = (int) $r['scan_id'];
        $expCtrs[]  = (int) $r['container_id'];
        // 값 목록으로 모은다(키로 모으면 숫자로만 된 패키지명이 int 키가 되어 int 로 바인딩된다).
        $expPkgs[]  = (string) $r['exe_pkg'];
    }
    $expScans = array_values(array_unique($expScans));
    $expCtrs  = array_values(array_unique($expCtrs));
    $expPkgs  = array_values(array_unique($expPkgs));
    if ($expPkgs) {
        $ph = static fn(array $a): string => implode(',', array_fill(0, count($a), '?'));
        $stmt = $pdo->prepare(
            'SELECT scan_id, container_id, package_name, COUNT(*) c
               FROM tb_finding
              WHERE scan_id IN (' . $ph($expScans) . ')
                AND container_id IN (' . $ph($expCtrs) . ')
                AND package_name IN (' . $ph($expPkgs) . ')
              GROUP BY scan_id, container_id, package_name'
        );
        $stmt->execute(array_merge($expScans, $expCtrs, $expPkgs));
        foreach ($stmt->fetchAll() as $r) {
            $expCveCounts[$r['scan_id'] . '|' . $r['container_id'] . '|' . $r['package_name']] = (int) $r['c'];
        }
    }

    return ['scopeCounts' => $scopeCounts, 'total' => $total,
            'page' => $page, 'rows' => $rows, 'cveCounts' => $expCveCounts];
}
