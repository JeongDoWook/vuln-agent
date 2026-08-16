<?php
declare(strict_types=1);

/**
 * container/queries.php — 컨테이너 상세(container.php)의 탭별 조회층.
 *   각 vg_container_load_*() 는 활성 탭 하나의 데이터만 읽어 {total, rows, …} 를 돌려준다
 *   (host/queries.php 와 같은 규약). **호출은 활성 탭 것만** — container.php 의 분기가 정한다.
 *   렌더는 이 파일의 책임이 아니다 — 탭별 HTML 은 container/tabs/*.php 가 갖는다.
 */

/**
 * 취약점 탭 — 이 컨테이너의 tb_finding.
 *   uq_find 좌측 접두가 (scan_id, container_id) 라 이 둘로 좁히면 인덱스를 그대로 탄다.
 *   호스트 화면과 달리 등급을 CRITICAL·HIGH 로 자르지 않는다 — 컨테이너 하나의 건수는
 *   자산 전체보다 작아 한 표에 담기고, 잘라 두면 "이미지에 무엇이 남아 있나" 를 못 센다.
 */
function vg_container_load_vuln_tab(PDO $pdo, int $sid, int $ctrId, int $perPage, int $offset, string $q): array {
    $where  = 'f.scan_id = ? AND f.container_id = ?';
    $params = [$sid, $ctrId];
    if ($q !== '') {
        $where .= ' AND (f.cve_id LIKE ? OR f.package_name LIKE ?)';
        $like = '%' . $q . '%';
        array_push($params, $like, $like);
    }

    $st = $pdo->prepare("SELECT COUNT(*) FROM tb_finding f WHERE $where");
    $st->execute($params);
    $total = (int) $st->fetchColumn();

    $st = $pdo->prepare(
        "SELECT f.severity, f.runtime_status, f.cve_id, f.package_name, f.installed_version,
                f.rationale, f.needs_restart, f.in_kev, c.epss, c.epss_percentile, c.ref_urls_json,
                " . VG_FIXED_VERSION_SUBQ . "
           FROM tb_finding f
           LEFT JOIN tb_cve c ON c.cve_id = f.cve_id
          WHERE $where
          ORDER BY FIELD(f.severity,'CRITICAL','HIGH','MEDIUM','LOW'), c.epss DESC, f.cve_id
          LIMIT $perPage OFFSET $offset"
    );
    $st->execute($params);
    return ['total' => $total, 'rows' => $st->fetchAll()];
}

/** 패키지 탭 — 이 컨테이너 안에 설치된 것. 호스트 것(container_id = 0)과 섞지 않는다. */
function vg_container_load_pkg_tab(PDO $pdo, int $sid, int $ctrId, int $perPage, int $offset, string $q): array {
    $where  = 'scan_id = ? AND container_id = ? AND is_deleted = 0';
    $params = [$sid, $ctrId];
    if ($q !== '') {
        $where .= ' AND (name LIKE ? OR source_pkg LIKE ? OR origin LIKE ? OR vendor LIKE ?)';
        $like = '%' . $q . '%';
        array_push($params, $like, $like, $like, $like);
    }

    $st = $pdo->prepare("SELECT COUNT(*) FROM tb_package WHERE $where");
    $st->execute($params);
    $total = (int) $st->fetchColumn();

    $st = $pdo->prepare(
        "SELECT manager, name, version, arch, source_pkg, source_version, origin, vendor, license
           FROM tb_package WHERE $where
          ORDER BY name, arch, version LIMIT $perPage OFFSET $offset"
    );
    $st->execute($params);
    return ['total' => $total, 'rows' => $st->fetchAll()];
}

/**
 * 런타임 탭 — 이 컨테이너 안에서 실제로 돌고 있는 것.
 *   노출(?epage=)과 프로세스(?page=)를 각자 페이지네이션한다(host.php 런타임 탭과 같은 규약).
 */
function vg_container_load_runtime_tab(PDO $pdo, int $sid, int $ctrId, int $perPage, int $offset, int $ePage, string $q): array {
    $eWhere  = 'scan_id = ? AND container_id = ?';
    $eParams = [$sid, $ctrId];
    if ($q !== '') {
        $eWhere .= ' AND (proc LIKE ? OR exe_pkg LIKE ?)';
        $like = '%' . $q . '%';
        array_push($eParams, $like, $like);
    }
    $st = $pdo->prepare("SELECT COUNT(*) FROM tb_exposure WHERE $eWhere");
    $st->execute($eParams);
    $exposureTotal = (int) $st->fetchColumn();

    // 검색을 초기화해도 ?epage= 는 URL 에 남을 수 있다(vg_toolbar 의 초기화는 page 만 지운다).
    //   그 값을 그대로 OFFSET 에 쓰면 총건수를 넘겨 빈 표가 뜬다 — 유효 범위로 접는다.
    $eMaxPage = max(1, (int) ceil($exposureTotal / $perPage));
    if ($ePage > $eMaxPage) { $ePage = $eMaxPage; }
    $eOffset = ($ePage - 1) * $perPage;

    $st = $pdo->prepare(
        "SELECT proc, proto, bind_addr, port, scope, exe_pkg, loaded_pkgs
           FROM tb_exposure WHERE $eWhere
          ORDER BY FIELD(scope,'EXTERNAL','LAN','BOUND','FILTERED','LOCAL','-'), port
          LIMIT $perPage OFFSET $eOffset"
    );
    $st->execute($eParams);
    $exposures = $st->fetchAll();

    $pWhere  = 'scan_id = ? AND container_id = ?';
    $pParams = [$sid, $ctrId];
    if ($q !== '') {
        $pWhere .= ' AND (comm LIKE ? OR username LIKE ? OR exe_pkg LIKE ?)';
        $like = '%' . $q . '%';
        array_push($pParams, $like, $like, $like);
    }
    $st = $pdo->prepare("SELECT COUNT(*) FROM tb_process WHERE $pWhere");
    $st->execute($pParams);
    $total = (int) $st->fetchColumn();

    $st = $pdo->prepare(
        "SELECT pid, comm, username, exe_pkg, loaded_pkgs
           FROM tb_process WHERE $pWhere ORDER BY comm LIMIT $perPage OFFSET $offset"
    );
    $st->execute($pParams);

    return ['total' => $total, 'rows' => $st->fetchAll(), 'exposures' => $exposures,
            'exposureTotal' => $exposureTotal, 'ePage' => $ePage];
}
