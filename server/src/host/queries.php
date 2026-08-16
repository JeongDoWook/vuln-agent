<?php
declare(strict_types=1);

/**
 * host/queries.php — 자산 상세(host.php)의 탭별 조회층.
 *   각 vg_host_load_*() 는 활성 탭 하나의 데이터만 읽어 {total, rows, …} 를 돌려준다.
 *   **호출은 여전히 활성 탭 것만 한다**(host.php 의 분기) — 여기 모아 뒀다고 전부 부르면
 *   설치 패키지·컨테이너·런타임의 무거운 쿼리가 한 화면에서 함께 돌아 화면이 느려진다(PR #579).
 *   렌더는 이 파일의 책임이 아니다 — 탭별 HTML 은 host/tabs/*.php 가 갖는다.
 */

// 재시작 필요 목록도 같은 성격의 미리보기다(프로세스·패키지로 묶은 상위 일부 + 전체 건수).
const VG_HOST_STALE_TOP = 20;

// --- 탭별 데이터 조회 (?tab= 에 따라 갈리는 SQL). 각자 {total, rows, ...} 형태의 배열을 반환한다. ---

function vg_host_load_vuln_tab(PDO $pdo, int $sid, int $critHighTotal, int $perPage, int $offset, ?string $q = null): array {
    /* 성격이 다른 두 부류를 한 목록에 섞고 페이지를 나누면, 어느 한쪽은 반드시 뒤로 밀린다.
     *   - 등급순으로 정렬했더니: 커널 재부팅 건(등급이 낮다)이 2페이지로 밀려 사라졌다.
     *   - 그래서 needs_restart 를 맨 위로 올렸더니: 이번엔 **CRITICAL 이 안 보였다**
     *     (실측: web01 은 재시작 필요 건이 앞을 다 채워 CRITICAL 2건이 44페이지 뒤로 갔다).
     * 정렬로는 못 푼다 — 표를 둘로 나눈다. 각자 자기 기준으로 정렬하고, 둘 다 첫 화면에 있다.
     *   표1(주 목록·페이지네이션): CRITICAL·HIGH — 등급 → EPSS 순
     *   표2(상위 N건 + 전체보기):  재시작·재부팅 필요 — 등급이 낮아도 놓치면 안 되는 부류
     *                              (이미 패치됐는데 옛 코드가 상주해 "패치됨"으로 사라진다)
     * 검색(q)은 표1(주 목록)에만 적용한다 — 표2는 "상위 N건은 놓치지 않는다"가 목적이라
     *   필터링하면 그 의도와 충돌한다.
     */
    /* 컨테이너 **이름**(cid)까지 함께 읽는다 — 조치 상태는 스캔이 바뀌어도 유지되는 자연키
     *   (host_id, 컨테이너 이름, cve_id, 패키지명)로 붙기 때문이다. 숫자 container_id 는
     *   스캔마다 새로 발급돼 그 키로 쓸 수 없다(finding_history.php 머리주석). */
    $sel = "SELECT f.severity, f.runtime_status, f.cve_id, f.package_name, f.installed_version, f.rationale,
                   f.needs_restart, f.container_id, f.in_kev, c.epss, c.epss_percentile, c.ref_urls_json,
                   IFNULL(ctr.cid, '') AS container_cid,
               " . VG_FIXED_VERSION_SUBQ . "
              FROM tb_finding f
              LEFT JOIN tb_cve c ON c.cve_id = f.cve_id
              LEFT JOIN tb_container ctr ON ctr.container_id = f.container_id";

    $where = "f.scan_id = ? AND f.severity IN ('CRITICAL','HIGH')";
    $params = [$sid];
    if ($q !== null && $q !== '') {
        $where .= ' AND (f.cve_id LIKE ? OR f.package_name LIKE ?)';
        $params[] = '%' . $q . '%';
        $params[] = '%' . $q . '%';
    }

    if ($q !== null && $q !== '') {
        $cnt = $pdo->prepare("SELECT COUNT(*) FROM tb_finding f WHERE $where");
        $cnt->execute($params);
        $total = (int) $cnt->fetchColumn();
    } else {
        $total = $critHighTotal;
    }

    $st = $pdo->prepare(
        "$sel WHERE $where
         ORDER BY FIELD(f.severity,'CRITICAL','HIGH'), c.epss DESC, f.cve_id
         LIMIT $perPage OFFSET $offset"
    );
    $st->execute($params);
    $rows = $st->fetchAll();

    $st = $pdo->prepare(
        "$sel WHERE f.scan_id = ? AND f.needs_restart = 1
         ORDER BY FIELD(f.severity,'CRITICAL','HIGH','MEDIUM','LOW'), c.epss DESC, f.cve_id
         LIMIT " . vg_ui_detail_preview_limit()
    );
    $st->execute([$sid]);
    $restartRows = $st->fetchAll();

    return ['total' => $total, 'rows' => $rows, 'restartRows' => $restartRows];
}

function vg_host_load_runtime_tab(PDO $pdo, int $sid, int $perPage, int $offset, int $ePage, ?string $q = null): array {
    // 노출·프로세스 모두 건수가 늘 수 있어 각자 페이지네이션한다(노출은 ?epage=, 프로세스는 ?page=).
    // 컨테이너 안의 프로세스·포트도 여기 함께 있다(container_id > 0).
    //   출처를 표시하지 않으면 컨테이너의 nginx 가 호스트의 nginx 처럼 보인다 → "위치" 열.
    $q = ($q !== null && $q !== '') ? $q : null;

    $eWhere = 'e.scan_id = ?';
    $eParams = [$sid];
    if ($q !== null) {
        $eWhere .= ' AND (e.proc LIKE ? OR e.exe_pkg LIKE ?)';
        $eParams[] = '%' . $q . '%';
        $eParams[] = '%' . $q . '%';
    }
    $cnt = $pdo->prepare("SELECT COUNT(*) FROM tb_exposure e WHERE $eWhere");
    $cnt->execute($eParams);
    $exposureTotal = (int) $cnt->fetchColumn();

    // vg_toolbar() 의 기본 "초기화" 링크는 page 만 지우고 epage 는 모른다(공용 컴포넌트, 이번
    //   범위에서 손 안 댐) — 검색 초기화 후에도 epage 가 URL 에 남을 수 있다. 그 값을 신뢰해
    //   그대로 OFFSET 에 쓰면 총건수를 넘겨 빈 표가 뜬다. 여기서 유효 범위로 접어 방어한다.
    $eMaxPage = max(1, (int) ceil($exposureTotal / $perPage));
    if ($ePage > $eMaxPage) { $ePage = $eMaxPage; }
    $eOffset = ($ePage - 1) * $perPage;

    $st = $pdo->prepare("SELECT e.proc, e.proto, e.bind_addr, e.port, e.scope, e.exe_pkg, e.loaded_pkgs,
                                IFNULL(c.cid, '') AS ctr
                           FROM tb_exposure e LEFT JOIN tb_container c ON c.container_id = e.container_id
                          WHERE $eWhere
                          ORDER BY FIELD(e.scope,'EXTERNAL','LAN','BOUND','FILTERED','LOCAL','-'), e.port
                          LIMIT $perPage OFFSET $eOffset");
    $st->execute($eParams);
    $exposures = $st->fetchAll();

    $pWhere = 'p.scan_id = ?';
    $pParams = [$sid];
    if ($q !== null) {
        $pWhere .= ' AND (p.comm LIKE ? OR p.username LIKE ? OR p.exe_pkg LIKE ?)';
        $pParams[] = '%' . $q . '%';
        $pParams[] = '%' . $q . '%';
        $pParams[] = '%' . $q . '%';
    }
    $cnt = $pdo->prepare("SELECT COUNT(*) FROM tb_process p WHERE $pWhere");
    $cnt->execute($pParams);
    $total = (int) $cnt->fetchColumn();

    $st = $pdo->prepare("SELECT p.pid, p.comm, p.username, p.exe_pkg, p.loaded_pkgs,
                                IFNULL(c.cid, '') AS ctr
                           FROM tb_process p LEFT JOIN tb_container c ON c.container_id = p.container_id
                          WHERE $pWhere ORDER BY p.comm LIMIT $perPage OFFSET $offset");
    $st->execute($pParams);
    $rows = $st->fetchAll();

    // 재시작 필요(옛 .so 를 물고 있는 프로세스)는 **억제를 취소하는** 신호라 런타임 축에 세운다.
    //   검색어와 무관하게 상태를 보여준다 — "지금 재시작이 필요한가" 는 목록 필터의 결과가 아니다.
    $stale = vg_stale_lib_summary($pdo, $sid, VG_HOST_STALE_TOP);

    return ['total' => $total, 'exposures' => $exposures, 'exposureTotal' => $exposureTotal,
            'rows' => $rows, 'ePage' => $ePage, 'stale' => $stale];
}

function vg_host_load_cce_tab(PDO $pdo, int $sid, int $perPage, int $offset, ?string $q = null): array {
    $where = 'f.scan_id = ?';
    $params = [$sid];
    if ($q !== null && $q !== '') {
        $where .= ' AND (f.code LIKE ? OR f.title LIKE ? OR f.ssg_rule_id LIKE ?)';
        $params[] = '%' . $q . '%';
        $params[] = '%' . $q . '%';
        $params[] = '%' . $q . '%';
    }
    $st = $pdo->prepare("SELECT COUNT(*) FROM tb_cce_finding f WHERE $where");
    $st->execute($params); $total = (int) $st->fetchColumn();
    // 점검 항목을 **검증된 룰셋(SSG)** 에 묶어 두었으므로, 그 룰의 기준 참조(CIS/NIST/STIG)를
    //   함께 읽어 화면이 근거를 인용할 수 있게 한다. 묶이지 않은 항목은 refs 가 비어 있다.
    $st = $pdo->prepare(
        "SELECT f.code, f.ssg_rule_id, f.title, f.result, f.severity, f.evidence, f.rationale,
                r.refs_json, r.title AS ssg_title
           FROM tb_cce_finding f
           LEFT JOIN tb_compliance_rule r ON r.rule_id = f.ssg_rule_id AND r.is_deleted = 0
          WHERE $where
          ORDER BY FIELD(f.result,'FAIL','NA','PASS'), FIELD(f.severity,'HIGH','MEDIUM','LOW'), f.code
          LIMIT $perPage OFFSET $offset"
    );
    $st->execute($params);
    $rows = $st->fetchAll();

    return ['total' => $total, 'rows' => $rows];
}

function vg_host_load_suppressed_tab(PDO $pdo, int $sid, int $suppressedCount, int $perPage, int $offset, ?string $q = null): array {
    $where = 'sf.scan_id = ?';
    $params = [$sid];
    if ($q !== null && $q !== '') {
        $where .= ' AND (sf.cve_id LIKE ? OR sf.package_name LIKE ?)';
        $params[] = '%' . $q . '%';
        $params[] = '%' . $q . '%';
    }

    if ($q !== null && $q !== '') {
        $cnt = $pdo->prepare("SELECT COUNT(*) FROM tb_suppressed_finding sf WHERE $where");
        $cnt->execute($params);
        $total = (int) $cnt->fetchColumn();
    } else {
        $total = $suppressedCount;
    }

    $st = $pdo->prepare(
        "SELECT cve_id, package_name, installed_version, base_severity, in_kev, suppress_reason,
                CASE WHEN sf.container_id = 0 THEN 'HOST'
                     ELSE COALESCE((SELECT c.name FROM tb_container c WHERE c.container_id = sf.container_id), CONCAT('container #', sf.container_id)) END AS target
           FROM tb_suppressed_finding sf WHERE $where
          ORDER BY FIELD(base_severity,'CRITICAL','HIGH','MEDIUM','LOW'), cve_id
          LIMIT $perPage OFFSET $offset"
    );
    $st->execute($params);
    $rows = $st->fetchAll();

    // 근거를 **행마다** 읽을 수 있게 한다: 어느 겹이 억제했는지(분류) + 그 겹의 원 데이터.
    //   원 데이터는 이 페이지의 행들만 한 번에 읽는다(N+1 금지 — suppression.php 참고).
    foreach ($rows as $i => $r) {
        $rows[$i]['layer'] = vg_suppress_layer($r['suppress_reason'] ?? null);
    }

    return [
        'total'    => $total,
        'rows'     => $rows,
        'evidence' => vg_suppress_evidence_map($pdo, $sid, $rows),
        'layers'   => vg_suppress_layer_counts($pdo, $sid),
    ];
}

/**
 * 스캔 이력 탭의 리소스 추이 — 표와 같은 tb_scan_run 을 시간순으로만 다시 읽는다.
 *   최신 N건을 DESC 로 뽑은 뒤 뒤집는다 — 표는 최신이 위, 차트는 최신이 오른쪽이라 방향이 반대다.
 *   (표는 페이지네이션되므로 차트가 그 페이지에 종속되면 안 된다 → 별도 조회다.)
 */
function vg_host_load_resource_trend(PDO $pdo, int $hostId): array {
    $st = $pdo->prepare(
        'SELECT collected_at, peak_rss_mb, cpu_seconds, mem_total_mb, cpu_cores, elapsed_seconds
           FROM tb_scan_run WHERE host_id = ? ORDER BY scan_run_id DESC LIMIT ' . vg_ui_trend_limit()
    );
    $st->execute([$hostId]);
    $resourceScans = array_reverse($st->fetchAll());

    // 스캔(행) 단위로 먼저 %를 계산한다 — 절대치를 먼저 모아 나중에 나누면 스캔마다
    //   다른 스펙(mem_total_mb/cpu_cores)이 섞여 값이 왜곡된다. 필요값이 하나라도 없거나
    //   분모가 0이면 그 스캔은 이 지표에서 제외(NULL) — 0/100 대체 금지.
    foreach ($resourceScans as &$s) {
        $s['mem_pct'] = vg_agent_mem_pct($s['peak_rss_mb'], $s['mem_total_mb']);
        $s['cpu_pct'] = vg_agent_cpu_pct($s['cpu_seconds'], $s['elapsed_seconds'], $s['cpu_cores']);
    }
    unset($s);

    return $resourceScans;
}

function vg_host_load_packages_tab(PDO $pdo, int $scanId, int $perPage, int $offset, string $q): array {
    $where = "scan_id = ? AND container_id = 0 AND manager IN ('dpkg','rpm','apk')";
    $params = [$scanId];
    if ($q !== '') {
        $where .= ' AND (name LIKE ? OR source_pkg LIKE ? OR origin LIKE ? OR vendor LIKE ?)';
        $like = '%' . $q . '%';
        array_push($params, $like, $like, $like, $like);
    }
    $st = $pdo->prepare("SELECT COUNT(*) FROM tb_package WHERE $where");
    $st->execute($params);
    $total = (int) $st->fetchColumn();

    $st = $pdo->prepare(
        "SELECT manager,name,version,arch,source_pkg,source_version,origin,vendor
           FROM tb_package WHERE $where
          ORDER BY name,arch,version LIMIT $perPage OFFSET $offset"
    );
    $st->execute($params);
    return ['total' => $total, 'rows' => $st->fetchAll()];
}

/**
 * 컨테이너 탭 — 이 스캔이 찾아낸 컨테이너 대장.
 *   에이전트는 k8s 위치(namespace/pod/container)·워크로드 참조·이미지 다이제스트·SBOM 까지 보내지만
 *   **도커 단독 호스트에서는 이 값들이 전부 비어 있다.** 그래서 열로 세우지 않고, 값이 있는 행에서만
 *   셀 안에 한 줄로 덧붙인다(렌더 쪽) — 빈칸만 늘어선 표를 만들지 않기 위해서다.
 */
function vg_host_load_containers_tab(PDO $pdo, int $scanId, int $perPage, int $offset, string $q): array {
    $where  = 'scan_id = ? AND is_deleted = 0';
    $params = [$scanId];
    // 대장(표·카드)과 별개로 컨테이너별 심각도 분포를 **한 번의 GROUP BY** 로 가져온다.
    //   행마다 세면 N+1 이 되고, 페이지 행에만 맞춰 세면 쿼리를 페이지마다 다시 조립해야 한다.
    //   uq_find 좌측 접두가 (scan_id, container_id) 라 이 집계는 인덱스 그대로다.
    $sev = $pdo->prepare(
        'SELECT container_id, severity, COUNT(*) c
           FROM tb_finding WHERE scan_id = ? AND container_id > 0
          GROUP BY container_id, severity'
    );
    $sev->execute([$scanId]);
    $sevByContainer = [];
    foreach ($sev->fetchAll() as $r) {
        $sevByContainer[(int) $r['container_id']][(string) $r['severity']] = (int) $r['c'];
    }

    if ($q !== '') {
        $where .= ' AND (cid LIKE ? OR name LIKE ? OR image LIKE ?
                         OR k8s_namespace LIKE ? OR k8s_pod LIKE ? OR workload_ref LIKE ?)';
        $like = '%' . $q . '%';
        array_push($params, $like, $like, $like, $like, $like, $like);
    }

    $st = $pdo->prepare("SELECT COUNT(*) FROM tb_container WHERE $where");
    $st->execute($params);
    $total = (int) $st->fetchColumn();

    // ORDER BY cid — uq_container(scan_id, cid) 좌측 접두가 scan_id 라 정렬까지 인덱스가 받는다.
    $st = $pdo->prepare(
        "SELECT container_id, cid, name, image, image_digest, k8s_namespace, k8s_pod, k8s_container,
                workload_ref, runtime_state, sbom_format, sbom_hash,
                os_id, os_version, manager, pkg_count
           FROM tb_container WHERE $where
          ORDER BY cid LIMIT $perPage OFFSET $offset"
    );
    $st->execute($params);
    return ['total' => $total, 'rows' => $st->fetchAll(), 'sevByContainer' => $sevByContainer];
}

/**
 * 계정 탭 — 이 스캔의 계정 대장 + 파생 컴플라이언스 판정.
 *   판정은 목록 한 페이지가 아니라 **전 계정**을 봐야 한다(90일 미로그인 계정이 3페이지에 있어도
 *   판정은 나와야 한다) → 판정용으로 계정 전체를 따로 읽는다. 호스트당 계정은 수십 개 규모지만
 *   상한을 걸어 비정상 데이터가 화면을 못 죽이게 한다.
 */
const VG_HOST_ACCOUNT_JUDGE_MAX = 5000;

function vg_host_load_accounts_tab(PDO $pdo, int $scanId, int $perPage, int $offset, string $q, string $filter): array {
    $where  = 'scan_id = ? AND is_deleted = 0';
    $params = [$scanId];
    if ($q !== '') {
        $where .= ' AND (username LIKE ? OR shell LIKE ? OR home LIKE ?)';
        $like = '%' . $q . '%';
        array_push($params, $like, $like, $like);
    }
    if ($filter === 'sudo') {
        $where .= ' AND is_sudoer = 1';
    } elseif ($filter === 'locked') {
        $where .= ' AND is_locked = 1';
    } elseif ($filter === 'human') {
        $where .= ' AND is_system = 0';
    } elseif ($filter === 'stale') {
        // 미로그인 = 로그인 이력이 없거나 임계일을 넘긴 것. 시스템 계정은 애초에 로그인하지 않는다.
        $where .= ' AND is_system = 0 AND (never_logged_in = 1 OR last_login_at < DATE_SUB(NOW(), INTERVAL ? DAY))';
        $params[] = vg_account_stale_login_days();
    }

    $st = $pdo->prepare("SELECT COUNT(*) FROM tb_host_account WHERE $where");
    $st->execute($params);
    $total = (int) $st->fetchColumn();

    $cols = 'username, uid, gid, shell, home, is_locked, is_sudoer, is_system,
             pw_last_change, pw_max_days, expire_date, last_login_at, never_logged_in';
    $st = $pdo->prepare(
        "SELECT $cols FROM tb_host_account WHERE $where
          ORDER BY is_system, username LIMIT $perPage OFFSET $offset"
    );
    $st->execute($params);
    $rows = $st->fetchAll();

    $limit = VG_HOST_ACCOUNT_JUDGE_MAX;
    $st = $pdo->prepare(
        "SELECT $cols FROM tb_host_account WHERE scan_id = ? AND is_deleted = 0
          ORDER BY username LIMIT $limit"
    );
    $st->execute([$scanId]);
    $all = $st->fetchAll();

    return ['total' => $total, 'rows' => $rows, 'judgments' => vg_account_judgments($all), 'allCount' => count($all)];
}

function vg_host_load_scans_tab(PDO $pdo, int $hostId, int $scanTotal, int $perPage, int $offset): array {
    $total = $scanTotal;
    $st = $pdo->prepare(
        "SELECT scan_run_id, scan_id, collected_at, received_at, content_changed,
                package_count, exposure_count, agent_version, elapsed_seconds, peak_rss_mb, cpu_seconds
           FROM tb_scan_run WHERE host_id = ? ORDER BY scan_run_id DESC LIMIT $perPage OFFSET $offset"
    );
    $st->execute([$hostId]);
    $rows = $st->fetchAll();

    $ids = [];
    foreach ($rows as $s) { $ids[] = (int) $s['scan_id']; }
    $sevByScan = vg_sev_by_scan_ids($pdo, $ids);

    return [
        'total' => $total,
        'rows' => $rows,
        'sevByScan' => $sevByScan,
        'resourceScans' => vg_host_load_resource_trend($pdo, $hostId),
    ];
}
