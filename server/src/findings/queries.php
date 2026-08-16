<?php
declare(strict_types=1);

/**
 * findings/queries.php — 탐지 결과 화면의 조회층. **탭마다 함수 하나**다.
 *
 *   ⚠ 세 탭을 한 함수로 "통합" 하지 마라. 세 표(tb_finding·tb_cce_finding·tb_exposure)를
 *   UNION 하면 큰 tb_finding 을 섞어 정렬·페이징하게 되어 인덱스가 죽는다 — 대시보드에서
 *   파생테이블로 리라이트했다가 **235ms → 42초**가 된 운영 실측이 있다(PR #555). 탭마다
 *   자기 쿼리 하나가 정답이고, 그래서 이 파일의 함수도 탭 수만큼이다.
 *
 *   각 함수는 findings.php 가 이미 검증한 값(화이트리스트를 통과한 필터·대상 스캔 집합)만
 *   받는다. SQL·바인딩 순서·정렬은 findings.php 에 있던 것을 그대로 옮긴 것이다.
 */

/** 호스트별 최신 스캔 (삭제된 호스트 제외) — 통합 뷰의 대상 스캔 집합. */
function vg_findings_load_hosts(PDO $pdo): array {
    return $pdo->query(
        'SELECT h.host_id, h.fqdn, h.os_id, h.os_version, t.mid AS scan_id
           FROM tb_host h
           JOIN ' . vg_latest_scan_subq() . ' t ON t.host_id = h.host_id
          WHERE h.is_deleted = 0
          ORDER BY h.last_seen DESC, h.fqdn'
    )->fetchAll();
}

/**
 * 최신 스캔에 딸린 컨테이너 — "판정 불가" 경고의 대상이다.
 *   CVE 탭 전용이라 다른 탭에서는 호출하지 않는다(안 쓰는 집계를 매 요청에 붙이지 않는다).
 */
function vg_findings_load_containers(PDO $pdo): array {
    return $pdo->query(
        'SELECT h.fqdn, c.cid, c.os_id, c.os_version, c.manager,
                CASE WHEN EXISTS (
                    SELECT 1 FROM tb_package p
                     WHERE p.scan_id = c.scan_id AND p.container_id = c.container_id
                ) THEN 1 ELSE c.pkg_count END AS pkg_count
           FROM tb_container c
           JOIN tb_scan s ON s.scan_id = c.scan_id
           JOIN tb_host h ON h.host_id = s.host_id
           JOIN ' . vg_latest_scan_subq() . ' t ON t.mid = s.scan_id
          WHERE h.is_deleted = 0
          ORDER BY h.fqdn, c.cid'
    )->fetchAll();
}

/**
 * CVE 탭 — 등급 KPI · 행동 큐 · 목록.
 *   $f: q sev st fx fst sort ctrId page perPage (findings.php 가 검증한 값)
 *   반환: counts actionCounts overdueFindingIds total rows notes firstSeen policy ctrLabel typeCount
 */
function vg_findings_load_cve(PDO $pdo, array $scanIds, array $targetHostIds, array $f): array {
    $q = (string) $f['q']; $sev = (string) $f['sev']; $st = (string) $f['st'];
    $fx = (string) $f['fx']; $fst = (string) $f['fst']; $sort = (string) $f['sort'];
    $ctrId = $f['ctrId']; $page = (int) $f['page']; $perPage = (int) $f['perPage'];

    $in = implode(',', array_fill(0, count($scanIds), '?'));
    $counts = ['CRITICAL'=>0,'HIGH'=>0,'MEDIUM'=>0,'LOW'=>0];
    $actionCounts = ['high' => 0, 'kev' => 0, 'external' => 0, 'restart' => 0, 'overdue' => 0];
    $overdueFindingIds = [];
    $ctrLabel = null;

    $policy = vg_compliance_policy();
    $statusJoin = "LEFT JOIN tb_finding_status fs
                          ON fs.host_id = s.host_id
                         AND fs.container_ref = COALESCE(ctr.cid, '')
                         AND fs.cve_id = f.cve_id
                         AND fs.package_name = f.package_name";

    // KPI 는 필터 무관 — 대상 스캔 전체 기준
    $typeCount = 0;
    $stmt = $pdo->prepare("SELECT severity, COUNT(*) c FROM tb_finding WHERE scan_id IN ($in) GROUP BY severity");
    $stmt->execute($scanIds);
    foreach ($stmt->fetchAll() as $r) {
        // 탭 뱃지의 CVE 건수는 이 집계를 그대로 합쳐 쓴다(같은 값을 두 번 세지 않는다).
        //   등급 카드는 알려진 4종만 세지만, 뱃지는 그 밖의 등급이 와도 빠지지 않게 전부 더한다.
        $typeCount = (int) $typeCount + (int) $r['c'];
        if (isset($counts[$r['severity']])) { $counts[$r['severity']] = (int) $r['c']; }
    }
    $actionCounts['high'] = $counts['CRITICAL'] + $counts['HIGH'];

    // 행동 큐의 신호는 모두 같은 대상 스캔 집합에서 센다. 기한 초과는 대시보드와 같은
    // High 이상 KEV 모집단이며 DONE·EXCEPTED는 제외한다.
    $stmt = $pdo->prepare(
        "SELECT SUM(f.in_kev = 1) kev, SUM(f.runtime_status = 'EXTERNAL') external_cnt,
                SUM(f.needs_restart = 1) restart_cnt
           FROM tb_finding f WHERE f.scan_id IN ($in) AND f.is_deleted = 0"
    );
    $stmt->execute($scanIds);
    $queueAgg = $stmt->fetch() ?: [];
    $actionCounts['kev'] = (int) ($queueAgg['kev'] ?? 0);
    $actionCounts['external'] = (int) ($queueAgg['external_cnt'] ?? 0);
    $actionCounts['restart'] = (int) ($queueAgg['restart_cnt'] ?? 0);

    $stmt = $pdo->prepare(
        "SELECT f.finding_id, s.host_id, COALESCE(ctr.cid, '') cid, f.cve_id, f.package_name,
                fs.status
           FROM tb_finding f
           JOIN tb_scan s ON s.scan_id = f.scan_id
           LEFT JOIN tb_container ctr ON ctr.container_id = f.container_id
           $statusJoin
          WHERE f.scan_id IN ($in) AND f.is_deleted = 0 AND f.in_kev = 1
            AND f.severity IN ('CRITICAL','HIGH')"
    );
    $stmt->execute($scanIds);
    $overdueCandidates = $stmt->fetchAll();
    $overdueKeys = [];
    foreach ($overdueCandidates as $candidate) {
        if (in_array((string) ($candidate['status'] ?? ''), ['DONE', 'EXCEPTED'], true)) { continue; }
        $overdueKeys[] = [(int) $candidate['host_id'], (string) $candidate['cid'],
                          (string) $candidate['cve_id'], (string) $candidate['package_name']];
    }
    $overdueSeen = vg_finding_first_seen_map($pdo, $overdueKeys, vg_finding_sla_lookback_days($policy));
    $kevDays = vg_finding_sla_days(true, 'CRITICAL', $policy);
    foreach ($overdueCandidates as $candidate) {
        if (in_array((string) ($candidate['status'] ?? ''), ['DONE', 'EXCEPTED'], true)) { continue; }
        $key = vg_finding_status_key((int) $candidate['host_id'], (string) $candidate['cid'],
                                     (string) $candidate['cve_id'], (string) $candidate['package_name']);
        $days = $overdueSeen[$key]['days'] ?? null;
        if ($days !== null && $kevDays !== null && (int) $days > $kevDays) {
            $overdueFindingIds[] = (int) $candidate['finding_id'];
        }
    }
    $actionCounts['overdue'] = count($overdueFindingIds);

    // 필터 WHERE 조립 (COUNT 와 목록 쿼리에 동일하게 사용)
    $where  = "f.scan_id IN ($in)";
    $params = $scanIds;
    if ($ctrId !== null) {
        // uq_find 가 (scan_id, container_id, …) 라 scan_id 범위 뒤 두 번째 컬럼 등치다 —
        //   IN 리스트 패턴을 그대로 두고 인덱스도 더 좁게 탄다.
        $where .= ' AND f.container_id = ?';
        $params[] = $ctrId;
        if ($ctrId === 0) {
            $ctrLabel = '호스트 자신(컨테이너 제외)';
        } else {
            $s = $pdo->prepare('SELECT cid FROM tb_container WHERE container_id = ?');
            $s->execute([$ctrId]);
            $cid = $s->fetchColumn();
            $ctrLabel = $cid !== false ? '컨테이너 ' . (string) $cid : '컨테이너 #' . $ctrId;
        }
    }
    if ($q !== '') {
        $where .= ' AND (f.cve_id LIKE ? OR f.package_name LIKE ?)';
        $params[] = '%' . $q . '%';
        $params[] = '%' . $q . '%';
    }
    if ($sev !== '') {
        if ($sev === 'HIGH+') {
            $where .= " AND f.severity IN ('CRITICAL','HIGH')";
        } else {
            $where .= ' AND f.severity = ?';
            $params[] = $sev;
        }
    }
    if ($st !== '') {
        $where .= ' AND f.runtime_status = ?';
        $params[] = $st;
    }
    // 조치 가능성 필터 — 벤더가 수정본을 안 낸 CVE(no_fix)는 "지금 할 수 있는 일이 없는" 것이다.
    //   기본은 전부 보여주되 **조치 가능한 것을 위로 올린다**(아래 ORDER BY).
    //   섞어서 등급순으로만 세우면 조치 불가 수백 건이 고칠 수 있는 몇 건을 덮어버린다.
    if ($fx === 'action')  { $where .= ' AND f.no_fix = 0'; }
    if ($fx === 'nofix')   { $where .= ' AND f.no_fix = 1'; }
    // 재시작·재부팅만 하면 되는 것 — 자산 상세의 "전체 보기" 가 여기로 온다.
    if ($fx === 'restart') { $where .= ' AND f.needs_restart = 1'; }
    if ($fx === 'kev')     { $where .= ' AND f.in_kev = 1'; }
    if ($fx === 'overdue') {
        $where .= $overdueFindingIds
            ? ' AND f.finding_id IN (' . implode(',', array_map('intval', $overdueFindingIds)) . ')'
            : ' AND 1 = 0';
    }

    // 조치 상태는 스캔이 바뀌어도 유지되는 **자연키**로 붙는다(host_id·컨테이너 이름·CVE·패키지) —
    //   tb_finding.finding_id 는 스캔마다 새로 발급되는 surrogate PK 라 붙일 수 없다.
    //   조인은 한 번뿐이고, 목록은 이미 페이지네이션돼 있으므로 현재 페이지 범위만 걸린다.
    //   uq_finding_status 가 host_id 선두라 이 조인은 그 유니크 인덱스를 탄다.
    // 기록이 없는 조합은 행 자체가 없다 = 미조치(OPEN). 그래서 OPEN 필터만 NULL 을 함께 받는다
    //   (3.8만 건에 OPEN 행을 미리 깔지 않는다는 설계의 대가를 여기서 한 줄로 치른다).
    $countFrom = 'tb_finding f';
    if ($fst !== '') {
        // COUNT 는 평소 조인이 없다 — 상태 필터가 걸렸을 때만 같은 조인을 붙여 목록과 수를 맞춘다.
        $countFrom = "tb_finding f
                      JOIN tb_scan s ON s.scan_id = f.scan_id
                      LEFT JOIN tb_container ctr ON ctr.container_id = f.container_id
                      $statusJoin";
        $where .= $fst === 'OPEN' ? " AND (fs.status IS NULL OR fs.status = 'OPEN')" : ' AND fs.status = ?';
        if ($fst !== 'OPEN') { $params[] = $fst; }
    }

    $stmt = $pdo->prepare("SELECT COUNT(*) FROM $countFrom WHERE $where");
    $stmt->execute($params);
    $total = (int) $stmt->fetchColumn();

    $offset = ($page - 1) * $perPage;

    // 조치 기한 기준일은 설정값을 그대로 읽는다(compliance 화면과 같은 숫자여야 한다).
    /* 기한 임박순 정렬 — 남은 일수는 "최초 발견 시각 + 등급별 기한" 이라 컬럼 하나로는 못 센다.
     *   그래서 이 정렬을 고른 경우에만, 대상 호스트의 역산 구간 안 스캔을 묶어 최초 시각을
     *   집계한 파생표를 조인한다(기본 정렬에서는 아예 붙지 않는다 — 목록의 기본 응답을
     *   무겁게 만들지 않는다). 화면에 찍는 값은 아래 페이지 단위 집계가 따로 준다. */
    $dueJoin = ''; $dueParams = []; $selectParams = [];
    $orderBy = "f.no_fix ASC, FIELD(f.severity,'CRITICAL','HIGH','MEDIUM','LOW'), c.epss DESC, f.cvss DESC, h.fqdn";
    $slaCase = "CASE WHEN f.in_kev = 1 THEN ? WHEN f.severity = 'CRITICAL' THEN ?
                     WHEN f.severity = 'HIGH' THEN ? ELSE NULL END";
    if ($sort === 'due') {
        $dueHostIds = $targetHostIds ?: [0];
        $hostIn = implode(',', array_fill(0, count($dueHostIds), '?'));
        $dueJoin = "LEFT JOIN (
                        SELECT s2.host_id AS h_id, COALESCE(c2.cid, '') AS c_ref,
                               f2.cve_id AS c_cve, f2.package_name AS c_pkg,
                               MIN(COALESCE(s2.received_at, s2.collected_at)) AS first_seen
                          FROM tb_finding f2
                          JOIN tb_scan s2 ON s2.scan_id = f2.scan_id AND s2.is_deleted = 0
                          LEFT JOIN tb_container c2 ON c2.container_id = f2.container_id
                         WHERE f2.is_deleted = 0 AND s2.host_id IN ($hostIn)
                           AND COALESCE(s2.received_at, s2.collected_at) >= DATE_SUB(NOW(), INTERVAL ? DAY)
                         GROUP BY s2.host_id, c_ref, f2.cve_id, f2.package_name
                    ) fsn ON fsn.h_id = s.host_id AND fsn.c_ref = COALESCE(ctr.cid, '')
                         AND fsn.c_cve = f.cve_id AND fsn.c_pkg = f.package_name";
        $dueParams = array_merge($dueHostIds, [vg_finding_sla_lookback_days($policy)]);
        // 기한 없는 등급(MEDIUM·LOW)과 최초 시각 미상은 맨 뒤로 — 알 수 없는 것을 급한 척하지 않는다.
        $selectParams = [$policy['kev'], $policy['crit'], $policy['high']];
        $orderBy = 'due_at IS NULL, due_at ASC, ' . $orderBy;
    }
    $dueSelect = $sort === 'due'
        ? ", DATE_ADD(fsn.first_seen, INTERVAL $slaCase DAY) AS due_at"
        : '';

    $stmt = $pdo->prepare(
        // 목록이 안 쓰는 값은 실어 오지 않는다: 요약(summary)·EPSS 백분위·참조 URL(JSON)·
        //   판정 출처(match_source)는 전부 상세(finding_history.php)가 보여준다.
        //   특히 ref_urls_json 은 CVE 한 건당 수 KB 짜리 JSON 이라 페이지 크기에 그대로 실렸다.
        "SELECT f.*, h.host_id, h.fqdn, c.epss,
                ctr.cid AS container_cid, ctr.image AS container_image,
                CASE WHEN f.container_id = 0 THEN s.os_id ELSE ctr.os_id END AS package_os_id,
                CASE WHEN f.container_id = 0 THEN s.os_version ELSE ctr.os_version END AS package_os_version,
                fe.fixed_version AS evidence_fixed_version,
                fs.status AS finding_status, fs.note AS finding_status_note
                $dueSelect,
            " . VG_FIXED_VERSION_SUBQ . "
         FROM tb_finding f
         JOIN tb_scan s ON s.scan_id = f.scan_id
         JOIN tb_host h ON h.host_id = s.host_id
         LEFT JOIN tb_container ctr ON ctr.container_id = f.container_id
         LEFT JOIN tb_cve c ON c.cve_id = f.cve_id
         LEFT JOIN tb_finding_evidence fe ON fe.finding_id = f.finding_id
         $statusJoin
         $dueJoin
         WHERE $where
         ORDER BY $orderBy
         LIMIT $perPage OFFSET $offset"
    );
    $stmt->execute(array_merge($selectParams, $dueParams, $params));
    $rows = $stmt->fetchAll();

    // 사람이 남긴 미조치 사유는 이 페이지에 보이는 행들만 한 번에 읽는다(N+1 방지).
    $noteKeys = [];
    foreach ($rows as $r) {
        $noteKeys[] = [(int) $r['host_id'], (string) ($r['container_cid'] ?? ''),
                       (string) $r['cve_id'], (string) $r['package_name']];
    }
    $notes = vg_remediation_notes_map($pdo, $noteKeys);

    // 조치 기한의 기준일(최초 발견 시각)도 이 페이지에 보이는 행들만 한 번에 읽는다(N+1 방지).
    //   기한이 있는 등급(KEV·CRITICAL·HIGH)만 물어본다 — MEDIUM·LOW 는 기한 자체가 없어
    //   되짚을 이유가 없다(그만큼 조회 대상이 준다).
    $slaKeys = [];
    foreach ($rows as $r) {
        if (vg_finding_sla_days((bool) $r['in_kev'], (string) $r['severity'], $policy) === null) { continue; }
        $slaKeys[] = [(int) $r['host_id'], (string) ($r['container_cid'] ?? ''),
                      (string) $r['cve_id'], (string) $r['package_name']];
    }
    $firstSeen = vg_finding_first_seen_map($pdo, $slaKeys, vg_finding_sla_lookback_days($policy));

    return ['counts' => $counts, 'actionCounts' => $actionCounts,
            'overdueFindingIds' => $overdueFindingIds, 'total' => $total, 'rows' => $rows,
            'notes' => $notes, 'firstSeen' => $firstSeen, 'policy' => $policy,
            'ctrLabel' => $ctrLabel, 'typeCount' => $typeCount];
}

/**
 * 보안설정(CCE) 탭 — 결과 분포 + 목록.
 *   $f: q sev res page perPage
 *   반환: resultCounts typeCount total page rows
 */
function vg_findings_load_cce(PDO $pdo, array $scanIds, array $f): array {
    $q = (string) $f['q']; $sev = (string) $f['sev']; $res = (string) $f['res'];
    $page = (int) $f['page']; $perPage = (int) $f['perPage'];

    $in = implode(',', array_fill(0, count($scanIds), '?'));
    $cceResultCounts = ['FAIL'=>0, 'PASS'=>0, 'NA'=>0];

    // 결과 분포는 필터 무관 — 대상 스캔 전체 기준(CVE 탭의 등급 KPI 와 같은 자리·같은 성격).
    //   NA 를 PASS 와 섞지 않는다: 위반 0건이 "준수" 로 읽히는 걸 이 제품은 반복해서 경계해 왔다.
    //   uq_cce(scan_id, code) 가 scan_id 선두라 IN 범위를 그대로 탄다.
    $stmt = $pdo->prepare("SELECT result, COUNT(*) c FROM tb_cce_finding WHERE scan_id IN ($in) GROUP BY result");
    $stmt->execute($scanIds);
    foreach ($stmt->fetchAll() as $r) {
        if (isset($cceResultCounts[$r['result']])) { $cceResultCounts[$r['result']] = (int) $r['c']; }
    }
    // 탭 뱃지는 이 탭의 기본값(위반)을 센다 — 탭을 눌렀을 때 보게 될 숫자와 같아야 한다.
    $typeCount = $cceResultCounts['FAIL'];

    $where  = "f.scan_id IN ($in)";
    $params = $scanIds;
    if ($res !== 'ALL') {
        $where .= ' AND f.result = ?';
        $params[] = $res;
    }
    if ($sev !== '') {
        $where .= ' AND f.severity = ?';
        $params[] = $sev;
    }
    if ($q !== '') {
        $where .= ' AND (f.code LIKE ? OR f.title LIKE ? OR f.ssg_rule_id LIKE ?)';
        $like = '%' . addcslashes($q, '%_\\') . '%';
        $params[] = $like; $params[] = $like; $params[] = $like;
    }

    $stmt = $pdo->prepare("SELECT COUNT(*) FROM tb_cce_finding f WHERE $where");
    $stmt->execute($params);
    $total = (int) $stmt->fetchColumn();
    if ($total > 0) { $page = min($page, (int) ceil($total / $perPage)); }
    $offset = ($page - 1) * $perPage;

    // 룰 상세는 compliance_rule.php 가 이미 갖고 있다 — 여기서는 기준 참조(CIS/NIST/STIG)만
    //   함께 읽어 근거를 인용하고 링크로 보낸다(host.php 의 CCE 탭과 같은 조인).
    $stmt = $pdo->prepare(
        "SELECT f.code, f.ssg_rule_id, f.title, f.result, f.severity, f.evidence, f.rationale,
                h.host_id, h.fqdn, r.refs_json
           FROM tb_cce_finding f
           JOIN tb_scan s ON s.scan_id = f.scan_id
           JOIN tb_host h ON h.host_id = s.host_id
           LEFT JOIN tb_compliance_rule r ON r.rule_id = f.ssg_rule_id AND r.is_deleted = 0
          WHERE $where
          ORDER BY FIELD(f.result,'FAIL','NA','PASS'), FIELD(f.severity,'HIGH','MEDIUM','LOW'), h.fqdn, f.code
          LIMIT $perPage OFFSET $offset"
    );
    $stmt->execute($params);
    $rows = $stmt->fetchAll();

    return ['resultCounts' => $cceResultCounts, 'typeCount' => $typeCount,
            'total' => $total, 'page' => $page, 'rows' => $rows];
}

/**
 * 노출 탭 — 범위 분포 + 목록 + 행별 CVE 건수.
 *   $f: q scope page perPage
 *   반환: scopeCounts typeCount total page rows cveCounts
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
    $typeCount = 0;
    foreach ($stmt->fetchAll() as $r) {
        $scopeCounts[(string) $r['sc']] = (int) $r['c'];
        $typeCount += (int) $r['c'];
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

    return ['scopeCounts' => $scopeCounts, 'typeCount' => $typeCount, 'total' => $total,
            'page' => $page, 'rows' => $rows, 'cveCounts' => $expCveCounts];
}

/**
 * 지금 탭이 아닌 유형의 건수 — 탭 머리에 붙는 요약이다. 각각 인덱스 선두(scan_id) 범위
 *   COUNT 하나뿐이라 값싸다(현재 탭 것은 이미 집계됐으므로 null 이 아니면 다시 세지 않는다).
 */
function vg_findings_type_counts(PDO $pdo, array $scanIds, array $typeCounts): array {
    $in = implode(',', array_fill(0, count($scanIds), '?'));
    if ($typeCounts['cve'] === null) {
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM tb_finding WHERE scan_id IN ($in)");
        $stmt->execute($scanIds);
        $typeCounts['cve'] = (int) $stmt->fetchColumn();
    }
    if ($typeCounts['cce'] === null) {
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM tb_cce_finding WHERE scan_id IN ($in) AND result = 'FAIL'");
        $stmt->execute($scanIds);
        $typeCounts['cce'] = (int) $stmt->fetchColumn();
    }
    if ($typeCounts['exposure'] === null) {
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM tb_exposure WHERE scan_id IN ($in)");
        $stmt->execute($scanIds);
        $typeCounts['exposure'] = (int) $stmt->fetchColumn();
    }
    return $typeCounts;
}
