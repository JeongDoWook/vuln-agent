<?php
declare(strict_types=1);

/**
 * findings/queries/cve.php — CVE 탭의 조회 하나.
 *   등급 KPI · 행동 큐(KEV·외부노출·재시작·기한초과) · 필터 조립 · 목록 · 페이지 단위 부가정보
 *   (미조치 사유·최초 발견 시각)까지 이 탭이 필요한 전부를 한 함수가 순서대로 읽는다.
 *   SQL·바인딩 순서·정렬은 findings.php 에 있던 것을 그대로 옮긴 것이다.
 */

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
