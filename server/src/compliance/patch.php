<?php
declare(strict_types=1);

/**
 * compliance/patch.php — 통제 1: 패치관리(ISMS-P 2.10.8 / ISO 27001 A.8.8).
 *   판정 기준값은 compliance/policy.php 가 소유하고, 여기서는 그 기준으로 집계만 한다.
 *
 *   ※ compliance.php 가 로드한다. 세션·인가·출력은 여기 두지 않는다(CLI 에서도 로드된다).
 */

require_once __DIR__ . '/../db.php';        // vg_pdo, vg_latest_scan_subq
require_once __DIR__ . '/policy.php';       // vg_compliance_policy 의 기준값

/**
 * 심각도 버킷 3종의 빈 집계판. 대상이 0건인 버킷도 **행 자체는 남긴다** —
 *   "위반 0건"과 "애초에 대상이 없음"은 화면에서 다른 말이어야 한다(targets 로 구분).
 * @return array<string, array<string, mixed>> 버킷키 => 집계
 */
function vg_compliance_patch_buckets_init(array $policy): array {
    $out = [];
    foreach (['KEV' => $policy['kev'], 'CRITICAL' => $policy['crit'], 'HIGH' => $policy['high']] as $key => $sla) {
        $out[$key] = [
            'key' => $key, 'label' => $key, 'sla_days' => (int) $sla,
            'violations' => 0, 'unjudged' => 0, 'targets' => 0,
            'max_history_days' => 0, 'judgeable_from' => null, 'restart_excluded' => 0,
        ];
    }
    return $out;
}

/**
 * 발견 1건이 속하는 버킷과 그 SLA. KEV 등재가 심각도보다 우선한다(가장 급하다).
 * @return array{0: string, 1: int}
 */
function vg_compliance_patch_bucket_of(array $row, array $policy): array {
    if (!empty($row['in_kev'])) { return ['KEV', (int) $policy['kev']]; }
    return $row['severity'] === 'CRITICAL' ? ['CRITICAL', (int) $policy['crit']] : ['HIGH', (int) $policy['high']];
}

/**
 * 통제 1: 패치관리(ISMS-P 2.10.8 / ISO 27001 A.8.8).
 *   판정: CRITICAL·HIGH 이면서 조치 가능(no_fix=0)하고 재시작 대기(needs_restart=1 — 패치는
 *   이미 됐고 프로세스 재시작만 남은 상태, 0009_findings_needs_restart.sql)가 아닌데 SLA
 *   기준일을 넘겨 아직 살아있는 건.
 *   "최초 미조치 시각"은 tb_finding 에 없다(matcher 가 스캔마다 재작성) — finding_history.php 의
 *   first_found_at 계산(그 (호스트,컨테이너,CVE,패키지) 조합이 처음 나타난 스캔의 수신 시각)과
 *   같은 근사를 쓰되, 건별 반복 호출 대신 배치 쿼리 1회로 묶는다(N+1 방지).
 *   컨테이너 주의: tb_container.container_id 는 스캔마다 새로 발급되는 surrogate PK 라 스캔
 *   간 그대로 비교하면 안 된다(finding_history.php:8-14 문서화됨) — 컨테이너 이름(cid)으로
 *   정규화해 매칭한다. 호스트 자신은 container_id=0 → cid ''.
 *   시각은 agent 자기신고인 collected_at 대신 서버 수신시각 received_at 을 우선한다
 *   (collected_at 은 신뢰 경계 밖 값 — vg_ingest_parse_collected_at() 이 상하한 검증 없이
 *   그대로 저장해, 침해된 호스트가 매 스캔 "지금"을 보내면 경과일을 조작할 수 있다).
 *
 *   **판정 불가(NA)**: 최초 발견 시각은 "보유한 스캔 이력 안에서" 역산한다. 그래서 그 호스트의
 *   이력이 SLA 기준일보다 짧으면 SLA 초과를 **구조적으로 검출할 수 없다** — 이력 30일짜리
 *   호스트에서 HIGH(60일) 위반은 아무리 방치해도 0건으로 나온다. 이걸 "준수"로 세면 데이터가
 *   모자라서 나온 0건을 조치를 잘해서 나온 0건처럼 보고하게 된다(허위 안심). 그런 건은 위반도
 *   준수도 아닌 판정 불가로 따로 센다. 최초 발견 시각을 못 찾은 건·수신시각이 미래인 이상
 *   데이터도 같은 이유로 판정 불가다(예전엔 조용히 넘겨 "준수" 쪽에 흡수됐다).
 *   **버킷 판정**: 통제 전체에 뱃지 하나만 달면, 이력이 짧아 판정 불가인 버킷 하나가 잘 지킨
 *   나머지 버킷까지 회색으로 눌러버린다(운영 실측: HIGH 만 판정 불가인데 KEV·CRITICAL 이 함께
 *   "판정 불가"로 보였다). 그래서 버킷(KEV/CRITICAL/HIGH)별로 위반·판정 불가·대상 건수를 따로
 *   집계해 돌려준다 — 화면이 3행을 각각 판정할 수 있게. 기존 키(na/na_unknown/…)는 스냅샷
 *   evidence 호환 때문에 그대로 둔다.
 * @param array $policy vg_compliance_policy() 결과(kev/crit/high/margin 일수)
 * @return array{violations: array<int, array<string, mixed>>, total: int, unjudged: int,
 *               na: array<int, array<string, mixed>>, na_unknown: int,
 *               buckets: array<int, array<string, mixed>>}
 */
function vg_compliance_load_patch(PDO $pdo, array $policy): array {
    $buckets = vg_compliance_patch_buckets_init($policy);
    $empty = ['violations' => [], 'total' => 0, 'unjudged' => 0, 'na' => [], 'na_unknown' => 0,
              'buckets' => array_values($buckets)];
    // 호스트별 최신 scan_id 를 먼저 작은 결과로 뽑아 **리터럴 IN() 리스트**로 건넨다.
    //   findings.php 와 같은 이유(20260723093110_findings_scan_severity_index.sql 주석) —
    //   JOIN 으로 얽으면 옵티마이저가 tb_finding 을 드라이빙 테이블로 골라 idx_find_scan_sev
    //   를 안 타고 전체스캔한다(실측: EXPLAIN type=ALL, 21만행). scan_id IN(...) 리터럴이면
    //   그 인덱스를 그대로 탄다.
    $hosts = $pdo->query(
        'SELECT h.host_id, h.fqdn, t.mid AS scan_id
           FROM tb_host h
           JOIN ' . vg_latest_scan_subq() . ' t ON t.host_id = h.host_id
          WHERE h.is_deleted = 0'
    )->fetchAll();
    if (!$hosts) {
        return $empty;
    }
    $fqdnByScan = [];
    $hostIdByScan = [];
    foreach ($hosts as $h) {
        $fqdnByScan[(int) $h['scan_id']] = (string) $h['fqdn'];
        $hostIdByScan[(int) $h['scan_id']] = (int) $h['host_id'];
    }
    $scanIds = array_keys($fqdnByScan);

    // 지금 살아있는(최신 스캔) CRITICAL·HIGH·조치가능 건. 컨테이너는 cid(이름)로 정규화
    //   (container_id 는 스캔마다 새로 발급되는 surrogate PK). idx_find_scan_sev 를 탄다.
    //   재시작 대기(needs_restart=1)는 판정 대상이 아니지만 **여기서 함께 읽는다** — 버킷의
    //   대상이 0건일 때 "왜 0건인지"(재시작 대기로 빠졌다)를 화면이 말할 수 있어야 한다.
    //   쿼리를 하나 더 두는 대신 같은 결과에서 갈라 쓴다(같은 인덱스, 한 번의 왕복).
    $in = implode(',', array_fill(0, count($scanIds), '?'));
    $st = $pdo->prepare(
        "SELECT f.scan_id, COALESCE(c.cid, '') AS cid, f.cve_id, f.package_name, f.severity,
                f.in_kev, f.needs_restart
           FROM tb_finding f
           LEFT JOIN tb_container c ON c.container_id = f.container_id AND c.is_deleted = 0
          WHERE f.scan_id IN ($in) AND f.severity IN ('CRITICAL','HIGH')
            AND f.no_fix = 0 AND f.is_deleted = 0"
    );
    $st->execute($scanIds);
    $active = [];
    foreach ($st->fetchAll() as $r) {
        $sid = (int) $r['scan_id'];
        $r['host_id'] = $hostIdByScan[$sid] ?? 0;
        $r['fqdn'] = $fqdnByScan[$sid] ?? '';
        [$bucket] = vg_compliance_patch_bucket_of($r, $policy);
        if ((int) $r['needs_restart'] === 1) {
            $buckets[$bucket]['restart_excluded']++;   // 패치 완료·재시작 대기 → 판정 대상 아님
            continue;
        }
        $buckets[$bucket]['targets']++;
        $active[] = $r;
    }
    if (!$active) {
        // 재시작 대기로 전부 빠졌을 수 있다 — 그 사실이 담긴 buckets 를 그대로 돌려준다.
        return ['violations' => [], 'total' => 0, 'unjudged' => 0, 'na' => [], 'na_unknown' => 0,
                'buckets' => array_values($buckets)];
    }

    // 최초 발견 시각 배치 조회 — tb_finding 을 host_id 로 훑으면 옵티마이저가 그걸 드라이빙으로
    //   안 써 전체스캔한다(실측: type=ALL, Using temporary). 대신 대상 호스트의 scan_id 목록을
    //   먼저 작은 tb_scan 에서 좁게 뽑아, 그 scan_id 리스트로 tb_finding 을 걸러
    //   idx_find_scan_sev(scan_id,severity) 를 태운다. 조회 구간은 VG_COMPLIANCE_HISTORY_LOOKBACK_DAYS
    //   로 제한한다 — 전체 스캔 이력을 다 훑을 이유가 없다.
    $hostIds = array_values(array_unique(array_map(static fn($r) => (int) $r['host_id'], $active)));
    $in = implode(',', array_fill(0, count($hostIds), '?'));

    // 호스트별 **실제 보유 이력 길이**(가장 오래된 스캔 ~ 지금). 판정 가능 여부의 근거라
    //   역산 구간(lookback)으로 자르지 않는다 — 자르면 "이력이 짧다"는 사실 자체를 못 본다.
    //   tb_scan 은 수집 1회당 1행이라 호스트 수 규모의 작은 집계다.
    $st = $pdo->prepare(
        "SELECT host_id,
                MIN(COALESCE(received_at, collected_at)) AS oldest_at,
                DATEDIFF(NOW(), MIN(COALESCE(received_at, collected_at))) AS history_days
           FROM tb_scan WHERE host_id IN ($in) AND is_deleted = 0 GROUP BY host_id"
    );
    $st->execute($hostIds);
    $historyByHost = [];
    foreach ($st->fetchAll() as $r) {
        if ($r['history_days'] === null) { continue; }   // 시각이 통째로 비면 판정 불가 취급
        $historyByHost[(int) $r['host_id']] = [
            'oldest_at' => (string) $r['oldest_at'],
            'days'      => max(0, (int) $r['history_days']),
        ];
    }

    // 역산 구간 = 가장 긴 SLA + 여유일. SLA 를 설정으로 올렸는데 구간이 안 따라오면
    //   경과일이 구간에서 잘려 위반이 검출되지 않는다 — 그래서 SLA 에 묶어 계산한다.
    $lookbackDays = max($policy['kev'], $policy['crit'], $policy['high']) + $policy['margin'];
    $st = $pdo->prepare(
        "SELECT scan_id FROM tb_scan
          WHERE host_id IN ($in) AND is_deleted = 0
            AND received_at >= DATE_SUB(NOW(), INTERVAL ? DAY)"
    );
    $st->execute([...$hostIds, $lookbackDays]);
    $histScanIds = array_map('intval', array_column($st->fetchAll(), 'scan_id'));

    $firstSeenMap = [];
    if ($histScanIds) {
        $in = implode(',', array_fill(0, count($histScanIds), '?'));
        // 경과일은 SQL 의 DATEDIFF 로 직접 계산 — PHP strtotime()/타임존 불일치와, 파싱 실패 시
        //   false 가 산술에서 0(1970년)으로 축약돼 무조건 위반이 되는 문제를 둘 다 없앤다.
        $st = $pdo->prepare(
            "SELECT s2.host_id, COALESCE(c2.cid, '') AS cid, f2.cve_id, f2.package_name,
                    MIN(COALESCE(s2.received_at, s2.collected_at)) AS first_seen,
                    DATEDIFF(NOW(), MIN(COALESCE(s2.received_at, s2.collected_at))) AS days_since
               FROM tb_finding f2
               JOIN tb_scan s2 ON s2.scan_id = f2.scan_id AND s2.is_deleted = 0
               LEFT JOIN tb_container c2 ON c2.container_id = f2.container_id AND c2.is_deleted = 0
              WHERE f2.scan_id IN ($in) AND f2.severity IN ('CRITICAL','HIGH') AND f2.is_deleted = 0
              GROUP BY s2.host_id, cid, f2.cve_id, f2.package_name"
        );
        $st->execute($histScanIds);
        foreach ($st->fetchAll() as $r) {
            $key = $r['host_id'] . '|' . $r['cid'] . '|' . $r['cve_id'] . '|' . $r['package_name'];
            $firstSeenMap[$key] = ['first_seen' => $r['first_seen'], 'days' => (int) $r['days_since']];
        }
    }

    $violations = [];
    $na = [];            // 심각도 구간별 판정 불가 집계
    $naUnknown = 0;      // 최초 발견 시각을 알 수 없어 경과일을 못 세는 건
    foreach ($active as $r) {
        $hostId = (int) $r['host_id'];
        [$bucket, $slaDays] = vg_compliance_patch_bucket_of($r, $policy);

        // ── 보유 이력이 SLA 보다 짧으면 위반을 검출할 방법 자체가 없다 → 판정 불가 ──
        //   여기서 continue 하지 않고 위반 0건으로 흘려보내면 그게 허위 안심이다.
        $hist = $historyByHost[$hostId] ?? null;
        if ($hist === null || $hist['days'] < $slaDays) {
            $b = $na[$bucket] ?? ['label' => $bucket, 'sla_days' => $slaDays, 'count' => 0,
                                  'max_history_days' => 0, 'judgeable_from' => null];
            $b['count']++;
            if ($hist !== null) {
                if ($hist['days'] > $b['max_history_days']) { $b['max_history_days'] = $hist['days']; }
                // 이 호스트가 판정 가능해지는 날 = 가장 오래된 스캔 + SLA. 구간 안에서 가장
                //   이른 날짜를 남긴다(= 이력이 가장 긴 호스트가 먼저 판정 가능해진다).
                $ts = strtotime($hist['oldest_at']);
                if ($ts !== false) {
                    $from = date('Y-m-d', strtotime('+' . $slaDays . ' day', $ts));
                    if ($b['judgeable_from'] === null || $from < $b['judgeable_from']) { $b['judgeable_from'] = $from; }
                }
            }
            $na[$bucket] = $b;
            $buckets[$bucket]['unjudged']++;
            if ($hist !== null && $hist['days'] > $buckets[$bucket]['max_history_days']) {
                $buckets[$bucket]['max_history_days'] = $hist['days'];
            }
            $buckets[$bucket]['judgeable_from'] = $b['judgeable_from'];
            continue;
        }

        $key = $r['host_id'] . '|' . $r['cid'] . '|' . $r['cve_id'] . '|' . $r['package_name'];
        $seen = $firstSeenMap[$key] ?? null;
        if ($seen === null) {   // 최초 시각 미상 → 준수가 아니라 판정 불가
            $naUnknown++;
            $buckets[$bucket]['unjudged']++;
            continue;
        }

        $days = $seen['days'];
        if ($days < 0) {
            // 서버 수신시각이 미래로 나온 데이터 이상 — 조용히 "위반 아님"으로 넘기지 않고 남긴다.
            error_log("[compliance] 음수 경과일(데이터 이상): host={$r['host_id']} cve={$r['cve_id']} days=$days");
            $naUnknown++;
            $buckets[$bucket]['unjudged']++;
            continue;
        }

        if ($days <= $slaDays) { continue; }

        $buckets[$bucket]['violations']++;
        $violations[] = [
            'host_id'   => (int) $r['host_id'],
            'fqdn'      => (string) $r['fqdn'],
            'cve_id'    => (string) $r['cve_id'],
            'package'   => (string) $r['package_name'],
            'severity'  => (string) $r['severity'],
            'in_kev'    => (bool) $r['in_kev'],
            'first_seen'=> $seen['first_seen'],
            'days'      => $days,
            'sla_days'  => $slaDays,
        ];
    }
    usort($violations, static fn($a, $b) => $b['days'] <=> $a['days']);

    // 급한 구간부터 보여준다(KEV → CRITICAL → HIGH) — 표시 순서를 화면이 다시 정하지 않게.
    $naRows = [];
    foreach (['KEV', 'CRITICAL', 'HIGH'] as $bucket) {
        if (isset($na[$bucket])) { $naRows[] = $na[$bucket]; }
    }
    $unjudged = $naUnknown;
    foreach ($naRows as $b) { $unjudged += $b['count']; }

    return [
        'violations' => $violations,
        'total'      => count($violations),
        'unjudged'   => $unjudged,
        'na'         => $naRows,
        'na_unknown' => $naUnknown,
        'buckets'    => array_values($buckets),
    ];
}
