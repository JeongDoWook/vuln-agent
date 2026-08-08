<?php
declare(strict_types=1);

/**
 * compliance.php — KISA ISMS-P / ISO 27001 공통 통제항목 컴플라이언스 매핑. 로그인 필요.
 *   vuln-agent 가 이미 갖고 있는 findings/tb_host/tb_scan 데이터만으로 자동판정 가능한
 *   통제만 다룬다(정책 문서·승인이력처럼 사람이 심사해야 하는 항목은 판정 없이 체크리스트로만
 *   노출 — vuln-agent 가 못 채우는 걸 억지로 채우면 신뢰도만 깎인다).
 *   ingest 파이프라인은 건드리지 않는다 — 기존 데이터를 읽어 그때그때 판정만 한다(저장 없음).
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require_once __DIR__ . '/../src/audit.php';
require_once __DIR__ . '/../src/setting.php';   // vg_setting_int — 조직별 SLA·컷라인
vg_require_menu('findings');

// SLA 기준의 **폴백값**. 실제 판정은 tb_setting 의 값을 쓰고(조직마다 SLA 가 다르다),
//   설정 행이 없거나 설정 테이블을 못 읽으면 여기 값으로 지금과 동일하게 동작한다.
//   KEV 등재가 가장 급하고, 그다음 CRITICAL, HIGH 순.
const VG_COMPLIANCE_SLA_KEV_DAYS  = 15;
const VG_COMPLIANCE_SLA_CRIT_DAYS = 30;
const VG_COMPLIANCE_SLA_HIGH_DAYS = 60;

// 위반 건수 → 준수 상태 컷라인의 폴백값. 세 통제가 전부 같은 어휘를 쓴다(사용자가 한 화면에서
//   "몇 건부터 부분준수인가"를 매 통제마다 다시 배우지 않게).
const VG_COMPLIANCE_PARTIAL_MAX = 5;   // 1~5건 = 부분준수, 6건 이상 = 미준수

/**
 * 판정 결과 → ['label'=>..., 'tone'=>...]. 통제 3종이 공유하는 판정 어휘(SSOT).
 *   $unjudged = 위반이 없는데도 **판정 자체가 불가능한 대상**이 남아있는가.
 *   위반 0건이라고 무조건 "준수"로 쓰지 않는 이유: 볼 수 있는 근거가 모자라서 0건인 것을
 *   준수로 표기하면 심사 증빙에 허위 안심(false assurance)을 싣게 된다. 이 제품이 CCE 에서
 *   이미 지키는 원칙("NA 를 PASS 와 구분한다")을 컴플라이언스 판정에도 똑같이 적용한다.
 *   톤은 'med'(주의) — 'ok'(초록)와 색이 확실히 달라 준수로 오인되지 않는다.
 */
function vg_compliance_status(int $violations, bool $unjudged = false, int $partialMax = VG_COMPLIANCE_PARTIAL_MAX): array {
    if ($violations === 0) {
        return $unjudged ? ['label' => '판정 불가', 'tone' => 'med'] : ['label' => '준수', 'tone' => 'ok'];
    }
    if ($violations <= $partialMax) { return ['label' => '부분준수', 'tone' => 'high']; }
    return ['label' => '미준수', 'tone' => 'crit'];
}

// first_seen 배치 쿼리가 되짚어볼 구간의 **여유일**. 실제 구간 = 가장 긴 SLA + 이 값.
//   절대 일수로 두지 않는 이유: SLA 를 늘려 놓고 구간이 그대로면 경과일이 구간 길이에서
//   잘려 위반이 아예 검출되지 않는다(= 이번에 고치는 허위 안심이 설정 실수로 재현된다).
//   여유를 두는 이유: 그보다 오래 지속된 발견은 어차피 이미 위반 확정이라 정확한 최초시각까지
//   알 필요가 없다(경계 밖에 실제 최초시각이 있어도, 경계 안에서 잡히는 first_seen 은 실제보다
//   항상 같거나 늦으므로 위반 판정이 과소평가되지 않는다).
const VG_COMPLIANCE_HISTORY_MARGIN_DAYS = 14;

/** 설정(tb_setting) + 폴백 상수로 조립한 판정 기준값 한 벌. 화면과 판정 함수가 함께 쓴다. */
function vg_compliance_policy(): array {
    return [
        'kev'    => vg_setting_int('compliance.sla_kev_days',  VG_COMPLIANCE_SLA_KEV_DAYS),
        'crit'   => vg_setting_int('compliance.sla_crit_days', VG_COMPLIANCE_SLA_CRIT_DAYS),
        'high'   => vg_setting_int('compliance.sla_high_days', VG_COMPLIANCE_SLA_HIGH_DAYS),
        'partial_max' => vg_setting_int('compliance.partial_max', VG_COMPLIANCE_PARTIAL_MAX),
        'margin' => vg_setting_int('compliance.history_lookback_margin_days', VG_COMPLIANCE_HISTORY_MARGIN_DAYS),
    ];
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
 * @param array $policy vg_compliance_policy() 결과(kev/crit/high/margin 일수)
 * @return array{violations: array<int, array<string, mixed>>, total: int, unjudged: int,
 *               na: array<int, array<string, mixed>>, na_unknown: int}
 */
function vg_compliance_load_patch(PDO $pdo, array $policy): array {
    $empty = ['violations' => [], 'total' => 0, 'unjudged' => 0, 'na' => [], 'na_unknown' => 0];
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

    // 지금 살아있는(최신 스캔) CRITICAL·HIGH·조치가능·재시작대기 아닌 건. 컨테이너는 cid(이름)로
    //   정규화(container_id 는 스캔마다 새로 발급되는 surrogate PK). idx_find_scan_sev 를 탄다.
    $in = implode(',', array_fill(0, count($scanIds), '?'));
    $st = $pdo->prepare(
        "SELECT f.scan_id, COALESCE(c.cid, '') AS cid, f.cve_id, f.package_name, f.severity, f.in_kev
           FROM tb_finding f
           LEFT JOIN tb_container c ON c.container_id = f.container_id AND c.is_deleted = 0
          WHERE f.scan_id IN ($in) AND f.severity IN ('CRITICAL','HIGH')
            AND f.no_fix = 0 AND f.needs_restart = 0 AND f.is_deleted = 0"
    );
    $st->execute($scanIds);
    $active = [];
    foreach ($st->fetchAll() as $r) {
        $sid = (int) $r['scan_id'];
        $r['host_id'] = $hostIdByScan[$sid] ?? 0;
        $r['fqdn'] = $fqdnByScan[$sid] ?? '';
        $active[] = $r;
    }
    if (!$active) {
        return $empty;
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
        [$bucket, $slaDays] = $r['in_kev']
            ? ['KEV', $policy['kev']]
            : ($r['severity'] === 'CRITICAL' ? ['CRITICAL', $policy['crit']] : ['HIGH', $policy['high']]);

        // ── 보유 이력이 SLA 보다 짧으면 위반을 검출할 방법 자체가 없다 → 판정 불가 ──
        //   여기서 continue 하지 않고 위반 0건으로 흘려보내면 그게 §7-1 허위 안심이다.
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
            continue;
        }

        $key = $r['host_id'] . '|' . $r['cid'] . '|' . $r['cve_id'] . '|' . $r['package_name'];
        $seen = $firstSeenMap[$key] ?? null;
        if ($seen === null) { $naUnknown++; continue; }   // 최초 시각 미상 → 준수가 아니라 판정 불가

        $days = $seen['days'];
        if ($days < 0) {
            // 서버 수신시각이 미래로 나온 데이터 이상 — 조용히 "위반 아님"으로 넘기지 않고 남긴다.
            error_log("[compliance] 음수 경과일(데이터 이상): host={$r['host_id']} cve={$r['cve_id']} days=$days");
            $naUnknown++;
            continue;
        }

        if ($days <= $slaDays) { continue; }

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
    ];
}

/**
 * 통제 2: 정보자산 식별(ISMS-P 1.2.1 / ISO 27001 A.5.9).
 *   판정: 연결상태(assets.php 의 정상/지연/오프라인/수집없음 분류 재사용) 기준 오프라인·수집없음
 *   자산 + 필수 자산정보(OS·IP) 누락 자산. 같은 호스트가 두 사유에 다 걸려도 위반 1건으로 센다
 *   (사유별로 중복 집계하면 "위반 건수"가 자산 대수보다 부풀어 부분준수/미준수 컷라인의 의미가 흐려진다).
 *
 *   **판정 불가(부분 수집)**: 에이전트가 root 가 아닌 계정으로 돌면 외부노출(소켓→프로세스)·
 *   라이브러리 로드 같은 자산 식별 근거를 아예 못 걷는다(agent 스크립트가 그때 경고한다).
 *   그런데 이 통제는 os_id/os_version/last_seen_ip 필드가 채워졌는지만 봐서, 근거가 빠진
 *   호스트도 "준수"로 집계됐다. meta.running_as 로 이미 아는 사실이므로 준수에서 빼고
 *   판정 불가로 분류한다 — 위반(=문제가 확인됨)과도 구분해야 하므로 별도 집계다.
 * @return array{violations: array<int, array<string, mixed>>, total: int, totalHosts: int,
 *               unjudged: int, unjudged_rows: array<int, array<string, mixed>>}
 */
function vg_compliance_load_asset(PDO $pdo, int $limit): array {
    $latestSubq = vg_latest_scan_subq();
    $fromSql = 'FROM tb_host h
                LEFT JOIN ' . $latestSubq . ' t ON t.host_id = h.host_id
                LEFT JOIN tb_scan s ON s.scan_id = t.mid
                LEFT JOIN (
                    SELECT host_fqdn, MAX(last_seen_at) AS last_seen_at
                      FROM tb_agent_token
                     WHERE is_revoked = 0 AND is_deleted = 0
                     GROUP BY host_fqdn
                ) agent_seen ON agent_seen.host_fqdn = h.fqdn';
    // assets.php 와 같은 식(format.php 의 SSOT) — 다른 식을 쓰면 자산 화면과 다른 대수가 나온다.
    $stateExpr = vg_asset_state_sql_expr();

    // totalHosts 는 상태 판정과 무관한 단순 등록 대수 — 상태 조인 없이 센다.
    $totalHosts = (int) $pdo->query('SELECT COUNT(*) FROM tb_host WHERE is_deleted = 0')->fetchColumn();

    $violCond = "($stateExpr IN ('offline','none')
                 OR h.os_id IS NULL OR h.os_id = ''
                 OR h.os_version IS NULL OR h.os_version = ''
                 OR h.last_seen_ip IS NULL OR h.last_seen_ip = '')";
    $whereViol = "h.is_deleted = 0 AND $violCond";
    $total = (int) $pdo->query("SELECT COUNT(*) $fromSql WHERE $whereViol")->fetchColumn();

    $st = $pdo->prepare(
        "SELECT h.host_id, h.fqdn, h.os_id, h.os_version, h.last_seen_ip, $stateExpr AS state
           $fromSql
          WHERE $whereViol
          ORDER BY h.fqdn
          LIMIT ?"
    );
    $st->bindValue(1, $limit, PDO::PARAM_INT);
    $st->execute();
    $rows = $st->fetchAll();

    $violations = [];
    foreach ($rows as $r) {
        $reasons = [];
        if ($r['state'] === 'offline') { $reasons[] = '오프라인'; }
        if ($r['state'] === 'none') { $reasons[] = '수집없음'; }
        if (empty($r['os_id']) || empty($r['os_version'])) { $reasons[] = 'OS 정보 누락'; }
        if (empty($r['last_seen_ip'])) { $reasons[] = 'IP 정보 누락'; }
        $violations[] = [
            'host_id' => (int) $r['host_id'],
            'fqdn'    => (string) $r['fqdn'],
            'reasons' => $reasons,
        ];
    }

    // ── 부분 수집(비-root) 호스트 = 판정 불가 ──
    //   이미 위반으로 잡힌 호스트는 뺀다(NOT (위반조건)) — 확인된 문제가 판정 불가로 희석되면
    //   위반 건수가 줄어 컷라인 판정이 느슨해진다. 위반 쪽이 더 강한 진술이므로 그쪽이 이긴다.
    //   running_as 는 스캔 원본(meta)에만 있어 raw_json 에서 그 한 값만 뽑는다.
    $runAsExpr = "LOWER(TRIM(COALESCE(JSON_UNQUOTE(JSON_EXTRACT(s.raw_json, '\$.meta.running_as')), '')))";
    $whereUnjudged = "h.is_deleted = 0 AND NOT $violCond AND $runAsExpr <> 'root'";
    $unjudged = (int) $pdo->query("SELECT COUNT(*) $fromSql WHERE $whereUnjudged")->fetchColumn();

    $unjudgedRows = [];
    if ($unjudged > 0) {
        $st = $pdo->prepare(
            "SELECT h.host_id, h.fqdn, $runAsExpr AS running_as
               $fromSql
              WHERE $whereUnjudged
              ORDER BY h.fqdn
              LIMIT ?"
        );
        $st->bindValue(1, $limit, PDO::PARAM_INT);
        $st->execute();
        foreach ($st->fetchAll() as $r) {
            $runAs = (string) ($r['running_as'] ?? '');
            $unjudgedRows[] = [
                'host_id' => (int) $r['host_id'],
                'fqdn'    => (string) $r['fqdn'],
                'reason'  => $runAs === ''
                    ? '수집 계정 미상 — 외부노출·라이브러리 로드 근거 누락'
                    : '비-root 수집(' . $runAs . ') — 외부노출·라이브러리 로드 근거 누락',
            ];
        }
    }

    return [
        'violations'    => $violations,
        'total'         => $total,
        'totalHosts'    => $totalHosts,
        'unjudged'      => $unjudged,
        'unjudged_rows' => $unjudgedRows,
    ];
}

/**
 * 통제 3: 보안시스템 운영(ISMS-P 2.10.1).
 *   판정: host.php 에 이미 있는 "설정 취약"(tb_cce_finding.result='FAIL') 판정을 최신 스캔
 *   기준으로 집계만 한다 — 판정 로직 자체는 새로 만들지 않는다(YAGNI).
 * @return array{violations: array<int, array<string, mixed>>, total: int}
 */
function vg_compliance_load_secconfig(PDO $pdo, int $limit): array {
    $latestSubq = vg_latest_scan_subq();
    $fromSql = "FROM tb_cce_finding cf
           JOIN $latestSubq t ON t.mid = cf.scan_id
           JOIN tb_host h ON h.host_id = t.host_id AND h.is_deleted = 0
          WHERE cf.result = 'FAIL' AND cf.is_deleted = 0";
    $total = (int) $pdo->query("SELECT COUNT(*) $fromSql")->fetchColumn();

    $st = $pdo->prepare(
        "SELECT t.host_id, h.fqdn, cf.code, cf.title, cf.severity, cf.rationale
           $fromSql
          ORDER BY FIELD(cf.severity,'HIGH','MEDIUM','LOW'), h.fqdn
          LIMIT ?"
    );
    $st->bindValue(1, $limit, PDO::PARAM_INT);
    $st->execute();
    $rows = $st->fetchAll();
    $violations = [];
    foreach ($rows as $r) {
        $violations[] = [
            'host_id'   => (int) $r['host_id'],
            'fqdn'      => (string) $r['fqdn'],
            'code'      => (string) $r['code'],
            'title'     => (string) $r['title'],
            'severity'  => (string) $r['severity'],
            'rationale' => (string) ($r['rationale'] ?? ''),
        ];
    }
    return ['violations' => $violations, 'total' => $total];
}

// 자동판정이 안 되는 통제 — 사람이 심사해야 하는 정책·승인이력류. 상태 판정 없이 항목명만.
const VG_COMPLIANCE_MANUAL_CHECKLIST = [
    ['ismsp' => 'ISMS-P 1.1.1~1.1.6 관리체계 기반 마련', 'iso' => 'ISO 27001 A.5.1 정보보안 정책',
     'desc' => '정보보안 정책·관리체계 범위가 문서로 수립·승인되어 있는가'],
    ['ismsp' => 'ISMS-P 2.5.1 사용자 계정 관리', 'iso' => 'ISO 27001 A.9.2 사용자 접근 관리',
     'desc' => '계정 발급·변경·해지에 대한 승인 이력이 남아있는가'],
    ['ismsp' => 'ISMS-P 2.5.3 접근권한 검토', 'iso' => 'ISO 27001 A.9.2.5 접근권한 검토',
     'desc' => '주기적으로 접근권한 적정성을 재검토하고 있는가'],
    ['ismsp' => 'ISMS-P 2.11.1 사고 예방 및 대응체계 구축', 'iso' => 'ISO 27001 A.5.24~A.5.28 정보보안 사고 관리',
     'desc' => '침해사고 대응 절차·연락체계가 문서화되어 있는가'],
    ['ismsp' => 'ISMS-P 2.12.1 재해복구 체계 구축', 'iso' => 'ISO 27001 A.5.29~A.5.30 업무연속성 관리',
     'desc' => '백업·복구 절차가 수립되고 정기적으로 검증되는가'],
];

$err = null;
$patch = ['violations' => [], 'total' => 0, 'unjudged' => 0, 'na' => [], 'na_unknown' => 0];
$asset = ['violations' => [], 'total' => 0, 'totalHosts' => 0, 'unjudged' => 0, 'unjudged_rows' => []];
$secconfig = ['violations' => [], 'total' => 0];
$policy = ['kev' => VG_COMPLIANCE_SLA_KEV_DAYS, 'crit' => VG_COMPLIANCE_SLA_CRIT_DAYS,
           'high' => VG_COMPLIANCE_SLA_HIGH_DAYS, 'partial_max' => VG_COMPLIANCE_PARTIAL_MAX,
           'margin' => VG_COMPLIANCE_HISTORY_MARGIN_DAYS];
$judgedAt = date('Y-m-d H:i');
$previewLimit = vg_ui_detail_preview_limit();
// findings 메뉴 권한만으로는 자산 인벤토리(assets 메뉴 전용 정보)를 우회 열람할 수 없게 별도 게이트.
$canViewAssets = vg_can('assets');

try {
    $pdo = vg_pdo();
    vg_log_activity($pdo, 'PAGE', null, 'view_compliance', '컴플라이언스 매핑 조회');
    $policy = vg_compliance_policy();   // 설정(tb_setting) 반영 — 세션락 해제 전에 한 번만 읽는다
    session_write_close();   // 인가·감사로그 이후 무거운 집계 전 세션락 해제(connectors.php 선례)
    $patch = vg_compliance_load_patch($pdo, $policy);
    if ($canViewAssets) {
        $asset = vg_compliance_load_asset($pdo, $previewLimit);
    }
    $secconfig = vg_compliance_load_secconfig($pdo, $previewLimit);
} catch (Throwable $e) {
    error_log('[compliance] ' . $e->getMessage());
    $err = '처리 중 오류가 발생했습니다.';
}

vg_header('컴플라이언스 매핑', 'compliance_mapping');
?>
  <?php vg_page_title(
      '컴플라이언스 매핑', 'COMPLIANCE',
      'KISA ISMS-P · ISO 27001 공통 통제항목을 vuln-agent 가 이미 수집한 데이터로 자동 판정합니다.'
  ); ?>

<?php if ($err !== null): ?>
  <?php vg_alert('오류 · ' . $err); ?>
<?php else:
    $sPatch = vg_compliance_status($patch['total'], $patch['unjudged'] > 0, $policy['partial_max']);
    $sAsset = vg_compliance_status($asset['total'], $asset['unjudged'] > 0, $policy['partial_max']);
    $sSec   = vg_compliance_status($secconfig['total'], false, $policy['partial_max']);
?>
  <?php
  // KPI 의 숫자는 "위반 건수"다. 위반 0건이어도 판정 불가가 남아 있으면 그 사실을 라벨에 함께
  //   적는다 — 숫자 0 만 보고 준수로 읽히면 안 된다(톤도 ok=초록이 아니라 med=주의로 바뀐다).
  $naSuffix = static fn(array $s, int $unjudged): string =>
      $s['label'] === '판정 불가' ? ' · 판정 불가 ' . number_format($unjudged) . '건' : '';
  ?>
  <div class="cards">
    <div class="kpi kpi--sm tone-<?= vg_h($sPatch['tone']) ?>"><b><?= $patch['total'] ?></b><span>패치관리 위반<?= vg_h($naSuffix($sPatch, (int) $patch['unjudged'])) ?></span></div>
    <?php if ($canViewAssets): ?>
      <div class="kpi kpi--sm tone-<?= vg_h($sAsset['tone']) ?>"><b><?= $asset['total'] ?></b><span>자산식별 위반<?= vg_h($naSuffix($sAsset, (int) $asset['unjudged'])) ?></span></div>
    <?php endif; ?>
    <div class="kpi kpi--sm tone-<?= vg_h($sSec['tone']) ?>"><b><?= $secconfig['total'] ?></b><span>보안설정 위반</span></div>
  </div>

  <div class="card">
    <div class="card__body">
      <div class="compliance-control__head">
        <div>
          <strong>패치관리</strong>
          <span class="why"> — ISMS-P 2.10.8 · ISO 27001 A.8.8</span>
        </div>
        <?= vg_badge($sPatch['label'], $sPatch['tone']) ?>
      </div>
      <p class="why">CRITICAL·HIGH 이면서 조치 가능(패치 존재)한데 SLA 기준일(KEV <?= (int) $policy['kev'] ?>일 ·
        CRITICAL <?= (int) $policy['crit'] ?>일 · HIGH <?= (int) $policy['high'] ?>일)을 넘겨 미조치 상태인 건수.
        위반 <?= number_format($patch['total']) ?>건 · 판정 불가 <?= number_format($patch['unjudged']) ?>건 ·
        판정 시각 <?= vg_h($judgedAt) ?></p>
      <?php
      // 판정 불가 사유를 그대로 노출한다 — "위반 0건"이 왜 준수를 뜻하지 않는지 화면에서 설명하지
      //   않으면, 근거가 모자란 0건이 다시 준수처럼 읽힌다(§7-1 이 지적한 허위 안심).
      if ($patch['unjudged'] > 0):
          $hints = [];
          foreach ($patch['na'] as $b) {
              $hints[] = sprintf(
                  '%s SLA %d일 · 보유 이력 최대 %d일 → 판정 불가 %s건%s',
                  $b['label'], (int) $b['sla_days'], (int) $b['max_history_days'], number_format((int) $b['count']),
                  $b['judgeable_from'] !== null ? ' (' . $b['judgeable_from'] . ' 이후 판정 가능)' : ''
              );
          }
          if ($patch['na_unknown'] > 0) {
              $hints[] = sprintf('최초 발견 시각을 확인할 수 없는 %s건 — 경과일을 계산할 수 없어 판정 불가',
                  number_format((int) $patch['na_unknown']));
          }
          vg_alert([
              'type'  => 'warn',
              'title' => '판정 불가 ' . number_format($patch['unjudged']) . '건 — 위반 0건이 곧 준수를 뜻하지 않습니다',
              'hints' => $hints,
          ]);
      endif; ?>
      <?php if ($patch['violations']):
          $shown = array_slice($patch['violations'], 0, $previewLimit);
      ?>
        <?php vg_table(
            [
                ['label' => '호스트'],
                ['label' => 'CVE'],
                ['label' => '패키지'],
                ['label' => '등급', 'width' => '6.5rem'],
                ['label' => '최초 발견'],
                ['label' => '경과/기준'],
            ],
            $shown,
            [
                'cell' => [
                    0 => fn($v) => '<a href="/host.php?id=' . (int) $v['host_id'] . '">' . vg_h($v['fqdn']) . '</a>',
                    1 => fn($v) => '<a href="/cve.php?cve=' . urlencode($v['cve_id']) . '">' . vg_h($v['cve_id']) . '</a>',
                    2 => fn($v) => vg_h($v['package']),
                    3 => fn($v) => vg_sev_badge($v['severity']) . ($v['in_kev'] ? ' ' . vg_badge('KEV', 'crit') : ''),
                    4 => fn($v) => '<span class="why">' . vg_h((string) $v['first_seen']) . '</span>',
                    5 => fn($v) => $v['days'] . '일 / ' . $v['sla_days'] . '일',
                ],
            ]
        ); ?>
        <?php if ($patch['total'] > count($shown)): ?>
          <p class="why">상위 <?= count($shown) ?>건만 표시 · 전체 <?= number_format($patch['total']) ?>건은
            <a href="/findings.php?sev=CRITICAL">탐지 결과에서 확인</a></p>
        <?php endif; ?>
      <?php endif; ?>
    </div>
  </div>

  <?php if ($canViewAssets): ?>
  <div class="card mt-lg">
    <div class="card__body">
      <div class="compliance-control__head">
        <div>
          <strong>정보자산 식별</strong>
          <span class="why"> — ISMS-P 1.2.1 · ISO 27001 A.5.9</span>
        </div>
        <?= vg_badge($sAsset['label'], $sAsset['tone']) ?>
      </div>
      <p class="why">등록 자산 <?= number_format($asset['totalHosts']) ?>대 중 오프라인·수집없음이거나 필수 자산정보(OS·IP)가
        누락된 자산 건수. 위반 <?= number_format($asset['total']) ?>건 ·
        판정 불가 <?= number_format($asset['unjudged']) ?>건 · 판정 시각 <?= vg_h($judgedAt) ?></p>
      <?php if ($asset['unjudged'] > 0):
          $hints = [];
          foreach ($asset['unjudged_rows'] as $u) { $hints[] = $u['fqdn'] . ' — ' . $u['reason']; }
          if ($asset['unjudged'] > count($asset['unjudged_rows'])) {
              $hints[] = sprintf('외 %s대', number_format($asset['unjudged'] - count($asset['unjudged_rows'])));
          }
          vg_alert([
              'type'  => 'warn',
              'title' => '판정 불가 ' . number_format($asset['unjudged']) . '대 — 부분 수집(root 아님)이라 식별 근거가 빠져 있습니다',
              'hints' => $hints,
          ]);
      endif; ?>
      <?php if ($asset['violations']):
          $shown = array_slice($asset['violations'], 0, $previewLimit);
      ?>
        <?php vg_table(
            [['label' => '호스트'], ['label' => '사유']],
            $shown,
            [
                'cell' => [
                    0 => fn($v) => '<a href="/host.php?id=' . (int) $v['host_id'] . '">' . vg_h($v['fqdn']) . '</a>',
                    1 => fn($v) => implode(' · ', array_map('vg_h', $v['reasons'])),
                ],
            ]
        ); ?>
        <?php if ($asset['total'] > count($shown)): ?>
          <p class="why">상위 <?= count($shown) ?>건만 표시 · 전체는 <a href="/assets.php">자산 화면에서 확인</a></p>
        <?php endif; ?>
      <?php endif; ?>
    </div>
  </div>
  <?php endif; ?>

  <div class="card mt-lg">
    <div class="card__body">
      <div class="compliance-control__head">
        <div>
          <strong>보안시스템 운영</strong>
          <span class="why"> — ISMS-P 2.10.1</span>
        </div>
        <?= vg_badge($sSec['label'], $sSec['tone']) ?>
      </div>
      <p class="why">최신 스캔 기준 보안설정 점검(SCAP) "설정 취약" 판정 건수. 위반 <?= number_format($secconfig['total']) ?>건 ·
        판정 시각 <?= vg_h($judgedAt) ?></p>
      <?php if ($secconfig['violations']):
          $shown = array_slice($secconfig['violations'], 0, $previewLimit);
      ?>
        <?php vg_table(
            [['label' => '호스트'], ['label' => '항목'], ['label' => '등급', 'width' => '6.5rem'], ['label' => '근거']],
            $shown,
            [
                'cell' => [
                    0 => fn($v) => '<a href="/host.php?id=' . (int) $v['host_id'] . '&amp;tab=cce">' . vg_h($v['fqdn']) . '</a>',
                    1 => fn($v) => vg_h($v['title']) . ' <span class="why">' . vg_h($v['code']) . '</span>',
                    2 => fn($v) => vg_sev_badge($v['severity']),
                    3 => fn($v) => vg_trunc($v['rationale'], 80),
                ],
            ]
        ); ?>
        <?php if ($secconfig['total'] > count($shown)): ?>
          <p class="why">상위 <?= count($shown) ?>건만 표시</p>
        <?php endif; ?>
      <?php endif; ?>
    </div>
  </div>

  <div class="card mt-lg">
    <div class="card__body">
      <strong>수동 확인 필요</strong>
      <p class="why">vuln-agent 가 자동판정할 수 없는 정책·승인이력류 통제입니다. 상태 판정 없이 점검 항목만 안내합니다.</p>
      <ul class="hint-list">
        <?php foreach (VG_COMPLIANCE_MANUAL_CHECKLIST as $item): ?>
          <li><?= vg_h($item['ismsp']) ?> · <?= vg_h($item['iso']) ?><br>
            <span class="why"><?= vg_h($item['desc']) ?></span></li>
        <?php endforeach; ?>
      </ul>
    </div>
  </div>
<?php endif; ?>
<?php vg_footer();
