<?php
declare(strict_types=1);

/**
 * compliance.php — KISA ISMS-P / ISO 27001 통제 자동판정 로직(웹·CLI 공용).
 *   원래 server/public/compliance.php 안에 있던 판정 함수들을 그대로 옮겨왔다.
 *   웹 화면(public/compliance.php)은 이 파일을 읽어 "지금" 을 렌더하고,
 *   스케줄러(bin/scheduler.php)는 같은 함수로 하루 1건 스냅샷을 적재한다 —
 *   판정 로직이 두 벌이면 화면과 증적이 서로 다른 답을 내기 시작한다(DRY).
 *
 *   ※ 이 파일은 CLI 에서도 로드된다. 세션·인가(vg_require_menu)·출력은 여기 두지 않는다.
 */

require_once __DIR__ . '/db.php';         // vg_pdo, vg_latest_scan_subq, vg_with_tx
require_once __DIR__ . '/format.php';     // vg_asset_state_sql_expr
require_once __DIR__ . '/setting.php';    // vg_setting_int — 조직별 SLA·컷라인
require_once __DIR__ . '/account_inventory.php';   // vg_account_judgments — 계정 판정(재사용)

// SLA 기준의 **폴백값**. 실제 판정은 tb_setting 의 값을 쓰고(조직마다 SLA 가 다르다),
//   설정 행이 없거나 설정 테이블을 못 읽으면 여기 값으로 지금과 동일하게 동작한다.
//   KEV 등재가 가장 급하고, 그다음 CRITICAL, HIGH 순.
const VG_COMPLIANCE_SLA_KEV_DAYS  = 15;
const VG_COMPLIANCE_SLA_CRIT_DAYS = 30;
const VG_COMPLIANCE_SLA_HIGH_DAYS = 60;

// 위반 건수 → 준수 상태 컷라인의 폴백값. 세 통제가 전부 같은 어휘를 쓴다(사용자가 한 화면에서
//   "몇 건부터 부분준수인가"를 매 통제마다 다시 배우지 않게).
const VG_COMPLIANCE_PARTIAL_MAX = 5;   // 1~5건 = 부분준수, 6건 이상 = 미준수

// first_seen 배치 쿼리가 되짚어볼 구간의 **여유일**. 실제 구간 = 가장 긴 SLA + 이 값.
//   절대 일수로 두지 않는 이유: SLA 를 늘려 놓고 구간이 그대로면 경과일이 구간 길이에서
//   잘려 위반이 아예 검출되지 않는다(= 허위 안심이 설정 실수로 재현된다).
//   여유를 두는 이유: 그보다 오래 지속된 발견은 어차피 이미 위반 확정이라 정확한 최초시각까지
//   알 필요가 없다(경계 밖에 실제 최초시각이 있어도, 경계 안에서 잡히는 first_seen 은 실제보다
//   항상 같거나 늦으므로 위반 판정이 과소평가되지 않는다).
const VG_COMPLIANCE_HISTORY_MARGIN_DAYS = 14;

/** 설정(tb_setting) + 폴백 상수로 조립한 판정 기준값 한 벌. 화면·스케줄러가 함께 쓴다. */
function vg_compliance_policy(): array {
    return [
        'kev'    => vg_setting_int('compliance.sla_kev_days',  VG_COMPLIANCE_SLA_KEV_DAYS),
        'crit'   => vg_setting_int('compliance.sla_crit_days', VG_COMPLIANCE_SLA_CRIT_DAYS),
        'high'   => vg_setting_int('compliance.sla_high_days', VG_COMPLIANCE_SLA_HIGH_DAYS),
        'partial_max' => vg_setting_int('compliance.partial_max', VG_COMPLIANCE_PARTIAL_MAX),
        'margin' => vg_setting_int('compliance.history_lookback_margin_days', VG_COMPLIANCE_HISTORY_MARGIN_DAYS),
    ];
}

// 스냅샷 1건이 담는 근거(evidence) 최대 개수. 무제한 JSON 은 행을 비대하게 만든다 —
//   위반이 수천 건인 환경에서 매일 전량을 박으면 스냅샷 테이블이 본 데이터보다 커진다.
//   상한을 넘으면 truncated=true 로 남겨 "잘렸다" 는 사실 자체를 증적에 기록한다.
const VG_COMPLIANCE_EVIDENCE_MAX = 500;

// 계정 통제가 한 번에 읽어 판정할 계정 행의 상한. host.php 의 VG_HOST_ACCOUNT_JUDGE_MAX(호스트
//   1대 5000행)와 같은 취지지만 이쪽은 전 호스트를 한 쿼리로 읽으므로 전체 상한이다.
//   상한에 닿으면 판정이 불완전하다는 사실을 서버 로그에 남긴다(조용히 자르지 않는다).
const VG_COMPLIANCE_ACCOUNT_ROW_MAX = 50000;

/**
 * 자동판정 통제 정의(SSOT) — 화면 제목·스냅샷의 control_key·framework_ids 가 전부 여기서 온다.
 *   키는 DB 에 그대로 저장되므로 바꾸면 과거 스냅샷과 이어지지 않는다(추가만 한다).
 */
const VG_COMPLIANCE_CONTROLS = [
    'patch'   => ['label' => '패치관리',        'framework' => 'ISMS-P 2.10.8 / ISO 27001 A.8.8'],
    'asset'   => ['label' => '정보자산 식별',   'framework' => 'ISMS-P 1.2.1 / ISO 27001 A.5.9'],
    'secops'  => ['label' => '보안시스템 운영', 'framework' => 'ISMS-P 2.10.1'],
    // 계정 관리는 예전엔 VG_COMPLIANCE_MANUAL_CHECKLIST(사람이 심사) 였다. 계정 인벤토리
    //   (tb_host_account)가 제품 안에 생기면서 증적이 DB 에 있으니 자동판정으로 올렸다 —
    //   수동 체크리스트에는 증적이 제품 밖에 있는 항목만 남긴다.
    //   접근권한 검토(2.5.3)는 접속기록 점검 기능이 제거되면서 자동판정 근거(tb_activity_review)가
    //   없어져 다시 수동 체크리스트로 내렸다 — 근거가 없는 통제를 준수로 찍지 않는다.
    'account'        => ['label' => '계정 관리',      'framework' => 'ISMS-P 2.5.1 / ISO 27001 A.9.2'],
];

/**
 * 판정 결과 → ['label'=>..., 'tone'=>...]. 자동판정 통제가 공유하는 판정 어휘(SSOT).
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

/**
 * 상태 라벨 → 톤. 스냅샷은 라벨만 저장하므로(판정 어휘가 SSOT) 화면에서 톤을 되찾는다.
 *   판정 어휘가 4종(준수·판정 불가·부분준수·미준수)이라 (위반건수, 판정불가여부) 조합을
 *   전부 돌려 라벨이 맞는 것을 찾는다 — 톤 표를 따로 두면 SSOT 가 둘이 된다.
 */
function vg_compliance_tone_of(string $label): string {
    foreach ([[0, false], [0, true], [1, false], [PHP_INT_MAX, false]] as [$n, $na]) {
        $s = vg_compliance_status($n, $na, VG_COMPLIANCE_PARTIAL_MAX);
        if ($s['label'] === $label) { return $s['tone']; }
    }
    return 'muted';
}

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
 *
 *   checked 는 **표시용 분모**다(판정에는 안 쓴다). 위반 174건이 큰 수인지 작은 수인지는
 *   전체 점검 항목 수를 모르면 읽을 수 없어서, 같은 조인으로 FAIL 필터만 뺀 총건수를 함께 센다.
 * @return array{violations: array<int, array<string, mixed>>, total: int, checked: int}
 */
function vg_compliance_load_secconfig(PDO $pdo, int $limit): array {
    $latestSubq = vg_latest_scan_subq();
    $scopeSql = "FROM tb_cce_finding cf
           JOIN $latestSubq t ON t.mid = cf.scan_id
           JOIN tb_host h ON h.host_id = t.host_id AND h.is_deleted = 0
          WHERE cf.is_deleted = 0";
    $fromSql = $scopeSql . " AND cf.result = 'FAIL'";
    $total = (int) $pdo->query("SELECT COUNT(*) $fromSql")->fetchColumn();
    $checked = (int) $pdo->query("SELECT COUNT(*) $scopeSql")->fetchColumn();

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
    return ['violations' => $violations, 'total' => $total, 'checked' => $checked];
}

/**
 * 통제 4: 계정 관리(ISMS-P 2.5.1 / ISO 27001 A.9.2).
 *   판정 로직을 새로 만들지 않는다 — account_inventory.php 의 vg_account_judgments() 가
 *   이미 계정 파생판정(미로그인·sudo·공유계정·휴면)을 갖고 있고 host.php 계정 탭이 그걸 쓴다.
 *   여기서는 호스트별 최신 스캔의 계정 행을 **한 번에** 읽어 그 함수에 넘기고 집계만 한다(DRY).
 *
 *   판정 매핑: FAIL = 위반 / REVIEW·NA = 판정 불가 / PASS = 준수.
 *   REVIEW 를 준수로 흡수하지 않는 이유는 그 함수 주석 그대로다 — 공유계정·휴면계정은
 *   **추정**이라 사람이 확인해야 하고, NA 는 원자료를 못 걷은 것이라 준수의 근거가 없다.
 *
 *   **계정 행이 0인 호스트는 "수집 대기"로 판정 불가**다. 0행을 준수로 세면, 에이전트가 아직
 *   계정 섹션을 안 보내는 동안 전 호스트가 "계정 관리 준수"로 보인다(허위 안심).
 * @return array{violations: array<int, array<string, mixed>>, total: int, totalHosts: int,
 *               unjudged: int, unjudged_rows: array<int, array<string, mixed>>, pending_hosts: int}
 */
function vg_compliance_load_account(PDO $pdo, int $limit): array {
    $hosts = $pdo->query(
        'SELECT h.host_id, h.fqdn, t.mid AS scan_id
           FROM tb_host h
           JOIN ' . vg_latest_scan_subq() . ' t ON t.host_id = h.host_id
          WHERE h.is_deleted = 0
          ORDER BY h.fqdn'
    )->fetchAll();
    $totalHosts = count($hosts);
    if (!$hosts) {
        return ['violations' => [], 'total' => 0, 'totalHosts' => 0, 'unjudged' => 0,
                'unjudged_rows' => [], 'pending_hosts' => 0];
    }

    // 호스트별로 쿼리를 돌리면 N+1 이다 — 최신 스캔 전체를 한 번에 읽어 PHP 에서 가른다.
    //   상한을 두는 이유는 host.php 의 VG_HOST_ACCOUNT_JUDGE_MAX 와 같다(비정상 데이터가
    //   화면을 죽이지 못하게). 상한에 닿으면 조용히 자르지 않고 로그를 남긴다.
    $scanIds = array_map(static fn($h) => (int) $h['scan_id'], $hosts);
    $in = implode(',', array_fill(0, count($scanIds), '?'));
    $cap = VG_COMPLIANCE_ACCOUNT_ROW_MAX;
    $st = $pdo->prepare(
        "SELECT scan_id, username, uid, gid, shell, home, is_locked, is_sudoer, is_system,
                pw_last_change, pw_max_days, expire_date, last_login_at, never_logged_in
           FROM tb_host_account
          WHERE scan_id IN ($in) AND is_deleted = 0
          ORDER BY scan_id, username
          LIMIT $cap"
    );
    $st->execute($scanIds);
    $rows = $st->fetchAll();
    if (count($rows) >= $cap) {
        error_log('[compliance] 계정 인벤토리 ' . $cap . '행 상한에 닿아 잘렸습니다 — 판정이 불완전합니다.');
    }
    $byScan = [];
    foreach ($rows as $r) { $byScan[(int) $r['scan_id']][] = $r; }

    $violations = [];
    $unjudgedRows = [];
    $unjudged = 0;
    $pending = 0;
    foreach ($hosts as $h) {
        $hostId = (int) $h['host_id'];
        $fqdn   = (string) $h['fqdn'];
        $accounts = $byScan[(int) $h['scan_id']] ?? [];
        if (!$accounts) {
            // 계정 목록 자체가 없다 = 아직 못 걷었다. 준수도 위반도 아니다.
            $pending++;
            $unjudged++;
            $unjudgedRows[] = ['host_id' => $hostId, 'fqdn' => $fqdn, 'code' => 'ACC-INVENTORY',
                'title' => '계정 인벤토리 수집', 'result' => 'NA',
                'reason' => '수집 대기 — 계정 목록을 아직 받지 못했습니다(에이전트 버전·실행 권한 확인).'];
            continue;
        }
        foreach (vg_account_judgments($accounts) as $j) {
            if ($j['result'] === 'FAIL') {
                $violations[] = [
                    'host_id' => $hostId, 'fqdn' => $fqdn,
                    'code'    => (string) $j['code'], 'title' => (string) $j['title'],
                    'result'  => 'FAIL',
                    // names 는 계정명·"UID 1000 공유: a, b" 같은 근거 문자열이다.
                    //   패스워드 해시는 애초에 수집·저장하지 않는다(account_inventory.php).
                    'names'   => array_values((array) ($j['names'] ?? [])),
                    'detail'  => (string) ($j['detail'] ?? ''),
                ];
                continue;
            }
            if ($j['result'] === 'PASS') { continue; }
            $unjudged++;
            $unjudgedRows[] = [
                'host_id' => $hostId, 'fqdn' => $fqdn,
                'code'    => (string) $j['code'], 'title' => (string) $j['title'],
                'result'  => (string) $j['result'],
                'reason'  => (string) ($j['detail'] ?? ''),
            ];
        }
    }

    return [
        'violations'    => $violations,
        'total'         => count($violations),
        'totalHosts'    => $totalHosts,
        'unjudged'      => $unjudged,
        'unjudged_rows' => array_slice($unjudgedRows, 0, $limit),
        'pending_hosts' => $pending,
    ];
}

// 자동판정이 안 되는 통제 — 사람이 심사해야 하는 정책·승인이력류. 상태 판정 없이 항목명만.
//   2.5.1(계정 관리)은 여기서 뺐다 — tb_host_account 로 자동판정 통제가 됐다
//   (VG_COMPLIANCE_CONTROLS 의 account).
//   나머지는 증적이 제품 밖(정책 문서·검토 승인이력·대응 절차·복구 계획)에 있어 자동판정이 안 된다.
const VG_COMPLIANCE_MANUAL_CHECKLIST = [
    ['ismsp' => 'ISMS-P 1.1.1~1.1.6 관리체계 기반 마련', 'iso' => 'ISO 27001 A.5.1 정보보안 정책',
     'desc' => '정보보안 정책·관리체계 범위가 문서로 수립·승인되어 있는가'],
    ['ismsp' => 'ISMS-P 2.5.3 접근권한 검토', 'iso' => 'ISO 27001 A.9.2.5 사용자 접근권한 검토',
     'desc' => '접근권한을 주기적으로 검토하고 그 결과를 승인·보관하는가'],
    ['ismsp' => 'ISMS-P 2.11.1 사고 예방 및 대응체계 구축', 'iso' => 'ISO 27001 A.5.24~A.5.28 정보보안 사고 관리',
     'desc' => '침해사고 대응 절차·연락체계가 문서화되어 있는가'],
    ['ismsp' => 'ISMS-P 2.12.1 재해복구 체계 구축', 'iso' => 'ISO 27001 A.5.29~A.5.30 업무연속성 관리',
     'desc' => '백업·복구 절차가 수립되고 정기적으로 검증되는가'],
];

/* =========================================================================
 * 스냅샷 — "지금" 판정을 하루 1건씩 남긴다.
 *   심사 증적의 본질은 시점이 아니라 시계열이다("작년 심사 시점엔 어땠나"에 답하려면
 *   그때의 판정이 저장돼 있어야 한다). 판정은 위 함수들이 하고, 여기서는 저장만 한다(SRP).
 * ========================================================================= */

/**
 * 근거 목록을 상한(VG_COMPLIANCE_EVIDENCE_MAX)으로 잘라 evidence JSON 구조로 만든다.
 *   잘렸다는 사실 자체가 증적이므로 truncated 플래그와 전체 건수를 함께 남긴다.
 * @param array<int, mixed> $items 근거 항목(이미 잘려 들어올 수 있다)
 */
function vg_compliance_evidence(array $items, int $total): array {
    $cap = VG_COMPLIANCE_EVIDENCE_MAX;
    return [
        'total'     => $total,
        'truncated' => $total > min(count($items), $cap),
        'items'     => array_slice(array_values($items), 0, $cap),
    ];
}

/**
 * 오늘(또는 지정일) 스냅샷이 이미 있는지. 스케줄러가 1분마다 도는데 매번 무거운 집계를
 *   다시 돌릴 이유가 없다 — 하루 1회만 실제로 판정하게 하는 게이트.
 */
function vg_compliance_snapshot_exists(PDO $pdo, ?string $date = null): bool {
    $st = $pdo->prepare('SELECT 1 FROM tb_compliance_snapshot WHERE snapshot_date = ? AND is_deleted = 0');
    $st->execute([$date ?? date('Y-m-d')]);
    return (bool) $st->fetchColumn();
}

/**
 * 자동판정 통제(VG_COMPLIANCE_CONTROLS)를 판정해 그날짜 스냅샷으로 적재한다(UPSERT — 같은 날 두 번 돌아도 행이 안 늘어난다).
 *   무거운 집계이므로 웹 요청이 아니라 스케줄러/CLI 에서만 부른다.
 *
 *   판정 기준은 **화면과 같은 vg_compliance_policy()** 를 쓴다. 스케줄러가 상수를 따로 쓰면
 *   설정을 바꾼 조직에서 화면과 증적의 판정 기준이 갈라진다 — 그 자체가 증적 오염이다.
 *   판정 불가 건수도 함께 저장한다. 위반 건수만 남기면 "판정 불가였다"는 사실이 증적에서
 *   사라져, 나중에 그 스냅샷을 "위반 0건 = 준수"로 되읽게 된다(허위 안심의 재발).
 * @param array|null $policy 판정 기준(생략 시 vg_compliance_policy())
 * @return array<string,array{total:int,unjudged:int}> control_key => 위반·판정 불가 건수
 */
function vg_compliance_take_snapshot(PDO $pdo, ?string $date = null, ?array $policy = null): array {
    $date   = $date ?? date('Y-m-d');
    $cap    = VG_COMPLIANCE_EVIDENCE_MAX;
    $policy = $policy ?? vg_compliance_policy();

    $patch = vg_compliance_load_patch($pdo, $policy);
    $asset = vg_compliance_load_asset($pdo, $cap);
    $sec   = vg_compliance_load_secconfig($pdo, $cap);
    $acct  = vg_compliance_load_account($pdo, $cap);

    // 근거는 "무엇이 위반이었나"를 나중에 되짚을 최소 식별자만 남긴다(원문 전체를 복사하지 않는다).
    //   판정 불가 사유도 같은 evidence JSON 안에 둔다 — 건수만 있고 사유가 없으면 나중에
    //   "왜 판정을 못 했나"를 다시 조사해야 한다.
    $controls = [
        'patch' => [
            'total'    => $patch['total'],
            'unjudged' => (int) $patch['unjudged'],
            'evidence' => vg_compliance_evidence(array_map(static fn($v) => [
                'host_id' => $v['host_id'], 'fqdn' => $v['fqdn'], 'cve_id' => $v['cve_id'],
                'package' => $v['package'], 'severity' => $v['severity'], 'days' => $v['days'],
            ], array_slice($patch['violations'], 0, $cap)), $patch['total'])
                + ['unjudged' => ['total' => (int) $patch['unjudged'], 'na' => $patch['na'],
                                  'unknown' => (int) $patch['na_unknown']]],
        ],
        'asset' => [
            'total'    => $asset['total'],
            'unjudged' => (int) $asset['unjudged'],
            'evidence' => vg_compliance_evidence(array_map(static fn($v) => [
                'host_id' => $v['host_id'], 'fqdn' => $v['fqdn'], 'reasons' => $v['reasons'],
            ], $asset['violations']), $asset['total'])
                + ['unjudged' => ['total' => (int) $asset['unjudged'], 'items' => $asset['unjudged_rows']]],
        ],
        'secops' => [
            'total'    => $sec['total'],
            'unjudged' => 0,   // 이 통제는 판정 불가 개념이 없다(FAIL 집계만)
            'evidence' => vg_compliance_evidence(array_map(static fn($v) => [
                'host_id' => $v['host_id'], 'fqdn' => $v['fqdn'],
                'code' => $v['code'], 'severity' => $v['severity'],
            ], $sec['violations']), $sec['total']),
        ],
        // 계정 근거에는 계정명이 들어간다. 패스워드 해시·비밀값은 애초에 수집·저장하지 않으므로
        //   증적에 실릴 수 없다(account_inventory.php 설계 원칙).
        'account' => [
            'total'    => $acct['total'],
            'unjudged' => (int) $acct['unjudged'],
            'evidence' => vg_compliance_evidence(array_map(static fn($v) => [
                'host_id' => $v['host_id'], 'fqdn' => $v['fqdn'],
                'code' => $v['code'], 'names' => $v['names'],
            ], array_slice($acct['violations'], 0, $cap)), $acct['total'])
                + ['unjudged' => ['total' => (int) $acct['unjudged'], 'items' => $acct['unjudged_rows'],
                                  'pending_hosts' => (int) $acct['pending_hosts']]],
        ],
    ];

    vg_with_tx($pdo, static function () use ($pdo, $date, $controls, $policy) {
        // 헤더 UPSERT. 소프트삭제됐던 날짜를 다시 찍으면 되살린다(같은 날짜는 항상 1건).
        $pdo->prepare(
            'INSERT INTO tb_compliance_snapshot (snapshot_date, taken_at)
                  VALUES (?, NOW())
             ON DUPLICATE KEY UPDATE taken_at = NOW(), is_deleted = 0, deleted_at = NULL'
        )->execute([$date]);

        // lastInsertId 는 UPDATE 경로에서 신뢰할 수 없다 — 날짜로 다시 읽는다.
        $st = $pdo->prepare('SELECT compliance_snapshot_id FROM tb_compliance_snapshot WHERE snapshot_date = ?');
        $st->execute([$date]);
        $snapId = (int) $st->fetchColumn();

        $ins = $pdo->prepare(
            'INSERT INTO tb_compliance_snapshot_control
                    (compliance_snapshot_id, control_key, framework_ids, status_label,
                     violation_count, unjudged_count, evidence)
             VALUES (?,?,?,?,?,?,?)
             ON DUPLICATE KEY UPDATE framework_ids = VALUES(framework_ids), status_label = VALUES(status_label),
                                     violation_count = VALUES(violation_count),
                                     unjudged_count = VALUES(unjudged_count), evidence = VALUES(evidence),
                                     is_deleted = 0, deleted_at = NULL'
        );
        foreach ($controls as $key => $c) {
            $ins->execute([
                $snapId,
                $key,
                VG_COMPLIANCE_CONTROLS[$key]['framework'],
                vg_compliance_status($c['total'], $c['unjudged'] > 0, $policy['partial_max'])['label'],
                $c['total'],
                $c['unjudged'],
                json_encode($c['evidence'], JSON_UNESCAPED_UNICODE),
            ]);
        }
    });

    return array_map(static fn($c) => ['total' => (int) $c['total'], 'unjudged' => (int) $c['unjudged']], $controls);
}

/**
 * 최근 스냅샷 추이. 날짜 내림차순으로 최대 $limit 일치.
 *   반환: [ ['date'=>'2026-08-08', 'taken_at'=>..., 'controls'=>['patch'=>['count'=>3,'unjudged'=>0,'label'=>'부분준수'], …]], … ]
 *   판정 불가 건수까지 돌려준다 — 화면이 "위반 0건"과 "판정 불가"를 색과 문구로 구분해야 한다.
 */
function vg_compliance_trend(PDO $pdo, int $limit): array {
    $st = $pdo->prepare(
        'SELECT s.snapshot_date, s.taken_at, c.control_key, c.violation_count, c.unjudged_count, c.status_label
           FROM (SELECT compliance_snapshot_id, snapshot_date, taken_at
                   FROM tb_compliance_snapshot
                  WHERE is_deleted = 0
                  ORDER BY snapshot_date DESC
                  LIMIT ?) s
           JOIN tb_compliance_snapshot_control c
             ON c.compliance_snapshot_id = s.compliance_snapshot_id AND c.is_deleted = 0
          ORDER BY s.snapshot_date DESC'
    );
    $st->bindValue(1, $limit, PDO::PARAM_INT);
    $st->execute();

    $rows = [];
    foreach ($st->fetchAll() as $r) {
        $d = (string) $r['snapshot_date'];
        if (!isset($rows[$d])) {
            $rows[$d] = ['date' => $d, 'taken_at' => (string) $r['taken_at'], 'controls' => []];
        }
        $rows[$d]['controls'][(string) $r['control_key']] = [
            'count'    => (int) $r['violation_count'],
            'unjudged' => (int) $r['unjudged_count'],
            'label'    => (string) $r['status_label'],
        ];
    }
    return array_values($rows);
}
