<?php
declare(strict_types=1);

/**
 * index.php — 대시보드 (로그인 필요).
 *   호스트별 최신 스캔 + 심각도 요약. 각 행에서 취약점 상세로.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require_once __DIR__ . '/../src/finding_sla.php';   // 조치 기한 — 목록 화면과 같은 계산을 그대로 쓴다
vg_require_menu('dashboard');

/**
 * 추세 창(窓) — 30일. "지난달보다 나아졌나" 에 답하는 최소 구간이다.
 *   14일이었던 적이 있는데(#221 에서 제거) 그때는 등급별 누적 막대라 창이 넓어질수록
 *   막대가 뭉갰다. 지금은 선 하나(High 이상)라 30일이 오히려 읽힌다.
 */
const VG_TREND_DAYS = 30;

$err = null; $rows = []; $totals = ['CRITICAL'=>0,'HIGH'=>0,'MEDIUM'=>0,'LOW'=>0];
$hostCount = 0; $total = 0; $sevByScan = [];
$kevCount = 0; $kevOverdue = 0; $urgent = []; $urgentTotal = 0; $nextFeed = null;
$kevSlaDays = 0;   // KEV 조치 기한(일) — 퍼널 4번 칸 라벨이 이 숫자를 그대로 말한다
$delta = []; $trend = [];
$page = vg_page();
$perPage = vg_perpage();
try {
    $pdo = vg_pdo();
    $hostCount = (int) $pdo->query('SELECT COUNT(*) FROM tb_host WHERE is_deleted = 0')->fetchColumn();

    // 다음 수집 예정 — enabled·비manual 커넥터 중 next_run_at 이 가장 이른 하나.
    //   manual 커넥터는 next_run_at 이 NULL 이라 자연히 제외된다(connectors.php 가 그렇게 저장).
    $nextFeed = $pdo->query(
        "SELECT name, connector_type, next_run_at FROM tb_feed_connector
          WHERE enabled = 1 AND is_deleted = 0 AND next_run_at IS NOT NULL
          ORDER BY next_run_at ASC LIMIT 1"
    )->fetch() ?: null;

    // 전 호스트의 "최신 스캔" 집합 — KPI·도넛·급한목록이 모두 이 기준을 쓴다.
    //   tb_finding 을 조인하는 아래 쿼리들은 WHERE scan_id IN(이 서브쿼리) 대신 JOIN 으로
    //   표현한다(cve.php·compliance_rule.php 와 동일 패턴). IN(서브쿼리) 로 두면 옵티마이저가
    //   호스트당 "최신 스캔 하나"가 아니라 tb_scan 전체(변경시에만 저장되지만 이력이 계속
    //   쌓인다 — 실측 호스트당 평균 6.5개)를 먼저 tb_finding 과 조인한 뒤에야 필터링해,
    //   스캔 이력이 쌓일수록 대시보드가 선형으로 느려진다(실측: "대응 우선순위" 카드 하나가
    //   7.2초 — EXPLAIN ANALYZE 로 확인. JOIN 전환 후 0.2초).
    //   tb_scan 자체(작은 표, 아래 resKpi)에는 이 문제가 없어 IN(서브쿼리)를 그대로 둔다.
    $latestJoin = "JOIN " . vg_latest_scan_subq() . " latest ON latest.host_id = s.host_id AND latest.mid = s.scan_id";

    /* KPI·퍼널 은 페이지 무관 — 전 호스트 최신 스캔의 심각도 총합.
     *
     * 퍼널의 네 칸(전체 → High 이상 → KEV → KEV 중 기한 초과)은 **같은 모집단을 좁혀 가는**
     * 수여야 의미가 있다. 그래서 KEV·외부노출도 별도 쿼리로 따로 세지 않고 이 한 번의
     * 스캔에서 함께 뽑는다 — 기준(tb_finding 행)이 하나로 고정되고, 예전에 KEV 만 자산·CVE·
     * 패키지로 묶어 세던 별도 쿼리(#354 에서 파생테이블로 최적화했던 것)도 사라진다.
     * 이 값들은 findings.php 의 등급 카드와 같은 기준이라 링크를 눌렀을 때 숫자가 이어진다.
     *
     * KEV 를 **High 이상 안에서만** 세는 건 퍼널이 진짜로 포함관계여야 하기 때문이다.
     * KEV 는 등급과 독립이라 MEDIUM 에도 붙는다(실측 dev 344건) — 전 등급으로 세면 3번째 칸이
     * 2번째 칸의 부분집합이 아니게 되고, 좁혀지는 그림 자체가 거짓말이 된다. 등급이 낮은 KEV 는
     * 아래 [주요 취약점 신호] 카드가 KEV 우선 정렬로 계속 보여준다(가려지지 않는다).
     */
    $totalsRows = $pdo->query(
        "SELECT f.severity, COUNT(*) c,
                SUM(f.in_kev = 1 AND f.severity IN ('CRITICAL','HIGH')) kev
           FROM tb_finding f
           JOIN tb_scan s ON s.scan_id = f.scan_id
           JOIN tb_host h ON h.host_id = s.host_id AND h.is_deleted = 0
           $latestJoin
          GROUP BY f.severity"
    )->fetchAll();
    foreach ($totalsRows as $f) {
        if (isset($totals[$f['severity']])) { $totals[$f['severity']] = (int) $f['c']; }
        $kevCount += (int) $f['kev'];
    }

    /* 퍼널 4번 칸 — **KEV 중 조치 기한 초과**.
     *
     * 모집단은 3번 칸(High 이상 중 KEV)과 정확히 같다. 그 안에서 기한을 넘긴 것만 센다 —
     * 퍼널이 포함관계를 그리는 그림이라, 4번 칸이 3번 칸의 부분집합이 아니게 되면 형태가
     * 거짓말이 된다. 그래서 "전체 기한 초과" 가 아니라 KEV 안에서만 센다(라벨도 그렇게 적는다).
     *
     * 기한 계산은 finding_sla.php 것을 그대로 쓴다 — 대시보드가 따로 세면 목록의 남은 일수
     * 뱃지와 숫자가 어긋난다(DRY). 완료·예외 처리된 건은 세지 않는 것도 목록과 같은 규칙
     * (vg_finding_due_cell 이 그 둘을 '—' 로 둔다).
     *
     * 성능: 되짚을 대상은 최신 스캔의 KEV(High 이상)뿐이다 — 3번 칸의 값이 곧 그 상한이라
     * 전체 탐지 건수(수십만)를 훑지 않는다. 최초 발견 시각은 목록 화면과 같은 배치 조회
     * 한 번으로 받는다(N+1 없음).
     */
    $policy     = vg_compliance_policy();
    $kevSlaDays = (int) vg_finding_sla_days(true, 'CRITICAL', $policy);   // KEV 기한이 등급보다 우선한다
    $kevRows = $pdo->query(
        "SELECT s.host_id, COALESCE(ctr.cid, '') AS cid, f.cve_id, f.package_name,
                fst.status AS fix_status
           FROM tb_finding f
           JOIN tb_scan s ON s.scan_id = f.scan_id
           JOIN tb_host h ON h.host_id = s.host_id AND h.is_deleted = 0
           $latestJoin
           LEFT JOIN tb_container ctr ON ctr.container_id = f.container_id
           LEFT JOIN tb_finding_status fst ON fst.host_id = s.host_id
                 AND fst.container_ref = COALESCE(ctr.cid, '')
                 AND fst.cve_id = f.cve_id AND fst.package_name = f.package_name
          WHERE f.in_kev = 1 AND f.severity IN ('CRITICAL','HIGH') AND f.is_deleted = 0"
    )->fetchAll();
    $kevKeys = [];
    foreach ($kevRows as $r) {
        $fixStatus = (string) ($r['fix_status'] ?? '');
        if ($fixStatus === 'DONE' || $fixStatus === 'EXCEPTED') { continue; }
        $kevKeys[] = [(int) $r['host_id'], (string) $r['cid'],
                      (string) $r['cve_id'], (string) $r['package_name']];
    }
    if ($kevKeys) {
        $kevFirstSeen = vg_finding_first_seen_map($pdo, $kevKeys, vg_finding_sla_lookback_days($policy));
        foreach ($kevKeys as $k) {
            $seen = $kevFirstSeen[vg_finding_status_key($k[0], $k[1], $k[2], $k[3])] ?? null;
            // 최초 발견 시각을 못 찾은 건은 세지 않는다 — 모르는 것을 초과로 단정하지 않는다
            //   (목록의 남은 일수 칸이 '–' 로 두는 것과 같은 판단).
            if ($seen !== null && (int) $seen['days'] > $kevSlaDays) { $kevOverdue++; }
        }
    }

    /* 최신 스캔의 실제 취약점 신호를 직접 보여준다.
     * 업무 상태나 내부 기한을 만들지 않고 KEV·외부 노출·런타임·심각도만으로 정렬한다.
     */
    $urgent = $pdo->query(
        "SELECT MIN(f.finding_id) finding_id,f.cve_id,f.package_name,h.host_id,h.fqdn,
                f.severity,f.runtime_status,f.in_kev
           FROM tb_finding f
           JOIN tb_scan s ON s.scan_id=f.scan_id
           $latestJoin
           JOIN tb_host h ON h.host_id=s.host_id AND h.is_deleted=0
          GROUP BY f.cve_id,f.package_name,h.host_id,h.fqdn,f.severity,f.runtime_status,f.in_kev
          ORDER BY (f.in_kev=1 AND f.runtime_status='EXTERNAL') DESC,f.in_kev DESC,
                   FIELD(f.runtime_status,'EXTERNAL','LISTENING','RUNNING','INSTALLED'),
                   FIELD(f.severity,'CRITICAL','HIGH','MEDIUM','LOW'),finding_id
          LIMIT " . vg_ui_dashboard_urgent_limit()
    )->fetchAll();
    $urgentTotal = (int) $pdo->query(
        "SELECT COUNT(*) FROM (
           SELECT f.cve_id,f.package_name,s.host_id,f.severity,f.runtime_status,f.in_kev
             FROM tb_finding f
             JOIN tb_scan s ON s.scan_id=f.scan_id
             JOIN " . vg_latest_scan_subq() . " latest ON latest.host_id=s.host_id AND latest.mid=s.scan_id
             JOIN tb_host h ON h.host_id=s.host_id AND h.is_deleted=0
            GROUP BY f.cve_id,f.package_name,s.host_id,f.severity,f.runtime_status,f.in_kev
         ) current_findings"
    )->fetchColumn();
    /* KPI 증감 — "지금 몇 건" 만으로는 나아지는지 알 수 없다. 7일 전과 비교한다.
     *
     * 스캔은 **바뀔 때만** 저장된다(feat/change-tracking) — 날짜가 듬성듬성하다.
     * 그래서 "7일 전 그날의 스캔" 만 보면 그날 스캔이 없는 호스트가 0건으로 세어져
     * "일주일 새 확 늘었다"는 거짓말이 된다. 호스트별로 **7일 전까지의 최신 스캔을
     * 이월(carry-forward)** 해서 합산한다 = 호스트별 MAX(scan_id) WHERE 날짜 <= 7일 전.
     */
    $weekAgoDay = date('Y-m-d', strtotime('-7 days'));
    $weekAgoScans = $pdo->query(
        "SELECT MAX(s.scan_id) AS mid
           FROM tb_scan s
           JOIN tb_host h ON h.host_id = s.host_id AND h.is_deleted = 0
          WHERE s.is_deleted = 0 AND DATE(s.collected_at) <= '$weekAgoDay'
          GROUP BY s.host_id"
    )->fetchAll();

    // 7일 전에 스캔이 하나도 없었으면 전부 0 — 그때 대비 지금 건수가 그대로 증가분이다.
    $weekAgo = ['CRITICAL' => 0, 'HIGH' => 0, 'MEDIUM' => 0, 'LOW' => 0];
    $sevOfScan = vg_sev_by_scan_ids($pdo, array_map(fn($s) => (int) $s['mid'], $weekAgoScans));
    foreach ($sevOfScan as $counts) {
        foreach ($weekAgo as $sev => $_) { $weekAgo[$sev] += (int) ($counts[$sev] ?? 0); }
    }
    foreach ($totals as $sev => $now) { $delta[$sev] = $now - $weekAgo[$sev]; }

    /* 최근 VG_TREND_DAYS 일 추세 — 날짜별 "High 이상" 건수.
     *
     * 이월(carry-forward) 규칙은 위 KPI 증감과 같다: 스캔은 바뀔 때만 저장되므로 그날 스캔이
     * 없는 호스트는 **직전 스캔 값을 이어 쓴다**(0 으로 떨구면 "취약점이 사라졌다"는 거짓말).
     * 대신 그날 실제 수집이 있었는지는 따로 표시해서(scanned) 차트가 점을 그날에만 찍는다.
     *
     * 읽는 스캔은 두 묶음뿐이다 — 창 안의 스캔 + 각 호스트가 창 시작 전에 가진 마지막 스캔
     * (이월의 출발점). 전체 스캔을 다 읽으면 이력이 쌓일수록 대시보드가 선형으로 느려진다.
     *
     * 사전집계 테이블을 새로 만들지 않았다: 기존 집계 자산(tb_package_summary·tb_scan_run)
     * 어디에도 스캔별 심각도 건수가 없고, 실측(dev: 호스트 208 · 스캔 951 · finding 42만)에서
     * 이 두 쿼리 합이 45ms 라 사전집계의 갱신 비용·정합성 부담을 살 이유가 없다(YAGNI).
     * 단, scan_id 목록은 **PHP 가 값으로 펼쳐** 넘긴다 — IN (서브쿼리) 로 두면 옵티마이저가
     * tb_finding 을 먼저 훑어 같은 결과에 2.06초가 걸렸다(실측).
     */
    $since = date('Y-m-d', strtotime('-' . (VG_TREND_DAYS - 1) . ' days'));
    $trendScans = $pdo->query(
        "SELECT s.scan_id AS id, s.host_id, DATE(s.collected_at) AS d
           FROM tb_scan s
           JOIN tb_host h ON h.host_id = s.host_id AND h.is_deleted = 0
          WHERE s.is_deleted = 0 AND DATE(s.collected_at) >= '$since'
          UNION
         SELECT s.scan_id, s.host_id, DATE(s.collected_at)
           FROM tb_scan s
           JOIN tb_host h ON h.host_id = s.host_id AND h.is_deleted = 0
           JOIN (SELECT host_id, MAX(scan_id) AS mid FROM tb_scan
                  WHERE is_deleted = 0 AND DATE(collected_at) < '$since'
                  GROUP BY host_id) b ON b.mid = s.scan_id"
    )->fetchAll();

    // 호스트별 (날짜, 스캔id) 를 id 순으로 — 이월은 "그날 이하의 마지막 스캔" 고르기다.
    $trendByHost = []; $scannedDays = [];
    foreach ($trendScans as $s) {
        if ($s['d'] === null) { continue; }   // collected_at 이 비어 있으면 어느 날짜에도 못 건다
        $trendByHost[(int) $s['host_id']][] = ['d' => (string) $s['d'], 'id' => (int) $s['id']];
        $scannedDays[(string) $s['d']] = true;
    }
    foreach ($trendByHost as &$list) { usort($list, fn($a, $b) => $a['id'] <=> $b['id']); }
    unset($list);

    // 스캔별 High 이상 건수 — 퍼널 2번째 칸과 같은 기준(CRITICAL + HIGH).
    $highByScan = [];
    $trendIds = array_values(array_unique(array_map(fn($s) => (int) $s['id'], $trendScans)));
    if ($trendIds) {
        $in = implode(',', array_fill(0, count($trendIds), '?'));
        $st = $pdo->prepare(
            "SELECT scan_id, COUNT(*) c FROM tb_finding
              WHERE scan_id IN ($in) AND severity IN ('CRITICAL','HIGH')
              GROUP BY scan_id"
        );
        $st->execute($trendIds);
        foreach ($st->fetchAll() as $r) { $highByScan[(int) $r['scan_id']] = (int) $r['c']; }
    }

    for ($i = VG_TREND_DAYS - 1; $i >= 0; $i--) {
        $day = date('Y-m-d', strtotime("-$i days"));
        $sum = 0; $any = false;
        foreach ($trendByHost as $list) {
            $pick = null;
            foreach ($list as $s) { if ($s['d'] <= $day) { $pick = $s['id']; } }   // 그날까지의 최신
            if ($pick === null) { continue; }   // 그날엔 아직 이 호스트가 없었다
            $any = true;
            $sum += (int) ($highByScan[$pick] ?? 0);
        }
        // 첫 수집 이전의 날은 "0건" 이 아니라 "아직 자료가 없음" 이다 — 선을 시작하지 않는다.
        if (!$any) { continue; }
        $trend[] = ['d' => $day, 'v' => $sum, 'scanned' => isset($scannedDays[$day])];
    }

    // 목록 대상 = 최신 스캔이 있는 비삭제 호스트 수(페이지네이션 총건).
    $total = (int) $pdo->query(
        'SELECT COUNT(*) FROM tb_host h WHERE h.is_deleted = 0
          AND EXISTS (SELECT 1 FROM tb_scan s WHERE s.host_id = h.host_id)'
    )->fetchColumn();

    $offset = ($page - 1) * $perPage;

    /* 호스트별 최신 스캔(한 페이지) — **위험도 높은 순**.
     *
     * 정렬은 반드시 SQL 에서 한다. 페이지네이션이 걸려 있어 PHP 로 현재 페이지만 정렬하면
     * 1페이지에 못 들어온 위험 호스트가 영영 안 보인다(지금은 11대라 한 페이지지만 자산이 늘면 깨진다).
     *
     * tb_finding 은 위 주석과 같은 이유로 IN(서브쿼리)가 아니라 JOIN 으로 붙인다.
     * LEFT JOIN 이어야 findings 0건인 호스트가 목록에서 사라지지 않는다.
     * COALESCE 가 필요한 이유: 매칭 행이 없으면 SUM(...) 이 NULL 이라 정렬·렌더가 흔들린다.
     * (scan_id, severity) 인덱스 idx_find_scan_sev 가 이 집계를 받쳐준다.
     */
    $rows = $pdo->query(
        "SELECT s.scan_id, s.collected_at, s.package_count, s.exposure_count, s.agent_version,
                h.host_id, h.fqdn, h.os_id, h.os_version,
                COALESCE(SUM(f.severity = 'CRITICAL'), 0) sev_critical,
                COALESCE(SUM(f.severity = 'HIGH'), 0)     sev_high,
                COALESCE(SUM(f.severity = 'MEDIUM'), 0)   sev_medium,
                COALESCE(SUM(f.severity = 'LOW'), 0)      sev_low
         FROM tb_scan s
         JOIN " . vg_latest_scan_subq() . " t ON t.mid = s.scan_id
         JOIN tb_host h ON h.host_id = s.host_id
         LEFT JOIN tb_finding f ON f.scan_id = s.scan_id
         WHERE h.is_deleted = 0
         GROUP BY s.scan_id, s.collected_at, s.package_count, s.exposure_count, s.agent_version,
                  h.host_id, h.fqdn, h.os_id, h.os_version
         ORDER BY sev_critical DESC, sev_high DESC, sev_medium DESC, sev_low DESC,
                  s.collected_at DESC, s.scan_id DESC
         LIMIT $perPage OFFSET $offset"
    )->fetchAll();

    // 심각도 카운트는 위 정렬용 집계를 그대로 쓴다 — vg_sev_by_scan_ids() 로 한 번 더 세지 않는다(DRY).
    foreach ($rows as $r) {
        $sevByScan[(int) $r['scan_id']] = [
            'CRITICAL' => (int) $r['sev_critical'], 'HIGH' => (int) $r['sev_high'],
            'MEDIUM'   => (int) $r['sev_medium'],   'LOW'  => (int) $r['sev_low'],
        ];
    }
} catch (Throwable $e) {
    error_log('[index] ' . $e->getMessage());
    $err = '처리 중 오류가 발생했습니다.';
}

vg_header('대시보드', 'dashboard');
?>
  <?php vg_page_title('대시보드', 'OVERVIEW', '전체 자산의 최신 탐지 결과를 요약합니다.'); ?>

<?php if ($err !== null): ?>
  <?php vg_alert('DB 오류 · ' . $err); ?>
<?php else: ?>
  <?php
  /* 상단은 결론 문장 + KPI 나열이 아니라 **좁혀지는 퍼널**이다.
   *
   * 이 숫자들의 실제 관계는 나열이 아니라 포함이다 — 전체 안에 High 이상이 있고, 그 안에
   * 악용 확인(KEV)이 있고, 그 안에 외부 노출이 있다. 관계를 형태로 그리면 "가장 먼저
   * 조치할 대상입니다" 라는 배너 문장이 필요 없어져서, 그 배너는 지웠다.
   *
   * 마지막 칸이 "오늘 할 일" 이다. 예전엔 KEV 중 외부 노출을 셌는데, 그건 기한 계산이
   * 이 저장소에 없어서 고른 대체 신호였다. 지금은 finding_sla.php 가 조치 기한을 계산하므로
   * 원래 의도대로 **KEV 중 기한 초과**를 센다 — "언제까지" 를 넘긴 것이 진짜 오늘 할 일이다.
   * (외부 노출 신호는 아래 [주요 취약점 신호] 카드가 정렬 기준으로 계속 보여준다.)
   *
   * 링크: findings.php 에 KEV 필터도, 기한 초과 필터도 없다 — 있는 것은 기한 임박순
   *   정렬(?sort=due)이고, 초과분이 그 목록 맨 위에 선다. 그래서 4번 칸은 그리로 보낸다
   *   (가장 가까운 목적지다). KEV 칸은 KEV 우선 정렬인 아래 카드로 보낸다(#signals) —
   *   숫자만 있고 못 누르는 칸을 만들지 않는다.
   */
  $crit = (int) $totals['CRITICAL'];
  $high = (int) $totals['HIGH'];
  $allCount = array_sum($totals);
  $funnelSteps = [
      ['n' => $allCount, 'label' => '탐지된 전체',
       'cap' => '자산 ' . number_format($hostCount) . '대 · 최신 스캔 기준',
       'href' => '/findings.php', 'title' => '탐지 결과 전체 목록'],
      ['n' => $crit + $high, 'label' => 'High 이상',
       'cap' => 'CRITICAL ' . number_format($crit) . ' · HIGH ' . number_format($high),
       'href' => '/findings.php?sev=HIGH', 'title' => 'HIGH 등급 목록 · CRITICAL 은 등급 카드에서'],
      ['n' => $kevCount, 'label' => '악용 확인(KEV)',
       'cap' => 'High 이상 중 · 실제 공격에 쓰임',
       'href' => '#signals', 'title' => 'KEV 순으로 정렬된 주요 취약점 신호'],
      ['n' => $kevOverdue, 'label' => 'KEV 중 기한 초과',
       'cap' => '조치 기한 ' . number_format($kevSlaDays) . '일 넘김 · 오늘 먼저 조치할 대상',
       'href' => '/findings.php?sort=due', 'title' => '조치 기한이 급한 순으로 정렬된 탐지 결과 (초과분이 맨 위)'],
  ];
  ?>
  <div class="funnel">
    <?php foreach ($funnelSteps as $i => $s):
      // 오른쪽으로 갈수록 무게가 커진다(s1 → s4). 다만 **0건이면 색을 걷는다** — 0 은
      //   "지금 볼 것이 없다" 는 뜻이라 위험색을 가져갈 이유가 없다(findings.php 의 등급 카드와 같은 규칙).
      $cls = 'funnel__step funnel__step--s' . ($i + 1) . ((int) $s['n'] === 0 ? ' funnel__step--zero' : '');
    ?>
      <a class="<?= $cls ?>" href="<?= vg_h($s['href']) ?>" title="<?= vg_h($s['title']) ?>">
        <b><?= number_format((int) $s['n']) ?></b>
        <span><?= vg_h($s['label']) ?></span>
        <span class="funnel__cap"><?= vg_h($s['cap']) ?></span>
      </a>
    <?php endforeach; ?>
  </div>
  <?php if ($nextFeed !== null):
    $secs = strtotime((string) $nextFeed['next_run_at']) - time();
    $rel  = $secs <= 0 ? '곧'
          : ($secs < 3600 ? (int) round($secs / 60) . '분 후'
          : ($secs < 86400 ? (int) round($secs / 3600) . '시간 후'
          : (int) round($secs / 86400) . '일 후'));
  ?>
  <div class="sub">다음 수집 예정 · <strong><?= vg_h((string) $nextFeed['next_run_at']) ?></strong>
    <span class="why"><?= vg_h($rel) ?> · <?= vg_h($nextFeed['name']) ?> (<?= vg_h(strtoupper((string) $nextFeed['connector_type'])) ?>)</span></div>
  <?php endif; ?>

  <div class="card">
    <strong>최근 <?= VG_TREND_DAYS ?>일 추세</strong>
    <span class="why">— 날짜별 High 이상 건수 · 수집이 없는 날은 직전 값을 이어 그린다(점은 수집한 날에만)</span>
    <div class="card__body"><?php vg_daily_trend($trend); ?></div>
  </div>

  <div class="card" id="signals">
    <strong>주요 취약점 신호</strong>
    <?php /* 정렬 기준과 "몇 건 중 몇 건" 이 각각 다른 why 로 붙어 제목 옆이 두 줄로 흘렀다 — 한 줄로 합친다.
             정렬 기준의 근거(KEV·노출·심각도)는 아래 [탐지 신호] 열이 행마다 다시 보여준다. */ ?>
    <span class="why">— KEV·노출·심각도 순<?php if ($urgentTotal > count($urgent)): ?>
      · 상위 <?= count($urgent) ?>건 / 총 <?= number_format($urgentTotal) ?>건 ·
      <a href="/findings.php">전체 보기 →</a><?php endif; ?></span>
    <div class="card__body">
    <?php
    vg_table(
        [
            ['label' => '등급', 'key' => 'severity', 'width' => '6rem', 'nowrap' => true],
            ['label' => 'CVE', 'width' => '13rem', 'nowrap' => true],
            ['label' => '호스트'],
            ['label' => '패키지'],
            ['label' => '탐지 신호', 'width' => '15rem'],
        ],
        $urgent,
        [
            'card'  => false,
            'empty' => [
                'icon'  => '✅',
                'title' => '급한 항목이 없습니다.',
                'hint'  => '악용이 확인됐거나 외부에 노출된 취약점이 없습니다.',
            ],
            'row_class' => fn($u) => vg_sev_row((string) $u['severity']),
            'cell' => [
                'severity' => fn($u) => vg_sev_badge((string) $u['severity']),
                1 => function ($u) {
                    $html = '<strong><a href="/cve.php?cve=' . urlencode((string) $u['cve_id']) . '">'
                          . vg_h((string) $u['cve_id']) . '</a></strong>';
                    if ($u['in_kev']) { $html .= ' ' . vg_badge('KEV', 'crit'); }
                    return $html;
                },
                2 => fn($u) => '<a href="/host.php?id=' . (int) $u['host_id'] . '">' . vg_h((string) $u['fqdn']) . '</a>',
                3 => fn($u) => vg_h((string) $u['package_name']),
                4 => function ($u) {
                    if ($u['in_kev'] && $u['runtime_status'] === 'EXTERNAL') {
                        return vg_badge('악용확인 + 외부노출', 'crit');
                    }
                    if ($u['in_kev']) {
                        return vg_badge('악용확인', 'warn') . ' ' . vg_status_badge($u['runtime_status']);
                    }
                    return vg_status_badge($u['runtime_status']);
                },
            ],
        ]
    );
    ?>
    </div>
  </div>

  <?php /* 등급별 전체 분포와 도넛은 지우지 않고 **접어서** 퍼널 아래로 내린다.
   * MEDIUM·LOW 는 "오늘 무엇을 할까" 를 바꾸지 않는 수라(실측 LOW 34,745) 상단에 두면
   * 자릿수만으로 CRITICAL 을 덮는다. 필요할 때 펴 보는 자리가 맞다. */ ?>
  <div class="card">
    <strong>등급별 분포</strong> <span class="why">— 7일 전 대비 증감과 도넛</span>
    <div class="card__body">
      <details>
        <summary>등급별 전체 분포 보기</summary>
        <div class="cards cards--grid">
          <div class="kpi"><b><?= number_format($hostCount) ?></b><span>호스트</span></div>
          <?php foreach (['CRITICAL','HIGH','MEDIUM','LOW'] as $s):
      // 증감은 방향을 색만으로 말하지 않는다 — ▲/▼ 기호를 같이 준다(색각 이상·흑백 출력).
      // 변화가 없으면(0) 칩 자체를 안 그린다 — "— 0" 은 알려주는 게 없이 카드만 시끄럽게 했다.
      $d = ($delta[$s] ?? 0) !== 0 ? $delta[$s] : null;
      $dir = $d === null ? '' : ($d > 0 ? 'up' : 'down');
      $dtxt = $d === null ? '' : ($d > 0 ? '▲ ' . number_format($d) : '▼ ' . number_format(abs($d)));
    ?>
          <a class="kpi tone-<?= vg_sev_tone($s) ?>" href="/findings.php?sev=<?= $s ?>">
            <b><?= number_format((int) $totals[$s]) ?></b><span><?= $s ?></span>
            <?php if ($d !== null): ?>
              <span class="kpi__delta <?= $dir ?>"><span class="sr-only">7일 전 대비 </span><?= vg_h($dtxt) ?></span>
            <?php endif; ?>
          </a>
        <?php endforeach; ?>
        </div>
        <div class="donut-wrap">
          <?php vg_sev_donut($totals, 152); ?>
          <div class="legend">
            <?php foreach (['CRITICAL','HIGH','MEDIUM','LOW'] as $s): ?>
              <div>
                <i class="tone-<?= vg_sev_tone($s) ?>"></i>
                <span><?= $s ?></span>
              </div>
            <?php endforeach; ?>
          </div>
        </div>
        <?php /* 도넛 바닥의 KEV 요약. 퍼널 3번째 칸과 **같은 수**다(같은 쿼리에서 나온다) —
                 접힌 안쪽에서 다시 세지 않는다. */ ?>
        <div class="donut-foot">
          <?= vg_badge('High 이상 중 KEV ' . number_format($kevCount) . '건', $kevCount > 0 ? 'crit' : 'ok') ?>
        </div>
      </details>
    </div>
  </div>

  <div class="card">
    <strong>호스트별 현황</strong> <span class="why">— 위험도 높은 순 · 각 호스트의 최신 스캔 기준</span>
    <div class="card__body">
  <?php
  vg_table(
      [
          ['label' => '호스트'],
          ['label' => 'OS'],
          ['label' => '패키지', 'align' => 'right'],
          ['label' => '노출', 'align' => 'right'],
          ['label' => '심각도'],
          ['label' => '수집시각', 'nowrap' => true],
          ['label' => '', 'nowrap' => true],
      ],
      $rows,
      [
          'card'  => false,
          'empty' => [
              'icon'  => '🖥️',
              'title' => '아직 수집된 스캔이 없습니다.',
              'hint'  => '에이전트를 --send 로 실행하면 여기에 나타납니다.',
          ],
          'cell' => [
              0 => fn($r) => '<strong><a href="/host.php?id=' . (int) $r['host_id'] . '">' . vg_h($r['fqdn']) . '</a></strong>',
              1 => fn($r) => vg_h($r['os_id']) . ' ' . vg_h($r['os_version']),
              2 => fn($r) => vg_h((string) (int) $r['package_count']),
              3 => fn($r) => vg_h((string) (int) $r['exposure_count']),
              // 막대 + 숫자 뱃지 — 막대로 "누가 더 나쁜지" 를 눈이 먼저 잡고, 숫자가 확인해준다.
              4 => function ($r) use ($sevByScan) {
                  $c = $sevByScan[(int) $r['scan_id']] ?? [];
                  return vg_sev_bar($c) . vg_sev_counts($c);
              },
              5 => fn($r) => '<span class="why">' . vg_h($r['collected_at']) . '</span>',
              6 => fn($r) => '<a href="/findings.php?scan_id=' . (int) $r['scan_id'] . '">취약점 →</a>',
          ],
      ]
  );
  if ($rows) { vg_page_nav($total, $perPage, $page); }
  ?>
    </div>
  </div>
<?php endif; ?>
<?php vg_footer();
