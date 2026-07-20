<?php
declare(strict_types=1);

/**
 * index.php — 대시보드 (로그인 필요).
 *   호스트별 최신 스캔 + 심각도 요약. 각 행에서 취약점 상세로.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
vg_require_menu('dashboard');

// "지금 급한 것" 에 보여줄 최대 건수. 나머지는 취약점 현황으로 넘긴다.
const VG_URGENT_TOP = 6;
// 에이전트 리소스 사용량 카드의 함대 평균 추이 — 최근 며칠치를 볼지.
const VG_RESOURCE_TREND_DAYS = 30;

$err = null; $rows = []; $totals = ['CRITICAL'=>0,'HIGH'=>0,'MEDIUM'=>0,'LOW'=>0];
$hostCount = 0; $total = 0; $sevByScan = [];
$kevCount = 0; $overdueCount = 0; $urgent = []; $urgentTotal = 0; $nextFeed = null;
$delta = []; $osDist = []; $topHosts = [];
$resKpi = null; $memTrend = []; $cpuTrend = [];
$page = vg_page();
$perPage = vg_perpage();
try {
    $pdo = vg_pdo();
    $hostCount = (int) $pdo->query('SELECT COUNT(*) FROM tb_hosts WHERE is_deleted = 0')->fetchColumn();

    // 다음 수집 예정 — enabled·비manual 커넥터 중 next_run_at 이 가장 이른 하나.
    //   manual 커넥터는 next_run_at 이 NULL 이라 자연히 제외된다(connectors.php 가 그렇게 저장).
    $nextFeed = $pdo->query(
        "SELECT name, connector_type, next_run_at FROM tb_feed_connectors
          WHERE enabled = 1 AND is_deleted = 0 AND next_run_at IS NOT NULL
          ORDER BY next_run_at ASC LIMIT 1"
    )->fetch() ?: null;

    // 전 호스트의 "최신 스캔" 집합 — KPI·도넛·급한목록이 모두 이 기준을 쓴다.
    $latestScans =
        "SELECT t.mid FROM " . vg_latest_scan_subq() . " t
          JOIN tb_hosts h ON h.id = t.host_id
         WHERE h.is_deleted = 0";

    // KPI 는 페이지 무관 — 전 호스트 최신 스캔의 심각도 총합.
    $totalsRows = $pdo->query(
        "SELECT f.severity, COUNT(*) c FROM tb_findings f
          WHERE f.scan_id IN ($latestScans)
          GROUP BY f.severity"
    )->fetchAll();
    foreach ($totalsRows as $f) { if (isset($totals[$f['severity']])) { $totals[$f['severity']] = (int) $f['c']; } }

    /* "지금 급한 것" — 대시보드에 없던, 정작 제일 필요한 답.
     *
     * 급함의 정의(순서대로):
     *   1) KEV 패치 기한이 지났다      — CISA 가 정한 기한. 유일하게 "언제까지" 가 있는 신호다.
     *   2) 악용이 확인됐고(KEV) 외부에 노출돼 있다
     *   3) 그 외 등급순
     * due_date 는 KEV 커넥터가 최근에야 받아오기 시작한 값이라 NULL 일 수 있다 — NULL 은 "기한 없음".
     */
    $urgent = $pdo->query(
        "SELECT f.cve_id, f.severity, f.package_name, f.runtime_status, f.in_kev,
                h.id AS host_id, h.fqdn, k.due_date,
                DATEDIFF(CURDATE(), k.due_date) AS days_over
           FROM tb_findings f
           JOIN tb_scans s ON s.id = f.scan_id
           JOIN tb_hosts h ON h.id = s.host_id
           LEFT JOIN tb_kev_catalog k ON k.cve_id = f.cve_id AND k.is_deleted = 0
          WHERE f.scan_id IN ($latestScans)
            AND (f.in_kev = 1 OR f.runtime_status = 'EXTERNAL')
          ORDER BY (k.due_date IS NOT NULL AND k.due_date < CURDATE()) DESC,
                   (f.in_kev = 1 AND f.runtime_status = 'EXTERNAL') DESC,
                   FIELD(f.severity,'CRITICAL','HIGH','MEDIUM','LOW'),
                   k.due_date
          LIMIT " . VG_URGENT_TOP
    )->fetchAll();

    // 급한 항목의 전체 건수 — 상위 N개만 보여주면서 "몇 건 중 몇 건인지" 를 말하지 않으면
    // 화면이 "이게 전부" 라고 거짓말을 한다. 나머지는 취약점 현황에서 본다.
    $urgentTotal = (int) $pdo->query(
        "SELECT COUNT(*) FROM tb_findings f
          WHERE f.scan_id IN ($latestScans)
            AND (f.in_kev = 1 OR f.runtime_status = 'EXTERNAL')"
    )->fetchColumn();

    // KEV 노출 건수 · 패치 기한 초과 건수(KPI)
    $kevCount = (int) $pdo->query(
        "SELECT COUNT(*) FROM tb_findings f WHERE f.scan_id IN ($latestScans) AND f.in_kev = 1"
    )->fetchColumn();
    $overdueCount = (int) $pdo->query(
        "SELECT COUNT(*) FROM tb_findings f
           JOIN tb_kev_catalog k ON k.cve_id = f.cve_id AND k.is_deleted = 0
          WHERE f.scan_id IN ($latestScans) AND k.due_date IS NOT NULL AND k.due_date < CURDATE()"
    )->fetchColumn();

    // OS 분포 — 비삭제 호스트를 os_id 기준으로 묶어 상위 10개. os_id 가 비어있으면 "미상".
    $osDist = $pdo->query(
        "SELECT COALESCE(NULLIF(os_id, ''), '미상') AS os_label, COUNT(*) c
           FROM tb_hosts
          WHERE is_deleted = 0
          GROUP BY os_label
          ORDER BY c DESC, os_label
          LIMIT 10"
    )->fetchAll();

    // 취약 자산 TOP10 — 호스트별 최신 스캔 기준 findings 건수 상위 10개.
    // "호스트별 현황" 표(전체·페이지네이션)와 별개로, 카드 안에서 한눈에 보는 용도.
    $topHosts = $pdo->query(
        "SELECT h.id AS host_id, h.fqdn, COUNT(f.id) c
           FROM tb_findings f
           JOIN tb_scans s ON s.id = f.scan_id
           JOIN tb_hosts h ON h.id = s.host_id
          WHERE f.scan_id IN ($latestScans)
          GROUP BY h.id, h.fqdn
          ORDER BY c DESC
          LIMIT 10"
    )->fetchAll();

    /* 에이전트 리소스 사용량 — "설치해도 서버 부담이 거의 없다" 를 함대 전체로 보여주는 카드.
     * KPI 는 전 호스트 최신 스캔 기준 평균(구버전 에이전트의 NULL 은 AVG() 가 자동으로 뺀다) —
     * 호스트당 1건 가중. 추이는 개별 스캔 산점이 아니라 날짜별 함대 평균(스캔 건수 가중) —
     * 모집단이 달라 KPI 와 추이 마지막 값이 정확히 같진 않다(화면 부제로 기준을 구분해 표시).
     */
    $resKpi = $pdo->query(
        "SELECT AVG(peak_rss_mb) avg_mem, AVG(cpu_seconds) avg_cpu
           FROM tb_scans WHERE id IN ($latestScans)"
    )->fetch() ?: null;

    // 메모리·CPU 를 한 쿼리로 같이 집계한다 — AVG() 가 컬럼별로 NULL 을 알아서 빼므로 굳이
    // 쿼리를 둘로 나눠 tb_scans 를 두 번 훑을 이유가 없다. "최근 N일" 라벨과 맞추려고
    // (N-1)일 전부터 오늘까지로 잡는다(DATE_SUB(...,N DAY) 는 N+1일치가 걸린다).
    $resTrendRows = $pdo->query(
        "SELECT DATE(s.collected_at) AS d, AVG(s.peak_rss_mb) AS peak_rss_mb, AVG(s.cpu_seconds) AS cpu_seconds
           FROM tb_scans s
           JOIN tb_hosts h ON h.id = s.host_id AND h.is_deleted = 0
          WHERE s.is_deleted = 0
            AND s.collected_at >= DATE_SUB(CURDATE(), INTERVAL " . (VG_RESOURCE_TREND_DAYS - 1) . " DAY)
          GROUP BY d
          ORDER BY d ASC"
    )->fetchAll();
    foreach ($resTrendRows as $t) {
        if ($t['peak_rss_mb'] !== null) { $memTrend[] = ['collected_at' => $t['d'], 'peak_rss_mb' => $t['peak_rss_mb']]; }
        if ($t['cpu_seconds'] !== null) { $cpuTrend[] = ['collected_at' => $t['d'], 'cpu_seconds' => $t['cpu_seconds']]; }
    }

    /* KPI 증감 — "지금 몇 건" 만으로는 나아지는지 알 수 없다. 7일 전과 비교한다.
     *
     * 스캔은 **바뀔 때만** 저장된다(feat/change-tracking) — 날짜가 듬성듬성하다.
     * 그래서 "7일 전 그날의 스캔" 만 보면 그날 스캔이 없는 호스트가 0건으로 세어져
     * "일주일 새 확 늘었다"는 거짓말이 된다. 호스트별로 **7일 전까지의 최신 스캔을
     * 이월(carry-forward)** 해서 합산한다 = 호스트별 MAX(id) WHERE 날짜 <= 7일 전.
     */
    $weekAgoDay = date('Y-m-d', strtotime('-7 days'));
    $weekAgoScans = $pdo->query(
        "SELECT MAX(s.id) AS mid
           FROM tb_scans s
           JOIN tb_hosts h ON h.id = s.host_id AND h.is_deleted = 0
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

    // 목록 대상 = 최신 스캔이 있는 비삭제 호스트 수(페이지네이션 총건).
    $total = (int) $pdo->query(
        'SELECT COUNT(*) FROM tb_hosts h WHERE h.is_deleted = 0
          AND EXISTS (SELECT 1 FROM tb_scans s WHERE s.host_id = h.id)'
    )->fetchColumn();

    $offset = ($page - 1) * $perPage;

    // 호스트별 최신 스캔(한 페이지)
    $rows = $pdo->query(
        "SELECT s.id AS scan_id, s.collected_at, s.package_count, s.exposure_count, s.agent_version,
                h.id AS host_id, h.fqdn, h.os_id, h.os_version
         FROM tb_scans s
         JOIN " . vg_latest_scan_subq() . " t ON t.mid = s.id
         JOIN tb_hosts h ON h.id = s.host_id
         WHERE h.is_deleted = 0
         ORDER BY s.collected_at DESC
         LIMIT $perPage OFFSET $offset"
    )->fetchAll();

    // 이 페이지 최신 스캔들의 심각도 카운트
    if ($rows) {
        $ids = [];
        foreach ($rows as $r) { $ids[] = (int) $r['scan_id']; }
        $sevByScan = vg_sev_by_scan_ids($pdo, $ids);
    }
} catch (Throwable $e) {
    $err = $e->getMessage();
}

vg_header('대시보드', 'dashboard');
?>
  <h1>대시보드</h1>

<?php if ($err !== null): ?>
  <?php vg_alert('DB 오류 · ' . $err); ?>
<?php else: ?>
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

  <div class="cards">
    <div class="kpi"><b><?= number_format($hostCount) ?></b><span>호스트</span></div>
    <?php foreach (['CRITICAL','HIGH','MEDIUM','LOW'] as $s):
      // 증감은 방향을 색만으로 말하지 않는다 — ▲/▼ 기호를 같이 준다(색각 이상·흑백 출력).
      $d = $delta[$s] ?? null;
      $dir = $d === null ? '' : ($d > 0 ? 'up' : ($d < 0 ? 'down' : 'flat'));
      $dtxt = $d === null ? '' : ($d > 0 ? '▲ ' . number_format($d)
                                : ($d < 0 ? '▼ ' . number_format(abs($d)) : '— 0'));
    ?>
      <a class="kpi tone-<?= vg_sev_tone($s) ?>" href="/findings.php?sev=<?= $s ?>">
        <b><?= number_format((int) $totals[$s]) ?></b><span><?= $s ?></span>
        <?php if ($d !== null): ?>
          <span class="kpi__delta <?= $dir ?>" title="7일 전 대비"><?= vg_h($dtxt) ?></span>
        <?php endif; ?>
      </a>
    <?php endforeach; ?>
    <div class="kpi tone-<?= $kevCount > 0 ? 'crit' : 'ok' ?>">
      <b><?= number_format($kevCount) ?></b><span>KEV 악용확인</span>
    </div>
    <div class="kpi tone-<?= $overdueCount > 0 ? 'crit' : 'ok' ?>">
      <b><?= number_format($overdueCount) ?></b><span>패치기한 초과</span>
    </div>
  </div>

  <div class="split">
    <div class="card">
      <strong>심각도 분포</strong>
      <div class="card__body center">
        <?php // 추세 카드가 빠져 도넛이 이 화면의 유일한 그래픽이 됐다 — 기본(132)보다 키운다. ?>
        <?php vg_sev_donut($totals, 152); ?>
        <div class="legend">
          <?php foreach (['CRITICAL','HIGH','MEDIUM','LOW'] as $s): ?>
            <div>
              <i class="tone-<?= vg_sev_tone($s) ?>"></i>
              <span><?= $s ?></span>
              <span class="n"><?= number_format((int) $totals[$s]) ?></span>
            </div>
          <?php endforeach; ?>
        </div>
      </div>
    </div>

    <div class="card">
      <strong>지금 급한 것</strong>
      <span class="why">— 패치 기한이 지났거나, 악용이 확인됐는데 외부에 노출된 것부터</span>
      <?php if ($urgentTotal > count($urgent)): ?>
        <span class="why">· 총 <?= number_format($urgentTotal) ?>건 중 상위 <?= count($urgent) ?>건 ·
          <a href="/findings.php?st=EXTERNAL">전체 보기 →</a></span>
      <?php endif; ?>
      <div class="card__body">
      <?php
      vg_table(
          [
              ['label' => '등급', 'key' => 'severity', 'width' => '6rem', 'nowrap' => true],
              ['label' => 'CVE', 'width' => '13rem', 'nowrap' => true],
              ['label' => '호스트'],
              ['label' => '패키지'],
              ['label' => '왜 급한가', 'width' => '15rem'],
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
                  // "왜 급한가" — 기한 초과가 최우선, 그다음이 악용확인+외부노출.
                  4 => function ($u) {
                      $over = $u['days_over'] !== null ? (int) $u['days_over'] : null;
                      if ($over !== null && $over > 0) {
                          return vg_badge('기한 ' . number_format($over) . '일 초과', 'crit')
                               . '<div class="why">기한 ' . vg_h((string) $u['due_date']) . '</div>';
                      }
                      if ($u['in_kev'] && $u['runtime_status'] === 'EXTERNAL') {
                          return vg_badge('악용확인 + 외부노출', 'crit');
                      }
                      return vg_status_badge($u['runtime_status']);
                  },
              ],
          ]
      );
      ?>
      </div>
    </div>
  </div>

  <div class="split split--even">
    <div class="card">
      <strong>OS 분포</strong>
      <span class="why">— 비삭제 호스트 기준 상위 <?= count($osDist) ?>개</span>
      <div class="card__body">
        <?php vg_hbar_list($osDist, 'os_label', 'c', ['icon' => '🖥️', 'title' => '등록된 호스트가 없습니다.']); ?>
      </div>
    </div>

    <div class="card">
      <strong>취약 자산 TOP10</strong>
      <span class="why">— 호스트별 최신 스캔의 findings 건수 기준</span>
      <div class="card__body">
        <?php vg_hbar_list($topHosts, 'fqdn', 'c', ['icon' => '✅', 'title' => '취약점이 있는 호스트가 없습니다.']); ?>
      </div>
    </div>
  </div>

  <div class="card">
    <strong>에이전트 리소스 사용량</strong>
    <span class="why">— 이 에이전트를 설치해도 서버에 부담이 거의 없다는 걸 함대 전체로 보여준다</span>
    <div class="card__body">
      <div class="cards">
        <div class="kpi">
          <b><?= vg_resource_mem($resKpi['avg_mem'] ?? null) ?></b>
          <span>평균 피크 메모리 · 최신 스캔</span>
        </div>
        <div class="kpi">
          <b><?= vg_resource_cpu($resKpi['avg_cpu'] ?? null) ?></b>
          <span>평균 CPU 소요시간 · 최신 스캔</span>
        </div>
      </div>
      <div class="split split--even">
        <div>
          <strong>메모리 추이</strong>
          <span class="why">— 일별 함대 평균(MB, 스캔 기준) · 최근 <?= VG_RESOURCE_TREND_DAYS ?>일</span>
          <?php vg_resource_trend($memTrend, 'peak_rss_mb', 'MB', 0, 'mem'); ?>
        </div>
        <div>
          <strong>CPU 추이</strong>
          <span class="why">— 일별 함대 평균(초, 스캔 기준) · 최근 <?= VG_RESOURCE_TREND_DAYS ?>일</span>
          <?php vg_resource_trend($cpuTrend, 'cpu_seconds', 's', 1, 'cpu'); ?>
        </div>
      </div>
    </div>
  </div>

  <div class="card">
    <strong>호스트별 현황</strong> <span class="why">— 각 호스트의 최신 스캔 기준</span>
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
