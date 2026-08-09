<?php
declare(strict_types=1);

/**
 * index.php — 대시보드 (로그인 필요).
 *   호스트별 최신 스캔 + 심각도 요약. 각 행에서 취약점 상세로.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
vg_require_menu('dashboard');

$err = null; $rows = []; $totals = ['CRITICAL'=>0,'HIGH'=>0,'MEDIUM'=>0,'LOW'=>0];
$hostCount = 0; $total = 0; $sevByScan = [];
$kevCount = 0; $urgent = []; $urgentTotal = 0; $nextFeed = null;
$delta = [];
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

    // KPI 는 페이지 무관 — 전 호스트 최신 스캔의 심각도 총합.
    $totalsRows = $pdo->query(
        "SELECT f.severity, COUNT(*) c
           FROM tb_finding f
           JOIN tb_scan s ON s.scan_id = f.scan_id
           JOIN tb_host h ON h.host_id = s.host_id AND h.is_deleted = 0
           $latestJoin
          GROUP BY f.severity"
    )->fetchAll();
    foreach ($totalsRows as $f) { if (isset($totals[$f['severity']])) { $totals[$f['severity']] = (int) $f['c']; } }

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
    $kevCount = (int) $pdo->query(
        "SELECT COUNT(*) FROM (
           SELECT latest.host_id,f.cve_id,f.package_name
             FROM " . vg_latest_scan_subq() . " latest
             JOIN tb_finding f ON f.scan_id=latest.mid AND f.in_kev=1
            GROUP BY latest.host_id,f.cve_id,f.package_name
         ) kev_findings"
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
          <span class="kpi__delta <?= $dir ?>" title="7일 전 대비"><?= vg_h($dtxt) ?></span>
        <?php endif; ?>
      </a>
    <?php endforeach; ?>
  </div>

  <div class="split">
    <div class="card">
      <strong>심각도 분포</strong>
      <div class="card__body center">
        <div class="donut-wrap">
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
        <?php /* 예전엔 이 두 값이 상단 KPI 줄에 점선 카드(kpi--static)로 있었는데, 링크형
         * 카드들 사이에서 톤이 안 맞아 붕 떠 보였다. 필터가 없는 "집계 전용" 값이라
         * 여기(도넛 카드 바닥)가 오히려 제자리 — 옆 "대응 우선순위" 카드와 높이를 맞추며
         * 생기는 여백도 이걸로 채운다. */ ?>
        <div class="donut-foot">
          <?= vg_badge('KEV 악용확인 ' . number_format($kevCount) . '건', $kevCount > 0 ? 'crit' : 'ok', '최신 스캔에서 CISA KEV에 등재된 취약점 수입니다.') ?>
        </div>
      </div>
    </div>

    <div class="card">
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
