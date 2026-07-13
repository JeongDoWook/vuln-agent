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

$err = null; $rows = []; $totals = ['CRITICAL'=>0,'HIGH'=>0,'MEDIUM'=>0,'LOW'=>0];
$hostCount = 0; $total = 0; $sevByScan = [];
$kevCount = 0; $overdueCount = 0; $urgent = []; $urgentTotal = 0; $nextFeed = null;
$page = max(1, (int) ($_GET['page'] ?? 1));
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
  <div class="sub">호스트별 최신 스캔 기준 요약 · 런타임 노출 맥락으로 우선순위화</div>

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
    <?php foreach (['CRITICAL','HIGH','MEDIUM','LOW'] as $s): ?>
      <a class="kpi tone-<?= vg_sev_tone($s) ?>" href="/findings.php?sev=<?= $s ?>">
        <b><?= (int) $totals[$s] ?></b><span><?= $s ?></span>
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
        <?php vg_sev_donut($totals); ?>
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
          ['label' => ''],
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
              4 => fn($r) => vg_sev_counts($sevByScan[(int) $r['scan_id']] ?? []),
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
