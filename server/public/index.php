<?php
declare(strict_types=1);

/**
 * index.php — 대시보드 (로그인 필요).
 *   호스트별 최신 스캔 + 심각도 요약. 각 행에서 취약점 상세로.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
vg_require_menu('dashboard');

$err = null; $rows = []; $totals = ['CRITICAL'=>0,'HIGH'=>0,'MEDIUM'=>0,'LOW'=>0]; $hostCount = 0;
try {
    $pdo = vg_pdo();
    $hostCount = (int) $pdo->query('SELECT COUNT(*) FROM tb_hosts WHERE is_deleted = 0')->fetchColumn();

    // 호스트별 최신 스캔
    $rows = $pdo->query(
        'SELECT s.id AS scan_id, s.collected_at, s.package_count, s.exposure_count, s.agent_version,
                h.id AS host_id, h.fqdn, h.os_id, h.os_version
         FROM tb_scans s
         JOIN (SELECT host_id, MAX(id) AS mid FROM tb_scans GROUP BY host_id) t ON t.mid = s.id
         JOIN tb_hosts h ON h.id = s.host_id
         WHERE h.is_deleted = 0
         ORDER BY s.collected_at DESC'
    )->fetchAll();

    // 최신 스캔들의 심각도 카운트
    $sevByScan = [];
    if ($rows) {
        $ids = [];
        foreach ($rows as $r) { $ids[] = (int) $r['scan_id']; }
        $in  = implode(',', array_fill(0, count($ids), '?'));
        $st  = $pdo->prepare("SELECT scan_id, severity, COUNT(*) c FROM tb_findings WHERE scan_id IN ($in) GROUP BY scan_id, severity");
        $st->execute($ids);
        foreach ($st->fetchAll() as $f) {
            $sevByScan[(int) $f['scan_id']][$f['severity']] = (int) $f['c'];
            if (isset($totals[$f['severity']])) { $totals[$f['severity']] += (int) $f['c']; }
        }
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
  <div class="cards">
    <div class="kpi big"><b><?= $hostCount ?></b><span>호스트</span></div>
    <?php foreach (['CRITICAL','HIGH','MEDIUM','LOW'] as $s): ?>
      <div class="kpi tone-<?= vg_sev_tone($s) ?>"><b><?= (int) $totals[$s] ?></b><span><?= $s ?></span></div>
    <?php endforeach; ?>
  </div>

  <?php
  vg_table(
      [
          ['label' => '호스트'],
          ['label' => 'OS'],
          ['label' => '패키지'],
          ['label' => '노출'],
          ['label' => '심각도'],
          ['label' => '수집시각'],
          ['label' => ''],
      ],
      $rows,
      [
          'empty' => '아직 수집된 스캔이 없습니다. 에이전트를 --send 로 실행하세요.',
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
  ?>
<?php endif; ?>
<?php vg_footer();
