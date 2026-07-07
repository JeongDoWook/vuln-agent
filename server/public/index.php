<?php
declare(strict_types=1);

/**
 * index.php — 대시보드 (로그인 필요).
 *   호스트별 최신 스캔 + 심각도 요약. 각 행에서 취약점 상세로.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
vg_require_login();

$err = null; $rows = []; $totals = ['CRITICAL'=>0,'HIGH'=>0,'MEDIUM'=>0,'LOW'=>0]; $hostCount = 0;
try {
    $pdo = vg_pdo();
    $hostCount = (int) $pdo->query('SELECT COUNT(*) FROM hosts')->fetchColumn();

    // 호스트별 최신 스캔
    $rows = $pdo->query(
        'SELECT s.id AS scan_id, s.collected_at, s.package_count, s.exposure_count, s.agent_version,
                h.fqdn, h.os_id, h.os_version
         FROM scans s
         JOIN (SELECT host_id, MAX(id) AS mid FROM scans GROUP BY host_id) t ON t.mid = s.id
         JOIN hosts h ON h.id = s.host_id
         ORDER BY s.collected_at DESC'
    )->fetchAll();

    // 최신 스캔들의 심각도 카운트
    $sevByScan = [];
    if ($rows) {
        $ids = [];
        foreach ($rows as $r) { $ids[] = (int) $r['scan_id']; }
        $in  = implode(',', array_fill(0, count($ids), '?'));
        $st  = $pdo->prepare("SELECT scan_id, severity, COUNT(*) c FROM findings WHERE scan_id IN ($in) GROUP BY scan_id, severity");
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
  <div class="err"><strong>DB 오류</strong> · <?= vg_h($err) ?></div>
<?php else: ?>
  <div class="cards">
    <div class="kpi big"><b><?= $hostCount ?></b><span>호스트</span></div>
    <?php foreach (['CRITICAL','HIGH','MEDIUM','LOW'] as $s): ?>
      <div class="kpi" style="background:<?= vg_sev_color($s) ?>;color:#fff;"><b><?= (int) $totals[$s] ?></b><span><?= $s ?></span></div>
    <?php endforeach; ?>
  </div>

  <div class="card">
    <?php if (!$rows): ?>
      <div class="empty">아직 수집된 스캔이 없습니다. 에이전트를 <code>--send</code> 로 실행하세요.</div>
    <?php else: ?>
      <table>
        <thead><tr>
          <th>호스트</th><th>OS</th><th>패키지</th><th>노출</th><th>심각도</th><th>수집시각</th><th></th>
        </tr></thead>
        <tbody>
        <?php foreach ($rows as $r): $sc = $sevByScan[(int)$r['scan_id']] ?? []; ?>
          <tr>
            <td><strong><?= vg_h($r['fqdn']) ?></strong></td>
            <td><?= vg_h($r['os_id']) ?> <?= vg_h($r['os_version']) ?></td>
            <td><?= (int) $r['package_count'] ?></td>
            <td><?= (int) $r['exposure_count'] ?></td>
            <td>
              <?php foreach (['CRITICAL','HIGH','MEDIUM','LOW'] as $s): if (!empty($sc[$s])): ?>
                <span class="badge" style="background:<?= vg_sev_color($s) ?>;" title="<?= $s ?>"><?= (int) $sc[$s] ?></span>
              <?php endif; endforeach; ?>
              <?php if (!$sc): ?><span class="why">–</span><?php endif; ?>
            </td>
            <td class="why"><?= vg_h($r['collected_at']) ?></td>
            <td><a href="/findings.php?scan_id=<?= (int) $r['scan_id'] ?>">취약점 →</a></td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
    <?php endif; ?>
  </div>
<?php endif; ?>
<?php vg_footer();
