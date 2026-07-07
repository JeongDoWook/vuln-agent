<?php
declare(strict_types=1);

/**
 * findings.php — 매처 판정 결과(우선순위 취약점). 로그인 필요.
 *   ?scan_id=N, 없으면 최신 스캔. 등급순 + 노출 근거(rationale).
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
vg_require_login();

$err = null; $scan = null; $rows = []; $counts = ['CRITICAL'=>0,'HIGH'=>0,'MEDIUM'=>0,'LOW'=>0];
try {
    $pdo = vg_pdo();
    if (isset($_GET['scan_id'])) {
        $scanId = (int) $_GET['scan_id'];
    } else {
        $scanId = (int) ($pdo->query('SELECT id FROM scans ORDER BY received_at DESC LIMIT 1')->fetchColumn() ?: 0);
    }
    if ($scanId > 0) {
        $st = $pdo->prepare('SELECT s.*, h.fqdn FROM scans s JOIN hosts h ON h.id = s.host_id WHERE s.id = ?');
        $st->execute([$scanId]);
        $scan = $st->fetch() ?: null;

        $st = $pdo->prepare(
            "SELECT f.*, c.summary,
                (SELECT a.fixed_version FROM cve_affected_packages a
                 WHERE a.cve_id = f.cve_id AND a.package_name = f.package_name
                   AND a.fixed_version IS NOT NULL LIMIT 1) AS fixed_version
             FROM findings f LEFT JOIN cves c ON c.cve_id = f.cve_id
             WHERE f.scan_id = ?
             ORDER BY FIELD(f.severity,'CRITICAL','HIGH','MEDIUM','LOW'), f.cvss DESC"
        );
        $st->execute([$scanId]);
        $rows = $st->fetchAll();
        foreach ($rows as $r) { if (isset($counts[$r['severity']])) { $counts[$r['severity']]++; } }
    }
} catch (Throwable $e) {
    $err = $e->getMessage();
}

vg_header('취약점', 'findings');
?>
  <h1>취약점 우선순위 <span style="font-size:.8rem;color:#8b93a1;">(매처 결과)</span></h1>
  <div class="sub">
    <?php if ($scan): ?>
      호스트 <strong><?= vg_h($scan['fqdn']) ?></strong> · scan #<?= (int) $scan['id'] ?> · <?= vg_h($scan['collected_at']) ?>
    <?php else: ?>스캔 없음<?php endif; ?>
  </div>

<?php if ($err !== null): ?>
  <div class="err"><strong>오류</strong> · <?= vg_h($err) ?></div>
<?php elseif (!$rows): ?>
  <div class="card"><div class="empty">이 스캔에 대한 판정 결과가 없습니다.</div></div>
<?php else: ?>
  <div class="cards">
    <?php foreach (['CRITICAL','HIGH','MEDIUM','LOW'] as $s): ?>
      <div class="kpi" style="background:<?= vg_sev_color($s) ?>;color:#fff;"><b><?= (int) $counts[$s] ?></b><span><?= $s ?></span></div>
    <?php endforeach; ?>
  </div>
  <div class="card">
    <table>
      <thead><tr>
        <th>등급</th><th>CVE</th><th>패키지</th><th>버전</th><th>CVSS</th><th>KEV</th><th>근거 (왜 위험한가)</th><th>조치</th>
      </tr></thead>
      <tbody>
      <?php foreach ($rows as $r): ?>
        <tr>
          <td><span class="badge" style="background:<?= vg_sev_color($r['severity']) ?>;"><?= vg_h($r['severity']) ?></span></td>
          <td><strong><?= vg_h($r['cve_id']) ?></strong>
            <?php if ($r['summary']): ?><div class="why"><?= vg_h(mb_strimwidth((string) $r['summary'], 0, 72, '…')) ?></div><?php endif; ?>
          </td>
          <td><?= vg_h($r['package_name']) ?></td>
          <td><code><?= vg_h($r['installed_version']) ?></code></td>
          <td><?= $r['cvss'] !== null ? vg_h((string) $r['cvss']) : '-' ?></td>
          <td><?= $r['in_kev'] ? '✔' : '' ?></td>
          <td class="why"><?= vg_h($r['rationale']) ?></td>
          <td class="why"><?= !empty($r['fixed_version']) ? '<span class="pill">' . vg_h($r['fixed_version']) . ' 이상</span>' : '패치 확인' ?></td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
  </div>
<?php endif; ?>
<?php vg_footer();
