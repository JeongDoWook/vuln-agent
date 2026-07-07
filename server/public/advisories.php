<?php
declare(strict_types=1);

/**
 * advisories.php — 국내 보안공지(KISA 보호나라). 로그인 필요.
 *   해외 도구가 안 하는 국내 특화 피드. 피드 커넥터(kisa)가 수집.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
vg_require_login();

$err = null; $rows = [];
try {
    $rows = vg_pdo()->query(
        'SELECT source, title, url, published, cve_ids FROM advisories
         ORDER BY published DESC, id DESC LIMIT 100'
    )->fetchAll();
} catch (Throwable $e) {
    $err = $e->getMessage();
}

vg_header('국내 보안공지', 'advisories');
?>
  <h1>🇰🇷 국내 보안공지 <span style="font-size:.8rem;color:#8b93a1;">(KISA 보호나라)</span></h1>
  <div class="sub">해외 스캐너가 다루지 않는 국내 보안공지. <a href="/connectors.php">피드 커넥터</a>(kisa)가 주기 수집.</div>

<?php if ($err !== null): ?>
  <div class="err"><strong>오류</strong> · <?= vg_h($err) ?></div>
<?php elseif (!$rows): ?>
  <div class="card"><div class="empty">아직 수집된 공지가 없습니다. 피드에서 <code>KISA 보안공지</code> 커넥터를 실행하세요.</div></div>
<?php else: ?>
  <div class="card">
    <table>
      <thead><tr><th>발행일</th><th>제목</th><th>관련 CVE</th><th></th></tr></thead>
      <tbody>
      <?php foreach ($rows as $r): ?>
        <tr>
          <td class="why" style="white-space:nowrap;"><?= vg_h($r['published'] ?? '–') ?></td>
          <td><?= vg_h($r['title']) ?></td>
          <td>
            <?php if (!empty($r['cve_ids'])): foreach (explode(',', (string) $r['cve_ids']) as $cv): ?>
              <span class="pill"><?= vg_h(trim($cv)) ?></span>
            <?php endforeach; else: ?><span class="why">–</span><?php endif; ?>
          </td>
          <td><a href="<?= vg_h($r['url']) ?>" target="_blank" rel="noopener">원문 →</a></td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
  </div>
<?php endif; ?>
<?php vg_footer();
