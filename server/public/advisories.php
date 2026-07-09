<?php
declare(strict_types=1);

/**
 * advisories.php — 국내 보안공지(KISA 보호나라). 로그인 필요.
 *   해외 도구가 안 하는 국내 특화 피드. 피드 커넥터(kisa)가 수집.
 *   검색(q: 제목/CVE) + 페이지네이션.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
vg_require_menu('advisories');

$err = null; $rows = []; $total = 0;
$q = trim((string) ($_GET['q'] ?? ''));
$page = max(1, (int) ($_GET['page'] ?? 1));

try {
    $pdo = vg_pdo();

    $where = 'is_deleted = 0';
    $params = [];
    if ($q !== '') {
        $where .= ' AND (title LIKE ? OR cve_ids LIKE ?)';
        $params[] = '%' . $q . '%';
        $params[] = '%' . $q . '%';
    }

    $stmt = $pdo->prepare("SELECT COUNT(*) FROM tb_advisories WHERE $where");
    $stmt->execute($params);
    $total = (int) $stmt->fetchColumn();

    $perPage = vg_perpage();
    $offset = ($page - 1) * $perPage;

    $stmt = $pdo->prepare(
        "SELECT source, title, url, published, cve_ids FROM tb_advisories
         WHERE $where
         ORDER BY published DESC, id DESC
         LIMIT $perPage OFFSET $offset"
    );
    $stmt->execute($params);
    $rows = $stmt->fetchAll();
} catch (Throwable $e) {
    $err = $e->getMessage();
}

vg_header('국내 보안공지', 'advisories');
?>
  <h1>🇰🇷 국내 보안공지 <span style="font-size:.8rem;color:#8b93a1;">(KISA 보호나라)</span></h1>
  <div class="sub">해외 스캐너가 다루지 않는 국내 보안공지. <a href="/connectors.php">피드 커넥터</a>(kisa)가 주기 수집.</div>

<?php if ($err !== null): ?>
  <div class="err"><strong>오류</strong> · <?= vg_h($err) ?></div>
<?php else: ?>
  <?php vg_toolbar([
      ['type' => 'search', 'name' => 'q', 'placeholder' => '제목 또는 CVE 검색', 'value' => $q],
  ]); ?>

  <?php
  $emptyMsg = $q !== '' ? '조건에 맞는 공지가 없습니다.' : '아직 수집된 공지가 없습니다. 피드에서 KISA 보안공지 커넥터를 실행하세요.';
  vg_table(
      [
          ['label' => '발행일'],
          ['label' => '제목'],
          ['label' => '관련 CVE'],
          ['label' => ''],
      ],
      $rows,
      [
          'empty' => $emptyMsg,
          'cell' => [
              0 => fn($r) => '<span class="why">' . vg_h($r['published'] ?? '–') . '</span>',
              1 => fn($r) => vg_trunc($r['title']),
              2 => function ($r) {
                  if (empty($r['cve_ids'])) { return '<span class="why">–</span>'; }
                  $html = '';
                  foreach (explode(',', (string) $r['cve_ids']) as $cv) {
                      $cv = trim($cv);
                      $html .= '<a class="pill" href="/cve.php?cve=' . urlencode($cv) . '">' . vg_h($cv) . '</a>';
                  }
                  return $html;
              },
              3 => fn($r) => '<a href="' . vg_h($r['url']) . '" target="_blank" rel="noopener">원문 →</a>',
          ],
      ]
  );
  if ($rows) { vg_page_nav($total, $perPage, $page); }
  ?>
<?php endif; ?>
<?php vg_footer();
