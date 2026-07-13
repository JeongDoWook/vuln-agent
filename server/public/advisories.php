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
$perPage = vg_perpage();

try {
    $pdo = vg_pdo();

    $where = 'is_deleted = 0';
    $params = [];
    if ($q !== '') {
        // 본문까지 검색 대상(수집된 건에 한함). 2천여 행이라 LIKE 스캔으로 충분.
        // CVE 검색은 cve_ids CSV 대신 정규화된 junction(tb_advisory_cves)을 본다.
        $where .= ' AND (title LIKE ? OR content LIKE ? OR EXISTS (
            SELECT 1 FROM tb_advisory_cves ac
             WHERE ac.advisory_id = tb_advisories.id AND ac.is_deleted = 0 AND ac.cve_id LIKE ?
        ))';
        $params[] = '%' . $q . '%';
        $params[] = '%' . $q . '%';
        $params[] = '%' . $q . '%';
    }

    $stmt = $pdo->prepare("SELECT COUNT(*) FROM tb_advisories WHERE $where");
    $stmt->execute($params);
    $total = (int) $stmt->fetchColumn();

    $offset = ($page - 1) * $perPage;

    $stmt = $pdo->prepare(
        "SELECT id, source, title, url, published
         FROM tb_advisories
         WHERE $where
         ORDER BY published DESC, id DESC
         LIMIT $perPage OFFSET $offset"
    );
    $stmt->execute($params);
    $rows = $stmt->fetchAll();

    // 관련 CVE 는 정션에서 배치 조회(N+1 방지) — advisory_id 로 묶어 각 행에 붙인다.
    if ($rows) {
        $ids = array_column($rows, 'id');
        $in  = implode(',', array_fill(0, count($ids), '?'));
        $cst = $pdo->prepare(
            "SELECT advisory_id, cve_id FROM tb_advisory_cves
             WHERE advisory_id IN ($in) AND is_deleted = 0 ORDER BY cve_id"
        );
        $cst->execute($ids);
        $byAdvisory = [];
        foreach ($cst->fetchAll(PDO::FETCH_ASSOC) as $c) {
            $byAdvisory[(int) $c['advisory_id']][] = $c['cve_id'];
        }
        foreach ($rows as &$row) {
            $row['cve_id_list'] = $byAdvisory[(int) $row['id']] ?? [];
        }
        unset($row);
    }
} catch (Throwable $e) {
    $err = $e->getMessage();
}

vg_header('국내 보안공지', 'advisories');
?>
  <h1>🇰🇷 국내 보안공지 <span class="hint">(KISA 보호나라)</span></h1>
  <div class="sub">해외 스캐너가 다루지 않는 국내 보안공지. <a href="/connectors.php">피드 커넥터</a>(kisa)가 본문까지 주기 수집. 제목을 누르면 상세를 봅니다.</div>

<?php if ($err !== null): ?>
  <?php vg_alert('오류 · ' . $err); ?>
<?php else: ?>
  <?php vg_toolbar([
      ['type' => 'search', 'name' => 'q', 'placeholder' => '제목 또는 CVE 검색', 'value' => $q],
  ]); ?>

  <?php
  vg_table(
      [
          ['label' => '발행일', 'nowrap' => true, 'width' => '8rem'],
          ['label' => '제목'],
          ['label' => '관련 CVE', 'width' => '26rem'],
      ],
      $rows,
      [
          'empty' => $q !== ''
              ? [
                  'icon'  => '🔍',
                  'title' => '조건에 맞는 공지가 없습니다.',
                  'hint'  => '제목·CVE·본문을 모두 검색합니다. 다른 검색어를 써 보세요.',
                  'cta'   => ['href' => '/advisories.php', 'label' => '검색 초기화'],
              ]
              : [
                  'icon'  => '🇰🇷',
                  'title' => '아직 수집된 공지가 없습니다.',
                  'hint'  => 'KISA 보안공지 커넥터를 실행하면 여기에 쌓입니다.',
                  'cta'   => ['href' => '/connectors.php', 'label' => '피드 커넥터로 이동'],
              ],
          'cell' => [
              0 => fn($r) => '<span class="why">' . vg_h($r['published'] ?? '–') . '</span>',
              // 제목을 누르면 상세로. 원문은 상세 안의 [원문 열기] 버튼에서 연다.
              1 => fn($r) => '<a href="/advisory.php?id=' . (int) $r['id'] . '">' . vg_trunc($r['title']) . '</a>',
              // CVE 를 수십 개 달고 오는 공지가 있다(예: 월간 브라우저 패치).
              // 전부 알약으로 깔면 행이 터지므로 앞 4개만 보이고 나머지는 "+N" 으로 접는다.
              2 => function ($r) {
                  $ids = $r['cve_id_list'] ?? [];
                  if (!$ids) { return '<span class="why">–</span>'; }

                  $shown = array_slice($ids, 0, 4);
                  $rest  = count($ids) - count($shown);

                  $html = '';
                  foreach ($shown as $cv) {
                      $html .= '<a class="pill" href="/cve.php?cve=' . urlencode($cv) . '">' . vg_h($cv) . '</a> ';
                  }
                  if ($rest > 0) {
                      // 나머지는 상세에서 전부 본다. title 로 원문 목록을 남겨 둔다.
                      $html .= '<a class="pill" href="/advisory.php?id=' . (int) $r['id'] . '"'
                             . ' title="' . vg_h(implode(', ', array_slice($ids, 4))) . '">+' . $rest . '</a>';
                  }
                  return $html;
              },
          ],
      ]
  );
  if ($rows) { vg_page_nav($total, $perPage, $page); }
  ?>
<?php endif; ?>
<?php vg_footer();
