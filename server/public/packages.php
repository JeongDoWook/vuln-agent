<?php
declare(strict_types=1);

/**
 * packages.php — 영향 패키지 목록. OSV 커넥터의 산출물(tb_cve_affected_packages)을
 *   "패키지 × 배포판" 단위로 접어서 보여준다. 로그인 필요(취약점 메뉴 권한 재사용).
 *
 *   CVE 목록(cves.php)은 행이 CVE 하나지만 여기는 패키지 하나다. 같은 테이블에 못 담아
 *   화면을 나눴다. 패키지명을 누르면 취약점 현황에서 그 패키지만 걸러 본다.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
vg_require_menu('findings');

// 정렬 화이트리스트. 사용자 입력을 SQL 에 직접 넣지 않는다.
const VG_PKG_SORTS = [
    'cves'    => ['col' => 'cve_cnt',  'label' => 'CVE 많은순'],
    'epss'    => ['col' => 'max_epss', 'label' => 'EPSS 높은순'],
    'package' => ['col' => 'package_name', 'label' => '패키지명순'],
];

$err = null; $rows = []; $total = 0; $ecos = []; $summaryAt = '';

$q    = trim((string) ($_GET['q'] ?? ''));
$eco  = trim((string) ($_GET['eco'] ?? ''));
$sort = (string) ($_GET['sort'] ?? '');
$page = vg_page();
$perPage = vg_perpage();

if (!isset(VG_PKG_SORTS[$sort])) { $sort = 'cves'; }

try {
    $pdo = vg_pdo();

    // 배포판 목록·개수·정렬은 사전집계 요약(tb_package_summary)에서 읽는다. 원본
    //   tb_cve_affected_packages(92만 행)를 매 로드 재집계하던 걸(운영 ~8초) OSV 실행 때 한 번
    //   요약해 둔 것(vg_rebuild_package_summary). 40K행이라 즉답이다.
    $ecos = $pdo->query(
        "SELECT DISTINCT ecosystem FROM tb_package_summary WHERE ecosystem <> '' ORDER BY ecosystem"
    )->fetchAll(PDO::FETCH_COLUMN);
    $ecoOptions = array_combine($ecos, $ecos) ?: [];
    if ($eco !== '' && !in_array($eco, $ecos, true)) { $eco = ''; }

    // 집계 기준 시각(요약을 마지막으로 다시 만든 때) — 목록이 언제 기준인지 화면에 밝힌다.
    $summaryAt = (string) ($pdo->query('SELECT MAX(updated_at) FROM tb_package_summary')->fetchColumn() ?: '');

    $where  = '1=1';
    $params = [];
    if ($q !== '') {
        $where .= ' AND package_name LIKE ?';
        $params[] = '%' . $q . '%';
    }
    if ($eco !== '') {
        $where .= ' AND ecosystem = ?';
        $params[] = $eco;
    }

    $stmt = $pdo->prepare("SELECT COUNT(*) FROM tb_package_summary WHERE $where");
    $stmt->execute($params);
    $total = (int) $stmt->fetchColumn();

    $offset = ($page - 1) * $perPage;
    $col = VG_PKG_SORTS[$sort]['col'];
    $stmt = $pdo->prepare(
        "SELECT package_name, ecosystem, cve_cnt, max_epss, fix_cnt, max_fixed
           FROM tb_package_summary
          WHERE $where
          ORDER BY $col DESC, package_name ASC
          LIMIT $perPage OFFSET $offset"
    );
    $stmt->execute($params);
    $rows = $stmt->fetchAll();
} catch (Throwable $e) {
    error_log('[packages] ' . $e->getMessage());
    $err = '처리 중 오류가 발생했습니다.';
}

vg_header('영향 패키지', 'packages');
?>
  <h1>영향 패키지 <span class="hint">(<?= number_format($total) ?>종)</span></h1>
  <?php if ($summaryAt !== ''): ?>
  <div class="sub"><span class="why">집계 기준 <?= vg_h($summaryAt) ?> (OSV 수집 시 갱신)</span></div>
  <?php endif; ?>

<?php if ($err !== null): ?>
  <?php vg_alert('오류 · ' . $err); ?>
<?php else: ?>
  <?php vg_toolbar([
      ['type' => 'search', 'name' => 'q', 'placeholder' => '패키지명 검색', 'value' => $q],
      ['type' => 'select', 'name' => 'eco', 'selected' => $eco, 'empty_label' => '배포판 전체',
       'options' => $ecoOptions],
      ['type' => 'select', 'name' => 'sort', 'selected' => $sort === 'cves' ? '' : $sort,
       'empty_label' => 'CVE 많은순', 'options' => ['epss' => 'EPSS 높은순', 'package' => '패키지명순']],
  ]); ?>

  <?php
  $hasFilter = $q !== '' || $eco !== '';
  vg_table(
      [
          ['label' => '패키지', 'width' => '20rem'],
          ['label' => '배포판', 'width' => '10rem'],
          ['label' => 'CVE 수', 'align' => 'right', 'width' => '6rem'],
          ['label' => '최고 EPSS', 'align' => 'right', 'width' => '11rem'],
          ['label' => '조치', 'width' => '18rem'],
      ],
      $rows,
      [
          'empty' => $hasFilter
              ? [
                  'icon'  => '🔍',
                  'title' => '조건에 맞는 패키지가 없습니다.',
                  'hint'  => '패키지명 검색어나 배포판 필터를 바꿔 보세요.',
                  'cta'   => ['href' => '/packages.php', 'label' => '필터 초기화'],
              ]
              : array_filter([
                  'icon'  => '📦',
                  'title' => '아직 수집된 패키지가 없습니다.',
                  'hint'  => 'OSV 커넥터가 스캔된 패키지를 조회해야 이 매핑이 만들어집니다.',
                  'cta'   => vg_connectors_empty_cta(),
              ]),
          'cell' => [
              // 패키지명 → 취약점 현황에서 그 패키지만 검색
              0 => fn($r) => '<a href="/findings.php?q=' . urlencode((string) $r['package_name']) . '">'
                             . vg_h((string) $r['package_name']) . '</a>',
              1 => fn($r) => !empty($r['ecosystem'])
                             ? vg_h((string) $r['ecosystem'])
                             : '<span class="why">–</span>',
              2 => fn($r) => number_format((int) $r['cve_cnt']),
              // 최고 EPSS: 텍스트("96.3%") 아래 게이지. 폭 = max_epss*100%.
              //   톤은 값 구간별(>=0.5 high / >=0.1 med / 그 외 low). 값 없으면 대시만.
              3 => function ($r) {
                  $txt = vg_epss_cell($r['max_epss'], null);
                  if ($r['max_epss'] === null || $r['max_epss'] === '') {
                      return $txt;
                  }
                  $e = (float) $r['max_epss'];
                  $tone = $e >= 0.5 ? 'high' : ($e >= 0.1 ? 'med' : 'low');
                  return $txt . '<div class="meter meter--' . $tone . '">'
                       . '<i style="width:' . number_format($e * 100, 1) . '%"></i></div>';
              },
              // 조치: fix_cnt/cve_cnt 진행바가 주된 시각요소. max_fixed 있으면 pill 로 함께.
              //   cve_cnt=0 은 0 나눗셈 방지. 완료율 100% 는 low(ok) 톤, 그 외 med.
              4 => function ($r) {
                  $cve   = (int) $r['cve_cnt'];
                  $fix   = (int) $r['fix_cnt'];
                  $ratio = $cve > 0 ? $fix / $cve : 0.0;
                  $tone  = $ratio >= 1.0 ? 'low' : 'med';
                  $bar   = '<div class="meter meter--' . $tone . '">'
                         . '<i style="width:' . number_format($ratio * 100, 1) . '%"></i></div>';
                  if (empty($r['max_fixed'])) {
                      return '<span class="why">패치 확인 (조치 ' . $fix . '/' . $cve . ')</span>' . $bar;
                  }
                  return '<span class="pill">' . vg_h((string) $r['max_fixed']) . ' 이상</span>'
                       . ' <span class="why">조치 ' . $fix . '/' . $cve . '</span>' . $bar;
              },
          ],
      ]
  );
  if ($rows) { vg_page_nav($total, $perPage, $page); }
  ?>
<?php endif; ?>
<?php vg_footer();
