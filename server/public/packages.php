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
    'package' => ['col' => 'a.package_name', 'label' => '패키지명순'],
];

$err = null; $rows = []; $total = 0; $ecos = [];

$q    = trim((string) ($_GET['q'] ?? ''));
$eco  = trim((string) ($_GET['eco'] ?? ''));
$sort = (string) ($_GET['sort'] ?? '');
$page = max(1, (int) ($_GET['page'] ?? 1));
$perPage = vg_perpage();

if (!isset(VG_PKG_SORTS[$sort])) { $sort = 'cves'; }

/**
 * 이 패키지를 전부 고치려면 올려야 할 버전 = 조치 버전 중 가장 높은 것.
 *
 * SQL MAX() 는 사전순이라 '3.0.13-0ubuntu3.9' > '3.0.13-0ubuntu3.11' 로 뒤집힌다.
 * strnatcmp 는 숫자 덩어리를 수로 비교해 11 > 9 를 지킨다. epoch('2:9.1...')도 앞자리
 * 숫자로 먼저 비교돼 일관된다. dpkg 완전 호환은 아니지만 표시용으로 충분하다.
 */
function vg_pkg_max_fixed(array $versions): ?string {
    $max = null;
    foreach ($versions as $v) {
        if ($v === null || $v === '') { continue; }
        if ($max === null || strnatcmp($v, $max) > 0) { $max = $v; }
    }
    return $max;
}

try {
    $pdo = vg_pdo();

    $ecos = $pdo->query(
        'SELECT DISTINCT ecosystem FROM tb_cve_affected_packages
          WHERE is_deleted = 0 AND ecosystem IS NOT NULL AND ecosystem <> "" ORDER BY ecosystem'
    )->fetchAll(PDO::FETCH_COLUMN);
    $ecoOptions = array_combine($ecos, $ecos) ?: [];
    if ($eco !== '' && !in_array($eco, $ecos, true)) { $eco = ''; }

    $where  = 'a.is_deleted = 0';
    $params = [];
    if ($q !== '') {
        $where .= ' AND a.package_name LIKE ?';
        $params[] = '%' . $q . '%';
    }
    if ($eco !== '') {
        $where .= ' AND a.ecosystem = ?';
        $params[] = $eco;
    }

    $from = 'FROM tb_cve_affected_packages a
             LEFT JOIN tb_cves c ON c.cve_id = a.cve_id AND c.is_deleted = 0';
    $group = 'GROUP BY a.package_name, a.ecosystem';

    $stmt = $pdo->prepare("SELECT COUNT(*) FROM (SELECT 1 $from WHERE $where $group) t");
    $stmt->execute($params);
    $total = (int) $stmt->fetchColumn();

    $offset = ($page - 1) * $perPage;
    $col = VG_PKG_SORTS[$sort]['col'];
    $stmt = $pdo->prepare(
        "SELECT a.package_name, a.ecosystem,
                COUNT(DISTINCT a.cve_id) AS cve_cnt,
                MAX(c.epss) AS max_epss,
                SUM(a.fixed_version IS NOT NULL) AS fix_cnt
         $from
         WHERE $where
         $group
         ORDER BY $col DESC, a.package_name ASC
         LIMIT $perPage OFFSET $offset"
    );
    $stmt->execute($params);
    $rows = $stmt->fetchAll();

    // 조치 버전은 화면에 뜬 패키지(최대 perPage 개)만 따로 읽어 PHP 에서 고른다.
    if ($rows) {
        $names = array_column($rows, 'package_name');
        $in    = implode(',', array_fill(0, count($names), '?'));
        $fx = $pdo->prepare(
            "SELECT package_name, ecosystem, fixed_version FROM tb_cve_affected_packages
              WHERE is_deleted = 0 AND fixed_version IS NOT NULL AND package_name IN ($in)"
        );
        $fx->execute($names);
        $byPkg = [];
        foreach ($fx->fetchAll() as $f) {
            $byPkg[$f['package_name'] . '|' . (string) $f['ecosystem']][] = $f['fixed_version'];
        }
        foreach ($rows as &$r) {
            $key = $r['package_name'] . '|' . (string) $r['ecosystem'];
            $r['max_fixed'] = vg_pkg_max_fixed($byPkg[$key] ?? []);
        }
        unset($r);
    }
} catch (Throwable $e) {
    $err = $e->getMessage();
}

vg_header('영향 패키지', 'packages');
?>
  <h1>영향 패키지 <span class="hint">(<?= number_format($total) ?>종)</span></h1>
  <div class="sub">
    <a href="/connectors.php">OSV 커넥터</a>가 스캔된 패키지를 조회해 찾아낸 "이 패키지가 이 CVE 에 취약하다" 매핑입니다.
    CVE 단위로 보려면 <a href="/cves.php">CVE 목록</a>.
  </div>

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
          ['label' => '패키지', 'width' => '16rem'],
          ['label' => '배포판', 'width' => '10rem'],
          ['label' => 'CVE 수', 'align' => 'right', 'width' => '6rem'],
          ['label' => '최고 EPSS', 'align' => 'right', 'width' => '9rem'],
          ['label' => '조치'],
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
              : [
                  'icon'  => '📦',
                  'title' => '아직 수집된 패키지가 없습니다.',
                  'hint'  => 'OSV 커넥터가 스캔된 패키지를 조회해야 이 매핑이 만들어집니다.',
                  'cta'   => ['href' => '/connectors.php', 'label' => '피드 커넥터로 이동'],
              ],
          'cell' => [
              // 패키지명 → 취약점 현황에서 그 패키지만 검색
              0 => fn($r) => '<a href="/findings.php?q=' . urlencode((string) $r['package_name']) . '">'
                             . vg_h((string) $r['package_name']) . '</a>',
              1 => fn($r) => !empty($r['ecosystem'])
                             ? vg_h((string) $r['ecosystem'])
                             : '<span class="why">–</span>',
              2 => fn($r) => number_format((int) $r['cve_cnt']),
              3 => fn($r) => vg_epss_cell($r['max_epss'], null),
              // 조치 버전이 있으면 "N 이상". 없으면 아직 패치가 안 나온 CVE 들이다.
              4 => function ($r) {
                  if (empty($r['max_fixed'])) {
                      return '<span class="why">패치 확인 (조치 0/' . (int) $r['cve_cnt'] . ')</span>';
                  }
                  return '<span class="pill">' . vg_h((string) $r['max_fixed']) . ' 이상</span>'
                       . ' <span class="why">조치 ' . (int) $r['fix_cnt'] . '/' . (int) $r['cve_cnt'] . '</span>';
              },
          ],
      ]
  );
  if ($rows) { vg_page_nav($total, $perPage, $page); }
  ?>
<?php endif; ?>
<?php vg_footer();
