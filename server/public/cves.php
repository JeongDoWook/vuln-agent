<?php
declare(strict_types=1);

/**
 * cves.php — 수집된 CVE 목록. 로그인 필요(취약점 메뉴 권한 재사용).
 *   검색(CVE-ID/요약) + 필터(심각도·KEV·연도) + 정렬(공개일/CVSS/EPSS) + 페이지네이션.
 *   행의 CVE-ID 를 누르면 cve.php 상세로 간다.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
vg_require_menu('findings');

// CVSS 기본점수 → 심각도 구간(NVD v3 기준)
const VG_SEV_RANGES = [
    'critical' => [9.0, 10.0],
    'high'     => [7.0, 8.9],
    'medium'   => [4.0, 6.9],
    'low'      => [0.1, 3.9],
];

// 정렬 화이트리스트. 사용자 입력을 SQL 에 직접 넣지 않는다.
const VG_CVE_SORTS = [
    'published' => ['col' => 'c.published', 'label' => '공개일'],
    'cvss'      => ['col' => 'c.cvss',      'label' => 'CVSS'],
    'epss'      => ['col' => 'c.epss',      'label' => 'EPSS'],
];

$err = null; $rows = []; $total = 0;

$q    = trim((string) ($_GET['q'] ?? ''));
$sev  = (string) ($_GET['sev'] ?? '');
$kev  = (string) ($_GET['kev'] ?? '');
$eTop = (string) ($_GET['epss'] ?? '');   // 상위 N% (탭)
$year = (string) ($_GET['year'] ?? '');
$sort = (string) ($_GET['sort'] ?? '');
$page = max(1, (int) ($_GET['page'] ?? 1));
$perPage = vg_perpage();

if (!isset(VG_CVE_SORTS[$sort])) { $sort = 'published'; }
if (!isset(VG_SEV_RANGES[$sev])) { $sev = ''; }
if ($kev !== '1') { $kev = ''; }
if (!in_array($eTop, ['1', '5', '10'], true)) { $eTop = ''; }
if (!preg_match('/^(19|20)\d{2}$/', $year)) { $year = ''; }

// EPSS 탭은 점수순으로 보는 게 기본. 사용자가 정렬을 고르면 그 선택이 이긴다.
if ($eTop !== '' && !isset($_GET['sort'])) { $sort = 'epss'; }

$years = [];
for ($y = (int) date('Y'); $y >= 1999; $y--) { $years[(string) $y] = $y . '년'; }

try {
    $pdo = vg_pdo();

    // KEV 는 존재 여부만 필요하므로 LEFT JOIN 후 IS NOT NULL 로 거른다.
    $from = 'FROM tb_cves c
             LEFT JOIN tb_kev_catalog k ON k.cve_id = c.cve_id AND k.is_deleted = 0';

    $where  = 'c.is_deleted = 0';
    $params = [];

    if ($q !== '') {
        $where .= ' AND (c.cve_id LIKE ? OR c.summary LIKE ?)';
        $params[] = '%' . $q . '%';
        $params[] = '%' . $q . '%';
    }
    if ($sev !== '') {
        [$lo, $hi] = VG_SEV_RANGES[$sev];
        $where .= ' AND c.cvss BETWEEN ? AND ?';
        $params[] = $lo;
        $params[] = $hi;
    }
    if ($kev === '1') {
        $where .= ' AND k.cve_id IS NOT NULL';
    }
    if ($eTop !== '') {
        // percentile 0.99 = 상위 1%. FIRST 가 주는 백분위를 그대로 임계값으로 쓴다.
        $where .= ' AND c.epss_percentile >= ?';
        $params[] = 1 - ((float) $eTop / 100);
    }
    if ($year !== '') {
        // BETWEEN 범위 조건이라야 published 인덱스를 탄다(YEAR() 함수는 못 탐).
        $where .= ' AND c.published BETWEEN ? AND ?';
        $params[] = $year . '-01-01';
        $params[] = $year . '-12-31';
    }

    $stmt = $pdo->prepare("SELECT COUNT(*) $from WHERE $where");
    $stmt->execute($params);
    $total = (int) $stmt->fetchColumn();

    $offset = ($page - 1) * $perPage;

    // MySQL 은 DESC 정렬에서 NULL 을 뒤로 보낸다 → 점수 미수집 CVE 가 상단을 차지하지 않는다.
    // "$col IS NULL" 을 앞에 붙이면 그 표현식 때문에 인덱스 순서가 깨져 filesort 가 된다.
    // cve_id 타이브레이크는 공짜다(InnoDB 보조 인덱스가 PK 를 품고 있어 역방향 스캔으로 처리).
    $col = VG_CVE_SORTS[$sort]['col'];
    $stmt = $pdo->prepare(
        "SELECT c.cve_id, c.summary, c.cvss, c.epss, c.epss_percentile, c.published,
                (k.cve_id IS NOT NULL) AS is_kev
         $from
         WHERE $where
         ORDER BY $col DESC, c.cve_id DESC
         LIMIT $perPage OFFSET $offset"
    );
    $stmt->execute($params);
    $rows = $stmt->fetchAll();
} catch (Throwable $e) {
    $err = $e->getMessage();
}

/** CVSS 점수를 심각도 라벨로. 점수가 없으면 '–'. */
function vg_cvss_sev(?string $cvss): string {
    if ($cvss === null || $cvss === '') { return ''; }
    $v = (float) $cvss;
    foreach (VG_SEV_RANGES as $name => [$lo, $hi]) {
        if ($v >= $lo && $v <= $hi) { return $name; }
    }
    return '';
}

vg_header('CVE 목록', 'cves');
?>
  <h1>CVE 목록 <span class="hint">(<?= number_format($total) ?>건)</span></h1>
  <div class="sub">
    <a href="/connectors.php">피드 커넥터</a>(kev/osv/nvd/epss)가 수집한 CVE.
    KEV 는 실제 악용이 확인된 취약점, EPSS 는 향후 30일 내 악용 확률입니다.
    패키지별로 보려면 <a href="/packages.php">영향 패키지</a>.
  </div>

<?php if ($err !== null): ?>
  <?php vg_alert('오류 · ' . $err); ?>
<?php else: ?>
  <?php
  // 탭 = 자주 쓰는 필터 프리셋. KEV 셀렉트를 대체한다(같은 필터에 컨트롤이 둘이면 헷갈린다).
  $tabs = [
      ['전체',         vg_qs(['kev' => null, 'epss' => null, 'page' => null]),                        $kev === '' && $eTop === ''],
      ['KEV 만',       vg_qs(['kev' => '1',  'epss' => null, 'page' => null]),                        $kev === '1'],
      ['EPSS 상위 1%', vg_qs(['epss' => '1', 'kev' => null, 'sort' => 'epss', 'page' => null]),       $eTop !== ''],
  ];
  echo '<div class="tabs">';
  foreach ($tabs as [$label, $href, $on]) {
      echo '<a class="pill' . ($on ? ' pill--on' : '') . '" href="/cves.php' . $href . '">' . vg_h($label) . '</a>';
  }
  echo '</div>';
  ?>
  <?php vg_toolbar([
      // 탭 선택은 폼 밖에 있다 → 히든으로 실어야 검색·정렬 후에도 탭이 유지된다.
      ['type' => 'hidden', 'name' => 'kev',  'value' => $kev],
      ['type' => 'hidden', 'name' => 'epss', 'value' => $eTop],
      ['type' => 'search', 'name' => 'q', 'placeholder' => 'CVE-ID 또는 요약 검색', 'value' => $q],
      ['type' => 'select', 'name' => 'sev', 'selected' => $sev, 'empty_label' => '심각도 전체',
       'options' => ['critical' => 'CRITICAL', 'high' => 'HIGH', 'medium' => 'MEDIUM', 'low' => 'LOW']],
      ['type' => 'select', 'name' => 'year', 'selected' => $year, 'empty_label' => '연도 전체',
       'options' => $years],
      // 기본값(공개일순)은 빈 값 옵션으로 표현 — 같은 항목이 두 번 뜨지 않게 한다.
      ['type' => 'select', 'name' => 'sort', 'selected' => $sort === 'published' ? '' : $sort,
       'empty_label' => '공개일순', 'options' => ['cvss' => 'CVSS 높은순', 'epss' => 'EPSS 높은순']],
  ]); ?>

  <?php
  $hasFilter = $q !== '' || $sev !== '' || $kev !== '' || $eTop !== '' || $year !== '';
  $emptyMsg = $hasFilter ? '조건에 맞는 CVE가 없습니다.' : '아직 수집된 CVE가 없습니다. 피드 커넥터를 실행하세요.';
  vg_table(
      [
          ['label' => 'CVE', 'width' => '11rem'],
          ['label' => '심각도', 'width' => '6rem'],
          ['label' => 'CVSS', 'align' => 'right', 'width' => '4rem'],
          ['label' => 'EPSS', 'align' => 'right', 'width' => '9rem'],
          ['label' => '공개일', 'width' => '7rem'],
          ['label' => '요약'],
      ],
      $rows,
      [
          'empty' => $emptyMsg,
          // 이 표엔 severity 컬럼이 없다 — CVSS 점수에서 등급을 파생시킨다(vg_cvss_sev 는 소문자를 준다).
          'row_class' => fn($r) => vg_sev_row(strtoupper(vg_cvss_sev($r['cvss'] === null ? null : (string) $r['cvss']))),
          'cell' => [
              0 => function ($r) {
                  $html = '<a href="/cve.php?cve=' . urlencode((string) $r['cve_id']) . '">' . vg_h((string) $r['cve_id']) . '</a>';
                  if (!empty($r['is_kev'])) {
                      $html .= ' ' . vg_badge('KEV', 'crit');
                  }
                  return $html;
              },
              1 => function ($r) {
                  $sev = vg_cvss_sev($r['cvss'] === null ? null : (string) $r['cvss']);
                  if ($sev === '') { return '<span class="why">–</span>'; }
                  return vg_sev_badge(strtoupper($sev));   // 톤 매핑은 대문자 키를 받는다
              },
              2 => fn($r) => $r['cvss'] !== null ? vg_h((string) $r['cvss']) : '<span class="why">–</span>',
              3 => fn($r) => vg_epss_cell($r['epss'], $r['epss_percentile']),
              4 => fn($r) => '<span class="why">' . vg_h($r['published'] ?? '–') . '</span>',
              5 => fn($r) => !empty($r['summary']) ? vg_trunc($r['summary'], 110) : '<span class="why">–</span>',
          ],
      ]
  );
  if ($rows) { vg_page_nav($total, $perPage, $page); }
  ?>
<?php endif; ?>
<?php vg_footer();
