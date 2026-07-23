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

// VG_SEV_RANGES · vg_cvss_sev() 는 format.php 에 있다 — cve.php 도 같은 구간을 쓴다.

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
$page = vg_page();
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
    // COUNT(*) 는 is_kev 뱃지를 안 그리므로, kev=1 필터가 아니면 조인이 필요 없다.
    // tb_kev_catalog(36만행) 건별 eq_ref 조인이 COUNT 를 15배 느리게 만든다(0.048s → 0.73s).
    $fromCount = $kev === '1' ? $from : 'FROM tb_cves c';

    $where  = 'c.is_deleted = 0';
    $params = [];

    if ($q !== '') {
        // "CVE-2024-1234" 뿐 아니라 "CVE" 없이 번호만("2024-1234", "1999-0003", "2024")
        // 입력하는 흔한 패턴도 ID 검색으로 잡는다 — 안 잡으면 하이픈 포함 숫자가 FULLTEXT
        // 토큰과 안 맞아 사실상 0건이 된다.
        if (preg_match('/^cve-?/i', $q) || preg_match('/^\d{4}(-\d*)?$/', $q)) {
            // summary FULLTEXT 를 같이 OR 하면 "CVE"·연도가 낱말로 쪼개져, 다른 CVE 를
            // 교차참조("...duplicate of CVE-1999-0032...")한 요약까지 잡혀 노이즈가 커진다
            // (실측: CVE-1999-0003 전체 입력이 요약 교차참조 때문에 62건까지 걸렸다) — 그래서
            // ID 형태 입력은 cve_id 접두 매칭만 쓴다(PK 인덱스, KISS).
            $norm = preg_match('/^cve/i', $q) ? $q : 'CVE-' . $q;
            // LIKE 의 %/_ 는 와일드카드라 사용자 입력에 그대로 남아 있으면 의도 밖 매칭이 된다.
            $where .= " AND c.cve_id LIKE ? ESCAPE '\\\\'";
            $params[] = strtr($norm, ['\\' => '\\\\', '%' => '\\%', '_' => '\\_']) . '%';
        } elseif (mb_strlen($q) < 3) {
            // innodb_ft_min_token_size(기본 3) 미만인 검색어는 FULLTEXT 가 무조건 0건을 준다
            // ("ls", "xz" 같은 2글자 검색이 고장난 것처럼 보임) — 이 경우만 기존 LIKE 로 폴백한다.
            // stopword 케이스(기술 용어 코퍼스라 흔치 않음)까지 감지해 폴백하는 건 과설계로 보고 넘긴다.
            $where .= " AND c.summary LIKE ? ESCAPE '\\\\'";
            $params[] = '%' . strtr($q, ['\\' => '\\\\', '%' => '\\%', '_' => '\\_']) . '%';
        } else {
            // summary 는 FULLTEXT(ft_cves_summary, db/migrations/20260719105602_*.sql). NATURAL
            // LANGUAGE MODE 는 검색어에 +-*"() 같은 예약문자가 섞여도 문법 오류 없이 그냥 단어로
            // 다뤄져 BOOLEAN MODE 특유의 이스케이프 처리가 필요 없다(KISS).
            $where .= ' AND MATCH(c.summary) AGAINST (? IN NATURAL LANGUAGE MODE)';
            $params[] = $q;
        }
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

    $stmt = $pdo->prepare("SELECT COUNT(*) $fromCount WHERE $where");
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
    error_log('[cves] ' . $e->getMessage());
    $err = '처리 중 오류가 발생했습니다.';
}

vg_header('CVE 목록', 'cves');
?>
  <?php vg_page_title('CVE 목록', 'VULNERABILITY CATALOG', '수집된 취약점을 악용 가능성과 위험도 기준으로 탐색합니다.', ['count' => $total]); ?>

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
  $emptySpec = $hasFilter
      ? [
          'icon'  => '🔍',
          'title' => '조건에 맞는 CVE가 없습니다.',
          'hint'  => '검색어나 등급·연도 필터를 바꿔 보세요.',
          'cta'   => ['href' => '/cves.php', 'label' => '필터 초기화'],
      ]
      : array_filter([
          'icon'  => '📭',
          'title' => '아직 수집된 CVE가 없습니다.',
          'hint'  => '피드 커넥터가 한 번은 돌아야 합니다.',
          'cta'   => vg_connectors_empty_cta(),
      ]);
  vg_table(
      [
          ['label' => 'CVE', 'width' => '13rem', 'nowrap' => true],
          ['label' => '심각도', 'width' => '6rem'],
          ['label' => 'CVSS', 'align' => 'right', 'width' => '4rem'],
          ['label' => 'EPSS', 'align' => 'right', 'width' => '9rem'],
          ['label' => '공개일', 'width' => '7rem'],
          ['label' => '요약'],
      ],
      $rows,
      [
          'empty' => $emptySpec,
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
