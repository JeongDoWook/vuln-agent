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
    $from = 'FROM tb_cve c
             LEFT JOIN tb_kev_catalog k ON k.cve_id = c.cve_id AND k.is_deleted = 0';
    // COUNT(*) 는 is_kev 뱃지를 안 그리므로, kev=1 필터가 아니면 조인이 필요 없다.
    // tb_kev_catalog(36만행) 건별 eq_ref 조인이 COUNT 를 15배 느리게 만든다(0.048s → 0.73s).
    $fromCount = $kev === '1' ? $from : 'FROM tb_cve c';

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

vg_header('CVE 카탈로그', 'cves');
?>
  <?php vg_page_title('CVE 카탈로그', 'CATALOG', '수집한 전체 CVE — 내 자산 해당분은 탐지 결과에서', ['count' => $total]); ?>

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
      ['type' => 'select', 'name' => 'sev', 'selected' => $sev, 'empty_label' => '심각도 전체',
       'options' => ['critical' => 'CRITICAL', 'high' => 'HIGH', 'medium' => 'MEDIUM', 'low' => 'LOW']],
      ['type' => 'select', 'name' => 'year', 'selected' => $year, 'empty_label' => '연도 전체',
       'options' => $years],
      // 기본값(공개일순)은 빈 값 옵션으로 표현 — 같은 항목이 두 번 뜨지 않게 한다.
      ['type' => 'select', 'name' => 'sort', 'selected' => $sort === 'published' ? '' : $sort,
       'empty_label' => '공개일순', 'options' => ['cvss' => 'CVSS 높은순', 'epss' => 'EPSS 높은순']],
      ['type' => 'search', 'name' => 'q', 'placeholder' => 'CVE-ID 또는 요약 검색', 'value' => $q],
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
          'hint'  => '데이터 수집을 한 번 실행해 주세요.',
          'cta'   => vg_connectors_empty_cta(),
      ]);
  vg_table(
      [
          // nowrap 이 아니다 — CVE-ID 뒤에 KEV 뱃지가 붙는데 nowrap 이면 한 줄을 넘겨 말줄임에
          //   먹혀 뱃지가 통째로 사라진다(실측: 1440px 에서 "CVE-2023-4911 …" 로만 보였다).
          //   findings.php 의 CVE 칸이 nowrap 을 안 쓰는 것과 같은 이유.
          ['label' => 'CVE', 'width' => '16%', 'title' => '누르면 이 CVE 의 상세로 갑니다'],
          // 심각도 뱃지(CRITICAL 69px)는 줄바꿈이 안 되는 고정 크기라 % 로 주면 표가 좁아질 때
          //   덮는다 — 870px 에서 45.8px 를 CVSS 열 위에 그렸다. 값 69 + 칸 여백 32 = 101 → 6.5rem.
          ['label' => '심각도', 'width' => '6.5rem'],
          // CVSS(얼마나 심한가)와 EPSS(실제로 악용될 확률)는 같이 봐야 뜻이 생긴다 — 칸을 둘로
          //   나눠 두면 좁은 폭에서 각각 줄바꿈만 하고 요약 칸을 밀어냈다. findings.php 의
          //   같은 칸과 같은 형태로 합친다(같은 뜻은 화면마다 같은 모양으로).
          // 머리글이 '위험도' 가 아니라 'CVSS' 인 이유: 값 앞에 붙이던 'CVSS' 접두어를 뺐기 때문이다
          //   (좁은 칸에서 접두어가 정작 점수를 밀어냈다). 점수 미수집이 대다수인 목록이라,
          //   빈 값은 'CVSS –' + 'EPSS –' 두 줄을 먹지 않고 한 줄로 접는다 — 아래 셀 콜백.
          ['label' => 'CVSS', 'align' => 'right', 'width' => '9rem',
              'title' => 'CVSS 기본점수 · 아랫줄은 EPSS(30일 내 악용 확률)'],
          // 날짜는 길이가 고정(YYYY-MM-DD)이라 % 가 아니라 rem 으로 준다 — % 로 두니 요약 칸이
          //   넓어진 만큼 여기가 줄어 "2023-10-…" 로 잘렸다(실측 1440px).
          ['label' => '공개일', 'width' => '6.5rem', 'nowrap' => true],
          ['label' => '요약'],
      ],
      $rows,
      [
          'empty' => $emptySpec,
          // 이 표엔 severity 컬럼이 없다 — CVSS 점수에서 등급을 파생시킨다(vg_cvss_sev 는 소문자를 준다).
          'row_class' => fn($r) => vg_sev_row(strtoupper(vg_cvss_sev($r['cvss'] === null ? null : (string) $r['cvss']))),
          'cell' => [
              // 행 진입 링크는 이 칸이 담당한다(요약 칸은 본문 색으로 남긴다 — 아래 4번).
              //   식별자는 <code> 로 감싸 줄바꿈을 막는다(app.css: td code 는 nowrap).
              0 => function ($r) {
                  $html = '<a href="/cve.php?cve=' . urlencode((string) $r['cve_id']) . '">'
                        . '<code>' . vg_h((string) $r['cve_id']) . '</code></a>';
                  if (!empty($r['is_kev'])) {
                      $html .= ' ' . vg_badge('KEV', 'crit', '악용이 확인된 취약점 — CISA KEV 등재');
                  }
                  return $html;
              },
              // 이 표의 심각도는 CVSS 에서 파생된다 — 점수가 없으면 등급이 '없는' 게 아니라
              //   **아직 매겨지지 않은** 것이다. 둘 다 '–' 로 쓰면 "위험하지 않다" 로 읽힌다.
              //   375,523건 중 대다수가 이 상태라 더욱 구분돼야 한다(advisory.php 가 같은 상황을
              //   '미수집' 뱃지로 구분하는 것과 같은 어휘).
              1 => function ($r) {
                  $sev = vg_cvss_sev($r['cvss'] === null ? null : (string) $r['cvss']);
                  if ($sev === '') {
                      return vg_badge('미평가', 'muted', 'CVSS 점수가 아직 수집되지 않아 등급을 매길 수 없습니다 — "위험하지 않음"이 아닙니다');
                  }
                  return vg_sev_badge(strtoupper($sev));   // 톤 매핑은 대문자 키를 받는다
              },
              // 값이 있는 것만 보인다. 예전엔 없는 값도 'CVSS –' / 'EPSS –' 두 줄을 그대로 먹어서,
              //   대다수가 미수집인 이 목록의 행 높이를 통째로 두 배로 만들었다.
              //   백분위("상위 N%")는 좁은 칸에서 세 줄로 접혀 행 높이를 끌어올린다 — 상세(cve.php)에 남긴다.
              2 => function ($r) {
                  $has = false;
                  $html = '';
                  if ($r['cvss'] !== null) {
                      $html .= '<strong>' . vg_h((string) $r['cvss']) . '</strong>';
                      $has = true;
                  }
                  if ($r['epss'] !== null && $r['epss'] !== '') {
                      $html .= '<div class="why">EPSS ' . vg_epss_cell($r['epss'], null) . '</div>';
                      $has = true;
                  }
                  return $has ? $html : '<span class="why" title="CVSS·EPSS 모두 아직 수집되지 않았습니다">–</span>';
              },
              3 => fn($r) => '<span class="why">' . vg_h($r['published'] ?? '–') . '</span>',
              // 요약은 두 줄까지만 보이고, 전체 문장은 CVE 상세에서 읽는다(잘린 부분은 title 에).
              //   예전엔 아예 링크를 걷었다 — 문장 전체가 강조색이 되면 다크 테마에서 본문이
              //   통째로 파랗게 떴기 때문이다(실측). 지금은 .body-link 가 그 문제만 없앤다:
              //   본문 색을 그대로 쓰고, 링크라는 사실은 hover 의 밑줄·색으로 알린다.
              //   덕분에 "읽던 문장을 그대로 눌러 상세로" 가 다시 가능해진다.
              4 => function ($r) {
                  $s = (string) ($r['summary'] ?? '');
                  if ($s === '') { return '<span class="why">–</span>'; }
                  return '<a class="clamp-2 body-link" href="/cve.php?cve=' . urlencode((string) $r['cve_id']) . '"'
                      . ' title="' . vg_h($s) . '">' . vg_h($s) . '</a>';
              },
          ],
      ]
  );
  if ($rows) { vg_page_nav($total, $perPage, $page); }
  ?>
<?php endif; ?>
<?php vg_footer();
