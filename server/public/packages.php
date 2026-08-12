<?php
declare(strict_types=1);

/**
 * packages.php — 패키지 목록. 서브탭으로 OS 패키지(OSV 커넥터 산출물,
 *   tb_cve_affected_package 요약)와 언어 패키지·라이선스(pip/npm/gem/composer/maven/
 *   nuget/cargo/go, SBOM/METADATA 기반)를 함께 보여준다. `?tab=os`(기본) / `?tab=lang`.
 *   예전 language-packages.php 화면을 그대로 흡수한 것 — 각 탭의 쿼리·필터 로직은
 *   원본 그대로 이식했다(중복 아님, OS 는 배포판 필터·언어는 매니저·위험도 필터라
 *   서로 다른 필터). 로그인 필요(취약점 메뉴 권한 재사용).
 *
 *   CVE 목록(cves.php)은 행이 CVE 하나지만 여기는 패키지 하나다. 같은 테이블에 못 담아
 *   화면을 나눴다. OS 패키지명을 누르면 취약점 현황에서 그 패키지만 걸러 본다.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require_once __DIR__ . '/../src/license_summary.php';   // VG_LANG_MANAGERS, vg_license_risk_*
vg_require_menu('findings');

// 정렬 화이트리스트(OS 탭). 사용자 입력을 SQL 에 직접 넣지 않는다.
const VG_PKG_SORTS = [
    'cves'    => ['col' => 'cve_cnt',  'label' => 'CVE 많은순'],
    'epss'    => ['col' => 'max_epss', 'label' => 'EPSS 높은순'],
    'package' => ['col' => 'package_name', 'label' => '패키지명순'],
];

// 서브탭 정의 — "os/lang 두 개" 라는 사실을 여기 하나로만 둔다. 화이트리스트 검증·
//   vg_subtabs() 렌더·hidden 필드 값이 전부 이 상수를 참조한다. 세 번째 탭을 추가할 때
//   여기 한 줄만 늘리면 된다. 각 탭 전용 필터명(clear)은 다른 탭으로 넘어갈 때 비워서
//   탭 간 검색어 의미 충돌(부분일치 vs 접두일치)이 새지 않게 한다.
const VG_PKG_TABS = [
    'os'   => ['label' => 'OS 패키지', 'clear' => ['q', 'manager', 'risk']],
    'lang' => ['label' => '언어 패키지·라이선스', 'clear' => ['q', 'eco', 'sort']],
];

$tab = (string) ($_GET['tab'] ?? 'os');
if (!isset(VG_PKG_TABS[$tab])) { $tab = 'os'; }

$err = null;
$page = vg_page();
$perPage = vg_perpage();

// ---- OS 패키지(tab=os) 상태 ----
$rows = []; $total = 0; $ecos = []; $summaryAt = '';
$q    = trim((string) ($_GET['q'] ?? ''));
$eco  = trim((string) ($_GET['eco'] ?? ''));
$sort = (string) ($_GET['sort'] ?? '');
if (!isset(VG_PKG_SORTS[$sort])) { $sort = 'cves'; }

// ---- 언어 패키지·라이선스(tab=lang) 상태 ----
$langRows = []; $langTotal = 0; $langSummaryAt = '';
$riskCounts = ['permissive' => 0, 'copyleft' => 0, 'unknown' => 0];
$manager = trim((string) ($_GET['manager'] ?? ''));
$risk    = trim((string) ($_GET['risk'] ?? ''));
$managerOptions = array_combine(VG_LANG_MANAGERS, VG_LANG_MANAGERS) ?: [];
if (!isset($managerOptions[$manager])) { $manager = ''; }
$riskOptions = ['permissive' => vg_license_risk_label('permissive'), 'copyleft' => vg_license_risk_label('copyleft'), 'unknown' => vg_license_risk_label('unknown')];
if (!isset($riskOptions[$risk])) { $risk = ''; }

try {
    $pdo = vg_pdo();

    if ($tab === 'os') {
        // 배포판 목록·개수·정렬은 사전집계 요약(tb_package_summary)에서 읽는다. 원본
        //   tb_cve_affected_package(92만 행)를 매 로드 재집계하던 걸(운영 ~8초) OSV 실행 때 한 번
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
            // 언어 탭과 동일하게 LIKE 메타문자(%, _, \)를 이스케이프해 사용자가 입력한
            // 문자 그대로 매칭한다(부분일치라 앞뒤 % 는 그대로 둔다).
            $where .= ' AND package_name LIKE ?';
            $params[] = '%' . addcslashes($q, '%_\\') . '%';
        }
        if ($eco !== '') {
            $where .= ' AND ecosystem = ?';
            $params[] = $eco;
        }

        $stmt = $pdo->prepare("SELECT COUNT(*) FROM tb_package_summary WHERE $where");
        $stmt->execute($params);
        $total = (int) $stmt->fetchColumn();

        // 오프셋에 상한을 둔다 — 언어 탭과 동일하게 총 건수 기준 마지막 페이지를 넘어가지 못하게 clamp.
        if ($total > 0) {
            $page = min($page, (int) ceil($total / $perPage));
        }
        $offset = ($page - 1) * $perPage;
        $col = VG_PKG_SORTS[$sort]['col'];
        $stmt = $pdo->prepare(
            "SELECT package_name, ecosystem, cve_cnt, max_epss, fix_cnt, max_fixed
               FROM tb_package_summary
              WHERE $where
              ORDER BY $col DESC, package_name ASC
              LIMIT ? OFFSET ?"
        );
        foreach ($params as $i => $v) {
            $stmt->bindValue($i + 1, $v);
        }
        $stmt->bindValue(count($params) + 1, $perPage, PDO::PARAM_INT);
        $stmt->bindValue(count($params) + 2, $offset, PDO::PARAM_INT);
        $stmt->execute();
        $rows = $stmt->fetchAll();

        /* kernel · kernel-core · kernel-abi-stablelists 처럼 **같은 소스 패키지에서 갈라진
         * 바이너리**는 CVE 수·최고 EPSS·조치 수치가 글자 그대로 같다. 정렬이 CVE 많은순이라
         * 목록 상단이 같은 값의 반복으로 채워지는데, 화면에는 "왜 같은지" 가 안 적혀 있어
         * 세 행을 각각 읽어 보게 된다. 집계 기준·정렬은 그대로 두고(사전집계 tb_package_summary
         * 를 건드리면 8초→0.05초 개선이 되돌아간다) 이어지는 같은 값에 꼬리표만 붙인다. */
        $prevAgg = null;
        foreach ($rows as $i => $r) {
            $agg = implode('|', [
                (string) ($r['ecosystem'] ?? ''), (string) $r['cve_cnt'],
                (string) ($r['max_epss'] ?? ''), (string) $r['fix_cnt'],
                (string) ($r['max_fixed'] ?? ''),
            ]);
            $rows[$i]['same_agg'] = ($prevAgg !== null && $agg === $prevAgg);
            $prevAgg = $agg;
        }
    } else {
        // KPI·위험도 집계는 사전집계 테이블에서만 읽는다(원본 tb_package 재집계 금지).
        // SUM(pkg_count) 를 쓴다 — COUNT(*) 는 (manager,name,license) 조합 종류 수라 목록 필터
        // 건수(설치 인스턴스 수, SUM(pkg_count) 기준)와 단위가 달라 KPI 와 목록이 서로 다른
        // 숫자를 보여줬다. pkg_count 컬럼을 여기서 실제로 사용해 통일한다.
        $langSummaryAt = (string) ($pdo->query('SELECT MAX(updated_at) FROM tb_package_license_summary')->fetchColumn() ?: '');
        foreach ($pdo->query('SELECT risk, SUM(pkg_count) AS c FROM tb_package_license_summary GROUP BY risk') as $r) {
            if (isset($riskCounts[$r['risk']])) { $riskCounts[$r['risk']] = (int) $r['c']; }
        }

        $mgrPlaceholders = implode(',', array_fill(0, count(VG_LANG_MANAGERS), '?'));
        $from = 'FROM tb_host h
                 JOIN ' . vg_latest_scan_subq() . ' latest ON latest.host_id = h.host_id
                 JOIN tb_scan s ON s.scan_id = latest.mid
                 JOIN tb_package p ON p.scan_id = s.scan_id
                 LEFT JOIN tb_container c ON c.container_id = p.container_id AND p.container_id <> 0
                 LEFT JOIN tb_package_license_summary sm
                        ON sm.manager = p.manager AND sm.name = p.name AND sm.license = p.license';
        $where  = "h.is_deleted = 0 AND p.is_deleted = 0 AND p.manager IN ($mgrPlaceholders)";
        $params = VG_LANG_MANAGERS;
        if ($q !== '') {
            // LIKE 메타문자(%, _, \) 를 이스케이프해 사용자가 입력한 문자 그대로 매칭한다.
            // MySQL LIKE 의 기본 이스케이프 문자가 backslash 라 addcslashes 만으로 충분하다.
            // 접두 검색(뒤쪽 % 만)으로 제한해 idx_package_manager_name(manager, name) 을 탄다 —
            // 앞쪽 와일드카드는 인덱스를 못 써 packages 40초 사고와 같은 무인덱스 스캔이 된다.
            $where .= ' AND p.name LIKE ?';
            $params[] = addcslashes($q, '%_\\') . '%';
        }
        if ($manager !== '') {
            $where .= ' AND p.manager = ?';
            $params[] = $manager;
        }
        if ($risk !== '') {
            $where .= ' AND COALESCE(sm.risk, \'unknown\') = ?';
            $params[] = $risk;
        }

        $st = $pdo->prepare("SELECT COUNT(*) $from WHERE $where");
        $st->execute($params);
        $langTotal = (int) $st->fetchColumn();

        // 오프셋에 상한을 둔다 — 총 건수 기준 마지막 페이지를 넘어가지 못하게 clamp.
        if ($langTotal > 0) {
            $page = min($page, (int) ceil($langTotal / $perPage));
        }
        $offset = ($page - 1) * $perPage;
        $st = $pdo->prepare(
            "SELECT h.host_id, h.fqdn, c.name AS container_name, p.manager, p.name, p.version, p.license,
                    COALESCE(sm.risk, 'unknown') AS risk, s.collected_at
               $from WHERE $where
              ORDER BY p.name, h.fqdn, p.version, p.package_id
              LIMIT $perPage OFFSET $offset"
        );
        $st->execute($params);
        $langRows = $st->fetchAll();
        // 표시용 위험도는 사전집계(요약) 조인이 아니라 vg_license_classify() 순수함수로 직접 계산한다
        // — 페이지당 $perPage 행뿐이라 가볍고, 요약 테이블이 아직 그 (manager,name,license) 조합을
        // 못 따라잡았어도("값은 있는데 뱃지는 미상") 항상 올바른 위험도를 보여준다. 필터(risk=)는
        // 여전히 요약 테이블을 쓴다 — 최대 1분(스케줄러 주기) 지연은 감수한다.
        foreach ($langRows as &$row) {
            $row['risk'] = vg_license_classify((string) ($row['license'] ?? ''));
        }
        unset($row);
    }
} catch (Throwable $e) {
    error_log('[packages] ' . $e->getMessage());
    $err = '처리 중 오류가 발생했습니다.';
}

vg_header($tab === 'lang' ? '언어 패키지 · 라이선스' : '패키지', 'packages');
?>
  <?php if ($tab === 'lang'): ?>
    <?php vg_page_title('언어 패키지 · 라이선스', 'SCA', 'pip/npm/gem/composer/maven/nuget/cargo/go 패키지의 라이선스를 확인합니다.', ['count' => $langTotal, 'count_label' => '건']); ?>
    <?php if ($langSummaryAt !== ''): ?>
    <div class="sub"><span class="why">집계 기준 <?= vg_h($langSummaryAt) ?> (OSV 수집 시 갱신) · 라이선스 값은 SBOM/METADATA/composer 소스에서만 채워집니다.</span></div>
    <?php endif; ?>
  <?php else: ?>
    <?php vg_page_title('패키지', 'PACKAGES', '패키지별 CVE와 수정 버전을 확인합니다.', ['count' => $total, 'count_label' => '종']); ?>
    <?php if ($summaryAt !== ''): ?>
    <div class="sub"><span class="why">집계 기준 <?= vg_h($summaryAt) ?> (OSV 수집 시 갱신)</span></div>
    <?php endif; ?>
  <?php endif; ?>

  <?php
  // 탭을 누르면 그 탭에 안 맞는 상대 탭 전용 필터(검색어 포함)를 비운다 — OS 탭의 부분일치
  // q 와 언어 탭의 접두일치 q 는 의미가 달라 그대로 들고 가면 빈 결과가 뜬다(Critical #2).
  $pkgTabs = [];
  foreach (VG_PKG_TABS as $key => $def) {
      $clear = array_fill_keys($def['clear'], null);
      $clear['tab'] = $key;
      $clear['page'] = null;
      $pkgTabs[$key] = ['label' => $def['label'], 'href' => vg_qs($clear)];
  }
  vg_subtabs($pkgTabs, $tab);
  ?>

<?php if ($err !== null): ?>
  <?php vg_alert('오류 · ' . $err); ?>
<?php elseif ($tab === 'lang'): ?>

  <div class="cards">
    <?php foreach (['copyleft', 'permissive', 'unknown'] as $rk): ?>
      <a href="<?= vg_h(vg_qs(['risk' => $risk === $rk ? '' : $rk, 'page' => 1, 'tab' => 'lang'])) ?>"
         class="kpi kpi--sm tone-<?= vg_h(vg_license_risk_tone($rk)) ?><?= $risk === $rk ? ' is-selected' : '' ?>">
        <b><?= number_format($riskCounts[$rk]) ?></b><span><?= vg_h(vg_license_risk_label($rk)) ?></span>
      </a>
    <?php endforeach; ?>
  </div>

  <?php
  // 위험도는 바로 위 KPI 카드가 토글한다(누르면 걸리고 다시 누르면 풀린다) — 같은 필터에
  //   컨트롤이 둘이면 어느 쪽이 이겼는지 헷갈린다(cves.php 의 KEV 탭·셀렉트 정리와 같은 판단).
  //   셀렉트는 빼되, 검색·매니저를 제출해도 선택이 풀리지 않게 hidden 으로 싣는다.
  vg_toolbar([
      ['type' => 'select', 'name' => 'manager', 'selected' => $manager,
       'empty_label' => '전체 매니저', 'options' => $managerOptions],
      ['type' => 'hidden', 'name' => 'risk', 'value' => $risk, 'reset' => true],
      ['type' => 'search', 'name' => 'q', 'placeholder' => '패키지명 검색', 'value' => $q],
      ['type' => 'hidden', 'name' => 'tab', 'value' => $tab],
  ]); ?>

  <?php
  $hasFilter = $q !== '' || $manager !== '' || $risk !== '';
  vg_table(
      [
          ['label' => '패키지', 'width' => '22%', 'class' => 'col-id'],
          ['label' => '매니저', 'width' => '10%'],
          ['label' => '버전', 'width' => '12%'],
          ['label' => '라이선스', 'width' => '20%'],
          ['label' => '위치', 'width' => '20%'],
          ['label' => '수집 시각', 'width' => '16%', 'nowrap' => true],
      ],
      $langRows,
      [
          'empty' => $hasFilter
              ? [
                  'icon'  => '🔍',
                  'title' => '조건에 맞는 언어 패키지가 없습니다.',
                  'hint'  => '검색어나 매니저·위험도 필터를 바꿔 보세요.',
                  'cta'   => ['href' => '/packages.php?tab=lang', 'label' => '필터 초기화'],
              ]
              : array_filter([
                  'icon'  => '📦',
                  'title' => '아직 수집된 언어 패키지가 없습니다.',
                  'hint'  => '에이전트가 pip/npm/gem/composer/maven/nuget/cargo/go 패키지를 수집해야 이 목록이 채워집니다.',
                  'cta'   => vg_connectors_empty_cta(),
              ]),
          'cell' => [
              0 => fn($r) => '<a href="/host.php?id=' . (int) $r['host_id'] . '&amp;tab=packages&amp;q='
                  . urlencode((string) $r['name']) . '"><strong>' . vg_h((string) $r['name']) . '</strong></a>',
              1 => fn($r) => '<code>' . vg_h((string) $r['manager']) . '</code>',
              2 => fn($r) => '<code>' . vg_h((string) ($r['version'] ?? '')) . '</code>',
              3 => function ($r) {
                  if (empty($r['license'])) { return '<span class="why">–</span>'; }
                  return vg_h((string) $r['license']) . ' '
                      . vg_badge(vg_license_risk_label((string) $r['risk']), vg_license_risk_tone((string) $r['risk']));
              },
              4 => fn($r) => '<a href="/host.php?id=' . (int) $r['host_id'] . '&amp;tab=packages&amp;q='
                  . urlencode((string) $r['name']) . '">'
                  . vg_h((string) $r['fqdn']) . '</a>'
                  . (!empty($r['container_name']) ? ' <span class="why">(' . vg_h((string) $r['container_name']) . ')</span>' : ''),
              5 => fn($r) => '<span class="why">' . vg_h((string) $r['collected_at']) . '</span>',
          ],
      ]
  );
  if ($langRows) { vg_page_nav($langTotal, $perPage, $page); }
  ?>

<?php else: ?>

  <?php vg_toolbar([
      ['type' => 'select', 'name' => 'eco', 'selected' => $eco, 'empty_label' => '배포판 전체',
       'options' => $ecoOptions],
      ['type' => 'select', 'name' => 'sort', 'selected' => $sort === 'cves' ? '' : $sort,
       'empty_label' => 'CVE 많은순', 'options' => ['epss' => 'EPSS 높은순', 'package' => '패키지명순']],
      ['type' => 'search', 'name' => 'q', 'placeholder' => '패키지명 검색', 'value' => $q],
      ['type' => 'hidden', 'name' => 'tab', 'value' => $tab],
  ]); ?>

  <?php
  /* "어느 패키지가 제일 많은 CVE 를 물고 있나" — 표의 CVE 수 열은 숫자만 줘서, 1위가 2위의
   * 몇 배인지가 안 읽힌다(실측: 상위 몇 종이 나머지를 합친 것보다 많은데 그게 안 보였다).
   * **새로 집계하지 않는다** — 이 화면이 이미 들고 있는 $rows 를 그대로 그린다. 이 표는
   * 사전집계(tb_package_summary)를 cve_cnt DESC 로 읽으므로, 정렬이 'CVE 많은순'이고
   * 1페이지일 때 $rows 앞부분이 곧 (현재 필터 기준) 진짜 상위다. 그 조건이 아니면
   * "상위"가 아닌 것을 상위라고 부르게 되므로 아예 그리지 않는다.
   * 막대 색은 그 패키지의 최고 EPSS 구간(vg_epss_tone) — 건수만이 아니라 "얼마나 급한지"도 같이 말한다. */
  /* '동일 집계' 행(kernel·kernel-core·kernel-debug…)을 그대로 그리면 길이가 똑같은 막대가
   * 8줄 깔려 순위가 아무것도 말하지 않는다(실측: 상위 8종이 전부 3,246건). 표가 이미
   * 계산해 둔 same_agg 로 대표 1종만 남긴다 — 새 집계 없이 그 플래그를 재사용한다. */
  $rankItems = [];
  if ($sort === 'cves' && $page === 1) {
      foreach ($rows as $r) {
          if (!empty($r['same_agg']) || (int) $r['cve_cnt'] <= 0) { continue; }
          $e = ($r['max_epss'] === null || $r['max_epss'] === '') ? 0.0 : (float) $r['max_epss'];
          $rankItems[] = [
              'label' => (string) $r['package_name']
                       . (!empty($r['ecosystem']) ? ' · ' . (string) $r['ecosystem'] : ''),
              'value' => (int) $r['cve_cnt'],
              'tone'  => $e > 0 ? vg_epss_tone($e) : 'info',
              'href'  => '/package.php?name=' . urlencode((string) $r['package_name'])
                       . '&eco=' . urlencode((string) $r['ecosystem']),
          ];
      }
  }
  // 막대 하나짜리 랭킹은 비교가 아니라 장식이다 — 2종 이상일 때만 그린다.
  if (count($rankItems) >= 2): ?>
    <div class="card">
      <strong>CVE 를 가장 많이 물고 있는 패키지</strong>
      <span class="why">— 현재 필터 기준 상위 · 막대 색은 그 패키지의 최고 EPSS 구간
        · 같은 소스에서 갈라진 바이너리(표의 '동일 집계')는 대표 1종만</span>
      <div class="card__body"><?php vg_rank_bars($rankItems, ['unit' => '건']); ?></div>
    </div>
  <?php endif; ?>

  <?php
  $hasFilter = $q !== '' || $eco !== '';
  vg_table(
      [
          ['label' => '패키지', 'width' => '30%', 'class' => 'col-id'],
          ['label' => '배포판', 'width' => '14%'],
          ['label' => 'CVE 수', 'align' => 'right', 'width' => '9%'],
          /* 같은 행에 막대가 둘(EPSS·조치율) 있는데 모양이 같아, 어느 막대가 무엇인지 화면에
           * 안 적혀 있었다. 열 머리글의 짧은 범례('title')로 각 막대가 무엇의 값인지 밝히고,
           * 칸 안에서도 막대 바로 위 글자가 그 막대를 가리키게 둔다. */
          ['label' => '최고 EPSS', 'align' => 'right', 'width' => '15%',
           'title' => '이 패키지의 CVE 중 가장 높은 악용 확률 — 막대 길이가 그 값입니다'],
          ['label' => '수정 버전 · 조치율', 'width' => '32%',
           'title' => '수정 버전이 확인된 CVE의 비율 — 막대 길이가 조치율입니다'],
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
              0 => fn($r) => '<a href="/package.php?name=' . urlencode((string)$r['package_name'])
                             . '&amp;eco=' . urlencode((string)$r['ecosystem']) . '">'
                             . vg_h((string) $r['package_name']) . '</a>'
                             . (!empty($r['same_agg'])
                                 // 라벨은 짧게 — 연속된 여러 행에 붙는 꼬리표라 길면 그 자체가 소음이 된다.
                                 ? ' ' . vg_badge('동일 집계', 'muted',
                                     '같은 소스 패키지에서 갈라진 바이너리라 CVE·EPSS·조치 수치가 앞 행과 같습니다')
                                 : ''),
              1 => fn($r) => !empty($r['ecosystem'])
                             ? vg_h((string) $r['ecosystem'])
                             : '<span class="why">–</span>',
              2 => fn($r) => number_format((int) $r['cve_cnt']),
              // 최고 EPSS: 텍스트("96.3%") 아래 게이지. 폭 = max_epss*100%.
              //   톤은 값 구간별(vg_epss_tone). 값 없으면 대시만(게이지 없음).
              3 => function ($r) {
                  $txt = vg_epss_cell($r['max_epss'], null);
                  if ($r['max_epss'] === null || $r['max_epss'] === '') {
                      return $txt;
                  }
                  $e = (float) $r['max_epss'];
                  return $txt . vg_meter(vg_epss_tone($e), $e * 100,
                      '최고 EPSS ' . number_format($e * 100, 1) . '% (악용 확률)');
              },
              /* 조치: max_fixed(있으면) + 조치율. 막대 바로 위 글자가 그 막대의 라벨이다.
               *   전건 조치(100%)는 **좋은 소식**이라 막대를 그리지 않고 ok 뱃지로 끝낸다 —
               *   예전엔 100% 도 다른 진행바와 같은 색 막대라 "다 됐다" 가 읽히지 않았다.
               *   cve_cnt=0 은 0 나눗셈 방지 + 비율 자체가 뜻이 없어 대시로 둔다. */
              4 => function ($r) {
                  $cve = (int) $r['cve_cnt'];
                  $fix = (int) $r['fix_cnt'];
                  $head = !empty($r['max_fixed'])
                      ? '<span class="pill">' . vg_h((string) $r['max_fixed']) . ' 이상</span> '
                      : '';
                  if ($cve <= 0) {
                      return $head . '<span class="why">–</span>';
                  }
                  $ratio = $fix / $cve;
                  if ($ratio >= 1.0) {
                      return $head . vg_badge('조치 완료 ' . $fix . '/' . $cve, 'ok',
                          '이 패키지의 CVE 전건에서 수정 버전이 확인됐습니다');
                  }
                  return $head
                       . '<span class="why">조치율 ' . number_format($ratio * 100, 1) . '%'
                       . ' (' . $fix . '/' . $cve . ')</span>'
                       . vg_meter('med', $ratio * 100,
                           '조치율 ' . number_format($ratio * 100, 1) . '% (수정 버전 확인 ' . $fix . '/' . $cve . ')');
              },
          ],
      ]
  );
  if ($rows) { vg_page_nav($total, $perPage, $page); }
  ?>

<?php endif; ?>
<?php vg_footer();
