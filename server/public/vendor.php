<?php
declare(strict_types=1);

/**
 * vendor.php — 배포판 벤더 판정 조회. 커넥터 5종(debtracker·rhoval·rhunfixed·ubuntuoval·kcve)이
 *   모아 둔 "벤더가 이 CVE 를 뭐라 했나" 의 원본을 사람이 볼 수 있게 한다.
 *   로그인 필요(취약점 메뉴 권한 재사용 — packages.php 와 같은 이유).
 *
 *   지금까지 이 데이터는 matcher.php 가 백포트 오탐을 억제하는 데만 쓰였다. 그래서 억제가
 *   의심스러울 때 "벤더가 정말 이 버전에서 고쳤다고 했나" 를 확인하려면 DB 에 직접 붙어야 했다.
 *
 *   소스별로 5페이지를 만들지 않고 **한 화면 + 소스 필터**다. 5개 테이블이 사실상 같은 모양
 *   (벤더/릴리스 + 패키지 + CVE + 고친버전 + 상태)이라 공통 컬럼으로 접히고, "이 CVE 를
 *   벤더들이 각각 뭐라 했나" 를 나란히 비교하는 게 이 페이지의 존재 이유다.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
// view.php 가 format.php 를 이미 require 하지만, VG_VENDOR_SEV_TONE 정의가
// VG_TONE_SEV(format.php) 를 직접 참조하므로 이 파일 스스로도 로드 순서를 보장해 둔다.
require_once __DIR__ . '/../src/format.php';
vg_require_menu('findings');

/**
 * 소스별 SELECT — 공통 컬럼(src·vendor·rel·pkg·cve_id·fixed·state·note)으로 접는다.
 * 다른 건 컬럼명·릴리스 축·소프트삭제 유무뿐이라, 추상 레이어를 두지 않고 여기 나란히 적는다.
 *
 *   'cve'/'rel'/'pkg' 는 WHERE 에 쓸 컬럼 표현식(kcve 만 JOIN 이라 별칭이 붙는다),
 *   'soft' 는 소프트삭제 컬럼 유무(커널 두 테이블엔 없다),
 *   'cols' 는 UNION 컬럼 순서·이름을 맞춘 SELECT 목록이다 — 다섯 갈래가 정확히 같아야 한다.
 *
 *   cve.php 의 VG_CVE_VENDOR_SRC 가 같은 테이블·컬럼을 이 CVE 하나로 좁혀 복제한다
 *   (의도적 중복 — cve.php 쪽 주석 참고). 여기 스키마를 바꾸면 그쪽도 같이 고칠 것.
 */
const VG_VENDOR_SRC = [
    'debtracker' => [
        'label' => '데비안 보안 트래커',
        'desc'  => '이 데비안 빌드가 아직도 취약한가 · 고칠 수는 있나',
        'from'  => 'tb_debian_tracker',
        'cve'   => 'cve_id',
        'rel'   => 'release_codename',
        'pkg'   => 'pkg_name',
        'soft'  => true,
        'cols'  => "'debtracker' AS src, 'debian' AS vendor, release_codename AS rel, pkg_name AS pkg,"
                 . " cve_id, fixed_version AS fixed,"
                 . " IF(has_fix = 1, '수정본 있음', '수정본 없음') AS state, urgency AS note,"
                 . " other_versions AS extra1, is_binary AS extra2",
    ],
    'rhoval' => [
        'label' => 'RHEL 계열 벤더 권고(OVAL)',
        'desc'  => '이 CVE 는 어느 EVR 에서 고쳐졌나',
        'from'  => 'tb_vendor_errata',
        'cve'   => 'cve_id',
        'rel'   => 'release_major',
        'pkg'   => 'pkg_name',
        'soft'  => true,
        'cols'  => "'rhoval' AS src, vendor, release_major AS rel, pkg_name AS pkg,"
                 . " cve_id, fixed_evr AS fixed, severity AS state, advisory AS note,"
                 . " NULL AS extra1, NULL AS extra2",
    ],
    'rhunfixed' => [
        'label' => 'Red Hat 미수정 CVE(조치 불가)',
        'desc'  => '벤더가 고칠 생각이 있는가 — 수정본이 없는 CVE',
        'from'  => 'tb_vendor_unfixed',
        'cve'   => 'cve_id',
        'rel'   => 'release_major',
        // 판정 단위가 바이너리 패키지가 아니라 컴포넌트(소스 패키지)다 — Red Hat 이 bzip2 로
        //   상태를 매기면 우리가 설치된 바이너리(bzip2-libs …)에 펼친다.
        'pkg'   => 'component',
        'soft'  => true,
        'cols'  => "'rhunfixed' AS src, vendor, release_major AS rel, component AS pkg,"
                 . " cve_id, NULL AS fixed, fix_state AS state, severity AS note,"
                 . " cvss AS extra1, checked_at AS extra2",
    ],
    'ubuntuoval' => [
        'label' => '우분투 보안 OVAL',
        'desc'  => '우분투가 고쳤나 · 고칠 수는 있나',
        'from'  => 'tb_ubuntu_oval',
        'cve'   => 'cve_id',
        'rel'   => 'release_codename',
        'pkg'   => 'pkg_name',
        'soft'  => true,
        'cols'  => "'ubuntuoval' AS src, 'ubuntu' AS vendor, release_codename AS rel, pkg_name AS pkg,"
                 . " cve_id, fixed_evr AS fixed, severity AS state, NULL AS note,"
                 . " NULL AS extra1, NULL AS extra2",
    ],
    'kcve' => [
        'label' => '리눅스 커널 CNA(kernel.org)',
        'desc'  => '이 커널 버전에 수정본이 들어 있나',
        // stream 별 수정 버전은 fixes 에, 메인라인 축(도입·수정)은 cves 에 있다 → JOIN 해야 한 줄이 된다.
        'from'  => 'tb_kernel_cve_fixes f JOIN tb_kernel_cves k ON k.cve_id = f.cve_id',
        'cve'   => 'f.cve_id',
        'rel'   => 'f.stream',
        'pkg'   => "'linux'",
        'soft'  => false,   // 커널 두 테이블엔 소프트삭제 컬럼이 없다(스키마 확인함).
        'cols'  => "'kcve' AS src, 'kernel' AS vendor, f.stream AS rel, 'linux' AS pkg,"
                 . " f.cve_id AS cve_id, f.fixed_version AS fixed,"
                 . " k.mainline_fixed AS state, k.introduced_version AS note,"
                 . " NULL AS extra1, NULL AS extra2",
    ],
];

// 벤더마다 심각도 어휘가 다르다(Red Hat: Important/Moderate · 우분투: high/negligible · 데비안 urgency).
//   CRITICAL/HIGH/MEDIUM/LOW 는 format.php 의 VG_TONE_SEV(공용 단일 소스)를 그대로 쓰고,
//   벤더 고유 어휘만 여기서 얹는다. 톤은 app.css 에 실제 있는 것만. 모르는 값은 muted 로 떨어진다.
const VG_VENDOR_SEV_TONE = VG_TONE_SEV + [
    'IMPORTANT' => 'high', 'MODERATE' => 'med',
    'NEGLIGIBLE' => 'muted', 'UNKNOWN' => 'muted', 'UNTRIAGED' => 'muted',
];

// Red Hat 조치 상태 — "지금 할 수 있는 일이 없다" 가 얼마나 확정적인지로 톤을 가른다.
const VG_VENDOR_FIXSTATE_TONE = [
    'Will not fix'         => 'danger',
    'Out of support scope' => 'muted',
    'Fix deferred'         => 'warn',
    'Under investigation'  => 'info',
    'Affected'             => 'warn',
    'Not affected'         => 'ok',
];

/** 벤더 심각도 문자열 → 톤 뱃지. 값이 없으면 빈 문자열(호출부가 대시를 찍는다). */
function vg_vendor_sev_badge(?string $sev): string {
    $sev = trim((string) $sev);
    if ($sev === '') { return ''; }
    return vg_badge($sev, VG_VENDOR_SEV_TONE[mb_strtoupper($sev)] ?? 'muted');
}

/**
 * 접두 일치 LIKE 패턴. 사용자가 넣은 %·_ 는 와일드카드가 아니라 글자로 다룬다.
 *   접두(`x%`)만 쓰는 이유: 부분일치(`%x%`)는 인덱스를 못 타 51만 행(rhoval)·43만 행(ubuntuoval)
 *   풀스캔이 된다. 접두 일치는 새 인덱스(is_deleted, cve_id, pkg_name)의 pkg_name 자리에서
 *   원본 조회 없이 걸러지고, CVE·릴리스 필터와 같이 쓰면 범위가 더 좁아진다.
 */
function vg_like_prefix(string $s): string {
    return addcslashes($s, '\\%_') . '%';
}

/**
 * 한 소스 갈래의 WHERE 절. $params 에 바인딩 값을 순서대로 쌓는다.
 *   $q 는 CVE 든 패키지든 하나만 넣으면 매칭되도록 (cve_id LIKE ? OR pkg_name LIKE ?) 로 OR 매칭한다.
 *   두 갈래 다 접두(prefix) LIKE 를 유지 — idx_*_cve(cve_id, pkg_name, is_deleted, release_*) 가
 *   cve_id 를 선두로 둔 커버링 인덱스라, OR 라도 원본 조회 없이 인덱스만 훑는다(부분일치로 바꾸면
 *   이 인덱스를 못 타 51만~78만행 풀스캔이 된다 — 절대 %x% 로 바꾸지 말 것).
 */
function vg_vendor_where(array $def, string $q, string $rel, array &$params): string {
    $w = [];
    if ($def['soft']) { $w[] = 'is_deleted = 0'; }
    if ($q !== '') {
        $like = vg_like_prefix($q);
        $w[] = '(' . $def['cve'] . ' LIKE ? OR ' . $def['pkg'] . ' LIKE ?)';
        $params[] = $like;
        $params[] = $like;
    }
    if ($rel !== '')  { $w[] = $def['rel'] . ' = ?';    $params[] = $rel; }
    return $w ? implode(' AND ', $w) : '1=1';
}

$err = null; $rows = []; $total = 0; $relOptions = [];

$q   = trim((string) ($_GET['q'] ?? ''));
$rel = trim((string) ($_GET['rel'] ?? ''));
$src = (string) ($_GET['src'] ?? '');
$page = vg_page();
$perPage = vg_perpage();

// 소스는 화이트리스트. 사용자 입력이 SQL(테이블명·컬럼명)에 그대로 들어가는 자리라 필수다.
if (!isset(VG_VENDOR_SRC[$src])) { $src = ''; }
$active = $src !== '' ? [$src => VG_VENDOR_SRC[$src]] : VG_VENDOR_SRC;

try {
    $pdo = vg_pdo();

    // 릴리스 옵션. 소스마다 릴리스 축이 달라(코드명·메이저·stream) 한 목록으로 합친다.
    //   is_deleted 를 걸지 않는다 — 릴리스 컬럼이 선두인 인덱스엔 is_deleted 가 없어서, 필터를
    //   붙이는 순간 느슨한 인덱스 스캔(값 목록만 훑기)이 깨지고 78만 행에 행별 원본 조회가 붙는다.
    //   이 목록은 필터 선택지일 뿐이고, 이 테이블들은 커넥터가 upsert 만 해 소프트삭제되지 않는다.
    //   (혹시 삭제된 행의 릴리스가 섞여도 고르면 빈 목록이 나올 뿐이라 오답을 만들지 않는다.)
    $relOptions = $pdo->query(
        "SELECT DISTINCT release_codename AS rel FROM tb_debian_tracker
          UNION SELECT DISTINCT release_major FROM tb_vendor_errata
          UNION SELECT DISTINCT release_major FROM tb_vendor_unfixed
          UNION SELECT DISTINCT release_codename FROM tb_ubuntu_oval
          UNION SELECT DISTINCT stream FROM tb_kernel_cve_fixes
          ORDER BY rel"
    )->fetchAll(PDO::FETCH_COLUMN);
    $relOptions = array_combine($relOptions, $relOptions) ?: [];
    if ($rel !== '' && !isset($relOptions[$rel])) { $rel = ''; }

    // 건수는 SQL 로 따로 센다. 전량을 PHP 배열에 올렸다가 운영에서 512MB 를 넘겨 죽은 이력이
    //   있는 테이블들이다(src/debtracker.php:70-72 · src/vendorerrata.php:199-201).
    //   COUNT 는 조기 종료가 없어(전건을 세야 한다) 이 페이지에서 제일 무거운 질의다. 그래서
    //   새 인덱스가 필터 컬럼(is_deleted·release_*)까지 담아 **인덱스만 읽고** 끝나게 했다 —
    //   원본을 행마다 뒤지지 않는다(실측 55만 행: 풀 테이블 스캔 3.23초 → 커버링 0.34초).
    $countParts = []; $countParams = [];
    foreach ($active as $def) {
        $where = vg_vendor_where($def, $q, $rel, $countParams);
        $countParts[] = "SELECT COUNT(*) AS n FROM {$def['from']} WHERE $where";
    }
    $stmt = $pdo->prepare('SELECT SUM(n) FROM (' . implode(' UNION ALL ', $countParts) . ') c');
    $stmt->execute($countParams);
    $total = (int) $stmt->fetchColumn();

    // 소스별 요약 카드용 건수 — 무필터 진입 시 55만+ 행이 뒤섞여 막막한 문제의 진입점(작업 3).
    //   src 선택과 무관하게 5종 전부 세되, q·rel 필터는 그대로 반영한다(N=5, COUNT 쿼리라 가볍다).
    $srcCounts = [];
    foreach (VG_VENDOR_SRC as $srcKey => $srcDef) {
        $srcCountParams = [];
        $srcWhere = vg_vendor_where($srcDef, $q, $rel, $srcCountParams);
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM {$srcDef['from']} WHERE $srcWhere");
        $stmt->execute($srcCountParams);
        $srcCounts[$srcKey] = (int) $stmt->fetchColumn();
    }

    $offset = ($page - 1) * $perPage;

    // 갈래마다 **자기 LIMIT 을 먼저 건다.** UNION 결과를 통째로 만들어 놓고 바깥에서 정렬·자르면
    //   100만 행이 임시테이블로 흘러든다(PHP 배열에 올리는 것과 같은 함정 — 자리만 SQL 로 옮긴
    //   것뿐이다). 각 갈래가 바깥과 **같은 순서로** 자기 상위 (offset+perPage) 건만 내놓으면,
    //   전체 상위 (offset+perPage) 건은 반드시 그 안에 있다 — 어느 갈래에서 잘려나간 행은 그
    //   갈래 안에만 이미 그만큼의 행이 앞서 있다는 뜻이라 전체 순위에도 못 든다.
    //   그래서 읽는 양이 5 × (offset+perPage) 로 묶인다.
    //   정렬 키: 갈래 안에선 (cve_id DESC, pkg DESC) — src 는 갈래마다 상수라 바깥 키와 일치한다.
    //   두 컬럼 다 DESC 인 건 취향이 아니라 인덱스 때문이다: 방향이 섞이면(DESC, ASC) 새 인덱스
    //   (cve_id, pkg_name, …)를 거꾸로 훑을 수 없어 filesort 가 붙는다 — LIMIT 이 있어도
    //   정렬 전에 조건에 맞는 행을 전부 읽어야 한다. 방향을 맞추면 역방향 스캔으로 10행만 읽는다
    //   (실측 EXPLAIN: Backward index scan · Using index · rows 10).
    $cap = $offset + $perPage;
    $listParts = []; $listParams = [];
    foreach ($active as $def) {
        $where = vg_vendor_where($def, $q, $rel, $listParams);
        $listParts[] = "(SELECT {$def['cols']} FROM {$def['from']} WHERE $where"
                     . " ORDER BY {$def['cve']} DESC, {$def['pkg']} DESC LIMIT $cap)";
    }
    $stmt = $pdo->prepare(
        'SELECT * FROM (' . implode(' UNION ALL ', $listParts) . ') v'
        . " ORDER BY cve_id DESC, src ASC, pkg DESC LIMIT $perPage OFFSET $offset"
    );
    $stmt->execute($listParams);
    $rows = $stmt->fetchAll();
} catch (Throwable $e) {
    error_log('[vendor] ' . $e->getMessage());
    $err = '처리 중 오류가 발생했습니다.';
}

vg_header('벤더 판정', 'vendor');
?>
  <h1>벤더 판정 <span class="hint">(<?= number_format($total) ?>건)</span></h1>
  <div class="sub"><span class="why">— 벤더별 패치 여부 원본 · 백포트 오탐 억제·조치불가 판정 근거</span></div>

<?php if ($err !== null): ?>
  <?php vg_alert('오류 · ' . $err); ?>
<?php else: ?>
  <?php
  // 소스별 진입점(작업 3) — 무필터로 들어왔을 때 5개 소스가 뒤섞인 채 페이지네이션만으로
  //   넘겨야 하는 막막함을 줄인다. 필터 프리셋 탭(cves.php)과 같은 .tabs/.pill 을 그대로 쓴다.
  echo '<div class="tabs">';
  foreach (VG_VENDOR_SRC as $k => $d) {
      $on = $src === $k;
      echo '<a class="pill' . ($on ? ' pill--on' : '') . '" href="/vendor.php' . vg_qs(['src' => $k, 'page' => null])
         . '" title="' . vg_h($d['desc']) . '">' . vg_h($d['label'])
         . ' <span class="why">' . number_format($srcCounts[$k]) . '건</span></a>';
  }
  echo '</div>';

  $srcOptions = [];
  foreach (VG_VENDOR_SRC as $k => $d) { $srcOptions[$k] = $d['label']; }
  vg_toolbar([
      ['type' => 'select', 'name' => 'src', 'selected' => $src, 'empty_label' => '소스 전체',
       'options' => $srcOptions],
      ['type' => 'search', 'name' => 'q', 'placeholder' => 'CVE 또는 패키지 검색 (예: CVE-2024, openssl)', 'value' => $q],
      ['type' => 'select', 'name' => 'rel', 'selected' => $rel, 'empty_label' => '릴리스 전체',
       'options' => $relOptions],
  ]);

  $hasFilter = $q !== '' || $rel !== '' || $src !== '';
  vg_table(
      [
          ['label' => '소스', 'width' => '11rem'],
          ['label' => '벤더/릴리스', 'width' => '12rem'],
          ['label' => '패키지', 'width' => '14rem'],
          ['label' => 'CVE', 'width' => '11rem', 'nowrap' => true],
          ['label' => '고친 버전', 'width' => '16rem'],
          ['label' => '상태'],
      ],
      $rows,
      [
          'empty' => $hasFilter
              ? [
                  'icon'  => '🔍',
                  'title' => '조건에 맞는 벤더 판정이 없습니다.',
                  'hint'  => 'CVE·패키지 모두 앞부분만 일치합니다(openssl → openssl-libs). 소스·릴리스 조합도 확인해 보세요.',
                  'cta'   => ['href' => '/vendor.php', 'label' => '필터 초기화'],
              ]
              : [
                  'icon'  => '🏷️',
                  'title' => '아직 수집된 벤더 판정이 없습니다.',
                  'hint'  => '벤더 판정 커넥터 5종(데비안 트래커·RHEL OVAL·Red Hat 미수정·우분투 OVAL·커널 CNA)이 한 번은 돌아야 합니다.',
                  'cta'   => ['href' => '/connectors.php', 'label' => '피드 커넥터로 이동'],
              ],
          'cell' => [
              0 => function ($r) {
                  $d = VG_VENDOR_SRC[$r['src']] ?? null;
                  return '<span class="pill" title="' . vg_h($d !== null ? $d['label'] . ' — ' . $d['desc'] : '')
                       . '">' . vg_h((string) $r['src']) . '</span>';
              },
              1 => fn($r) => vg_h((string) $r['vendor']) . '<span class="why">/</span>' . vg_h((string) $r['rel']),
              // 패키지명 → 취약점 현황에서 그 패키지만 걸러 본다(packages.php 와 같은 연결).
              2 => fn($r) => '<a href="/findings.php?q=' . urlencode((string) $r['pkg']) . '">'
                             . vg_trunc((string) $r['pkg'], 32) . '</a>',
              // cve.php 가 '/^CVE-\d{4}-\d+$/i' 아니면 오류로 튕긴다(정상 동작). 데비안 트래커의
              //   TEMP-<날짜>-<해시> 같은 정식 CVE 미배정 식별자는 링크 없이 텍스트로만 보여준다.
              //   이 컬럼은 5개 소스가 섞인 결과라, debtracker 가 아닌 소스에서 비정형 식별자가
              //   와도 "데비안" 이라고 단정하지 않도록 소스별로 문구를 나눈다.
              3 => function ($r) {
                  // 커넥터가 넣은 원본에 앞뒤 공백·개행이 섞이면 앵커 매칭이 실패해 멀쩡한 CVE 도
                  //   임시 식별자 취급을 받는다 — 판정·출력 모두 trim() 한 값을 쓴다.
                  $cveId = trim((string) $r['cve_id']);
                  if (preg_match('/^CVE-\d{4}-\d+$/i', $cveId)) {
                      $out = '<a href="/cve.php?cve=' . urlencode($cveId) . '">' . vg_h($cveId) . '</a>';
                      // 벤더 원문 링크는 여기 debtracker·ubuntuoval 만 반영한다 — rhoval 은 advisory 가
                      //   있는 상태 셀(cell 5)에서, rhunfixed 도 advisory 가 없어 cell 5 에서 다룬다.
                      if (in_array($r['src'], ['debtracker', 'ubuntuoval'], true)) {
                          $extUrl = vg_vendor_cve_url((string) $r['src'], $cveId);
                          if ($extUrl !== null) {
                              $out .= ' <a class="why" href="' . vg_h($extUrl) . '" target="_blank" rel="noopener" title="벤더 공식 페이지에서 보기">↗</a>';
                          }
                      }
                      return $out;
                  }
                  $tip = $r['src'] === 'debtracker'
                      ? '데비안 보안 트래커 임시 식별자(정식 CVE 미배정)'
                      : '정식 CVE 가 배정되지 않은 벤더 자체 식별자';
                  // .why 는 이 파일에서 "부가·희미한 보조 텍스트"(벤더/릴리스 구분자, 상태 뱃지 부연
                  //   설명 등) 용도라, 값 자체가 유효한 식별자인 여기엔 안 맞는다 — 클래스 없이 title 만.
                  // 컬럼 폭이 nowrap 11rem 이고 TEMP-<날짜>-<해시> 는 20자를 넘기는 게 흔해
                  //   그대로 두면 표를 가로로 밀어낸다(2번 컬럼의 vg_trunc(...,32) 와 같은 이유).
                  //   vg_trunc() 는 잘릴 때 자체 title 을 붙이는데, 그러면 이 tip 설명을 감싼 title
                  //   과 중첩돼 안쪽 것에 덮인다 — 그래서 직접 잘라 tip+원문을 하나의 title 로 합친다.
                  $full = $tip . ' · ' . $cveId;
                  return '<span title="' . vg_h($full) . '">' . vg_h(mb_strimwidth($cveId, 0, 16, '…')) . '</span>';
              },
              // 고친 버전. rhunfixed 는 **고친 버전이 없는 게 핵심**이라(수정본 자체가 없다)
              //   그 자리에 조치 상태를 뱃지로 둔다 — 이게 "조치 불가" 의 근거다.
              4 => function ($r) {
                  if ($r['src'] === 'rhunfixed') {
                      $st = (string) $r['state'];
                      return vg_badge($st, VG_VENDOR_FIXSTATE_TONE[$st] ?? 'warn', '벤더 조치 상태 · 수정본 없음');
                  }
                  // 데비안은 목록엔 없는 필드(예외 버전·바이너리 여부)가 있다(작업 2) — title 로 노출.
                  $tip = '';
                  if ($r['src'] === 'debtracker') {
                      $tipParts = [((int) $r['extra2']) === 1 ? '바이너리 패키지' : '소스 패키지'];
                      $ov = trim((string) ($r['extra1'] ?? ''));
                      if ($ov !== '') { $tipParts[] = '예외 버전 ' . $ov; }
                      $tip = implode(' · ', $tipParts);
                  }
                  $tipAttr = $tip !== '' ? ' title="' . vg_h($tip) . '"' : '';
                  if (empty($r['fixed'])) {
                      return '<span class="why"' . $tipAttr . '>수정본 없음</span>';
                  }
                  return '<span class="pill"' . $tipAttr . '>' . vg_h((string) $r['fixed']) . '</span>';
              },
              // 상태 — 소스마다 답의 성격이 다르다. 억지로 한 어휘로 접지 않고 각자의 말을 보여준다.
              5 => function ($r) {
                  $state = (string) ($r['state'] ?? '');
                  $note  = (string) ($r['note'] ?? '');
                  switch ($r['src']) {
                      case 'debtracker':
                          // has_fix — 수정본이 나왔는지. urgency 는 데비안이 매긴 긴급도.
                          $out = vg_badge($state, $state === '수정본 있음' ? 'ok' : 'warn');
                          return $note !== '' ? $out . ' <span class="why">긴급도 ' . vg_h($note) . '</span>' : $out;
                      case 'rhoval':
                          $out = vg_vendor_sev_badge($state);
                          if ($note !== '') {
                              // note 는 advisory(RHSA-2024:1234 등) — 레드햇·알마리눅스만 원문 URL 을 안다(작업 1).
                              $advUrl = vg_vendor_advisory_url((string) $r['vendor'], $note, (string) $r['rel']);
                              $out .= $advUrl !== null
                                  ? ' <a class="why" href="' . vg_h($advUrl) . '" target="_blank" rel="noopener">' . vg_h($note) . '</a>'
                                  : ' <span class="why">' . vg_h($note) . '</span>';
                          }
                          return $out !== '' ? $out : '<span class="why">–</span>';
                      case 'rhunfixed':
                          // 조치 상태는 고친버전 칸이 이미 말한다 → 여기는 심각도 + CVE 원문.
                          $out = vg_vendor_sev_badge($note);
                          $tipParts = [];
                          $cvss = trim((string) ($r['extra1'] ?? ''));
                          if ($cvss !== '') { $tipParts[] = 'CVSS ' . $cvss; }
                          $checkedAt = trim((string) ($r['extra2'] ?? ''));
                          if ($checkedAt !== '') { $tipParts[] = '확인일 ' . substr($checkedAt, 0, 10); }
                          $tip = implode(' · ', $tipParts);
                          $cveUrl = vg_vendor_cve_url('rhunfixed', trim((string) $r['cve_id']));
                          if ($cveUrl !== null) {
                              $out .= ($out !== '' ? ' ' : '') . '<a class="why" href="' . vg_h($cveUrl) . '" target="_blank" rel="noopener"'
                                    . ($tip !== '' ? ' title="' . vg_h($tip) . '"' : '') . '>CVE 확인 ↗</a>';
                          } elseif ($tip !== '') {
                              $out .= ($out !== '' ? ' ' : '') . '<span class="why" title="' . vg_h($tip) . '">ⓘ</span>';
                          }
                          return $out !== '' ? $out : '<span class="why">–</span>';
                      case 'kcve':
                          // 스트림별 수정본(고친 버전 칸)의 부가 정보 — 메인라인 축.
                          $parts = [];
                          if ($note !== '')  { $parts[] = '도입 ' . $note; }
                          if ($state !== '') { $parts[] = '메인라인 ' . $state; }
                          return $parts
                              ? '<span class="why">' . vg_h(implode(' · ', $parts)) . '</span>'
                              : '<span class="why">–</span>';
                      default:   // ubuntuoval
                          $out = vg_vendor_sev_badge($state);
                          return $out !== '' ? $out : '<span class="why">–</span>';
                  }
              },
          ],
      ]
  );
  if ($rows) { vg_page_nav($total, $perPage, $page); }
  ?>
<?php endif; ?>
<?php vg_footer();
