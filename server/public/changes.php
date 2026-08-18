<?php
declare(strict_types=1);

/**
 * changes.php — 변화 추적(시계열). 로그인 필요(취약점 메뉴 권한 재사용).
 *   각 호스트의 "최근 2개 스캔"을 비교해 무엇이 달라졌는지 보여준다.
 *     - 신규   : 지난 스캔엔 없다가 이번에 생긴 취약점
 *     - 해결   : 지난 스캔엔 있었는데 이번에 사라진 것
 *     - 등급↑/↓: 양쪽에 있으나 심각도가 바뀐 것
 *   취약점 식별자는 (cve_id, package_name). 새 테이블 없이 tb_finding 만 대조한다.
 *
 *   이 파일은 요청 처리 · 활성 탭 결정 · 화면 머리(도식·탭 줄·필터) · 탭 디스패치만 갖는다.
 *   조회는 src/changes/queries.php, 셀 렌더는 src/changes/render.php, 탭 본문은
 *   src/changes/tabs/<탭>.php 다(활성 탭 것 하나만 읽는다).
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require_once __DIR__ . '/../src/audit.php';   // vg_log_activity — auth.php 가 이미 로드했을 수 있다
require_once __DIR__ . '/../src/distro.php'; // vg_osv_ecosystem — 패키지 상세 링크(vg_package_detail_link)
require_once __DIR__ . '/../src/finding_history.php'; // vg_finding_history_url — 행별 상세(판정 근거) 진입로
require_once __DIR__ . '/../src/changes/render.php';  // 표 셀·뱃지·탭 줄 (두 목록이 공유한다)
require_once __DIR__ . '/../src/changes/queries.php'; // 변화 대조 · 패키지 변경 · 추이 조회
require_once __DIR__ . '/../src/changes/tabs.php';    // vg_change_render_tab — 활성 탭 파일 하나만 require
vg_require_menu('findings');

$err = null;
$changes = [];
$summary = ['new' => 0, 'up' => 0, 'down' => 0, 'resolved' => 0];
$hostOptions = [];
$baselineHosts = [];   // 스캔이 1개뿐이라 비교 불가(첫 수집)

$hostId = (int) ($_GET['host'] ?? 0);
$type   = (string) ($_GET['type'] ?? '');
$q      = trim((string) ($_GET['q'] ?? ''));   // CVE·패키지명 부분일치 검색
$page   = vg_page();
$perPage = vg_perpage();
if (!isset(VG_CHANGE_TYPES[$type])) { $type = ''; }

// 회차별 추이 탭의 구간 선택. 'all' 은 무한정 불러오지 않도록 vg_ui_trend_limit() 로 상한을 건다.
$windowOptions = ['5' => '최근 5회차', '10' => '최근 10회차', 'all' => '전체 기간'];
$window = (string) ($_GET['window'] ?? '10');
if (!isset($windowOptions[$window])) { $window = '10'; }
$windowLimit = $window === 'all' ? vg_ui_trend_limit() : (int) $window;

// 취약점 변화 / 패키지 변경 / 추이 — 세 목록을 세로로 쌓지 않고 탭으로 가른다.
//   ?page= 는 활성 탭에만 적용된다(페이저가 하나만 살아 있게).
$tab = (string) ($_GET['tab'] ?? 'vuln');
if (!in_array($tab, ['vuln', 'pkg', 'trend'], true)) { $tab = 'vuln'; }

$pkgChanges = []; $pkgTotal = 0;
$trendRounds = []; $trendResolvedAll = [];
$trendSummary = ['new' => 0, 'up' => 0, 'down' => 0, 'resolved' => 0];
$trendNeedsHost = false;

try {
    $pdo = vg_pdo();

    // 패키지 변경 총 건수는 탭 뱃지에 늘 뜨므로 항상 센다. 목록은 그 탭일 때만 읽는다.
    $pkgTotal = vg_change_pkg_count($pdo, $hostId, $q);
    if ($tab === 'pkg') {
        $pkgChanges = vg_change_pkg_load($pdo, $hostId, $q, $perPage, ($page - 1) * $perPage);
    }

    $scans = vg_change_host_scans($pdo);
    $hostOptions = $scans['hostOptions'];

    $diff = vg_change_diff($pdo, $scans['perHost'], $hostId);
    $changes = $diff['changes'];
    $summary = $diff['summary'];
    $baselineHosts = $diff['baselineHosts'];

    if ($type !== '') {
        $changes = array_values(array_filter($changes, fn($c) => $c['type'] === $type));
    }
    if ($q !== '') {
        // CVE·패키지명 대소문자 무시 부분일치(둘 다 ASCII라 stripos 로 충분).
        $changes = array_values(array_filter(
            $changes,
            fn($c) => stripos($c['cve_id'], $q) !== false || stripos($c['package_name'], $q) !== false
        ));
    }

    // 추이 탭 — 호스트 전체 합산은 findings 자기조인급 비용이 나므로(queries.php 머리주석과
    // 같은 이유) 호스트를 선택했을 때만 계산한다. 전체는 안내 문구로 유도.
    if ($tab === 'trend') {
        if ($hostId <= 0 || !isset($hostOptions[$hostId])) {
            // 존재하지 않거나 삭제된 호스트 id 는 존재하는 것처럼 라벨을 만들지 않는다 — 그냥 미선택으로 취급.
            $trendNeedsHost = true;
        } else {
            $trendFqdn = $hostOptions[$hostId];
            $trendData = vg_trend_load($pdo, $hostId, $trendFqdn, $windowLimit);
            $trendRounds = $trendData['rounds'];
            $trendResolvedAll = $trendData['resolved'];
            $trendSummary = $trendData['summary'];
        }
    }

    /* 열람 감사 — 이 화면은 자산별 CVE·패키지 변경 이력을 보여준다. 같은 성격의
     *   nofix-packages.php 는 남기는데 여기만 빠져 있어서, "누가 어느 자산의 변화를 봤나"가
     *   기록되지 않았다. scope_id 는 비운다(scope 가 'PAGE' 인데 host_id 를 넣으면 페이지 id 로 읽힌다). */
    vg_log_activity($pdo, 'PAGE', null, 'view_changes', '변화 추적 조회',
        ['tab' => $tab, 'host_id' => $hostId, 'type' => $type, 'q' => $q]);
} catch (Throwable $e) {
    error_log('[changes] ' . $e->getMessage());
    $err = '처리 중 오류가 발생했습니다.';
}

vg_header('변화 추적', 'changes');
?>
  <?php vg_page_title('변화 추적', 'CHANGES'); ?>

  <?php /* 탐지 결과 계열의 갈래 — 정의는 nav.php 의 vg_findings_subtabs() 한 곳에만 있다.
           사이드바엔 '탐지 결과' 하나만 있고 이 화면은 이 줄로만 들어온다. */ ?>
  <?php vg_findings_subtabs('changes'); ?>


<?php if ($err !== null): ?>
  <?php vg_alert('오류 · ' . $err); ?>
<?php else: ?>

  <?php
  /* 두 단의 탭을 시각적으로 가른다 — 위 줄(.subtabs)은 화면 전환, 이 줄(.tabs/.pill)은
   * 이 화면 안의 갈래. 그리고 요약 KPI 는 두 탭 줄 **사이**에 두지 않는다(예전엔 거기 끼어
   * 있어서 "지금 어디에 있는지" 를 잃었다). KPI 는 '취약점 변화' 탭의 내용이라 그 탭 안으로
   * 내렸다 — 실제로 그 4개는 취약점 변화 목록의 type 필터이기도 하다. */
  $total = count($changes);
  vg_change_tabs([
      'vuln'  => ['label' => '취약점 변화', 'n' => $total],
      'pkg'   => ['label' => '패키지 변경', 'n' => $pkgTotal],
      'trend' => ['label' => '추이'],
  ], $tab);
  ?>

  <?php if ($tab === 'vuln'): ?>
    <?php
    /* 요약 KPI — '취약점 변화' 탭의 내용이다(다른 탭에선 뜻이 없다). 눌러서 그 변화유형만
     *   거른다(다시 누르면 풀린다). 0건이면 톤을 뺀다 — "신규 0건" 은 좋은 소식인데 붉은
     *   테두리가 붙으면 경고로 읽힌다.
     *   이 카드 줄과 아래 툴바는 **탭 본문보다 위**에 있어야 하므로(탭 파일로 내리면 필터
     *   아래로 밀려 순서가 바뀐다) 탭 파일이 아니라 여기 화면 머리에 남는다. */
    $changeTone = ['new' => 'crit', 'up' => 'high', 'down' => 'low', 'resolved' => 'ok'];
    ?>
    <div class="cards">
      <?php foreach (VG_CHANGE_TYPES as $k => $lbl): ?>
        <a class="kpi kpi--sm<?= $summary[$k] > 0 ? ' tone-' . vg_h($changeTone[$k]) : '' ?><?= $type === $k ? ' is-selected' : '' ?>"
           href="<?= vg_h(vg_qs(['type' => $type === $k ? '' : $k, 'tab' => 'vuln', 'page' => 1])) ?>">
          <b><?= number_format((int) $summary[$k]) ?></b><span><?= vg_h($lbl) ?></span>
        </a>
      <?php endforeach; ?>
    </div>
  <?php endif; ?>

  <?php
  // 변화유형 필터는 취약점 변화 탭에만, 구간 필터는 추이 탭에만 뜻이 있다.
  //   추이 탭엔 검색어(q)도 뜻이 없다 — 회차 전체를 보는 화면이라.
  $filters = [];
  $filters[] = ['type' => 'select', 'name' => 'host', 'selected' => (string) ($hostId ?: ''),
                'empty_label' => '전체 호스트', 'options' => $hostOptions];
  if ($tab === 'vuln') {
      $filters[] = ['type' => 'select', 'name' => 'type', 'selected' => $type,
                    'empty_label' => '전체 변화', 'options' => VG_CHANGE_TYPES];
  }
  if ($tab === 'trend') {
      $filters[] = ['type' => 'select', 'name' => 'window', 'selected' => $window,
                    'empty_label' => '최근 10회차(기본)', 'options' => $windowOptions];
  }
  if ($tab !== 'trend') {
      $filters[] = ['type' => 'search', 'name' => 'q', 'placeholder' => 'CVE·패키지명 검색', 'value' => $q];
  }
  $filters[] = ['type' => 'hidden', 'name' => 'tab', 'value' => $tab];
  vg_toolbar($filters);

  if ($baselineHosts) {
      // 호스트 수가 많으면(운영에서 실측 50+대) 한 줄 텍스트로는 화면을 다 차지한다 —
      // findings.php 의 "판정 불가" 목록과 같은 컴포넌트(.hint-list, 스크롤 캡)를 재사용한다.
      echo '<div class="sub">기준선(첫 수집이라 비교 대상 없음)</div>';
      echo '<ul class="hint-list">';
      foreach ($baselineHosts as $bh) { echo '<li>' . vg_h($bh) . '</li>'; }
      echo '</ul>';
  }

  // 활성 탭 하나만 그린다. 탭 파일은 전역을 주워 쓰지 않고 아래 열거한 값만 받는다.
  vg_change_render_tab($tab, [
      'pdo' => $pdo, 'err' => $err, 'page' => $page, 'perPage' => $perPage,
      'changes' => $changes, 'total' => $total, 'type' => $type, 'hostId' => $hostId, 'q' => $q,
      'pkgChanges' => $pkgChanges, 'pkgTotal' => $pkgTotal,
      'trendNeedsHost' => $trendNeedsHost, 'trendRounds' => $trendRounds,
      'trendResolvedAll' => $trendResolvedAll, 'trendSummary' => $trendSummary,
  ]);
  ?>
<?php endif; ?>
<?php vg_footer();
