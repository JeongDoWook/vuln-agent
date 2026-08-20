<?php
declare(strict_types=1);

/**
 * depgraph.php — 패키지 의존성 그래프(무엇이 이 패키지를 끌어왔나). 로그인 필요.
 *   ?id=<host_id>            자산의 최신 스캔 기준
 *   &cid=<container_id>      0=호스트 자신, 양수=그 컨테이너 (엣지가 있는 단위만 선택지에 뜬다)
 *   &mgr=&name=&ver=         대상 패키지를 지정하면 역추적/정방향 탭이 열린다
 *   &tab=from|to|tree        &page=&per_page= 는 전체 트리의 루트 페이지네이션
 *
 * ── 이 화면이 답하는 것 ──────────────────────────────────────────────────
 *   에이전트가 보내온 SBOM(CycloneDX dependencies)·pom.xml 직접선언 엣지는 지금까지
 *   저장만 되고 읽는 화면이 없었다. 취약한 라이브러리가 나왔을 때 실무에서 먼저 묻는 건
 *   "이건 왜 깔려 있나(누가 끌어왔나)" 인데, 설치 패키지 목록으로는 답이 안 나온다.
 *
 *   조회 단위가 (스캔 × 컨테이너)인 이유: tb_package_dependency 의 유니크 키
 *   uk_pkg_dep_edge 좌측 접두가 (scan_id, container_id)라 이 둘로 좁혀야 인덱스를 탄다.
 *   패키지명만으로 전역 검색하면 인덱스가 없어 풀스캔이 된다 — 그래서 패키지 카탈로그
 *   화면(package.php)이 아니라 자산 상세(host.php)에서 들어온다. 심각도 조회도 같은
 *   단위로 좁힌다(vg_deptree_severity) — 이 화면은 조회 범위를 넓히지 않는다.
 *
 * ── 그림은 이 파일이 갖고 있지 않다 ──────────────────────────────────────
 *   중첩 박스(카드 안의 카드)로 그리던 것을 **가로 계층 트리**로 바꿨다. 깊이가 3단만
 *   넘어가도 무엇이 무엇에 매달렸는지 안 보이고 화면 폭을 계단식으로 먹었다.
 *   그 트리의 배치·SVG 출력은 **src/deptree.php** 가 소유한다 — 자산 상세의 '의존성' 탭이
 *   같은 그림을 그리므로, 복사해 두면 한쪽만 고쳐진 채로 갈라진다(DRY).
 *   이 파일에 남는 것은 이 화면만의 것뿐이다: 조회 단위 선택·대상 패키지 역추적 탭·
 *   루트 페이지네이션·pom 직접선언 목록.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require_once __DIR__ . '/../src/audit.php';       // vg_log_activity
require_once __DIR__ . '/../src/packagedep.php';  // 조회·그래프 조립
require_once __DIR__ . '/../src/deptree.php';     // 트리 배치·SVG 렌더(자산 상세 '의존성' 탭과 공유)
vg_require_menu_any('assets', 'findings');   // 의존성 그래프: 자산 상세에서만 들어온다(자산 상세와 같은 범위)

$hostId = (int) ($_GET['id'] ?? 0);
$cid    = isset($_GET['cid']) ? (int) $_GET['cid'] : -1;
$mgr    = trim((string) ($_GET['mgr'] ?? ''));
$pkg    = trim((string) ($_GET['name'] ?? ''));
$ver    = trim((string) ($_GET['ver'] ?? ''));
$tab    = (string) ($_GET['tab'] ?? '');

$err = null;
$host = null;
$scan = null;
$groups = [];          // [container_id => ['edges'=>n,'label'=>…]]
$graph = null;
$load = ['edges' => [], 'loaded' => 0, 'truncated' => false];
$target = '';          // 대상 패키지 키(지정됐고 그래프에 있을 때만)
$targetMissing = false;
$sevOf = [];           // 노드 키 => 최고 심각도(CRITICAL…LOW)

try {
    $pdo = vg_pdo();
    $st = $pdo->prepare('SELECT host_id, fqdn FROM tb_host WHERE host_id = ? AND is_deleted = 0');
    $st->execute([$hostId]);
    $host = $st->fetch() ?: null;

    if ($host) {
        $st = $pdo->prepare('SELECT scan_id, collected_at FROM tb_scan WHERE host_id = ? ORDER BY scan_id DESC LIMIT 1');
        $st->execute([$hostId]);
        $scan = $st->fetch() ?: null;
    }

    if ($scan) {
        $scanId = (int) $scan['scan_id'];
        $groups = vg_pkgdep_containers($pdo, $scanId);
        // 요청한 단위에 엣지가 없으면(북마크·직접입력) 엣지가 있는 첫 단위로 떨군다.
        if (!isset($groups[$cid])) { $cid = $groups ? (int) array_key_first($groups) : 0; }

        if ($groups) {
            $load  = vg_pkgdep_load($pdo, $scanId, $cid);
            $graph = vg_pkgdep_build($load['edges']);
            $sevOf = vg_deptree_severity($pdo, $scanId, $cid, $graph);

            if ($mgr !== '' && $pkg !== '' && $ver !== '') {
                $key = vg_pkgdep_key($mgr, $pkg, $ver);
                if (isset($graph['nodes'][$key])) { $target = $key; } else { $targetMissing = true; }
            }
        }

        // 열람 감사 — 어느 자산의 의존성 구조를 누가 봤는지가 이 화면의 감사 포인트다.
        vg_log_activity($pdo, 'HOST', $hostId, 'view_depgraph',
            '패키지 의존성 그래프 열람: ' . (string) ($host['fqdn'] ?? ''),
            ['container_id' => $cid, 'edges' => $load['loaded'], 'package' => $target],
            subject: (string) ($host['fqdn'] ?? ''), action: 'READ');
    }
} catch (Throwable $e) {
    error_log('[depgraph] ' . $e->getMessage());
    $err = '의존성 그래프를 불러오는 중 오류가 발생했습니다.';
}

// 탭은 대상 패키지가 있을 때만 갈래가 생긴다. 화이트리스트 밖 값은 기본으로 떨군다.
$tabs = $target !== '' ? ['from', 'to', 'tree'] : ['tree'];
if (!in_array($tab, $tabs, true)) { $tab = $tabs[0]; }

/** 이 화면의 링크 조립 — 자산 상세의 '의존성' 탭도 같은 URL 을 만드므로 정본은 deptree.php 다. */
$linkFor = function (array $over) use ($hostId, $cid): string {
    return vg_deptree_url($hostId, $cid, $over);
};
// $graph['roots'] 를 노드마다 in_array() 로 선형 탐색하면 O(N·R) 이 된다(목록 라벨·트리 노드
// 양쪽에서 노드마다 최대 2회) — 해시화해서 isset() 으로 본다.
$rootSet = $graph !== null ? array_fill_keys($graph['roots'], true) : [];
/* 트리 렌더가 받는 한 벌 — 노드 색(심각도)·역할 판정(루트/대상)·노드 링크.
 *   목록 라벨(vg_deptree_role)과 SVG 노드가 **같은 배열**을 보므로 판정이 갈리지 않는다. */
$treeCtx = ['sev' => $sevOf, 'roots' => $rootSet, 'target' => $target, 'link' => $linkFor];
/** 노드 키 → 라벨(이름 @ 버전 + 관리자). 경로 목록·pom 목록처럼 SVG 가 아닌 자리에서 쓴다. */
$nodeLabel = function (string $key) use ($linkFor, $target, $treeCtx): string {
    $p = vg_pkgdep_parts($key);
    $html = '<a href="' . vg_h($linkFor([
        'mgr' => $p['manager'], 'name' => $p['name'], 'ver' => $p['version'], 'tab' => 'from',
    ])) . '">' . vg_h($p['name']) . '</a>'
        . ' <span class="why">' . vg_h($p['version']) . '</span>'
        . ' <code>' . vg_h($p['manager']) . '</code>';
    if (vg_deptree_role($key, $treeCtx) === 'root') { $html .= ' ' . vg_badge('루트', 'ok'); }
    if ($key === $target) { $html .= ' ' . vg_badge('지금 보는 패키지', 'med'); }
    return $html;
};

vg_header($host['fqdn'] ?? '의존성 그래프', 'assets');

if ($err !== null) {
    vg_page_title('의존성 그래프', 'DEPENDENCY GRAPH');
    vg_alert('오류 · ' . $err);
    vg_footer();
    return;
}
if (!$host) {
    vg_page_title('자산을 찾을 수 없습니다', 'DEPENDENCY GRAPH');
    echo '<div class="card">';
    vg_empty(['icon' => 'host', 'title' => '요청한 자산이 없습니다.', 'cta' => ['href' => '/assets.php', 'label' => '자산 목록']]);
    echo '</div>';
    vg_footer();
    return;
}

$meta = [
    '<a href="/host.php?id=' . (int) $hostId . '">← 자산 상세</a>',
];
if ($scan) { $meta[] = '최신 수집 ' . vg_h((string) $scan['collected_at']); }
$meta[] = '엣지 ' . number_format($load['loaded']) . '개';
vg_hero(vg_h((string) $host['fqdn']), $meta, null, 'ok', '');
?>

<?php if (!$scan): ?>
  <div class="card"><?php vg_empty([
      'icon' => 'feed',
      'title' => '아직 수집된 스캔이 없습니다.',
      'cta'   => ['href' => '/host.php?id=' . (int) $hostId, 'label' => '자산 상세로'],
  ]); ?></div>
<?php elseif (!$groups): ?>
  <div class="card"><?php vg_empty([
      'icon' => 'package',
      'title' => '이 자산의 최신 스캔에는 의존성 엣지가 없습니다.',
      'cta'   => ['href' => '/host.php?id=' . (int) $hostId . '&tab=packages', 'label' => '설치 패키지 보기'],
  ]); ?></div>
<?php else: ?>

  <?php if (count($groups) > 1): ?>
  <div class="card">
    <strong>조회 단위</strong>
    <div class="card__body">
      <nav class="subtabs">
      <?php foreach ($groups as $gid => $g): ?>
        <a<?= $gid === $cid ? ' class="on"' : '' ?> href="<?= vg_h('/depgraph.php?id=' . (int) $hostId . '&cid=' . (int) $gid) ?>">
          <?= vg_h($g['label']) ?></a>
      <?php endforeach; ?>
      </nav>
    </div>
  </div>
  <?php endif; ?>

  <?php
  if ($load['truncated']) {
      vg_alert([
          'type'  => 'warn',
          'title' => '엣지가 상한(' . number_format(VG_PKGDEP_EDGE_MAX) . '개)에서 잘렸습니다',
      ]);
  }
  if ($targetMissing) {
      vg_alert([
          'type'  => 'warn',
          'title' => '요청한 패키지가 이 조회 단위의 엣지에 없습니다',
      ]);
  }
  ?>

  <?php if ($target !== ''): ?>
  <div class="card">
    <strong><?= vg_h(vg_pkgdep_parts($target)['name']) ?></strong>
    <span class="why"><?= vg_h(vg_pkgdep_parts($target)['version']) ?> · <?= vg_h(vg_pkgdep_parts($target)['manager']) ?></span>
    <div class="card__body">
      <p><a href="<?= vg_h($linkFor(['tab' => 'tree'])) ?>">전체 트리 보기</a></p>
    </div>
  </div>
  <?php
  vg_subtabs([
      'from' => ['label' => '무엇이 끌어왔나', 'href' => $linkFor(['mgr' => $mgr, 'name' => $pkg, 'ver' => $ver, 'tab' => 'from'])],
      'to'   => ['label' => '무엇을 끌어오나', 'href' => $linkFor(['mgr' => $mgr, 'name' => $pkg, 'ver' => $ver, 'tab' => 'to'])],
      'tree' => ['label' => '전체 트리', 'href' => $linkFor(['mgr' => $mgr, 'name' => $pkg, 'ver' => $ver, 'tab' => 'tree'])],
  ], $tab);
  ?>
  <?php endif; ?>

  <?php
  /* 트리 한 장은 deptree.php 가 그린다(자산 상세 '의존성' 탭과 같은 함수). 이 화면은
   *   **어느 루트를 그릴지**와 남은 노드 예산만 정한다. */
  $drawTree = function (string $root) use ($graph, $treeCtx, &$nodeBudget): void {
      vg_deptree_render($graph, $root, $nodeBudget, $treeCtx);
  };
  $nodeBudget = VG_PKGDEP_NODE_MAX;   // 이 화면 전체가 나눠 쓰는 노드 예산
  ?>

  <?php if ($tab === 'from'): ?>
  <div class="card">
    <strong>이 패키지를 끌어온 경로</strong>
    <div class="card__body">
    <?php
    $r = vg_pkgdep_paths($graph, $target);
    if ($r['truncated']) {
        vg_alert([
            'type'  => 'warn',
            'title' => '경로가 상한(' . VG_PKGDEP_PATH_MAX . '개 · 깊이 ' . VG_PKGDEP_DEPTH_MAX . '단계)에서 잘렸습니다',
        ]);
    }
    if (count($r['paths']) === 1 && count($r['paths'][0]) === 1) {
        vg_empty(['icon' => '□', 'title' => '이 패키지를 끌어온 부모가 없습니다.']);
    } else {
        echo '<ol class="dep-paths">';
        foreach ($r['paths'] as $path) {
            echo '<li><ol class="dep-path">';
            foreach ($path as $node) { echo '<li>' . $nodeLabel($node) . '</li>'; }
            echo '</ol></li>';
        }
        echo '</ol>';
    }
    ?>
    </div>
  </div>

  <?php elseif ($tab === 'to'): ?>
  <div class="card">
    <strong>이 패키지가 끌어오는 의존성</strong>
    <div class="card__body">
    <?php
    if (!vg_pkgdep_children($graph, $target)) {
        vg_empty(['icon' => 'package', 'title' => '이 패키지가 끌어오는 의존성이 없습니다(말단 노드).']);
    } else {
        $drawTree($target);
    }
    ?>
    </div>
  </div>

  <?php else: ?>
  <?php if (!$graph['roots']): ?>
  <div class="card">
    <strong>전체 트리</strong>
    <div class="card__body">
    <?php vg_empty(['icon' => 'package', 'title' => '루트가 없습니다.']); ?>
    </div>
  </div>
  <?php else: ?>
  <?php
  // 루트가 수십 개인 자산(설치 패키지 800개대)에서는 SVG 하나가 화면을 감당 못 한다 —
  //   루트 단위로 페이지를 나누고, 노드 예산이 먼저 바닥나면 그 사실을 아래 요약에 숫자로 밝힌다.
  $rootsAll  = $graph['roots'];
  $perPage   = vg_perpage(VG_DEPTREE_ROOTS_PER_PAGE);
  $pageCount = max(1, (int) ceil(count($rootsAll) / $perPage));
  $page      = min(vg_page(), $pageCount);
  $rootsPage = array_slice($rootsAll, ($page - 1) * $perPage, $perPage);

  $rootsShown = 0;
  foreach ($rootsPage as $root) {
      if ($nodeBudget <= 0) { break; }
      $rootsShown++;
      ?>
  <div class="card">
    <div class="card__body"><?php $drawTree($root); ?></div>
  </div>
      <?php
  }
  $rootsSkipped = count($rootsPage) - $rootsShown;
  ?>
  <div class="card">
    <strong>전체 트리</strong>
    <span class="why">루트 <?= number_format(count($rootsAll)) ?>개 중 <?= number_format($rootsShown) ?>개 표시
      · 노드 <?= number_format(count($graph['nodes'])) ?>개</span>
    <?php if ($rootsSkipped > 0): ?>
      <span class="why"><?= vg_badge('노드 상한(' . number_format(VG_PKGDEP_NODE_MAX) . '개)에서 잘림 · 이 페이지의 나머지 루트 ' . number_format($rootsSkipped) . '개 미표시', 'warn') ?></span>
    <?php endif; ?>
    <div class="card__body"><?php vg_page_nav(count($rootsAll), $perPage, $page); ?></div>
  </div>
  <?php endif; ?>

  <?php if ($graph['pom']): ?>
  <div class="card">
    <strong>pom.xml 직접 선언</strong>
    <div class="card__body">
      <ul class="dep-tree">
      <?php foreach ($graph['pom'] as $k): ?>
        <li><?= $nodeLabel($k) ?></li>
      <?php endforeach; ?>
      </ul>
    </div>
  </div>
  <?php endif; ?>
  <?php endif; ?>

<?php endif; ?>
<?php vg_footer();
