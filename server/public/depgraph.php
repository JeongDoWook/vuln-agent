<?php
declare(strict_types=1);

/**
 * depgraph.php — 패키지 의존성 그래프(무엇이 이 패키지를 끌어왔나). 로그인 필요.
 *   ?id=<host_id>            자산의 최신 수집 기준
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
$fixTargets = [];      // 손댈 대상(부모)별 묶음 — "이 하나를 올리면 N건"
$fixFloor = ['by_label' => [], 'by_key' => []];   // 취약 패키지 => 필요한 최소 버전(피드가 준 수정버전)
$fixTruncated = false; // 위 묶음이 상한(취약점 행·경로)에서 잘렸나
$targetOrigin = null;  // 대상 패키지의 판정(direct/transitive/unknown)
$targetPaths = ['paths' => [], 'truncated' => false];
$pathMarks = ['nodes' => [], 'edges' => []];   // 취약 하위 → 루트 경로 강조

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
            $index = vg_pkgdep_index($graph);
            /* 취약점 한 벌로 **두 가지**를 만든다: 노드 색칠과 조치 묶음. 조회를 나누면 같은
             *   단위에 같은 질문을 두 번 하게 되고, 상한이 어긋나면 "색은 칠했는데 조치
             *   목록엔 없다" 가 된다 — 그래서 vg_pkgdep_unit_findings() 한 번만 읽는다. */
            $findRows = vg_pkgdep_unit_findings($pdo, $scanId, $cid);
            $sevOf    = vg_deptree_severity_map($findRows, $index);
            $unit       = vg_pkgdep_rollup_unit($graph, $index, $cid, $findRows);
            $fixTargets = vg_pkgdep_rollup_sort($unit['agg']);
            $fixFloor   = vg_pkgdep_fix_floor($index, $findRows);
            $fixTruncated = $unit['path_truncated']
                || count($findRows) >= VG_PKGDEP_ROLLUP_FINDING_MAX;

            if ($mgr !== '' && $pkg !== '' && $ver !== '') {
                $key = vg_pkgdep_key($mgr, $pkg, $ver);
                if (isset($graph['nodes'][$key])) { $target = $key; } else { $targetMissing = true; }
            }
            if ($target !== '') {
                // 역추적은 여기서 한 번만 한다 — '무엇이 끌어왔나' 목록·경로 강조·조치 문장이
                //   같은 결과를 나눠 쓴다(따로 부르면 상한에 걸린 경로가 화면마다 달라진다).
                $targetPaths  = vg_pkgdep_paths($graph, $target);
                $pathMarks    = vg_deptree_path_marks($targetPaths['paths']);
                $targetOrigin = vg_pkgdep_origin($graph, $index, $pkg, $ver);
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
// 조치방안 문장이 가리키는 "올릴 부모" — 전이일 때만 있다(직접이면 올릴 부모가 따로 없다).
//   트리의 역할 표식(vg_deptree_role)이 문장과 같은 노드를 짚게 하려고 여기서 한 번만 만든다.
$fixParents = $targetOrigin !== null && $targetOrigin['verdict'] === 'transitive'
    ? array_fill_keys($targetOrigin['parents'], true) : [];
/* 트리 렌더가 받는 한 벌 — 노드 색(심각도)·역할 판정(루트/대상/올릴 부모)·노드 링크.
 *   목록 라벨(vg_deptree_role)과 SVG 노드가 **같은 배열**을 보므로 판정이 갈리지 않는다. */
$treeCtx = ['sev' => $sevOf, 'roots' => $rootSet, 'target' => $target, 'link' => $linkFor,
            'path' => $pathMarks['nodes'], 'pathedge' => $pathMarks['edges'], 'fixparents' => $fixParents];
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
      'title' => '아직 수집 이력이 없습니다.',
      'cta'   => ['href' => '/host.php?id=' . (int) $hostId, 'label' => '자산 상세로'],
  ]); ?></div>
<?php elseif (!$groups): ?>
  <div class="card"><?php vg_empty([
      'icon' => 'package',
      'title' => '이 자산의 최신 수집에는 의존성 엣지가 없습니다.',
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
   *   **어느 루트를 그릴지**와 남은 노드 예산만 정한다.
   *   $ctxOverride 는 'to' 탭(무엇을 끌어오나)에서 경로 강조를 끄는 데 쓴다 — 그 탭은
   *   대상에서 **자식 방향**으로 내려가는 트리라 루트→대상 경로(조상 방향)의 노드가 그
   *   트리 안에 없다. pathedge 를 그대로 넘기면 대상 노드 하나만 빼고 트리 전체가
   *   "경로 밖"으로 흐려져 버린다 — 이 탭에는 강조할 경로 자체가 없으므로 꺼 둔다. */
  $drawTree = function (string $root, array $ctxOverride = []) use ($graph, $treeCtx, &$nodeBudget): void {
      vg_deptree_render($graph, $root, $nodeBudget, $ctxOverride + $treeCtx);
  };
  $nodeBudget = VG_PKGDEP_NODE_MAX;   // 이 화면 전체가 나눠 쓰는 노드 예산
  ?>

  <?php if ($tab === 'from'): ?>
  <?php
  /* ── 조치방안(이 패키지 하나) ────────────────────────────────────────────────
   *   "무엇이 끌어왔나" 다음에 실무자가 바로 묻는 것은 "그래서 뭘 올리나" 다. 트리는
   *   구조만 보여줄 뿐 그 답을 안 한다 — 여기서 한 문장으로 답한다.
   *   **말할 수 있는 것과 없는 것을 가른다**: 자식이 몇 버전이어야 하는지는 피드가 준
   *   사실(fixed_version)이라 말하고, **부모를 몇으로 올려야 하는지는 말하지 않는다** —
   *   우리 DB 에는 설치된 스냅샷만 있고 업스트림의 버전별 의존 관계표가 없다.
   *   취약하지 않은 패키지에는 이 카드를 아예 그리지 않는다(빈 카드는 잡음이다). */
  $tSev  = (string) ($sevOf[$target] ?? '');
  $tNeed = (string) ($fixFloor['by_key'][$target] ?? '');
  if ($tSev !== ''):
      $tp = vg_pkgdep_parts($target);
      $tParent = $targetOrigin !== null && $targetOrigin['verdict'] === 'transitive'
          ? vg_pkgdep_parts((string) $targetOrigin['parents'][0]) : null;
  ?>
  <div class="card">
    <strong>조치방안</strong>
    <span class="why"><?= vg_sev_badge($tSev) ?></span>
    <div class="card__body">
    <?php if ($tParent !== null): ?>
      <p><span class="pill">직접 조치 불가</span>
        이 패키지는 <strong><?= vg_h($tParent['name']) ?></strong>
        <span class="why"><?= vg_h($tParent['version']) ?></span>
        <?php if (count($targetOrigin['parents']) > 1): ?>
          <span class="why">외 <?= count($targetOrigin['parents']) - 1 ?>개</span>
        <?php endif; ?>
        아래로 딸려 들어왔습니다(루트가 직접 선언한 의존성).
        이 패키지만 바꾸면 부모가 깨지므로 <strong>그 부모를 올려</strong>
        <?php if ($tNeed !== ''): ?>
          <strong><?= vg_h($tp['name']) ?> <?= vg_h($tNeed) ?> 이상</strong>을 끌어오게 해야 합니다.
        <?php else: ?>
          안전한 버전을 끌어오게 해야 합니다.
        <?php endif; ?>
      </p>
      <ul class="dep-tree">
      <?php foreach ($targetOrigin['parents'] as $pk): $pp = vg_pkgdep_parts((string) $pk); ?>
        <li><?= $nodeLabel($pk) ?>
          <a class="pill" href="<?= vg_h($linkFor([
              'mgr' => $pp['manager'], 'name' => $pp['name'], 'ver' => $pp['version'], 'tab' => 'to',
          ])) ?>">무엇을 끌어오나</a></li>
      <?php endforeach; ?>
      </ul>
      <?php
      /* 위 문장·목록이 이미 말한 것을 그림으로 옮긴다 — 이 카드가 가리키는 경로만 뽑은
       *   작은 세로 그림(전체 트리는 아래 '전체 트리' 카드가 그대로 맡는다). 부모가 여럿이면
       *   경로도 여럿이라 최대 3개까지 나란히 두고, 넘는 만큼은 "외 N개"로 밝힌다(조용히
       *   자르지 않는다) — vg_pkgdep_paths() 가 이미 구한 $targetPaths 를 그대로 쓴다. */
      $miniPaths = array_slice($targetPaths['paths'], 0, 3);
      $miniMore  = count($targetPaths['paths']) - count($miniPaths);
      ?>
      <?php if ($miniPaths): ?>
      <div class="deptree-mini-group">
        <?php foreach ($miniPaths as $mp): vg_deptree_path_svg($mp, $treeCtx); endforeach; ?>
      </div>
      <?php if ($miniMore > 0): ?>
        <p class="why">경로 <?= number_format(count($targetPaths['paths'])) ?>개 중 3개만 그림으로 표시
          · 외 <?= number_format($miniMore) ?>개는 위 목록에서 확인하세요.</p>
      <?php endif; ?>
      <?php endif; ?>
      <p class="why">올릴 부모의 버전은 제시하지 않습니다 — 설치된 스냅샷만 수집하므로
        "부모의 어느 버전이 안전한 자식을 끌어오는가" 는 이 데이터로 알 수 없습니다.
        부모의 배포처(레지스트리·릴리스 노트)에서 확인하세요.</p>
    <?php elseif ($tNeed !== ''): ?>
      <p><span class="pill">직접 조치</span>
        이 패키지를 <strong><?= vg_h($tp['name']) ?> <?= vg_h($tNeed) ?> 이상</strong>으로 올리세요.</p>
    <?php else: ?>
      <p>이 패키지를 직접 올릴 수 있습니다. <span class="why">수정 버전이 아직 알려지지 않았습니다 —
        벤더 권고를 확인하세요.</span></p>
    <?php endif; ?>
    </div>
  </div>
  <?php endif; ?>
  <div class="card">
    <strong>이 패키지를 끌어온 경로</strong>
    <div class="card__body">
    <?php
    $r = $targetPaths;   // 위에서 한 번 구한 것을 그대로 쓴다
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
        $drawTree($target, ['path' => [], 'pathedge' => []]);
    }
    ?>
    </div>
  </div>

  <?php else: ?>
  <?php
  /* ── 조치방안(이 조회 단위 전체) ───────────────────────────────────────────
   *   트리는 "무엇이 무엇에 매달렸나" 까지만 답한다. 취약한 하위가 여럿일 때 실무자가 정말
   *   묻는 것은 "그래서 뭘 먼저 올리나" 이고, 그 답은 부모 기준으로 묶어야 나온다.
   *   집계는 vg_pkgdep_rollup_unit() — 자산 상세의 '먼저 올릴 대상' 과 **같은 함수·같은 단위**라
   *   두 화면의 건수가 어긋나지 않는다. 전이 취약점이 없으면 그리지 않는다(빈 카드는 잡음). */
  if ($fixTargets):
      $fixTop = array_slice($fixTargets, 0, VG_PKGDEP_ROLLUP_TOP);
      $fixHeaders = [
          ['label' => '먼저 올릴 대상'],
          ['label' => '최고 등급', 'key' => 'severity'],
          ['label' => '해결 건수', 'align' => 'right', 'nowrap' => true],
          ['label' => '끌어오는 취약 패키지 · 필요한 최소 버전'],
      ];
      $fixOpts = [
          'card'      => false,
          'row_class' => fn($p) => vg_sev_row((string) $p['severity']),
          'cell'      => [
              0 => function ($p) use ($linkFor) {
                  $t = vg_pkgdep_parts((string) $p['key']);
                  return '<strong>' . vg_h($t['name']) . '</strong> <span class="why">' . vg_h($t['version']) . '</span>'
                      . ' <a class="pill" href="' . vg_h($linkFor([
                          'mgr' => $t['manager'], 'name' => $t['name'], 'ver' => $t['version'], 'tab' => 'to',
                      ])) . '">무엇을 끌어오나</a>';
              },
              'severity' => fn($p) => vg_sev_badge((string) $p['severity']),
              2 => fn($p) => '<strong>' . number_format((int) $p['count']) . '</strong>건',
              // 자식의 필요 버전은 피드가 준 사실이라 여기서 말한다(부모의 목표 버전은 말하지 않는다).
              3 => function ($p) use ($fixFloor) {
                  $shown = array_slice($p['packages'], 0, VG_PKGDEP_ROLLUP_PKG_TOP);
                  $more  = count($p['packages']) - count($shown);
                  $out = [];
                  foreach ($shown as $label) {
                      $need = (string) ($fixFloor['by_label'][$label] ?? '');
                      $out[] = vg_h($label) . ($need !== '' ? ' <strong>→ ' . vg_h($need) . ' 이상</strong>' : '');
                  }
                  return '<span class="why">' . implode(', ', $out)
                      . ($more > 0 ? ' 외 ' . $more . '개' : '') . '</span>';
              },
          ],
      ];
  ?>
  <div class="card">
    <strong>조치방안 · 먼저 올릴 대상 <span class="hint">(<?= number_format(count($fixTargets)) ?>개)</span></strong>
    <span class="why">
      <?php if (count($fixTargets) > count($fixTop)): ?>
        <?= number_format(count($fixTargets)) ?>개 중 상위 <?= count($fixTop) ?>개 ·
      <?php endif; ?>
      취약한 하위 의존성은 그것만 갈아끼울 수 없습니다 — 끌어온 부모를 올려야 합니다
    </span>
    <?php if ($fixTruncated): ?>
      <span class="why"><?= vg_badge('경로·취약점이 상한에서 잘려 대상이 더 있을 수 있음', 'warn') ?></span>
    <?php endif; ?>
    <?php vg_table($fixHeaders, $fixTop, $fixOpts); ?>
    <div class="card__body">
      <p class="why"><strong>올릴 부모의 버전은 제시하지 않습니다.</strong> 수집하는 것은 자산에
        <em>설치된 스냅샷</em>(이 부모가 지금 무엇을 끌어오는가)이지 업스트림의
        <em>버전별 의존 관계표</em>(부모의 몇 버전이 무엇을 끌어오는가)가 아닙니다 —
        근거 없는 버전은 지어내지 않습니다. 오른쪽 칸의 "→ N 이상" 은 <em>자식</em>이 만족해야 할
        조건이며 피드가 준 수정 버전입니다.</p>
    </div>
  </div>
  <?php endif; ?>
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
  /* 대상 패키지를 지정하고 들어왔으면 **그 대상에 닿는 루트만** 그린다. 루트가 수십 개인
   *   자산에서 전체를 페이지로 넘기면 강조된 경로가 몇 페이지 뒤에 숨어 보이지 않는다.
   *   경로가 하나도 안 잡히면(pom 직접선언처럼 루트가 없는 노드) 원래대로 전부 그린다. */
  $rootsAll = $graph['roots'];
  if ($target !== '') {
      $hit = [];
      foreach ($targetPaths['paths'] as $path) {
          if ($path && isset($rootSet[$path[0]])) { $hit[$path[0]] = true; }
      }
      if ($hit) { $rootsAll = array_values(array_filter($rootsAll, fn($r) => isset($hit[$r]))); }
  }
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
