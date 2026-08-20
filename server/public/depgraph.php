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
 *   단위로 좁힌다(vg_depgraph_severity) — 이 화면은 조회 범위를 넓히지 않는다.
 *
 * ── 왜 SVG 를 서버가 직접 그리나 ─────────────────────────────────────────
 *   중첩 박스(카드 안의 카드)로 그리던 것을 **가로 계층 트리**로 바꿨다. 깊이가 3단만
 *   넘어가도 무엇이 무엇에 매달렸는지 안 보이고 화면 폭을 계단식으로 먹었다.
 *   이 서버의 CSP 는 default-src 'self' 라 인라인 <script> 를 쓸 수 없으므로(charts.php
 *   vg_chart() 주석 참고) 좌표 계산은 PHP 가 하고 SVG 만 내보낸다 — vg_sev_donut() 과 같다.
 *   그래프 라이브러리(d3 등)는 들이지 않는다(YAGNI/KISS).
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require_once __DIR__ . '/../src/audit.php';       // vg_log_activity
require_once __DIR__ . '/../src/packagedep.php';  // 조회·그래프 조립
vg_require_menu_any('assets', 'findings');   // 의존성 그래프: 자산 상세에서만 들어온다(자산 상세와 같은 범위)

/* ── 가로 계층 트리의 배치 상수(SVG 논리좌표, px) ──────────────────────────
 *   화면 코드에 숫자를 박지 않고 여기 한곳에서만 정한다. 값을 바꾸면 트리 전체가 따라온다. */
const VG_DEPTREE_ROOTS_PER_PAGE = 10;   // 한 페이지에 그리는 루트 수(?per_page 로 바꾼다)
const VG_DEPTREE_NODE_W  = 280;         // 노드 박스 폭
const VG_DEPTREE_NODE_H  = 30;          // 노드 박스 높이
const VG_DEPTREE_GAP_X   = 56;          // 열(depth) 사이 가로 간격 = 엣지 곡선이 놓이는 폭
const VG_DEPTREE_GAP_Y   = 8;           // 형제 사이 세로 간격
const VG_DEPTREE_PAD     = 12;          // SVG 바깥 여백
const VG_DEPTREE_CHAR_W  = 6.4;         // 12px 글자 한 칸의 근사폭 — 이름 말줄임 계산용
const VG_DEPTREE_META_W  = 82;          // 노드 오른쪽 칸(버전/심각도 배지)의 폭

/**
 * 이 조회 단위(스캔 × 컨테이너)의 취약점 → 그래프 노드 키별 **최고 심각도**.
 *   조회 범위를 넓히지 않는다: uq_find 좌측 접두가 (scan_id, container_id)라 엣지 조회와
 *   같은 단위로 좁혀야 인덱스를 탄다. 패키지명 전역 역추적은 인덱스가 없어 풀스캔이 된다.
 *   매칭은 vg_pkgdep_index() 의 이름+버전 색인을 그대로 쓴다 — **이름만으로는 맞추지 않는다**
 *   (같은 스캔에 alpine 의 openssl 과 rpm 의 openssl 이 함께 있으면 서로 물려받는다).
 */
function vg_depgraph_severity(PDO $pdo, int $scanId, int $containerId, array $graph): array
{
    $st = $pdo->prepare(
        'SELECT package_name, installed_version, severity
           FROM tb_finding
          WHERE scan_id = ? AND container_id = ? AND is_deleted = 0
          LIMIT ' . VG_PKGDEP_ROLLUP_FINDING_MAX
    );
    $st->execute([$scanId, $containerId]);
    $rows = $st->fetchAll();
    if (!$rows) { return []; }

    $idx = vg_pkgdep_index($graph);
    $out = [];
    foreach ($rows as $r) {
        $name = (string) $r['package_name'];
        $ver  = (string) $r['installed_version'];
        $sev  = (string) $r['severity'];
        $keys = $idx['by_name_ver'][$name . '|' . $ver]
            ?? ($idx['by_name_norm'][$name . '|' . vg_pkgdep_version_norm($ver)] ?? []);
        foreach ($keys as $k) {
            if (!isset($out[$k]) || vg_pkgdep_sev_rank($sev) < vg_pkgdep_sev_rank($out[$k])) {
                $out[$k] = $sev;
            }
        }
    }
    return $out;
}

/**
 * 가로 계층 트리 배치 — 루트 하나를 좌(부모)→우(자식) 열로 눕히고 형제는 위→아래로 쌓는다.
 *   고전적인 tidy tree: **리프를 순서대로 쌓고, 부모의 y 는 자식들 y 의 중앙**에 둔다.
 *   반환: ['nodes' => [['key','x','y','hidden'], …], 'edges' => [[x1,y1,x2,y2], …],
 *          'w' => SVG 폭, 'h' => SVG 높이, 'drawn' => 그린 노드 수]
 *   $budget 은 화면 전체가 나눠 쓰는 남은 노드 수다(참조로 깎는다) — 루트가 수십 개인
 *   자산에서 SVG 하나가 페이지를 통째로 먹지 않게 한다. 바닥나면 그 아래는 hidden 으로만 센다.
 *   $seen 은 **경로 단위** 방문 집합이다(순환 방지) — 전역으로 두면 여러 부모가 공유하는
 *   라이브러리가 처음 만난 가지에서만 펼쳐져 다른 가지가 통째로 비어 보인다.
 */
function vg_deptree_layout(array $graph, string $root, int &$budget): array
{
    $nodes = [];
    $edges = [];
    $cursorY = VG_DEPTREE_PAD;   // 다음 리프가 놓일 위쪽 좌표
    $maxDepth = 0;

    $place = function (string $key, int $depth, array $seen) use (
        &$place, $graph, &$nodes, &$edges, &$cursorY, &$maxDepth, &$budget
    ): ?float {
        if ($budget <= 0) { return null; }
        $budget--;
        if ($depth > $maxDepth) { $maxDepth = $depth; }

        $kids = vg_pkgdep_children($graph, $key);
        $seen[$key] = true;
        $childY = [];
        $hidden = 0;
        if ($kids && $depth >= VG_PKGDEP_DEPTH_MAX) {
            $hidden = count($kids);          // 깊이 상한 — 여기서 접는다
        } else {
            foreach ($kids as $k) {
                if (isset($seen[$k])) { $hidden++; continue; }   // 순환 참조라 더 펴지 않는다
                $y = $place($k, $depth + 1, $seen);
                if ($y === null) { $hidden++; continue; }        // 노드 예산 소진
                $childY[] = $y;
            }
        }

        if ($childY) {
            $y = ($childY[0] + $childY[count($childY) - 1]) / 2;
        } else {
            $y = $cursorY + VG_DEPTREE_NODE_H / 2;
            $cursorY += VG_DEPTREE_NODE_H + VG_DEPTREE_GAP_Y;
        }
        $x = VG_DEPTREE_PAD + $depth * (VG_DEPTREE_NODE_W + VG_DEPTREE_GAP_X);
        $nodes[] = ['key' => $key, 'x' => $x, 'y' => $y, 'hidden' => $hidden];
        foreach ($childY as $cy) {
            $edges[] = [$x + VG_DEPTREE_NODE_W, $y, $x + VG_DEPTREE_NODE_W + VG_DEPTREE_GAP_X, $cy];
        }
        return $y;
    };
    $place($root, 0, []);

    $h = max($cursorY - VG_DEPTREE_GAP_Y + VG_DEPTREE_PAD, VG_DEPTREE_NODE_H + VG_DEPTREE_PAD * 2);
    $w = VG_DEPTREE_PAD * 2 + ($maxDepth + 1) * VG_DEPTREE_NODE_W + $maxDepth * VG_DEPTREE_GAP_X;
    return ['nodes' => $nodes, 'edges' => $edges, 'w' => (int) $w, 'h' => (int) ceil($h), 'drawn' => count($nodes)];
}

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
            $sevOf = vg_depgraph_severity($pdo, $scanId, $cid, $graph);

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

/** 이 화면 안에서만 쓰는 링크 조립 — 대상 패키지·컨테이너·탭을 한곳에서 만든다(DRY). */
$linkFor = function (array $over) use ($hostId, $cid): string {
    $q = ['id' => $hostId, 'cid' => $cid] + $over;
    $parts = [];
    foreach ($q as $k => $v) {
        if ($v === null || $v === '') { continue; }
        $parts[] = urlencode((string) $k) . '=' . urlencode((string) $v);
    }
    return '/depgraph.php?' . implode('&', $parts);
};
// $graph['roots'] 를 노드마다 in_array() 로 선형 탐색하면 O(N·R) 이 된다(목록 라벨·트리 노드
// 양쪽에서 노드마다 최대 2회) — 해시화해서 isset() 으로 본다.
$rootSet = $graph !== null ? array_fill_keys($graph['roots'], true) : [];
/** 노드의 표시 역할(루트/대상/기타) 판정을 한곳으로 모은다 — 목록 라벨과 SVG 노드가 이걸 쓴다. */
$roleOf = function (string $key) use ($rootSet, $target): string {
    if (isset($rootSet[$key])) { return 'root'; }
    if ($key === $target) { return 'target'; }
    return 'other';
};
/** 노드 키 → 라벨(이름 @ 버전 + 관리자). 경로 목록·pom 목록처럼 SVG 가 아닌 자리에서 쓴다. */
$nodeLabel = function (string $key) use ($linkFor, $target, $roleOf): string {
    $p = vg_pkgdep_parts($key);
    $html = '<a href="' . vg_h($linkFor([
        'mgr' => $p['manager'], 'name' => $p['name'], 'ver' => $p['version'], 'tab' => 'from',
    ])) . '">' . vg_h($p['name']) . '</a>'
        . ' <span class="why">' . vg_h($p['version']) . '</span>'
        . ' <code>' . vg_h($p['manager']) . '</code>';
    if ($roleOf($key) === 'root') { $html .= ' ' . vg_badge('루트', 'ok'); }
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
          <?= vg_h($g['label']) ?><span class="n"><?= number_format($g['edges']) ?></span></a>
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
      'to'   => ['label' => '무엇을 끌어오나', 'href' => $linkFor(['mgr' => $mgr, 'name' => $pkg, 'ver' => $ver, 'tab' => 'to']),
                 'n' => count(vg_pkgdep_children($graph, $target))],
      'tree' => ['label' => '전체 트리', 'href' => $linkFor(['mgr' => $mgr, 'name' => $pkg, 'ver' => $ver, 'tab' => 'tree'])],
  ], $tab);
  ?>
  <?php endif; ?>

  <?php
  /**
   * 노드 한 칸(SVG <a> 안의 rect·text) — 왼쪽 악센트 바 + 이름(왼쪽) + 버전/심각도(오른쪽)만.
   *   악센트 색: 취약점이 있으면 그 심각도 톤, 루트면 --accent, 그 외는 --line-2.
   *   관리자·잘린 전체 이름처럼 칸에 안 들어가는 사실은 <title>(툴팁)로 넘긴다.
   *   좌표·크기는 SVG 속성이라 CSS 가 가질 수 없다. 색은 전부 class 로만 준다(app.css 소유).
   */
  $svgNode = function (array $n) use ($roleOf, $linkFor, $sevOf): string {
      $p    = vg_pkgdep_parts($n['key']);
      $sev  = (string) ($sevOf[$n['key']] ?? '');
      $role = $roleOf($n['key']);
      $tone = $sev !== '' ? vg_sev_tone($sev) : ($role === 'root' ? 'info' : 'muted');

      $x   = (float) $n['x'];
      $y   = round((float) $n['y'], 1);
      $top = round($y - VG_DEPTREE_NODE_H / 2, 1);

      // 오른쪽 칸: 취약점이 있으면 심각도 배지, 없으면 버전.
      $rightW = $sev !== '' ? strlen($sev) * 5.6 + 14 : VG_DEPTREE_META_W;
      $avail  = VG_DEPTREE_NODE_W - 12 - 8 - $rightW - 10;
      $name   = mb_strimwidth($p['name'], 0, max(4, (int) ($avail / VG_DEPTREE_CHAR_W)), '…');

      $href = $linkFor(['mgr' => $p['manager'], 'name' => $p['name'], 'ver' => $p['version'], 'tab' => 'from']);
      $svg  = '<a href="' . vg_h($href) . '" class="deptree__node">'
          . '<title>' . vg_h($p['name'] . ' ' . $p['version'] . ' · ' . $p['manager']
              . ($sev !== '' ? ' · ' . $sev : '')) . '</title>'
          . '<rect class="deptree__box' . ($role === 'target' ? ' deptree__box--on' : '') . '"'
          . ' x="' . $x . '" y="' . $top . '" width="' . VG_DEPTREE_NODE_W . '" height="' . VG_DEPTREE_NODE_H . '" rx="7"/>'
          . '<rect class="deptree__accent tone-' . $tone . '"'
          . ' x="' . ($x + 1.5) . '" y="' . ($top + 4) . '" width="3.5" height="' . (VG_DEPTREE_NODE_H - 8) . '" rx="2"/>'
          . '<text class="deptree__name" x="' . ($x + 12) . '" y="' . $y . '">' . vg_h($name) . '</text>';

      if ($sev !== '') {
          $px = round($x + VG_DEPTREE_NODE_W - 10 - $rightW, 1);
          $svg .= '<rect class="deptree__pill tone-' . $tone . '" x="' . $px . '" y="' . round($y - 8, 1) . '"'
              . ' width="' . round($rightW, 1) . '" height="16" rx="8"/>'
              . '<text class="deptree__pilltext tone-' . $tone . '" x="' . round($px + $rightW / 2, 1) . '" y="' . $y . '">'
              . vg_h($sev) . '</text>';
      } else {
          $svg .= '<text class="deptree__meta" x="' . ($x + VG_DEPTREE_NODE_W - 10) . '" y="' . $y . '">'
              . vg_h(mb_strimwidth($p['version'], 0, (int) (VG_DEPTREE_META_W / VG_DEPTREE_CHAR_W), '…')) . '</text>';
      }
      // 접힌 자식(깊이·노드 상한, 순환)이 있으면 그 수를 노드 오른쪽에 남긴다 — 조용히 자르지 않는다.
      if ($n['hidden'] > 0) {
          $svg .= '<text class="deptree__more" x="' . ($x + VG_DEPTREE_NODE_W + 8) . '" y="' . $y . '">+'
              . (int) $n['hidden'] . '</text>';
      }
      return $svg . '</a>';
  };
  /**
   * 트리 한 장 — 좌표는 vg_deptree_layout() 이 계산하고 여기서는 그리기만 한다(SRP).
   *   부모→자식은 3차 베지에로 잇는다(두 열의 가운데를 제어점으로 잡아 좌우로 흐르는 곡선).
   *   SVG 폭은 노드가 정하므로 늘이지 않는다 — 넘치면 .deptree 안에서만 가로로 스크롤한다.
   */
  $drawTree = function (string $root) use ($graph, $svgNode, &$nodeBudget): void {
      $l = vg_deptree_layout($graph, $root, $nodeBudget);
      $p = vg_pkgdep_parts($root);
      echo '<div class="deptree">';
      echo '<svg class="deptree__svg" width="' . $l['w'] . '" height="' . $l['h'] . '"'
          . ' viewBox="0 0 ' . $l['w'] . ' ' . $l['h'] . '" role="img"'
          . ' aria-label="' . vg_h($p['name'] . ' 의존성 트리 · 노드 ' . $l['drawn'] . '개') . '">';
      foreach ($l['edges'] as [$x1, $y1, $x2, $y2]) {
          $mid = round(($x1 + $x2) / 2, 1);
          echo '<path class="deptree__edge" d="M' . $x1 . ',' . round($y1, 1) . ' C' . $mid . ',' . round($y1, 1)
              . ' ' . $mid . ',' . round($y2, 1) . ' ' . $x2 . ',' . round($y2, 1) . '"/>';
      }
      foreach ($l['nodes'] as $n) { echo $svgNode($n); }
      echo '</svg></div>';
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
