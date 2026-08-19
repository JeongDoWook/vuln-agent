<?php
declare(strict_types=1);

/**
 * depgraph.php — 패키지 의존성 그래프(무엇이 이 패키지를 끌어왔나). 로그인 필요.
 *   ?id=<host_id>            자산의 최신 스캔 기준
 *   &cid=<container_id>      0=호스트 자신, 양수=그 컨테이너 (엣지가 있는 단위만 선택지에 뜬다)
 *   &mgr=&name=&ver=         대상 패키지를 지정하면 역추적/정방향 탭이 열린다
 *   &tab=from|to|tree
 *
 * ── 이 화면이 답하는 것 ──────────────────────────────────────────────────
 *   에이전트가 보내온 SBOM(CycloneDX dependencies)·pom.xml 직접선언 엣지는 지금까지
 *   저장만 되고 읽는 화면이 없었다. 취약한 라이브러리가 나왔을 때 실무에서 먼저 묻는 건
 *   "이건 왜 깔려 있나(누가 끌어왔나)" 인데, 설치 패키지 목록으로는 답이 안 나온다.
 *
 *   조회 단위가 (스캔 × 컨테이너)인 이유: tb_package_dependency 의 유니크 키
 *   uk_pkg_dep_edge 좌측 접두가 (scan_id, container_id)라 이 둘로 좁혀야 인덱스를 탄다.
 *   패키지명만으로 전역 검색하면 인덱스가 없어 풀스캔이 된다 — 그래서 패키지 카탈로그
 *   화면(package.php)이 아니라 자산 상세(host.php)에서 들어온다.
 *
 *   그래프 라이브러리를 들이지 않는다(YAGNI/KISS) — 접이식 목록(<details>)으로 충분하다.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require_once __DIR__ . '/../src/audit.php';       // vg_log_activity
require_once __DIR__ . '/../src/packagedep.php';  // 조회·그래프 조립
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
/** 노드 키 → 라벨(이름 @ 버전 + 관리자). 대상 노드면 강조한다. */
$nodeLabel = function (string $key) use ($linkFor, $target, $graph): string {
    $p = vg_pkgdep_parts($key);
    $html = '<a href="' . vg_h($linkFor([
        'mgr' => $p['manager'], 'name' => $p['name'], 'ver' => $p['version'], 'tab' => 'from',
    ])) . '">' . vg_h($p['name']) . '</a>'
        . ' <span class="why">' . vg_h($p['version']) . '</span>'
        . ' <code>' . vg_h($p['manager']) . '</code>';
    if ($graph !== null && in_array($key, $graph['roots'], true)) {
        $html .= ' ' . vg_badge('루트', 'ok');
    }
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
vg_hero(vg_h((string) $host['fqdn']), $meta, null, 'ok', '', 'DEPENDENCY GRAPH');
?>

<div class="card">
  <strong>무엇이 이 패키지를 끌어왔나</strong>
</div>

<?php if (!$scan): ?>
  <div class="card"><?php vg_empty([
      'icon' => 'feed',
      'title' => '아직 수집된 스캔이 없습니다.',
      'hint'  => '에이전트가 한 번이라도 수집해야 의존성 엣지가 생깁니다.',
      'cta'   => ['href' => '/host.php?id=' . (int) $hostId, 'label' => '자산 상세로'],
  ]); ?></div>
<?php elseif (!$groups): ?>
  <div class="card"><?php vg_empty([
      'icon' => 'package',
      'title' => '이 자산의 최신 스캔에는 의존성 엣지가 없습니다.',
      'hint'  => '의존성은 SBOM(CycloneDX) 또는 pom.xml 에서만 나옵니다 — 둘 다 없는 자산은 이 화면이 비어 있는 것이 정상입니다.',
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
          'hints' => ['이 화면은 그 뒤의 엣지를 보지 않습니다 — 아래 트리·경로가 전체가 아닐 수 있습니다.'],
      ]);
  }
  if ($targetMissing) {
      vg_alert([
          'type'  => 'warn',
          'title' => '요청한 패키지가 이 조회 단위의 엣지에 없습니다',
          'hints' => ['조회 단위(컨테이너)를 바꾸거나 아래 전체 트리에서 찾아보세요.'],
      ]);
  }
  ?>

  <?php if ($target !== ''): ?>
  <div class="card">
    <strong><?= vg_h(vg_pkgdep_parts($target)['name']) ?></strong>
    <span class="why"><?= vg_h(vg_pkgdep_parts($target)['version']) ?> · <?= vg_h(vg_pkgdep_parts($target)['manager']) ?></span>
    <div class="card__body">
      <p class="why"><a href="<?= vg_h($linkFor(['tab' => 'tree'])) ?>">대상 지정 해제 — 전체 트리 보기</a></p>
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
   * org-chart 카드 트리 — 각 노드를 .ctrcard 로 그리고, 자식이 있으면 그 안에 중첩
   * .ctree__list 를 접이식(<details>)으로 담는다. 깊이·노드 상한에 걸리면 그 카드 안에
   * "잘렸다"고 적는다. $seen 은 **경로 단위** 방문 집합이다(순환 방지) — 전역으로 두면
   * 여러 부모가 공유하는 라이브러리가 처음 만난 가지에서만 펼쳐져 다른 가지가 통째로
   * 비어 보인다.
   */
  $renderCard = function (string $key, int $depth, array $seen) use (&$renderCard, $graph, $nodeLabel, $target, &$nodeCount): string {
      $kids = vg_pkgdep_children($graph, $key);
      $label = $nodeLabel($key);
      $nodeCount++;

      $tone = ($graph !== null && in_array($key, $graph['roots'], true)) ? 'ok'
          : (($key === $target) ? 'med' : 'muted');
      $head = '<div class="ctrcard__head">' . $label . '</div>';

      if (!$kids) {
          return '<li class="ctrcard tone-' . $tone . '">' . $head . '</li>';
      }
      if ($depth >= VG_PKGDEP_DEPTH_MAX) {
          return '<li class="ctrcard tone-' . $tone . '">' . $head
              . '<span class="why">깊이 상한(' . VG_PKGDEP_DEPTH_MAX . ')에서 접음 · 하위 '
              . count($kids) . '개 미표시</span></li>';
      }
      if ($nodeCount >= VG_PKGDEP_NODE_MAX) {
          return '<li class="ctrcard tone-' . $tone . '">' . $head
              . '<span class="why">표시 상한(' . VG_PKGDEP_NODE_MAX . '개)에서 접음 · 하위 '
              . count($kids) . '개 미표시</span></li>';
      }
      $seen[$key] = true;
      $inner = '';
      foreach ($kids as $k) {
          if (isset($seen[$k])) {
              $inner .= '<li class="ctrcard tone-muted">' . '<div class="ctrcard__head">' . $nodeLabel($k)
                  . ' <span class="why">— 순환 참조라 더 펴지 않음</span></div></li>';
              continue;
          }
          $inner .= $renderCard($k, $depth + 1, $seen);
      }
      return '<li class="ctrcard tone-' . $tone . '">' . $head
          . '<details open><summary>의존 ' . count($kids) . '개</summary><ul class="ctree__list">'
          . $inner . '</ul></details></li>';
  };
  /** 루트(또는 대상) 하나의 .ctree 몸통 — .ctree__root 가 그 노드 자신, 자식은 카드 그리드. */
  $renderTree = function (string $root) use ($renderCard, $graph, $nodeLabel, &$nodeCount): void {
      $nodeCount++;
      $kids = vg_pkgdep_children($graph, $root);
      echo '<div class="ctree">';
      echo '<div class="ctree__root"><span class="ctree__icon" aria-hidden="true">📦</span>'
          . '<div class="ctree__rootid">' . $nodeLabel($root) . '</div></div>';
      if ($kids) {
          echo '<ul class="ctree__list">';
          foreach ($kids as $k) { echo $renderCard($k, 1, [$root => true]); }
          echo '</ul>';
      } else {
          echo '<p class="why">하위 의존성 없음</p>';
      }
      echo '</div>';
  };
  $nodeCount = 0;
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
            'title' => '경로가 상한에서 잘렸습니다',
            'hints' => ['경로 ' . VG_PKGDEP_PATH_MAX . '개 · 깊이 ' . VG_PKGDEP_DEPTH_MAX . '단계 상한 때문일 수도, 순환 참조를 만나 그 지점에서 끊었기 때문일 수도 있습니다.'],
        ]);
    }
    if (count($r['paths']) === 1 && count($r['paths'][0]) === 1) {
        vg_empty([
            'icon'  => '□',
            'title' => '이 패키지를 끌어온 부모가 없습니다.',
            'hint'  => 'SBOM 의 루트 자신이거나, pom.xml 직접선언(부모를 모르는 형태)입니다.',
        ]);
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
        $renderTree($target);
    }
    ?>
    </div>
  </div>

  <?php else: ?>
  <?php if (!$graph['roots']): ?>
  <div class="card">
    <strong>전체 트리</strong>
    <div class="card__body">
    <?php vg_empty(['icon' => 'package', 'title' => '루트가 없습니다.', 'hint' => 'pom.xml 직접선언만 있으면 부모가 없어 트리가 만들어지지 않습니다 — 아래 목록을 보세요.']); ?>
    </div>
  </div>
  <?php else: ?>
  <div class="card">
    <strong>전체 트리</strong>
    <span class="why">루트 <?= number_format(count($graph['roots'])) ?>개 · 노드 <?= number_format(count($graph['nodes'])) ?>개</span>
  </div>
  <?php foreach ($graph['roots'] as $root): ?>
  <div class="card">
    <div class="card__body"><?php $renderTree($root); ?></div>
  </div>
  <?php endforeach; ?>
  <?php if ($nodeCount >= VG_PKGDEP_NODE_MAX): ?>
  <div class="card">
    <p class="why">표시 상한 <?= number_format(VG_PKGDEP_NODE_MAX) ?>개에 걸려 일부 가지를 접었습니다 — 특정 패키지를 눌러 그 패키지 기준으로 다시 보세요.</p>
  </div>
  <?php endif; ?>
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
