<?php
declare(strict_types=1);
/* 의존성 탭 — "이 자산에 깔린 것이 무엇을 끌어왔나"를 가로 계층 트리로 보여준다.
 *
 *   그림(배치·SVG)은 src/deptree.php 가 소유한다 — 전용 화면 depgraph.php 와 **같은 함수**를
 *   부른다. 이 파일이 정하는 것은 그 화면과 갈리는 부분뿐이다: 조회 단위 안내, 루트 페이지,
 *   상한 고지, 그리고 더 깊은 조회(대상 패키지 역추적·다른 컨테이너)를 그 화면으로 넘기는 링크.
 *
 *   조회는 host.php 의 ?tab=depgraph 분기에서만 돈다 — 자산 상세는 자주 열리는 화면이라
 *   다른 탭을 볼 때 엣지 조회가 함께 돌면 안 된다. */
?>
<?php if ($depGraph === null || !$depGraph['roots']): ?>
  <div class="card">
    <strong>의존성</strong>
    <div class="card__body">
    <?php vg_empty([
        'icon'  => 'package',
        'title' => '이 자산의 최신 수집에는 그릴 의존성 트리가 없습니다.',
        'hint'  => '루트를 가진 SBOM 엣지가 있어야 트리가 그려집니다(pom.xml 직접 선언만 있으면 전용 화면에서 볼 수 있습니다).',
        'cta'   => ['href' => vg_deptree_url((int) $hostId, (int) $depUnit), 'label' => '의존성 그래프 화면으로'],
    ]); ?>
    </div>
  </div>
<?php else:
  /* 노드 링크는 전용 화면으로 보낸다 — 탭은 이 자산의 전체 트리만 맡고, "무엇이 끌어왔나"
   *   역추적은 거기서 이어진다(탭에 그 갈래까지 넣으면 자산 상세가 두 화면이 된다). */
  $depLink = function (array $over) use ($hostId, $depUnit): string {
      return vg_deptree_url((int) $hostId, (int) $depUnit, $over);
  };
  $depCtx = [
      'sev'    => $depSev,
      'roots'  => array_fill_keys($depGraph['roots'], true),
      'target' => '',
      'link'   => $depLink,
  ];
  // 루트 단위로 페이지를 나눈다($total 은 host.php 가 센 루트 수). 활성 탭의 ?page= 를 그대로 쓴다.
  $depPageCount = max(1, (int) ceil($total / $perPage));
  $depPage      = max(1, min((int) $page, $depPageCount));
  $depRoots     = array_slice($depGraph['roots'], ($depPage - 1) * $perPage, $perPage);
  $depBudget    = VG_PKGDEP_NODE_MAX;   // 이 탭 전체가 나눠 쓰는 노드 예산
?>
  <?php if ($depLoad['truncated']): ?>
    <?php vg_alert([
        'type'  => 'warn',
        'title' => '엣지가 상한(' . number_format(VG_PKGDEP_EDGE_MAX) . '개)에서 잘렸습니다',
    ]); ?>
  <?php endif; ?>

  <div class="card">
    <strong>의존성 트리</strong>
    <span class="why"> · 엣지 <?= number_format((int) $depLoad['loaded']) ?>개
      · 루트 <?= number_format($total) ?>개 · 노드 <?= number_format(count($depGraph['nodes'])) ?>개</span>
    <?php /* 어느 단위를 그리고 있는지 밝힌다 — 호스트에 엣지가 없으면 컨테이너로 떨어진다. */ ?>
    <?php if (count($depUnits) > 1 || $depUnit !== 0): ?>
      <?= vg_badge('조회 단위 · ' . (string) ($depUnits[$depUnit]['label'] ?? '호스트'), 'info') ?>
    <?php endif; ?>
    <div class="actions">
      <a class="btn btn--sm btn--ghost" href="<?= vg_h(vg_deptree_url((int) $hostId, (int) $depUnit)) ?>"
         title="대상 패키지 역추적·다른 조회 단위"><?= vg_icon('chart') ?>의존성 그래프 화면</a>
    </div>
    <div class="card__body">
      <?php vg_deptree_legend(); ?>
      <span class="why">노드를 누르면 그 패키지를 무엇이 끌어왔는지 볼 수 있습니다.</span>
    </div>
  </div>

  <?php
  $depShown = 0;
  foreach ($depRoots as $depRoot) {
      if ($depBudget <= 0) { break; }
      $depShown++;
      ?>
  <div class="card">
    <div class="card__body"><?php vg_deptree_render($depGraph, $depRoot, $depBudget, $depCtx); ?></div>
  </div>
      <?php
  }
  $depSkipped = count($depRoots) - $depShown;
  ?>
  <?php if ($depSkipped > 0): ?>
    <?php /* 조용히 자르지 않는다 — 몇 개가 안 그려졌는지 숫자로 밝힌다. */ ?>
    <div class="card">
      <?= vg_badge('노드 상한(' . number_format(VG_PKGDEP_NODE_MAX) . '개)에서 잘림 · 이 페이지의 나머지 루트 '
          . number_format($depSkipped) . '개 미표시', 'warn') ?>
    </div>
  <?php endif; ?>
  <?php vg_page_nav($total, $perPage, $depPage); ?>
<?php endif; ?>
