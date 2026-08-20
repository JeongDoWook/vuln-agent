<?php
declare(strict_types=1);
/* 설치 패키지 탭 — 이 컨테이너 안에 깔린 것. 페이저는 page/per_page. */
?>
  <div class="card">
    <strong>설치 패키지</strong>
    <span class="why"> · 이 컨테이너 안 <?= number_format($packageTotal) ?>개
      <?= $ctrOs !== '' ? '· ' . vg_h($ctrOs) : '' ?></span>
    <?php if ($depEdgeTotal > 0): ?>
      <span class="why"> · <a href="/depgraph.php?id=<?= (int) $hostId ?>&amp;cid=<?= (int) $container['container_id'] ?>">의존성 그래프</a></span>
    <?php endif; ?>
    <div class="card__body">
    <?php
    vg_table(
        [
            ['label' => '패키지', 'key' => 'name', 'class' => 'col-id'],
            ['label' => '설치 버전', 'key' => 'version'],
            ['label' => '아키텍처', 'key' => 'arch'],
            ['label' => '관리자', 'key' => 'manager'],
            ['label' => '소스 패키지', 'key' => 'source_pkg'],
            ['label' => '출처', 'key' => 'origin'],
        ],
        $rows,
        [
            'card' => false,
            'empty' => $hasFilter
                ? [
                    'icon'  => '🔍',
                    'title' => '검색 조건에 맞는 패키지가 없습니다.',
                    'cta'   => ['href' => vg_qs(['q' => null, 'page' => null]), 'label' => '검색 초기화'],
                ]
                : [
                    'icon'  => '□',
                    'title' => '이 컨테이너에서 수집된 패키지가 없습니다.',
                    'hint'  => '패키지 DB 가 없는 이미지(distroless·scratch)이거나 수집이 실패한 경우입니다.',
                ],
            'cell' => [
                'name'    => fn($p) => '<strong>' . vg_h((string) $p['name']) . '</strong>',
                'version' => fn($p) => '<code>' . vg_h((string) ($p['version'] ?? '')) . '</code>',
                'arch'    => fn($p) => $p['arch'] ? vg_h((string) $p['arch']) : '<span class="why">–</span>',
                'manager' => fn($p) => '<code>' . vg_h((string) $p['manager']) . '</code>',
                'source_pkg' => function ($p) {
                    if (empty($p['source_pkg'])) { return '<span class="why">–</span>'; }
                    return vg_h((string) $p['source_pkg'])
                        . (!empty($p['source_version']) ? ' <span class="why">' . vg_h((string) $p['source_version']) . '</span>' : '');
                },
                'origin'  => fn($p) => $p['origin']
                    ? vg_h((string) $p['origin'])
                    : (!empty($p['vendor']) ? vg_h((string) $p['vendor']) : '<span class="why">–</span>'),
            ],
        ]
    );
    ?>
    </div>
  </div>
  <?php vg_page_nav($total, $perPage, $page); ?>
