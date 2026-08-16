<?php
declare(strict_types=1);
/* 런타임 탭 — 노출 소켓과 실행 프로세스. 한 탭에 표가 둘이라 페이저도 둘이다:
   노출은 epage, 프로세스는 page(host.php 런타임 탭과 같은 규약). 이름은 container.php 가
   정해 $ePage/$page 로 넘긴다 — 여기서 다시 정하면 두 표가 서로를 민다. */
?>
  <div class="card">
    <strong>런타임 노출</strong>
    <span class="why">— 이 컨테이너가 연 포트. 호스트로 포워딩된 포트는 밖에서 그대로 닿는다</span>
    <?php /* 범위 뱃지의 색 뜻 — 어휘는 vg_scope_label(), 톤은 $scopeTone(호스트 상세와 같은 표)이다. */ ?>
    <?php vg_legend(array_map(
        fn(string $sc): array => ['label' => vg_scope_label($sc), 'tone' => $scopeTone[$sc]],
        array_keys($scopeTone)
    ), ['inline' => true, 'caption' => '노출 범위']); ?>
    <div class="card__body">
    <?php
    vg_table(
        [
            ['label' => '범위'],
            ['label' => '프로세스', 'key' => 'proc'],
            ['label' => '포트'],
            ['label' => '실행패키지', 'key' => 'exe_pkg'],
            ['label' => '로드한 패키지'],
        ],
        $exposures,
        [
            'card' => false,
            'empty' => $hasFilter
                ? [
                    'icon'  => '🔍',
                    'title' => '검색 결과가 없습니다.',
                    'cta'   => ['href' => vg_qs(['q' => null, 'page' => null, 'epage' => null]), 'label' => '검색 초기화'],
                ]
                : [
                    'icon'  => '✅',
                    'title' => '이 컨테이너에는 리스닝 소켓이 없습니다.',
                ],
            'cell' => [
                0 => fn($e) => vg_badge(vg_scope_label((string) $e['scope']), $scopeTone[$e['scope']] ?? 'muted'),
                2 => fn($e) => vg_h((string) $e['proto']) . '/' . (int) $e['port'],
                4 => fn($e) => '<span class="why">' . vg_trunc($e['loaded_pkgs'], 60) . '</span>',
            ],
        ]
    );
    ?>
    </div>
  </div>
  <?php vg_page_nav($exposureTotal, $perPage, $ePage, 'epage'); ?>

  <div class="card mt-lg">
    <strong>실행 프로세스</strong>
    <span class="why">— 이 컨테이너 안에서 돌고 있는 프로그램과 그 소속 패키지</span>
    <div class="card__body">
    <?php
    vg_table(
        [
            ['label' => 'PID'],
            ['label' => '프로세스', 'key' => 'comm'],
            ['label' => '사용자'],
            ['label' => '실행 패키지', 'key' => 'exe_pkg'],
            ['label' => '로드한 패키지'],
        ],
        $rows,
        [
            'card' => false,
            'empty' => $hasFilter
                ? [
                    'icon'  => '🔍',
                    'title' => '검색 결과가 없습니다.',
                    'cta'   => ['href' => vg_qs(['q' => null, 'page' => null, 'epage' => null]), 'label' => '검색 초기화'],
                ]
                : [
                    'icon'  => '🗂️',
                    'title' => '이 컨테이너의 프로세스 정보가 없습니다.',
                    'hint'  => '구버전 에이전트로 수집된 스캔이거나 컨테이너가 멈춘 상태입니다.',
                ],
            'cell' => [
                0 => fn($pr) => '<span class="why">' . (int) $pr['pid'] . '</span>',
                2 => fn($pr) => '<span class="why">' . vg_h((string) $pr['username']) . '</span>',
                4 => fn($pr) => '<span class="why">' . vg_trunc($pr['loaded_pkgs'], 60) . '</span>',
            ],
        ]
    );
    ?>
    </div>
  </div>
  <?php vg_page_nav($total, $perPage, $page); ?>
