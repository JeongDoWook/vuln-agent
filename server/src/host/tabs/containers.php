<?php
declare(strict_types=1);
/* 컨테이너 탭 — 호스트 아래 컨테이너를 조밀한 표로. */ ?>
    <?php vg_toolbar([
        ['type' => 'search', 'name' => 'q', 'placeholder' => '컨테이너·이미지·네임스페이스 검색', 'value' => $q],
        ['type' => 'hidden', 'name' => 'tab', 'value' => $tab],
        ['type' => 'hidden', 'name' => 'id', 'value' => (string) $hostId],
    ]); ?>
    <?php
    /* 카드 격자에서 **표**로 되돌린 이유: 한 호스트에 컨테이너가 24개씩 붙으면 카드는
     *   스크롤만 길어지고 정작 "어느 컨테이너가 더 나쁜가" 를 나란히 비교할 수 없다.
     *   비교가 이 탭의 목적이라 한 컨테이너를 한 행에 놓고, 위험은 미터 바 + 등급별 숫자로
     *   같은 자리에서 읽히게 한다(색만으로 말하지 않는다 — 숫자가 항상 함께 있다).
     *   카드에만 있던 값(k8s 위치·다이제스트·SBOM 해시·워크로드)은 **버리는 게 아니라**
     *   상세로 내린다 — container.php 의 히어로와 '이미지 식별' 카드가 그 값들의 정본이다.
     *   버튼 셋(상세 열기/패키지/런타임)도 '상세 →' 하나로 줄인다. 패키지·런타임은 상세 안의
     *   탭이라 여기서 세 갈래로 벌려 둘 이유가 없다.
     *   JS·차트 라이브러리는 여전히 쓰지 않는다(CSP·오프라인 배포) — 미터 폭 계산뿐이다. */
    // 런타임 상태 톤 — dead 만 위험으로 올린다(멈춘 컨테이너는 위험이 아니라 사실).
    $stateTone = ['running' => 'ok', 'restarting' => 'med', 'dead' => 'high'];
    // 심각도 높은 컨테이너부터 보여준다 — 정렬은 SQL 단(vg_host_load_containers_tab, LIMIT/OFFSET 전)
    // 에서 전수 기준으로 이미 끝났다. 여기서 다시 정렬하면 이 페이지 안에서만 재배열되어
    // 뒷페이지에 남은 CRITICAL 을 못 끌어오므로, 이 뷰는 받은 순서를 그대로 그린다.

    /** 이 컨테이너의 심각도 분포([등급=>건수]) — 표의 여러 칸이 같은 값을 다시 찾지 않게 한 번만 꺼낸다. */
    $sevOf = fn(array $c): array => $sevByContainer[(int) $c['container_id']] ?? [];
    /** 등급별 건수 칸. 0 은 지우지 않고 흐리게만 둔다 — 빈칸이면 "안 셌다"로 읽힌다. */
    $sevCell = function (string $sev) use ($sevOf): callable {
        return function (array $c) use ($sev, $sevOf): string {
            $n = (int) ($sevOf($c)[$sev] ?? 0);
            return $n > 0 ? number_format($n) : '<span class="why">0</span>';
        };
    };
    $href = fn(array $c): string =>
        '/container.php?id=' . (int) $hostId . '&cid=' . urlencode((string) $c['cid']);
    ?>
    <div class="card">
      <strong>컨테이너</strong>
      <span class="why"> · 최신 수집 기준 <?= number_format($containerTotal) ?>개 · 컨테이너는 호스트와 OS 가 다를 수 있습니다</span>
      <div class="card__body">
        <?php
        vg_table(
            [
                ['label' => '컨테이너', 'width' => '20%', 'class' => 'col-id'],
                ['label' => '이미지', 'width' => '24%', 'class' => 'col-id'],
                ['label' => '위험 분포', 'width' => '13%'],
                // CRITICAL 열은 시안에 없었지만 남긴다 — 이 표에서 가장 급한 값이고,
                //   빼면 그 건수를 볼 자리가 화면에서 사라진다(카드 범례가 갖고 있던 값이다).
                ['label' => 'CRIT',   'align' => 'right', 'width' => '4.5rem', 'nowrap' => true],
                ['label' => 'HIGH',   'align' => 'right', 'width' => '4.5rem', 'nowrap' => true],
                ['label' => 'MEDIUM', 'align' => 'right', 'width' => '5rem',   'nowrap' => true],
                ['label' => 'LOW',    'align' => 'right', 'width' => '4.5rem', 'nowrap' => true],
                ['label' => '패키지',  'align' => 'right', 'width' => '5rem',   'nowrap' => true],
                ['label' => '상세',    'width' => '5rem', 'nowrap' => true],
            ],
            $rows,
            [
                'card'  => false,
                'empty' => $hasFilter
                    ? [
                        'icon'  => 'search',
                        'title' => '검색 조건에 맞는 컨테이너가 없습니다.',
                        'cta'   => ['href' => vg_qs(['q' => null, 'page' => null]), 'label' => '검색 초기화'],
                    ]
                    : '수집된 컨테이너가 없습니다.',
                // 행 왼쪽 띠 = 그 컨테이너의 최고 등급. 취약점이 없으면 띠를 가져가지 않는다.
                'row_class' => function (array $c) use ($sevOf): string {
                    $sev = $sevOf($c);
                    foreach (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as $s) {
                        if (($sev[$s] ?? 0) > 0) { return vg_sev_row($s); }
                    }
                    return '';
                },
                'cell' => [
                    // 이름 앞에 런타임 상태 뱃지 — "지금 도는 것인가" 가 이름과 같은 자리에서 읽혀야 한다.
                    0 => function (array $c) use ($href, $stateTone): string {
                        $state = (string) ($c['runtime_state'] ?? '');
                        $out = $state !== '' ? vg_badge($state, $stateTone[$state] ?? 'muted') . ' ' : '';
                        $out .= '<a href="' . vg_h($href($c)) . '">' . vg_h((string) $c['cid']) . '</a>';
                        if (!empty($c['name']) && (string) $c['name'] !== (string) $c['cid']) {
                            $out .= ' <span class="why">' . vg_h((string) $c['name']) . '</span>';
                        }
                        return $out;
                    },
                    // 이미지는 식별자라 넘치면 말줄임하고 전체 값은 title 에 남긴다(지우는 게 아니라 접는 것).
                    //   OS 는 그 아래 줄 — 컨테이너가 호스트와 다른 OS 일 수 있다는 게 이 탭의 전제다.
                    1 => function (array $c): string {
                        $image = (string) ($c['image'] ?? '');
                        $os    = trim((string) ($c['os_id'] ?? '') . ' ' . (string) ($c['os_version'] ?? ''));
                        $out = $image !== ''
                            ? '<code title="' . vg_h($image) . '">' . vg_h($image) . '</code>'
                            : '<span class="why">이미지 미상</span>';
                        $out .= '<div class="why">' . ($os !== '' ? vg_h($os) : 'OS 미상')
                             . (!empty($c['manager']) ? ' · ' . vg_h((string) $c['manager']) : '') . '</div>';
                        return $out;
                    },
                    // 미터 바 — 세그먼트 사이 2px 간격은 .riskbar 가 갖는다(HIGH·MEDIUM 이 맞닿으면
                    //   색각이상 기준으로 구분이 안 된다). 폭 계산(width:N%)은 vg_sev_bar() 몫이다.
                    2 => function (array $c) use ($sevOf): string {
                        $bar = vg_sev_bar($sevOf($c));
                        return $bar !== '' ? $bar : '<span class="why">판정된 취약점 없음</span>';
                    },
                    3 => $sevCell('CRITICAL'),
                    4 => $sevCell('HIGH'),
                    5 => $sevCell('MEDIUM'),
                    6 => $sevCell('LOW'),
                    7 => fn(array $c): string => number_format((int) $c['pkg_count']),
                    8 => fn(array $c): string => '<a href="' . vg_h($href($c)) . '">상세 →</a>',
                ],
            ]
        );
        ?>
      </div>
    </div>
    <?php vg_page_nav($total, $perPage, $page); ?>
