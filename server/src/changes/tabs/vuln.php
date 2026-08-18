<?php
/**
 * changes/tabs/vuln.php — '취약점 변화' 탭의 표.
 *   쓰는 값(changes.php 가 $ctx 로 넘긴다): $changes $err $pdo $page $perPage $total $type $hostId $q
 *   셀 렌더는 changes/render.php 의 공용 함수들이다(추이 탭의 '해결된 항목' 표와 같은 모양).
 */
$paged = array_slice($changes, ($page - 1) * $perPage, $perPage);

// 사유 판별: 현재 페이지 행만 대상으로 tb_pkg_change 를 한 번에 대조(N+1 금지).
if ($err === null && $paged) {
    try {
        vg_attach_change_reason($pdo, $paged);
    } catch (Throwable $e) {
        error_log('[changes] detail lookup: ' . $e->getMessage());
    }
}

vg_table(
    [
        // 폭은 머리글 글자까지 담아야 한다 — th 는 nowrap 이라 좁으면 옆 열을 덮고,
        //   맨 끝 열('수집 시각')이 넘치면 표가 카드 밖으로 밀린다(861px 에서 1px 넘쳤다).
        //   남는 폭은 자유폭인 '호스트'·'패키지' 가 나눠 갖는다 — 열을 새로 늘리지 않은 이유가
        //   이것이다: 열이 하나 늘면 그 폭은 결국 식별자(호스트·패키지)에서 빠져 나온다.
        // 변화 뱃지 + 그 이유(문장)를 한 칸에 담는다. 사유는 nowrap 을 주지 않아 접힌다.
        ['label' => '변화 · 사유', 'width' => '16%',
         'title' => '무엇이 달라졌는지와, 왜 그렇게 됐는지(패키지 변경 이력 대조 결과)'],
        ['label' => '호스트'],
        // 'CVE-2023-44487' + KEV 뱃지 + 칸 여백이 들어가야 한다 — 16%(1030px 표에서 165px)는
        //   nowrap·말줄임이라 KEV 뱃지가 잘려 나갔다. 1440px 에서 이 칸의 실측 필요폭은
        //   180px(값 + 뱃지 + 칸 여백 35) → 11.5rem.
        ['label' => 'CVE', 'width' => '11.5rem', 'nowrap' => true],
        ['label' => '패키지'],
        // 등급 뱃지도 고정 크기다 — 12% 는 870px 에서 66px 라 CRITICAL 뱃지가 18.3px 넘쳤다.
        //   여기엔 이전 등급·외부노출까지 가로로 눕혀 담는다:
        //   'MEDIUM →' + 뱃지 + '외부노출' 셋이 동시에 오는 건 등급 변화 행뿐이다. 흔한 조합
        //   (등급 뱃지 + 외부노출)이 한 줄에 들어가는 값으로 잡는다 — 10rem(160px)에선 실측
        //   4px 이 모자라 두 줄로 접혔다 → 11rem.
        ['label' => '등급 · 노출', 'width' => '11rem'],
        // 'YYYY-MM-DD HH:MM:SS'(19자)는 이 폭에 안 들어가 말줄임으로 잘렸다 —
        //   열을 넓히는 대신 분까지만 보이고(초는 이 목록의 판단에 안 쓴다) 전체는 title 로.
        //   그렇게 줄인 값의 실측 필요폭이 143px 이다 → 9rem.
        ['label' => '수집 시각', 'width' => '9rem', 'nowrap' => true],
    ],
    $paged,
    [
        'empty' => ($type !== '' || $hostId || $q !== '')
            ? [
                'icon'  => '🔍',
                'title' => '조건에 맞는 변화가 없습니다.',
                'hint'  => '검색어나 호스트·변화유형 필터를 바꿔 보세요.',
                'cta'   => ['href' => '/changes.php', 'label' => '필터 초기화'],
            ]
            : [
                'icon'  => '📉',
                'title' => '아직 비교할 변화가 없습니다.',
                'hint'  => '호스트마다 스캔이 2회 이상 쌓여야 직전과 비교할 수 있습니다.',
            ],
        'row_class' => fn($r) => vg_sev_row((string) $r['severity']),
        'cell' => [
            0 => fn($r) => vg_change_type_cell($r),
            1 => fn($r) => '<a href="/host.php?id=' . (int) $r['host_id'] . '">' . vg_h($r['fqdn']) . '</a>',
            2 => fn($r) => '<a href="/cve.php?cve=' . urlencode($r['cve_id']) . '">' . vg_h($r['cve_id']) . '</a>'
                          . ($r['in_kev'] ? ' ' . vg_badge('KEV', 'crit') : ''),
            3 => fn($r) => vg_change_package_cell($r),
            4 => fn($r) => vg_change_severity_cell($r),
            5 => fn($r) => vg_change_when_cell($r),
        ],
    ]
);
if ($paged) { vg_page_nav($total, $perPage, $page); }
