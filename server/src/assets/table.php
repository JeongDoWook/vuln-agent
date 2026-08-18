<?php
declare(strict_types=1);

/**
 * assets/table.php — 자산 목록 표(머리글 폭 배분·셀 렌더)만 갖는다.
 *   조회는 assets/queries.php, 색 어휘(톤)는 화면(assets.php)이 정해 넘긴다.
 *   표 아래 색 범례는 걷었다 — '정상·지연·오프라인'·'C · 기밀' 처럼 뱃지가 이미 글자를 달고 있어
 *   색→이름 대응을 따로 설명할 자리가 아니었다.
 */

/**
 * @param bool $canConfirm 관리자면 체크박스 열이 붙는다(인가 자체는 POST 처리부가 정한다).
 * @param bool $filtered   검색·필터가 걸린 상태인가(빈 목록 안내 문구가 갈린다).
 * @param array $stateTone,$gradeTone 색 어휘 — 지금 이 표는 쓰지 않는다(범례를 걷었다).
 *        같은 값을 KPI 카드·등급 모달이 계속 쓰므로 호출부 계약은 그대로 둔다.
 */
function vg_assets_render_table(
    array $rows,
    array $sevByScan,
    bool $canConfirm,
    bool $filtered,
    string $stateHelp,
    array $stateTone,
    array $gradeTone
): void {
    // 폭 배분: 목록 표는 table-layout:fixed 다(app.css 의 '목록 화면' 구역).
    //   단위를 두 가지로 나눠 쓴다 — 이 표가 표 모드로 처음 뜨는 1061px 에서 실측한 값이 기준이다.
    //   · 줄바꿈이 불가능한 고정 크기 값(뱃지·<code>·버튼)이 담기는 열은 rem 이다. % 로 주면 표가
    //     좁아질 때 그 값보다 좁아지는데, 값은 안 줄어드니 그대로 옆 열 위에 그려진다. 실제로
    //     '상태' 6.5%(1061px 에서 48px)가 오프라인 뱃지(65px)를 못 담아 OS 열을 32px 덮었고,
    //     '에이전트' 는 구버전 뱃지가 13px 덮었다(가로 스크롤은 안 생겨 #377 의 넘침 검사엔 안 잡혔다).
    //     필요한 폭 = 값의 폭 + 칸 여백(.6rem×2): 뱃지 65+19=84 → 5.5rem, 구버전 뱃지 53+19=72 → 5rem.
    //   · 접거나 잘라도 되는 텍스트 열(OS·리소스·수치·수집시각·심각도 건수)은 그대로 % 다.
    //   · 남는 폭은 호스트명이 갖는다(폭을 안 준 열). 예전엔 심각도가 남는 폭을 다 가져가
    //     1920px 에서 건수 뱃지 4개에 344px 를 썼다 — 그 폭은 잘려 나가던 식별자 쪽이 써야 한다.
    /* 등급 확정은 관리자만 한다 — 체크박스 열도 관리자에게만 보인다($canConfirm 은 화면이 넘긴다).
     *   (인가 자체는 POST 처리부가 정한다. 여기서 숨기는 건 안 되는 조작을 보여주지 않기 위해서다.) */
    $headers = [];
    if ($canConfirm) {
        // 체크박스만 담는 열이라 폭이 늘 같다 → % 가 아니라 rem(아래 폭 배분 기준 그대로).
        //   머리글은 글자가 아니라 **이 페이지 전체 선택** 체크박스다 — 무엇을 고르는 건지는
        //   고르는 자리(표 머리)에서 읽혀야 한다. 예전엔 목록·페이지네이션 아래 카드에 있어서
        //   체크는 위에서 하고 전체선택은 저 아래에 있었다.
        $headers[] = [
            'label' => '', 'key' => 'pick', 'width' => '2.5rem', 'align' => 'center',
            'label_html' => '<input type="checkbox" data-checkall="host_ids[]"'
                . ' aria-label="이 페이지 전체 선택" title="이 페이지 전체 선택">',
        ];
    }
    /* 열은 "이 행을 열어볼지 말지" 를 정하는 것만 남긴다(docs/dev/ui-design-system.md 의 목록·상세 분담).
     *   여기서 뺀 다섯 열은 지운 게 아니라 호스트 상세(host.php)로 옮긴 것이다:
     *     담당 부서 → 자산 설정 탭의 등급 검토 카드 · OS/IP/패키지 수/에이전트 버전 → 식별부(히어로) 메타.
     *   에이전트 '구버전' 신호도 그 히어로 메타가 그대로 이어받는다(신호를 잃지 않는다). */
    $headers = array_merge($headers, [
        // 뺀 열들의 폭은 남는 폭을 갖는 식별자(호스트)와 위험(심각도)이 가져간다.
        ['label' => '호스트', 'key' => 'fqdn', 'class' => 'col-id', 'width' => '34%'],
        ['label' => '상태', 'key' => 'state', 'width' => '5.5rem', 'title' => $stateHelp],
        // 등급 열도 뱃지(고정 크기)라 % 가 아니라 rem 이다 — 위 주석의 기준을 그대로 따른다.
        //   'C · 기밀'(약 62px) + 칸 여백(.6rem×2 ≈ 19px) → 5.5rem.
        //   확정된 자산의 뱃지는 'C · 기밀' 로 스스로 말하지만, 확정 전 뱃지는 'C 제안' 이라
        //   문자만 남는다 — 그 뜻을 표 아래 범례가 아니라 **열 머리글의 툴팁**으로 붙인다
        //   (어휘는 VG_ASSET_GRADES 가 소유한다. 여기서 분류표를 다시 적지 않는다).
        ['label' => '등급', 'key' => 'grade', 'width' => '5.5rem',
         'title' => implode(' / ', VG_ASSET_GRADES)],
        ['label' => '심각도', 'key' => 'sev', 'width' => '22%'],
        ['label' => '최신 수집', 'key' => 'collected_at', 'width' => '14%', 'nowrap' => true],
    ]);
    // 액션 열만 % 가 아니라 rem 이다. 삭제 버튼은 폭이 늘 같은 고정 크기 조작부라 비율로 줄 이유가 없고,
    //   비율로 주면 표가 좁아질 때 버튼보다 좁아진다 — 실제로 900px 에서 9%(=51px)가 68px 버튼을
    //   못 담아 카드를 16.7px 밀어냈다(가로 스크롤). 5rem 이면 어느 폭에서도 버튼이 들어간다.

    vg_table(
        $headers,
        $rows,
        [
            // 빈 이유가 셋이라 메시지도 셋 — "필터 때문에 빈 것" 과 "자산이 없는 것" 은 다른 상황이다.
            'empty' => $filtered
                ? [
                    'icon'  => '🔍',
                    'title' => '조건에 맞는 자산이 없습니다.',
                    'hint'  => '검색어나 상태·등급·부서 필터를 바꿔 보세요.',
                    'cta'   => ['href' => '/assets.php', 'label' => '필터 초기화'],
                ]
                : [
                    'icon'  => '🖥️',
                    'title' => '등록된 자산이 없습니다.',
                    'hint'  => '자산은 에이전트가 수집을 보내면 자동 등록됩니다. 상단의 [에이전트 설치 안내]를 따르세요.',
                ],
            'cell' => [
                // 일괄 확정 대상 선택. 폼 안에 표가 들어 있어 그대로 같이 전송된다.
                //   data-name 은 모달의 "무엇을 확정하는가" 요약이 읽는다(app.js 가 textContent 로만 쓴다).
                'pick' => fn($r) => '<input type="checkbox" name="host_ids[]" value="' . (int) $r['host_id']
                    . '" data-name="' . vg_h($r['fqdn']) . '" aria-label="' . vg_h($r['fqdn']) . ' 선택">',
                // 칸을 넘치는 긴 FQDN 은 col-id 가 말줄임으로 접는다 — 전체 이름은 title 로 남긴다.
                'fqdn'  => fn($r) => '<strong><a href="/host.php?id=' . (int) $r['host_id'] . '" title="' . vg_h($r['fqdn']) . '">' . vg_h($r['fqdn']) . '</a></strong>',
                'state' => fn($r) => vg_asset_state(
                    $r['scan_id'] !== null,
                    $r['poll_age_min'],
                    $r['age_min'],
                    (int) $r['poll_schedule_seconds']
                ),
                // 확정 등급이 있으면 그것만 보여준다. 없을 때만 제안값을 '제안' 꼬리표와 함께 —
                //   둘을 나란히 두면 어느 쪽이 확정인지 흐려진다("판정은 사람이, 초안은 시스템이").
                'grade' => fn($r) => $r['grade'] !== null
                    ? vg_asset_grade_badge((string) $r['grade'], false, (string) ($r['grade_reason'] ?? ''))
                    : vg_asset_grade_badge(
                        $r['grade_suggested'], true, (string) ($r['grade_suggested_reason'] ?? '')
                    ),
                // 뱃지를 누르면 그 호스트·등급의 취약점 목록으로.
                'sev' => fn($r) => vg_sev_counts(
                    $sevByScan[(int) $r['scan_id']] ?? [],
                    fn(string $s) => '/findings.php?host=' . (int) $r['host_id'] . '&sev=' . $s
                ),
                /* 12% 로는 'YYYY-MM-DD HH:MM:SS'(19자)가 안 들어가 '2026-08-11 23:2…' 로 잘려
                 *   시각을 못 읽었다. 열을 넓히는 대신 **형식을 줄인다** — 이 목록에서 필요한 건
                 *   분까지고(초 단위 판단을 여기서 하지 않는다), 전체 값은 title 로 남긴다. */
                'collected_at' => function ($r) {
                    $at = (string) ($r['collected_at'] ?? '');
                    if ($at === '') { return '<span class="why">–</span>'; }
                    return '<span class="why" title="' . vg_h($at) . '">' . vg_h(substr($at, 0, 16)) . '</span>';
                },
            ],
        ]
    );
}
