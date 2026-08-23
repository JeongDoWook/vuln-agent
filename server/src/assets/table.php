<?php
declare(strict_types=1);

/**
 * assets/table.php — 자산 목록 표(머리글 폭 배분·셀 렌더)만 갖는다.
 *   조회는 assets/queries.php, 색 어휘(톤)는 화면(assets.php)이 정해 넘긴다.
 *   표 아래 색 범례는 걷었다 — '정상·지연·오프라인'·'C · 기밀' 처럼 뱃지가 이미 글자를 달고 있어
 *   색→이름 대응을 따로 설명할 자리가 아니었다.
 */

require_once __DIR__ . '/../netiface.php';   // vg_iface_is_virtual() — IP 툴팁의 가상 인터페이스 필터링용

/* IP 툴팁에 나열하는 주소 개수 상한. 호스트가 신고할 수 있는 주소는 최대 256개다
 *   (ingest/network.php 의 VG_HOST_ADDR_MAX_ROWS) — 그대로 이으면 툴팁이 화면을 덮는다.
 *   전체 목록은 자산 상세가 갖는다. */
const VG_ASSET_IP_TITLE_MAX = 8;

/**
 * @param bool $canConfirm 관리자면 체크박스 열이 붙는다(인가 자체는 POST 처리부가 정한다).
 * @param bool $filtered   검색·필터가 걸린 상태인가(빈 목록 안내 문구가 갈린다).
 * @param array $ipsByHost host_id => 주소 목록(대표가 맨 앞). queries.php 가 조회 한 번으로 묶어 준다.
 * @param array $trendByHost host_id => '14일 추세' 스파크라인 점 목록. queries.php 가 배치로 묶어 준다.
 * @param array $stateTone,$gradeTone 색 어휘 — 지금 이 표는 쓰지 않는다(범례를 걷었다).
 *        같은 값을 KPI 카드·등급 모달이 계속 쓰므로 호출부 계약은 그대로 둔다.
 */
function vg_assets_render_table(
    array $rows,
    array $sevByScan,
    array $ipsByHost,
    array $trendByHost,
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
    //     '심각도'·'최신 수집' 도 같은 이유로 rem 이다 — 심각도는 등급 뱃지 최대 4개(실측 129.6px,
    //     세 자리 건수 포함)+여백 → 10rem, 최신 수집은 'YYYY-MM-DD HH:MM'(실측 96px)+여백 → 8rem.
    //     예전엔 %(22%·14%)였는데, table-layout:fixed 는 표 폭이 넓어질수록(1920px 등) % 열을
    //     비례해서 계속 키운다 — 뱃지 3개가 채 안 쓰는 폭에 낭비가 109px(1440px 실측)까지 벌어졌다
    //     (사용자 지적). 내용이 늘 같은 길이인 열은 rem 으로 그 낭비 자체를 없앤다.
    //   · 접거나 잘라도 되는 텍스트 열은 % 다 — 지금 이 표에서는 호스트(식별자) 하나뿐이다.
    //   · 남는 폭은 그 호스트명이 갖는다(유일한 % 열이라 나머지 rem 열을 뺀 전부를 가져간다).
    //     예전엔 심각도가 % 라서 남는 폭을 나눠 갖다가 1920px 에서 건수 뱃지 4개에 344px 를
    //     썼다 — 그 폭은 말줄임되는 식별자 쪽이 가져가야 진짜로 쓰인다.
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
        // 이 표의 유일한 % 열 — 나머지(IP·상태·등급·심각도·14일 추세·최신 수집)를 rem 으로
        //   뺀 나머지 전부를 가져간다(이 파일 위 폭 배분 기준). col-id 라 넘치면 말줄임+title 로
        //   접히므로(값을 잃지 않는다) 좁아질 걱정 없이 남는 폭을 다 줘도 된다 — 반대로
        //   고정 크기 뱃지 열(심각도·상태·등급)은 좁히면 옆 열 위에 그려지므로 rem 이 안전하다.
        ['label' => '호스트', 'key' => 'fqdn', 'class' => 'col-id', 'width' => '40%'],
        /* IP 는 <code> 로 그리는 고정 크기 값이라 % 가 아니라 rem 이다(위 폭 배분 기준).
         *   'xxx.xxx.xxx.xxx'(≈105px) + ' +5'(≈24px) + 칸 여백(.6rem×2 ≈ 19px) → 9.5rem. */
        ['label' => 'IP', 'key' => 'ip', 'width' => '9.5rem', 'nowrap' => true,
         'title' => '호스트가 신고한 IPv4(가상 인터페이스 제외) — 대표 1개, 나머지는 +N'],
        ['label' => '상태', 'key' => 'state', 'width' => '5.5rem', 'title' => $stateHelp],
        // 등급 열도 뱃지(고정 크기)라 % 가 아니라 rem 이다 — 위 주석의 기준을 그대로 따른다.
        //   'C · 기밀'(약 62px) + 칸 여백(.6rem×2 ≈ 19px) → 5.5rem.
        //   확정된 자산의 뱃지는 'C · 기밀' 로 스스로 말하지만, 확정 전 뱃지는 'C 제안' 이라
        //   문자만 남는다 — 그 뜻을 표 아래 범례가 아니라 **열 머리글의 툴팁**으로 붙인다
        //   (어휘는 VG_ASSET_GRADES 가 소유한다. 여기서 분류표를 다시 적지 않는다).
        ['label' => '등급', 'key' => 'grade', 'width' => '5.5rem',
         'title' => implode(' / ', VG_ASSET_GRADES)],
        /* 뱃지 최대 4개(CRITICAL/HIGH/MEDIUM/LOW, 세 자리 건수 포함)가 실측 129.6px, +칸 여백
         *   → 10rem(위 폭 배분 기준). 예전엔 22% 였는데 표가 넓어질수록 비례해서 계속 커져
         *   1440px 에서만도 낭비가 109px 였다(사용자 지적) — 내용 길이가 늘 같은 열이라 rem 이 맞다. */
        ['label' => '심각도', 'key' => 'sev', 'width' => '10rem'],
        /* 스파크라인은 svg(120px 고정) + 값 + 증감이라 뱃지·IP 와 같은 고정폭 값이다(rem).
         *   좁은 화면(표 모드가 빠듯해지는 구간)에서는 다른 열을 줄이지 않고 이 열을 통째로
         *   숨긴다 — col-trend 는 app.css 의 반응형 절이 갖는다(열 다이어트 규약, 이 파일
         *   위 주석의 "뺀 다섯 열" 과 같은 판단 — 값을 지우는 게 아니라 상세로 미루는 것도
         *   아니고 그냥 좁은 화면에서 접는다, 자산 상세엔 이미 다른 형태의 추세가 있다). */
        ['label' => '14일 추세', 'key' => 'trend', 'width' => '13rem', 'class' => 'col-trend',
         'title' => '최근 14일간 CRITICAL·HIGH(조치 대상) 건수 추세'],
        /* 'YYYY-MM-DD HH:MM'(실측 96px, cell 의 collected_at 콜백이 분까지만 자른다) + 칸 여백
         *   → 8rem — 길이가 항상 같은 값이라 %(예전 14%) 대신 rem 이 맞다(위 폭 배분 기준). */
        ['label' => '최신 수집', 'key' => 'collected_at', 'width' => '8rem', 'nowrap' => true],
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
                /* IP — 호스트당 여러 개다(실측: 물리 NIC 1 + docker0·브리지·calico 5).
                 *   전부 세우면 이 열 하나가 표를 밀어내므로 대표 하나만 세우고 나머지는
                 *   '+N' 으로 접는다. 접은 값은 버리는 게 아니라 title 로 남는다 —
                 *   자산 상세(host.php)에 가지 않아도 "왜 이 IP 로 검색됐나"가 여기서 읽힌다.
                 *   대표 선정 기준은 queries.php 의 vg_assets_sort_addresses() 가 갖는다. */
                'ip' => function ($r) use ($ipsByHost) {
                    $addrs = $ipsByHost[(int) $r['host_id']] ?? [];
                    // 백필 전 자산·수집 이력이 없는 자산은 주소가 없다 — 빈 칸을 자리표시
                    //   문구로 채우지 않는다(다른 열의 '–' 와 같은 어휘).
                    if ($addrs === []) { return '<span class="why">–</span>'; }
                    /* 툴팁도 대표 IP 와 같은 기준을 쓴다 — docker0·br-·calico 등 가상
                     *   인터페이스는 밖에서 그 주소로 자산에 닿지 않아 나열해도 소음이다.
                     *   전부 가상이면(가상 인터페이스뿐인 호스트) 빈 툴팁보다는 원본이 낫다. */
                    $physical = array_values(array_filter(
                        $addrs,
                        static fn(array $a): bool => !vg_iface_is_virtual($a['iface'] ?? null)
                    ));
                    $tipAddrs = $physical !== [] ? $physical : $addrs;
                    /* 대표 IP 는 $addrs[0] 이다 — queries.php 의 vg_assets_sort_addresses() 가
                     *   이미 물리 인터페이스를 앞으로 정렬해 둔다. $tipAddrs 를 다시 뒤져
                     *   대표를 고르면 같은 정책을 여기서 한 번 더 판정하는 셈이라 no-op 이고,
                     *   대표 선정 정책은 queries.php 한 곳에만 둔다. */
                    /* 툴팁에 전부 나열하지 않는다 — 주소는 호스트당 최대 256행까지 들어올 수
                     *   있어(ingest/network.php 의 상한) 그대로 이으면 툴팁이 화면을 덮는다. */
                    $all = [];
                    foreach (array_slice($tipAddrs, 0, VG_ASSET_IP_TITLE_MAX) as $a) {
                        $iface = (string) ($a['iface'] ?? '');
                        $all[] = $a['ip'] . ($iface !== '' ? ' (' . $iface . ')' : '');
                    }
                    $title = implode(' · ', $all)
                        . (count($tipAddrs) > VG_ASSET_IP_TITLE_MAX ? ' … 외 '
                            . (count($tipAddrs) - VG_ASSET_IP_TITLE_MAX) . '개' : '');
                    $html = '<code title="' . vg_h($title) . '">' . vg_h($addrs[0]['ip']) . '</code>';
                    $rest = count($tipAddrs) - 1;
                    if ($rest > 0) {
                        // 숫자만 남는 자리라 title 로 무엇을 세는지 밝힌다(접근성).
                        $html .= ' <span class="why" title="' . vg_h($title) . '">+' . $rest . '</span>';
                    }
                    return $html;
                },
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
                // 이력이 없는(수집 없음) 자산은 vg_sparkline() 이 스스로 옅은 '–' 로 받는다.
                'trend' => fn($r) => vg_sparkline($trendByHost[(int) $r['host_id']] ?? [], [
                    'label' => 'CRITICAL·HIGH', 'unit' => '건', 'days' => VG_ASSET_TREND_DAYS,
                ]),
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
