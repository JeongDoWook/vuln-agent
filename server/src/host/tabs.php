<?php
declare(strict_types=1);

/**
 * host/tabs.php — 활성 탭 **하나**의 렌더 파일만 읽어 그린다.
 *
 *   왜 파일을 나눠 두고 하나만 읽나: 자산 상세는 탭마다 무거운 조회를 갖는다(설치 패키지·
 *   컨테이너·런타임). 한 화면에서 전부 돌면 화면이 느려지고 페이저도 서로 엉킨다(PR #579) —
 *   "활성 탭 것만" 이라는 규칙을 조회(host.php 의 분기)에 이어 **파일 구조로도 못박는다.**
 *
 *   렌더 파일은 이 함수의 지역 스코프에서 실행된다. 그래서 페이지의 전역을 암묵적으로 주워 쓸
 *   수 없고, 쓰는 값은 호출부가 $ctx 로 열거해 넘긴 것뿐이다(빠뜨리면 그 자리에서 드러난다).
 */
/**
 * 탭 줄 정의(배열 순서 = 표시 순서). n 은 라벨 옆 숫자(null 이면 숨김).
 *   숫자는 이미 센 값($n)을 그대로 받는다 — 탭 줄을 그리려고 다시 세지 않는다.
 *   여기 담긴 키가 곧 탭 줄에 서는 탭이다. host.php 의 $validTabs 는 그보다 넓다 —
 *   'suppressed' 는 URL 로는 유효하지만 탭이 아니라 취약점 탭의 필터로 그려진다.
 *
 *   'icon' 은 icons.php 의 이름, 'group' 은 vg_subtabs() 가 인접 탭과 비교해 구분선을 넣는
 *   묶음 키다(사용자 피드백 — "탭이 그냥 막 나열되어 있는 느낌"). 8개를 셋으로 나눈다:
 *   위협(취약점·보안 설정) · 자산 구성(패키지·컨테이너·런타임·계정) · 이력/관리(스캔 이력·자산 설정).
 *   탭이 가리키는 조회·URL 은 그대로다 — 순서와 시각 묶음만 더한다.
 */
function vg_host_tab_defs(array $n): array {
    $tabDefs = [
        'vuln'    => ['label' => '취약점',    'n' => $n['vulnTotal'], 'icon' => 'cve', 'group' => 'threat'],
        'cce'     => ['label' => '보안 설정', 'n' => $n['cceFail'], 'icon' => 'shield', 'group' => 'threat'],
        'packages'=> ['label' => '설치 패키지', 'n' => $n['packageTotal'], 'icon' => 'package', 'group' => 'asset'],
        // 컨테이너 대장 — 호스트와 OS 가 다를 수 있는 별도 자산이라 목록을 따로 준다.
        'containers'=> ['label' => '컨테이너', 'n' => $n['containerTotal'], 'icon' => 'container', 'group' => 'asset'],
        // 이 탭은 노출 소켓과 실행 프로세스 두 목록을 함께 제공하므로 둘의 합계를 표시한다.
        'runtime' => ['label' => '런타임',    'n' => $n['runtimeTotal'], 'icon' => 'process', 'group' => 'asset'],
        // 계정 대장 — "설정 정책"이 아니라 실제로 존재하는 계정(ISMS-P 2.5.x · N2SF AC).
        'accounts'=> ['label' => '계정',      'n' => $n['accountTotal'], 'icon' => 'user', 'group' => 'asset'],
    ];
    /* '억제' 는 탭이 아니다 — 취약점 탭 안의 **보기 필터**다(vg_host_render_risk_views).
     *   ?tab=suppressed 는 URL 로 그대로 살아 있지만(북마크·기존 링크) 탭 줄에는 서지 않는다. */
    // 스캔 이력 = 회차 표 + 그 회차들의 에이전트 리소스 추이(예전 '리소스' 탭을 흡수).
    $tabDefs['scans'] = ['label' => '스캔 이력', 'n' => $n['scanTotal'], 'icon' => 'clock', 'group' => 'meta'];
    /* 자산 설정 = 수집 제어 + 자산 등급 + 자산 삭제. 위험을 읽는 탭들 뒤에 둔다.
     *   등급 카드·삭제 카드는 예전엔 **모든 탭 아래**에 매번 붙어 있었다 — 취약점을 보러 온
     *   사람이 탭을 옮길 때마다 열 칸짜리 등급 확정 폼을 지나쳐야 했다. 한 곳으로 모은다. */
    $tabDefs['manage'] = ['label' => '자산 설정', 'n' => null, 'icon' => 'settings', 'group' => 'meta'];
    return $tabDefs;
}

/**
 * 탭 줄 — **한 줄(1단)** 로 그린다.
 *
 *   예전엔 상위 4개(위험·구성·준거·이력) + 그 그룹의 하위 줄로 된 2단이었다(vg_asset_tabs).
 *   탭 수를 줄이려던 것인데, 실제로는 "탭을 타고 타고" 들어가야 목적지가 나와서 더 멀어졌다
 *   (사용자 피드백). 깊이를 1단으로 되돌리되 **폭은 늘리지 않는다** — 억제를 취약점 탭의
 *   필터로 내려 탭 자체를 하나 줄였다(9개 → 8개).
 *
 *   href 는 여기서 직접 만든다. vg_subtabs 의 기본값은 page 만 지우는데, 검색어(q)·노출
 *   페이지(epage)·계정 필터(acc)는 탭마다 다른 목록을 가리켜 그대로 넘기면 빈 표가 뜬다.
 */
function vg_host_render_tabline(array $tabDefs, string $tab): void {
    // 억제 목록을 보고 있어도 탭 줄이 가리키는 곳은 '취약점' 이다(그 탭의 한 보기이므로).
    $active = $tab === 'suppressed' ? 'vuln' : $tab;
    foreach ($tabDefs as $key => $def) {
        $tabDefs[$key]['href'] = vg_qs([
            'tab' => $key, 'page' => null, 'epage' => null, 'q' => null, 'acc' => null,
        ]);
    }
    vg_subtabs($tabDefs, $active);
}

/**
 * 위험 탭의 보기 전환(취약점 ↔ 억제됨) — 탭이 아니라 필터다.
 *
 *   억제는 "왜 안전한지 남긴 근거"라 계속 보여야 하지만, 두 목록은 테이블도 열도 달라
 *   한 표로 합칠 수 없다(tb_finding vs tb_suppressed_finding — 합치면 UNION 이 되어
 *   페이지네이션이 인덱스를 못 탄다). **쿼리는 그대로 둔 채 진입만 한 층 위로 올린다.**
 *   억제가 0건이면 고를 것이 하나뿐이라 아예 그리지 않는다.
 */
function vg_host_render_risk_views(string $tab, int $vulnTotal, int $suppressedCount): void {
    if ($suppressedCount <= 0) { return; }
    $views = [
        'vuln'       => '취약점 ' . number_format($vulnTotal),
        'suppressed' => '억제됨 ' . number_format($suppressedCount),
    ];
    echo '<div class="tabs">';
    foreach ($views as $key => $label) {
        $href = vg_qs(['tab' => $key, 'page' => null, 'q' => null]);
        echo '<a class="pill' . ($tab === $key ? ' pill--on' : '') . '" href="' . vg_h($href) . '">'
            . vg_h($label) . '</a>';
    }
    echo '</div>';
}

function vg_host_render_tab(string $tab, array $ctx): void {
    // $tab 은 host.php 가 화이트리스트($validTabs)로 확정한 값이지만, 경로 조립이므로 한 번 더 좁힌다.
    if (preg_match('/^[a-z]+$/', $tab) !== 1) { return; }
    $file = __DIR__ . '/tabs/' . $tab . '.php';
    if (!is_file($file)) { return; }
    extract($ctx, EXTR_SKIP);
    require $file;
}
