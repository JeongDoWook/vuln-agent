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
 *   억제 탭은 건이 있을 때만 존재하는데, 이 규칙은 host.php 의 $validTabs 와 **같은 조건**이다
 *   (없는 탭을 그리면 눌렀을 때 기본 탭으로 떨어진다).
 */
function vg_host_tab_defs(array $n): array {
    $tabDefs = [
        'vuln'    => ['label' => '취약점',    'n' => $n['vulnTotal']],
        'packages'=> ['label' => '설치 패키지', 'n' => $n['packageTotal']],
        // 컨테이너 대장 — 호스트와 OS 가 다를 수 있는 별도 자산이라 목록을 따로 준다.
        'containers'=> ['label' => '컨테이너', 'n' => $n['containerTotal']],
        // 이 탭은 노출 소켓과 실행 프로세스 두 목록을 함께 제공하므로 둘의 합계를 표시한다.
        'runtime' => ['label' => '런타임',    'n' => $n['runtimeTotal']],
        'cce'     => ['label' => '보안 설정', 'n' => $n['cceFail']],
        // 계정 대장 — "설정 정책"이 아니라 실제로 존재하는 계정(ISMS-P 2.5.x · N2SF AC).
        'accounts'=> ['label' => '계정',      'n' => $n['accountTotal']],
    ];
    if ($n['suppressedCount'] > 0) { $tabDefs['suppressed'] = ['label' => '억제', 'n' => $n['suppressedCount']]; }
    // 스캔 이력 = 회차 표 + 그 회차들의 에이전트 리소스 추이(예전 '리소스' 탭을 흡수).
    $tabDefs['scans'] = ['label' => '스캔 이력', 'n' => $n['scanTotal']];
    /* 자산 설정 = 수집 제어 + 자산 등급 + 자산 삭제. 위험을 읽는 탭들 뒤에 둔다.
     *   등급 카드·삭제 카드는 예전엔 **모든 탭 아래**에 매번 붙어 있었다 — 취약점을 보러 온
     *   사람이 탭을 옮길 때마다 열 칸짜리 등급 확정 폼을 지나쳐야 했다. 한 곳으로 모은다. */
    $tabDefs['manage'] = ['label' => '자산 설정', 'n' => null];
    return $tabDefs;
}

function vg_host_render_tab(string $tab, array $ctx): void {
    // $tab 은 host.php 가 화이트리스트($validTabs)로 확정한 값이지만, 경로 조립이므로 한 번 더 좁힌다.
    if (preg_match('/^[a-z]+$/', $tab) !== 1) { return; }
    $file = __DIR__ . '/tabs/' . $tab . '.php';
    if (!is_file($file)) { return; }
    extract($ctx, EXTR_SKIP);
    require $file;
}
