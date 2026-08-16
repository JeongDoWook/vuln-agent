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
function vg_host_render_tab(string $tab, array $ctx): void {
    // $tab 은 host.php 가 화이트리스트($validTabs)로 확정한 값이지만, 경로 조립이므로 한 번 더 좁힌다.
    if (preg_match('/^[a-z]+$/', $tab) !== 1) { return; }
    $file = __DIR__ . '/tabs/' . $tab . '.php';
    if (!is_file($file)) { return; }
    extract($ctx, EXTR_SKIP);
    require $file;
}
