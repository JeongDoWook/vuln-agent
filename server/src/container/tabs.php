<?php
declare(strict_types=1);

/**
 * container/tabs.php — 활성 탭 **하나**의 렌더 파일만 읽어 그린다(host/tabs.php 와 같은 규약).
 *
 *   렌더 파일은 이 함수의 지역 스코프에서 실행된다. 그래서 페이지의 전역을 암묵적으로 주워 쓸
 *   수 없고, 쓰는 값은 호출부가 $ctx 로 열거해 넘긴 것뿐이다(빠뜨리면 그 자리에서 드러난다).
 */
function vg_container_render_tab(string $tab, array $ctx): void {
    // $tab 은 container.php 가 화이트리스트($validTabs)로 확정한 값이지만, 경로 조립이므로 한 번 더 좁힌다.
    if (preg_match('/^[a-z]+$/', $tab) !== 1) { return; }
    $file = __DIR__ . '/tabs/' . $tab . '.php';
    if (!is_file($file)) { return; }
    extract($ctx, EXTR_SKIP);
    require $file;
}
