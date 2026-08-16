<?php
declare(strict_types=1);

/**
 * cve/sections.php — CVE 상세(cve.php)의 섹션 렌더 디스패처.
 *
 *   자산 상세(host/tabs.php)와 달리 여기 섹션들은 **한 화면에 전부** 그려진다(탭이 아니라
 *   앵커 내비다). 그래도 파일을 가르는 이유는 같다 — 한 파일에 6백 줄이 쌓이면 어느 섹션이
 *   무엇을 쓰는지가 안 보이고, 세 섹션이 각자 다른 페이저 파라미터를 쓰는 이 화면에선
 *   그 경계가 곧 버그 경계다(#278).
 *
 *   렌더 파일은 이 함수의 지역 스코프에서 실행된다. 그래서 페이지의 전역을 암묵적으로 주워 쓸
 *   수 없고, 쓰는 값은 호출부가 $ctx 로 열거해 넘긴 것뿐이다(빠뜨리면 그 자리에서 드러난다).
 */
function vg_cve_render_section(string $name, array $ctx): void {
    // 호출부가 리터럴로만 부르지만 경로 조립이므로 한 번 더 좁힌다(host/tabs.php 와 같은 규약).
    if (preg_match('/^[a-z]+$/', $name) !== 1) { return; }
    $file = __DIR__ . '/sections/' . $name . '.php';
    if (!is_file($file)) { return; }
    extract($ctx, EXTR_SKIP);
    require $file;
}
