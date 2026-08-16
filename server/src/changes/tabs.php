<?php
declare(strict_types=1);

/**
 * changes/tabs.php — 활성 탭 **하나**의 렌더 파일만 읽어 그린다(host/tabs.php 와 같은 규칙).
 *
 *   왜 하나만 읽나: 이 화면의 탭은 서로 다른 조회를 갖는다(변화 대조 벌크로드 · 패키지 변경
 *   페이징 · 회차별 추이). 조회가 활성 탭 것만 도는 것과 같은 이유로 렌더 파일도 하나만 읽는다.
 *
 *   렌더 파일은 이 함수의 지역 스코프에서 실행된다 — 페이지의 전역을 암묵적으로 주워 쓸 수
 *   없고, 쓰는 값은 호출부가 $ctx 로 열거해 넘긴 것뿐이다(빠뜨리면 그 자리에서 드러난다).
 */
function vg_change_render_tab(string $tab, array $ctx): void {
    // $tab 은 changes.php 가 화이트리스트로 확정한 값이지만, 경로 조립이므로 한 번 더 좁힌다.
    if (preg_match('/^[a-z]+$/', $tab) !== 1) { return; }
    $file = __DIR__ . '/tabs/' . $tab . '.php';
    if (!is_file($file)) { return; }
    extract($ctx, EXTR_SKIP);
    require $file;
}
