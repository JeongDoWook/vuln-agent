<?php
declare(strict_types=1);

/**
 * findings/tabs.php — 활성 탭 **하나**의 렌더 파일만 읽어 그린다(host/tabs.php 와 같은 규칙).
 *
 *   왜 하나만 읽나: 탐지 유형 세 탭은 서로 다른 표(tb_finding·tb_cce_finding·tb_exposure)를
 *   보고, 조회도 활성 탭 것만 돈다(합치면 인덱스가 죽는다 — queries.php 머리주석). 렌더도
 *   같은 규칙을 파일 구조로 못박는다.
 *
 *   렌더 파일은 이 함수의 지역 스코프에서 실행된다 — 페이지의 전역을 암묵적으로 주워 쓸 수
 *   없고, 쓰는 값은 호출부가 $ctx 로 열거해 넘긴 것뿐이다(빠뜨리면 그 자리에서 드러난다).
 */
function vg_findings_render_tab(string $type, array $ctx): void {
    // $type 은 findings.php 가 화이트리스트(VG_FINDING_TYPES)로 확정한 값이지만,
    //   경로 조립이므로 한 번 더 좁힌다.
    if (preg_match('/^[a-z]+$/', $type) !== 1) { return; }
    $file = __DIR__ . '/tabs/' . $type . '.php';
    if (!is_file($file)) { return; }
    extract($ctx, EXTR_SKIP);
    require $file;
}
