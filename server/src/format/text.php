<?php
declare(strict_types=1);

/**
 * format/text.php — 문자열 자체를 다루는 것들: 이스케이프 · 말줄임 · 도움말 툴팁.
 *   다른 포맷 파일이 전부 이 파일의 vg_h() 위에 선다(그래서 format.php 가 제일 먼저 require 한다).
 */

function vg_h(?string $s): string {
    return htmlspecialchars((string) $s, ENT_QUOTES, 'UTF-8');
}

/**
 * 표시 직전에만 쓰는 경량 필터 — 제어문자·양방향 오버라이드(U+202E 등)를 지운다.
 *   에스케이프(vg_h)는 HTML 인젝션은 막아도 "화면에 뭐라고 보이는가"는 안 바꾼다. SBOM
 *   컴포넌트 name/license/vendor 는 스캔 대상이 준 원문을 그대로 저장하므로, 파일명을
 *   역순으로 보이게 하는 RLO 문자 같은 걸 심어도 vg_h 만으로는 안 걸러진다. DB 원문은
 *   그대로 두고(감사 증거) 화면에 뿌릴 값만 걸러낸다.
 */
function vg_strip_ctrl(?string $s): string {
    return preg_replace('/[\x00-\x1F\x7F\x{200E}\x{200F}\x{202A}-\x{202E}\x{2066}-\x{2069}]/u', '', (string) $s) ?? '';
}

// 긴 텍스트 말줄임 + 툴팁(title 에 원문). 안 잘리면 그냥 이스케이프만.
function vg_trunc(?string $text, int $len = 72): string {
    $text = (string) $text;
    $cut = mb_strimwidth($text, 0, $len, '…');
    if ($cut === $text) {
        return vg_h($text);
    }
    return '<span class="trunc" title="' . vg_h($text) . '">' . vg_h($cut) . '</span>';
}

/**
 * 도움말 툴팁. 본문에 늘어놓으면 화면이 무거워지는 부연설명을 아이콘 뒤로 보낸다.
 * 공통 data-tip 레이어를 쓴다. 브라우저 기본 title 의 지연과 OS별 모양 차이를 피한다.
 */
function vg_help(string $text): string {
    return '<span class="help" data-tip="' . vg_h($text) . '" aria-label="' . vg_h($text)
        . '" tabindex="0" role="note">?</span>';
}
