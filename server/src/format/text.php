<?php
declare(strict_types=1);

/**
 * format/text.php — 문자열 자체를 다루는 것들: 이스케이프 · 말줄임 · 도움말 툴팁.
 *   다른 포맷 파일이 전부 이 파일의 vg_h() 위에 선다(그래서 format.php 가 제일 먼저 require 한다).
 */

function vg_h(?string $s): string {
    return htmlspecialchars((string) $s, ENT_QUOTES, 'UTF-8');
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

/**
 * 접두 일치(`x%`) LIKE 패턴. 사용자가 넣은 %·_ 는 와일드카드가 아니라 글자로 다룬다.
 * 부분 일치(`%x%`)가 필요한 화면은 앞에 '%' 를 하나 더 붙여 쓴다(`'%' . vg_like_prefix($s)`) —
 * 이 함수가 이미 값 뒤에 '%' 를 붙이므로 앞만 더하면 양끝 와일드카드가 된다.
 */
function vg_like_prefix(string $s): string {
    return addcslashes($s, '\\%_') . '%';
}
