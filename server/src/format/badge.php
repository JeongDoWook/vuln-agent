<?php
declare(strict_types=1);

/**
 * format/badge.php — 톤 프리미티브. "무엇을 말하는가"가 아니라 "어떤 모양으로 말하는가"만 안다.
 *   색은 CSS 의 .tone-* 과 .meter--* 가 정한다 — PHP 는 톤 이름만 고른다.
 *   심각도·상태·자산상태 등 어휘 파일들이 전부 이 두 함수를 통해 마크업을 낸다.
 */

/** 임의의 라벨을 톤 뱃지로. $label 은 여기서 이스케이프한다. */
function vg_badge(string $label, string $tone = 'muted', string $title = ''): string {
    return '<span class="badge tone-' . vg_h($tone) . '"'
        . ($title !== '' ? ' title="' . vg_h($title) . '"' : '')
        . '>' . vg_h($label) . '</span>';
}

/**
 * 값 게이지(진행바) 마크업 — "0~100 중 어디" 를 시각적으로 보인다. 숫자만으로는 크기 감이 안 온다.
 *   cve.php(CVSS)·packages.php(최고 EPSS·조치 완료율)가 공유한다. $tone 은 meter-- 뒤 클래스
 *   (crit/high/med/low). $pct 는 채움 비율(%) — 0~100 밖은 잘라낸다.
 *   width:N% 인라인은 app.css 규칙의 명시적 예외(게이지 폭 계산).
 *
 *   $label 은 "이 막대가 무엇의 값인지" — 같은 행에 EPSS 게이지와 조치율 게이지가 나란히 서면
 *   모양이 같아서 화면만 봐선 구분이 안 된다. 값까지 포함해 그 자체로 읽히게 넘긴다
 *   (예: '최고 EPSS 99.9%'). title(마우스)·aria-label(스크린리더) 양쪽으로 나간다.
 *   기본 null — 안 넘기면 예전과 똑같은 마크업이다.
 */
function vg_meter(string $tone, float $pct, ?string $label = null): string {
    $pct  = max(0.0, min(100.0, $pct));
    $attr = ($label !== null && $label !== '')
        ? ' title="' . vg_h($label) . '" aria-label="' . vg_h($label) . '"'
        : '';
    return '<div class="meter meter--' . vg_h($tone) . '"' . $attr . '>'
         . '<i style="width:' . number_format($pct, 1) . '%"></i></div>';
}
