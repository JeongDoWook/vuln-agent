<?php
declare(strict_types=1);

/**
 * components/signal.php — 지표·시각 설명: KPI 스트립·판단 신호 네 축·색 범례·
 *   판단 순서. 전부 "수치와 색이 무슨 뜻인지" 를 말하는 것들이라 한 파일에 둔다.
 *   아이콘은 인라인 SVG 다 — CSP 가 default-src 'self' 라 외부 아이콘 폰트를 못 쓰고,
 *   유니코드 문자는 컬러 이모지로 렌더돼 currentColor 를 안 따라간다(#584).
 */

require_once __DIR__ . '/../../format.php';
require_once __DIR__ . '/prop.php';       // vg_kpi_strip()·vg_decision_flow() 의 vg_local_href()

/** 같은 화면의 KPI를 같은 간격·톤 규칙으로 렌더한다.
 *
 *  role="list"/"listitem" 은 두지 않는다 — 항목이 링크(<a>)일 때 role="listitem" 이 링크
 *  역할을 덮어써 스크린리더가 링크로 읽지 않는다(누를 수 있다는 사실 자체가 사라진다).
 *  리스트라는 사실보다 "누를 수 있다"가 중요한 줄이라, 네이티브 <a> 역할을 살린다.
 */
function vg_kpi_strip(array $items, array $opts = []): void {
    $tones = ['crit', 'high', 'med', 'low', 'ok', 'muted'];
    $classes = 'kpi-strip' . (!empty($opts['compact']) ? ' kpi-strip--compact' : '');
    echo '<div class="' . vg_h($classes) . '">';
    foreach ($items as $item) {
        if (!is_array($item)) { continue; }
        $value = (string) ($item['value'] ?? '–');
        $label = (string) ($item['label'] ?? '');
        $tone = (string) ($item['tone'] ?? 'muted');
        $tone = in_array($tone, $tones, true) ? $tone : 'muted';
        $numeric = str_replace(',', '', $value);
        $zero = is_numeric($numeric) && (float) $numeric === 0.0;
        $class = 'kpi' . (!empty($opts['compact']) ? ' kpi--sm' : '')
            . ' tone-' . $tone . ($zero ? ' kpi--zero' : '')
            . (!empty($item['selected']) ? ' is-selected' : '');
        $title = !empty($item['title']) ? ' title="' . vg_h((string) $item['title']) . '"' : '';
        $href = vg_local_href($item['href'] ?? null);
        $tag = $href !== null ? 'a' : 'div';
        echo '<' . $tag . ' class="' . vg_h($class) . '"'
            . ($href !== null ? ' href="' . vg_h($href) . '"' : '') . $title . '>'
            . '<b>' . vg_h($value) . '</b><span>' . vg_h($label) . '</span></' . $tag . '>';
    }
    echo '</div>';
}

/**
 * 판단 신호 네 축의 아이콘 — 단색 라인 SVG. 사이드바의 vg_nav_icon() 과 같은 방식·같은
 * 굵기 규칙을 쓴다(새 아이콘 체계를 만들지 않는다).
 *
 * 유니코드 문자(◎ ⚡ ◆ ↻)를 쓰다가 바꿨다: ⚡(U+26A1)이 환경에 따라 **컬러 이모지 폰트**로
 * 렌더돼 currentColor 를 안 따라간다 — 심각도 색을 아이콘에 싣는 설계인데 하필 '악용' 축만
 * 색이 죽었다. 나머지 셋도 한글 폰트 환경에서 광학 크기·베이스라인이 제각각이라 네 칸이
 * 나란히 서지 않았다. stroke="currentColor" 인 SVG 는 톤 토큰 색을 그대로 상속한다.
 *
 * 모양은 장식이 아니라 축의 표시다: 노출=경계 밖으로 나감 · 악용=실제로 겨냥된 표적 ·
 * 등급=위험 경고(사이드바 '탐지 결과'와 같은 삼각형) · 조치=손봐야 할 일(렌치).
 * 이스케이프가 필요 없는 정적 마크업이라 그대로 돌려준다.
 */
function vg_signal_icon(string $axis): string {
    static $paths = [
        'exposure' => '<path d="M11 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h6"/><polyline points="16 8 21 12 16 16"/><line x1="9" y1="12" x2="21" y2="12"/>',
        'exploit'  => '<circle cx="12" cy="12" r="7.5"/><circle cx="12" cy="12" r="2.5"/><line x1="12" y1="1.5" x2="12" y2="4.5"/><line x1="12" y1="19.5" x2="12" y2="22.5"/><line x1="1.5" y1="12" x2="4.5" y2="12"/><line x1="19.5" y1="12" x2="22.5" y2="12"/>',
        'severity' => '<path d="m10.29 3.86-8.4 14.55A2 2 0 0 0 3.62 21h16.76a2 2 0 0 0 1.73-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
        'action'   => '<path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/>',
    ];
    $p = $paths[$axis] ?? '<circle cx="12" cy="12" r="9"/>';
    return '<svg class="ico" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor"'
        . ' stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' . $p . '</svg>';
}

/**
 * 판단 신호를 노출→악용→등급→조치의 고정 네 칸으로 렌더한다.
 * 값이 없는 도메인은 state=na, 아직 받은 값이 없으면 state=unknown을 쓴다.
 */
function vg_signal_slots(array $signals): void {
    $axes = [
        'exposure' => ['label' => '노출'],
        'exploit'  => ['label' => '악용'],
        'severity' => ['label' => '등급'],
        'action'   => ['label' => '조치'],
    ];
    $tones = ['crit', 'high', 'med', 'low', 'ok', 'muted'];
    $states = ['value', 'na', 'unknown'];
    echo '<div class="signal-slots" role="group" aria-label="판단 신호">';
    foreach ($axes as $axis => $meta) {
        $spec = is_array($signals[$axis] ?? null) ? $signals[$axis] : [];
        $state = (string) ($spec['state'] ?? ($spec ? 'value' : 'unknown'));
        $state = in_array($state, $states, true) ? $state : 'unknown';
        $tone = (string) ($spec['tone'] ?? 'muted');
        $tone = $state === 'value' && in_array($tone, $tones, true) ? $tone : 'muted';
        $value = $state === 'na' ? '해당 없음' : ($state === 'unknown' ? '미제공' : (string) ($spec['value'] ?? '미제공'));
        // 아이콘은 정적 SVG 마크업이라 이스케이프하지 않는다(접근성은 옆의 텍스트 라벨이 담당).
        echo '<span class="signal-slot signal-slot--' . vg_h($axis) . ' tone-' . vg_h($tone)
            . '" data-axis="' . vg_h($axis) . '" data-state="' . vg_h($state) . '">'
            . '<span class="signal-slot__icon" aria-hidden="true">' . vg_signal_icon($axis) . '</span>'
            . '<span class="signal-slot__text"><small>' . vg_h($meta['label']) . '</small>'
            . '<b>' . vg_h($value) . '</b></span></span>';
    }
    echo '</div>';
}

/**
 * 색 범례 — 화면의 색이 무슨 뜻인지 점과 단어로만 말한다(문장 금지).
 *   심각도 4단계·노출 범위·PASS/FAIL 처럼 색으로 등급을 말하는 화면은 그 색을 처음 보는
 *   사람이 읽을 수 없다. 그 한 줄을 채우는 자리다.
 *
 *   마크업·색은 도넛 옆 범례(.legend)를 그대로 쓴다 — 같은 것을 두 벌 만들지 않는다(DRY).
 *   index.php·host.php 가 인라인으로 갖고 있는 같은 마크업은 다음 웨이브에서 이 헬퍼로 모은다.
 *
 *   $items: [['label'=>'CRITICAL', 'tone'=>'crit', 'n'=>12], …]  ('n' 은 선택 — 건수)
 *   $opts:  'inline' — 한 줄로 눕힌다(.legend--inline). 'caption' — 앞에 붙는 짧은 제목('심각도').
 *
 *   새 색을 만들지 않는다: 톤 어휘(crit/high/med/low/ok/muted/info/purple)만 받고,
 *   어휘 밖 값은 muted 로 눕힌다(vg_badge()·vg_sev_row() 와 같은 규칙).
 */
function vg_legend(array $items, array $opts = []): void {
    $tones = ['crit', 'high', 'med', 'low', 'ok', 'muted', 'info', 'purple'];
    $items = array_values(array_filter($items, 'is_array'));
    if (!$items) { return; }

    $class = 'legend' . (!empty($opts['inline']) ? ' legend--inline' : '');
    $caption = (string) ($opts['caption'] ?? '');
    echo '<div class="' . vg_h($class) . '" role="group" aria-label="' . vg_h($caption !== '' ? $caption . ' 범례' : '범례') . '">';
    if ($caption !== '') {
        echo '<span class="legend__cap">' . vg_h($caption) . '</span>';
    }
    foreach ($items as $item) {
        $tone = (string) ($item['tone'] ?? 'muted');
        $tone = in_array($tone, $tones, true) ? $tone : 'muted';
        echo '<div><i class="tone-' . vg_h($tone) . '"></i><span>' . vg_h((string) ($item['label'] ?? '')) . '</span>';
        if (($item['n'] ?? null) !== null) {
            echo '<span class="n">' . number_format((int) $item['n']) . '</span>';
        }
        echo '</div>';
    }
    echo '</div>';
}

/** 위험/근거에서 재검증까지 이어지는 상세 화면의 공통 판단 순서. */
function vg_decision_flow(array $steps): void {
    echo '<nav class="decision-flow" data-decision-flow aria-label="판단과 조치 순서"><ol>';
    foreach (array_values($steps) as $i => $step) {
        $href = vg_local_href($step['href'] ?? null) ?? '#';
        echo '<li><a href="' . vg_h($href) . '"><b>' . number_format($i + 1) . '</b><span>'
            . vg_h((string) ($step['label'] ?? '')) . '</span><small>'
            . vg_h((string) ($step['hint'] ?? '')) . '</small></a></li>';
    }
    echo '</ol></nav>';
}
