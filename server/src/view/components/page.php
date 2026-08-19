<?php
declare(strict_types=1);

/**
 * components/page.php — 페이지 뼈대: 제목 줄·상세 히어로·섹션 탭.
 *   "지금 무엇을 보고 있나" 만 화면 위쪽에 세운다. 화면을 해설하는 부제·결론 문장은 두지 않는다.
 */

require_once __DIR__ . '/../../format.php';
require_once __DIR__ . '/paging.php';   // vg_subtabs() 의 기본 href 가 vg_qs() 를 쓴다.
require_once __DIR__ . '/../icons.php'; // vg_subtabs() 가 탭 정의의 선택적 'icon' 키를 vg_icon() 으로 그린다.

/**
 * 화면 제목 — **카드가 아니라 얇은 헤더 줄이다.** 예전엔 흰 카드로 세로 150px 를 먹었는데
 * 담긴 건 제목 + 설명 한 줄뿐이라, 1440×675 첫 화면에서 정작 표가 두 행밖에 안 보였다.
 * 부제 인자($description)는 없앴다 — 화면을 해설하는 줄은 두지 않는다는 규약이 생겨
 * 호출부 전부가 빈 문자열을 넘기게 됐고, 인자가 남아 있으면 다시 문장이 자란다.
 * 두 번째 인자 $eyebrow('OVERVIEW' 등)는 예전에도 화면에 안 그렸고 지금도 안 그린다.
 * 자리만 지키는 인자다.
 */
function vg_page_title(string $title, string $eyebrow, array $opts = []): void {
    $class = trim('page-title ' . (!empty($opts['actions']) ? 'page-title--actions ' : '') . (string) ($opts['class'] ?? ''));
    echo '<header class="' . vg_h($class) . '"><div class="page-title__text"><h1>' . vg_h($title);
    if (array_key_exists('count', $opts)) { echo ' <span class="hint">(' . number_format((int) $opts['count']) . vg_h((string) ($opts['count_label'] ?? '건')) . ')</span>'; }
    if (!empty($opts['hint'])) { echo ' <span class="hint">' . vg_h((string) $opts['hint']) . '</span>'; }
    if (!empty($opts['suffix_html'])) { echo ' ' . (string) $opts['suffix_html']; }
    echo '</h1>';
    echo '</div>';
    if (!empty($opts['actions'])) { echo '<div class="page-title__actions">' . $opts['actions'] . '</div>'; }
    echo '</header>';
}

/* 화면 결론 배너(vg_verdict)는 없앴다 — 한 문장으로 결론을 말하고 숫자를 붙이던 자리인데,
 *   그 문장은 바로 아래 표·KPI 가 이미 가진 값을 되풀이하는 해설이었다. 목록 화면은 값만
 *   세우고 판단은 상세에서 한다. `.verdict*` 규칙도 app.css 에서 같이 걷었다. */

/**
 * 상세 페이지 히어로 — "무엇을 보고 있나(좌) + 얼마나 위험한가(우)".
 * 왼쪽 띠 색이 위험도다. host.php 가 인라인으로 갖고 있던 것을 공용으로 뺐다.
 *   $title·$meta 는 이미 이스케이프된 HTML (호출부가 vg_h 책임 — 링크·뱃지를 섞어 넣어야 해서).
 *   $riskLabel 이 null 이면 위험도 칸 없이 식별부만.
 *   $riskTone 은 톤 어휘(crit/high/med/low/ok/muted). 라벨과 톤을 분리한 건 "양호" 처럼
 *   심각도 어휘에 없는 라벨을 써야 할 때가 있기 때문이다(vg_sev_tone 은 그걸 muted 로 떨군다).
 */
function vg_hero(string $title, array $meta = [], ?string $riskLabel = null, string $riskTone = 'ok', string $riskCap = '최고 위험도', string $eyebrow = 'DETAIL', ?string $actions = null): void {
    echo '<div class="hero hero--' . vg_h($riskLabel !== null ? $riskTone : 'ok') . '">';
    echo '<div class="hero__id"><h1>' . $title . '</h1>';
    if ($meta) {
        echo '<div class="hero__meta">' . implode(' <span class="why">·</span> ', $meta) . '</div>';
    }
    echo '</div>';
    if ($riskLabel !== null) {
        echo '<div class="hero__risk"><span class="badge tone-' . vg_h($riskTone) . ' badge--lg">' . vg_h($riskLabel) . '</span>'
            . '<span class="cap">' . vg_h($riskCap) . '</span></div>';
    }
    if ($actions !== null) {
        echo '<div class="hero__actions">' . $actions . '</div>';
    }
    echo '</div>';
}

/**
 * 섹션 탭(밑줄형). 첫 화면에 다 쏟지 않고 갈래로 나눠 담는 자리.
 *   $tabs: ['vuln' => ['label'=>'취약점', 'n'=>12], 'runtime' => ['label'=>'런타임', 'n'=>null], …]
 *   'n' 이 null 이 아니면 라벨 옆에 건수를 붙인다. href 를 주면 별도 페이지로 이동하고,
 *   없으면 같은 페이지의 ?tab= 값을 바꾼다.
 *   'icon' (선택) — icons.php 의 아이콘 이름. 없으면 지금까지처럼 아이콘 없이 그린다.
 *   'group' (선택) — 인접한 두 탭의 group 이 서로 다르면 그 경계에 옅은 구분선을 넣는다
 *   (host.php 의 "위협/자산 구성/이력" 묶음처럼 탭이 많은 화면에서만 쓴다 — 안 주면 지금까지의
 *   화면(packages.php 등)은 구분선 없이 그대로다).
 */
function vg_subtabs(array $tabs, string $active): void {
    echo '<nav class="subtabs">';
    $prevGroup = null;
    foreach ($tabs as $key => $def) {
        $group = $def['group'] ?? null;
        $classes = [];
        if ($active === (string) $key) { $classes[] = 'on'; }
        if ($group !== null && $prevGroup !== null && $group !== $prevGroup) { $classes[] = 'subtabs__sep'; }
        if ($group !== null) { $prevGroup = $group; }
        $cls = $classes ? ' class="' . vg_h(implode(' ', $classes)) . '"' : '';
        $href = (string) ($def['href'] ?? vg_qs(['tab' => $key, 'page' => null]));
        echo '<a' . $cls . ' href="' . vg_h($href) . '">';
        if (!empty($def['icon'])) { echo vg_icon((string) $def['icon']); }
        echo vg_h((string) ($def['label'] ?? $key));
        if (($def['n'] ?? null) !== null) {
            echo '<span class="n">' . number_format((int) $def['n']) . '</span>';
        }
        echo '</a>';
    }
    echo '</nav>';
}
