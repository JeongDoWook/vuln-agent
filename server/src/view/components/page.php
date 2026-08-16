<?php
declare(strict_types=1);

/**
 * components/page.php — 페이지 뼈대: 제목 줄·결론 배너·상세 히어로·섹션 탭.
 *   "이 화면이 무엇이고 결론이 무엇인가" 를 화면 위쪽에 세우는 것들이다.
 */

require_once __DIR__ . '/../../format.php';
require_once __DIR__ . '/paging.php';   // vg_subtabs() 의 기본 href 가 vg_qs() 를 쓴다.

/**
 * 화면 제목 — **카드가 아니라 얇은 헤더 줄이다.** 예전엔 흰 카드로 세로 150px 를 먹었는데
 * 담긴 건 제목 + 설명 한 줄뿐이라, 1440×675 첫 화면에서 정작 표가 두 행밖에 안 보였다.
 * 시그니처는 그대로 둔다(호출부 41곳) — 두 번째 인자 $eyebrow('OVERVIEW' 등)는 예전에도
 * 화면에 안 그렸고 지금도 안 그린다. 자리만 지키는 인자다.
 */
function vg_page_title(string $title, string $eyebrow, string $description = '', array $opts = []): void {
    $class = trim('page-title ' . (!empty($opts['actions']) ? 'page-title--actions ' : '') . (string) ($opts['class'] ?? ''));
    echo '<header class="' . vg_h($class) . '"><div class="page-title__text"><h1>' . vg_h($title);
    if (array_key_exists('count', $opts)) { echo ' <span class="hint">(' . number_format((int) $opts['count']) . vg_h((string) ($opts['count_label'] ?? '건')) . ')</span>'; }
    if (!empty($opts['hint'])) { echo ' <span class="hint">' . vg_h((string) $opts['hint']) . '</span>'; }
    if (!empty($opts['suffix_html'])) { echo ' ' . (string) $opts['suffix_html']; }
    echo '</h1>';
    if ($description !== '') { echo '<p>' . vg_h($description) . '</p>'; }
    echo '</div>';
    if (!empty($opts['actions'])) { echo '<div class="page-title__actions">' . $opts['actions'] . '</div>'; }
    echo '</header>';
}

/**
 * 화면 결론 배너 — "이 화면이 무엇을 증명하는가" 를 수치와 함께 한 줄로 세운다.
 *   표와 KPI 는 값을 보여줄 뿐 결론을 말하지 않는다. 그래서 화면을 열고도 "그래서 뭐가
 *   된다는 거지" 가 남는다 — 그 한 줄을 화면 최상단(제목 바로 아래)에 놓는 자리다.
 *
 *   $tone     : ok|warn|crit|muted — 왼쪽 띠와 배경 톤
 *   $headline : 결론 한 문장 (예: "통제 5종 중 1종 준수 · 2종 부분준수 · 1종 미준수")
 *   $stats    : [['label'=>'준수','value'=>'1','tone'=>'ok'], …] — 큰 숫자로 나열(톤 생략 가능)
 *   $note     : 판단 근거·기준시각 등 작은 보조 한 줄 (선택)
 *
 *   compliance.php 라면 이렇게 부른다:
 *     vg_verdict('warn',
 *         '통제 5종 중 1종 준수 · 2종 부분준수 · 1종 미준수 · 1종 판정불가',
 *         [['label' => '준수', 'value' => '1', 'tone' => 'ok'],
 *          ['label' => '부분준수', 'value' => '2', 'tone' => 'warn'],
 *          ['label' => '미준수', 'value' => '1', 'tone' => 'crit'],
 *          ['label' => '판정불가', 'value' => '1', 'tone' => 'muted']],
 *         '기준: 2026-08-12 03:00 수집분 · 자산 12대 전수');
 *
 *   삽입은 각 화면(다음 작업)에서 한다 — 여기서는 컴포넌트와 표현만 정의한다.
 */
function vg_verdict(string $tone, string $headline, array $stats = [], string $note = ''): void {
    $tone = in_array($tone, ['ok', 'warn', 'crit', 'muted'], true) ? $tone : 'muted';
    echo '<div class="verdict verdict--' . vg_h($tone) . '" role="status">';
    echo '<div class="verdict__main"><strong class="verdict__headline">' . vg_h($headline) . '</strong>';
    if ($note !== '') {
        echo '<span class="verdict__note">' . vg_h($note) . '</span>';
    }
    echo '</div>';
    if ($stats) {
        echo '<div class="verdict__stats">';
        foreach ($stats as $s) {
            $st = (string) ($s['tone'] ?? '');
            $cls = 'verdict__stat' . (in_array($st, ['ok', 'warn', 'crit', 'muted'], true) ? ' verdict__stat--' . $st : '');
            echo '<div class="' . vg_h($cls) . '"><b>' . vg_h((string) ($s['value'] ?? '–')) . '</b>'
                . '<span>' . vg_h((string) ($s['label'] ?? '')) . '</span></div>';
        }
        echo '</div>';
    }
    echo '</div>';
}

/**
 * 상세 페이지 히어로 — "무엇을 보고 있나(좌) + 얼마나 위험한가(우)".
 * 왼쪽 띠 색이 위험도다. host.php 가 인라인으로 갖고 있던 것을 공용으로 뺐다.
 *   $title·$meta 는 이미 이스케이프된 HTML (호출부가 vg_h 책임 — 링크·뱃지를 섞어 넣어야 해서).
 *   $riskLabel 이 null 이면 위험도 칸 없이 식별부만.
 *   $riskTone 은 톤 어휘(crit/high/med/low/ok/muted). 라벨과 톤을 분리한 건 "양호" 처럼
 *   심각도 어휘에 없는 라벨을 써야 할 때가 있기 때문이다(vg_sev_tone 은 그걸 muted 로 떨군다).
 */
function vg_hero(string $title, array $meta = [], ?string $riskLabel = null, string $riskTone = 'ok', string $riskCap = '최고 위험도', string $eyebrow = 'DETAIL'): void {
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
    echo '</div>';
}

/**
 * 섹션 탭(밑줄형). 첫 화면에 다 쏟지 않고 갈래로 나눠 담는 자리.
 *   $tabs: ['vuln' => ['label'=>'취약점', 'n'=>12], 'runtime' => ['label'=>'런타임', 'n'=>null], …]
 *   'n' 이 null 이 아니면 라벨 옆에 건수를 붙인다. href 를 주면 별도 페이지로 이동하고,
 *   없으면 같은 페이지의 ?tab= 값을 바꾼다.
 */
function vg_subtabs(array $tabs, string $active): void {
    echo '<nav class="subtabs">';
    foreach ($tabs as $key => $def) {
        $cls = $active === (string) $key ? ' class="on"' : '';
        $href = (string) ($def['href'] ?? vg_qs(['tab' => $key, 'page' => null]));
        echo '<a' . $cls . ' href="' . vg_h($href) . '">'
            . vg_h((string) ($def['label'] ?? $key));
        if (($def['n'] ?? null) !== null) {
            echo '<span class="n">' . number_format((int) $def['n']) . '</span>';
        }
        echo '</a>';
    }
    echo '</nav>';
}
