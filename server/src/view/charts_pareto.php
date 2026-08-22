<?php
declare(strict_types=1);

/**
 * charts_pareto.php — 파레토(막대=건수 내림차순 · 선=누적 비율) 카드 하나.
 *
 *   왜 charts.php 가 아니라 별도 파일인가: 여러 워커가 charts.php 에 동시에 손대고 있어
 *   (대시보드 지형도·퍼널 등) 같은 파일을 건드리면 병합 충돌이 난다. 이 파일은 그래서
 *   charts.php 의 헬퍼(vg_nice_max)를 **참조만** 하고 그 파일 내용은 바꾸지 않는다.
 *   같은 이유로 view.php(aggregator)의 require 목록에도 안 넣는다 — 그 목록도 공유 파일이라
 *   같은 줄 근처를 여러 워커가 건드리면 충돌한다. 대신 이 파일 자체가 자기 의존성을
 *   전부 require_once 하므로(charts.php 와 같은 패턴), 쓰는 화면이 이 파일 하나만
 *   require 하면 된다.
 *
 *   왜 서버 렌더 SVG 인가: CSP 가 default-src 'self' 라 인라인 <script> 가 안 돈다
 *   (charts.php 의 지형도·퍼널과 같은 이유). Chart.js(vg_chart)를 안 쓰는 이유는 이 화면들이
 *   대량 목록이라 상위 N 개만 뽑는 정적 그림이면 충분하고, 캔버스·데이터셋 배선을 더할
 *   이유가 없어서다.
 *
 *   데이터는 이 파일이 만들지 않는다 — packages.php·nofix-packages.php·asset-packages.php
 *   가 각자 "무엇을 셀지" 를 정해 [['label'=>…, 'value'=>int, 'href'=>''], …] 로 넘기고,
 *   이 함수는 "어떻게 그릴지" 만 맡는다(vg_rank_bars 와 같은 역할 분리).
 */

require_once __DIR__ . '/../format.php';    // vg_h
require_once __DIR__ . '/components.php';   // vg_empty
require_once __DIR__ . '/charts.php';       // vg_nice_max

/** 상위 몇 종까지 그릴지 — 세 화면이 공유하는 값. SQL 의 LIMIT 도 이 상수를 쓴다
 *  (그려지지 않을 행까지 뽑는 과집계를 만들지 않기 위해). */
const VG_PARETO_TOP = 16;

/**
 * $items: [['label'=>string,'value'=>int|float,'href'=>?string], …]. 정렬·상위 N 자르기는
 *   이 함수가 한다(vg_rank_bars 규약과 동일 — 호출부가 순서를 다시 지키게 하지 않는다).
 * $opts:
 *   'total_value' (int|float|null) 누적 비율의 분모(예: 전체 High 이상 건수). 없으면 그려지는
 *      항목들의 합으로 대신한다 — 그 경우 마지막 막대에서 누적이 100%에 닿는다(상위 항목이
 *      곧 전체일 때만 정확한 근사). **호출부가 상위 N 밖의 나머지까지 아는 화면이면 반드시 준다**
 *      (packages.php·asset-packages.php 는 SQL 윈도우 함수로, nofix-packages.php 는 이미 불러온
 *      전체 그룹 합으로 넘긴다).
 *   'total_items' (int|null) 모집단 종류 수(예: 48). 없으면 count($items).
 *   'unit'      값 단위(예: '건'). 'item_unit' 항목 단위(예: '종').
 *   'threshold' 누적 기준선 비율(기본 0.5 = 50%).
 *   'top'       그릴 상위 개수(기본 VG_PARETO_TOP).
 *   'empty'     vg_empty() 스펙.
 *   'alt'       SVG 접근성 설명 머리말.
 */
function vg_pareto(array $items, array $opts = []): void {
    $clean = [];
    foreach ($items as $it) {
        if (!is_array($it)) { continue; }
        $v = (float) ($it['value'] ?? 0);
        if ($v <= 0) { continue; }
        $clean[] = [
            'label' => (string) ($it['label'] ?? ''),
            'value' => $v,
            'href'  => (string) ($it['href'] ?? ''),
        ];
    }
    usort($clean, static fn(array $a, array $b): int => $b['value'] <=> $a['value']);

    $top = max(1, (int) ($opts['top'] ?? VG_PARETO_TOP));
    $shown = array_slice($clean, 0, $top);
    $n = count($shown);

    // 막대 하나짜리 파레토는 누적선이 곧장 100%라 아무것도 말하지 않는다 — vg_rank_bars 와
    //   같은 기준(2종 이상)으로 아예 그리지 않는다.
    if ($n < 2) {
        vg_empty($opts['empty'] ?? [
            'icon'  => 'chart',
            'title' => '파레토를 그리기엔 항목이 부족합니다.',
            'hint'  => '집계 대상이 2종 이상이면 여기에 분포가 표시됩니다.',
        ]);
        return;
    }

    $unit      = (string) ($opts['unit'] ?? '');
    $itemUnit  = (string) ($opts['item_unit'] ?? '종');
    $threshold = (float) ($opts['threshold'] ?? 0.5);
    if ($threshold <= 0 || $threshold >= 1) { $threshold = 0.5; }

    $shownSum = 0.0;
    foreach ($shown as $it) { $shownSum += $it['value']; }
    $totalValue = $opts['total_value'] ?? null;
    // 분모는 그려지는 항목들의 합보다 작을 수 없다(설사 호출부가 잘못된 값을 줘도 100%를 넘는
    //   누적 비율을 그리지 않기 위한 안전판).
    $totalValue = max($totalValue !== null ? (float) $totalValue : $shownSum, $shownSum);
    $totalItems = max($n, (int) ($opts['total_items'] ?? $n));

    // 누적값·누적비율·임계값을 처음 넘는 지점(0-base 인덱스).
    $running = 0.0;
    $cumVal = []; $cumPct = []; $pivot = null;
    foreach ($shown as $i => $it) {
        $running += $it['value'];
        $cumVal[$i] = $running;
        $pct = $totalValue > 0 ? min(100.0, $running / $totalValue * 100) : 0.0;
        $cumPct[$i] = $pct;
        if ($pivot === null && $pct >= $threshold * 100) { $pivot = $i; }
    }

    // 논리좌표 720×280 — .chart svg 가 폭에 맞춰 늘린다(charts.php 의 change_bars 와 같은 규약).
    $W = 720; $H = 280;
    $padL = 42; $padR = 46; $padT = 14; $padB = 86;
    $plotW = $W - $padL - $padR;
    $plotH = $H - $padT - $padB;

    $rawMax = 0;
    foreach ($shown as $it) { $rawMax = max($rawMax, (int) ceil($it['value'])); }
    $valMax = vg_nice_max($rawMax);

    $slot = $plotW / $n;
    $barW = min(30.0, $slot * 0.62);
    $xAt  = static fn(int $i): float => $padL + $slot * $i + $slot / 2;
    $yVal = static fn(float $v) => $padT + $plotH - ($valMax > 0 ? $plotH * ($v / $valMax) : 0.0);
    $yPct = static fn(float $p) => $padT + $plotH - $plotH * ($p / 100);

    $thresholdLabel = (string) round($threshold * 100);
    $alt = (string) ($opts['alt'] ?? '파레토')
         . ' · 상위 ' . $n . $itemUnit
         . ($pivot !== null ? ' · 누적 ' . $thresholdLabel . '%까지 ' . ($pivot + 1) . $itemUnit : '');

    echo '<div class="chart">';
    echo '<svg viewBox="0 0 ' . $W . ' ' . $H . '" role="img" aria-label="' . vg_h($alt) . '">';

    // 누적 임계선(점선) + 라벨 — 막대보다 먼저 그려 막대 아래 깔리게 한다.
    $thY = $yPct($threshold * 100);
    echo '<line class="pareto__threshold" x1="' . $padL . '" y1="' . round($thY, 1) . '"'
        . ' x2="' . ($W - $padR) . '" y2="' . round($thY, 1) . '"></line>';
    echo '<text class="chart__tick" x="' . ($W - $padR + 4) . '" y="' . round($thY + 3.5, 1) . '"'
        . ' text-anchor="start">누적 ' . $thresholdLabel . '%</text>';

    // 값 축(왼쪽) · 비율 축(오른쪽) 끝값 라벨.
    echo '<text class="chart__tick" x="' . ($padL - 6) . '" y="' . round($padT + $plotH + 3.5, 1) . '">0</text>';
    echo '<text class="chart__tick" x="' . ($padL - 6) . '" y="' . round($padT + 3.5, 1) . '">'
        . number_format($valMax) . '</text>';
    echo '<text class="chart__tick" x="' . ($W - $padR + 4) . '" y="' . round($padT + $plotH + 3.5, 1) . '"'
        . ' text-anchor="start">0%</text>';
    echo '<text class="chart__tick" x="' . ($W - $padR + 4) . '" y="' . round($padT + 3.5, 1) . '"'
        . ' text-anchor="start">100%</text>';

    // 막대 — 톤은 심각도가 아니라 "값" 하나뿐이라 info(강조색) 하나로 통일한다.
    foreach ($shown as $i => $it) {
        $x = $xAt($i);
        $y = $yVal($it['value']);
        $h = max(0.0, $padT + $plotH - $y);
        $tag = $it['href'] !== '' ? 'a' : 'g';
        echo '<' . $tag . ($it['href'] !== '' ? ' href="' . vg_h($it['href']) . '"' : '') . '>';
        echo '<rect class="chart__bar tone-info" x="' . round($x - $barW / 2, 1) . '" y="' . round($y, 1) . '"'
            . ' width="' . round($barW, 1) . '" height="' . round($h, 1) . '">';
        echo '<title>' . vg_h(($i + 1) . '위 · ' . $it['label'] . ' · ' . number_format((int) $it['value']) . $unit
            . ' · 누적 ' . round($cumPct[$i], 1) . '%') . '</title>';
        echo '</rect></' . $tag . '>';
    }

    // 누적선 + 점.
    $pts = [];
    foreach ($shown as $i => $it) { $pts[] = round($xAt($i), 1) . ',' . round($yPct($cumPct[$i]), 1); }
    echo '<polyline class="pareto__line" points="' . implode(' ', $pts) . '"></polyline>';
    foreach ($shown as $i => $it) {
        echo '<circle class="pareto__dot" cx="' . round($xAt($i), 1) . '" cy="' . round($yPct($cumPct[$i]), 1) . '" r="2.6">'
            . '<title>' . vg_h($it['label'] . ' · 누적 ' . round($cumPct[$i], 1) . '%') . '</title></circle>';
    }

    // x축 라벨 — 12~16개가 가로로 다 들어가지 않아 -40도로 눕힌다(charts.php 에 이런 축이
    //   없어 새로 만든 것 — chart__lbl 자체는 그대로 재사용하고 앵커만 --end 로 바꾼다).
    foreach ($shown as $i => $it) {
        $lx = round($xAt($i), 1);
        $ly = $padT + $plotH + 14;
        $label = mb_strlen($it['label']) > 12 ? mb_substr($it['label'], 0, 11) . '…' : $it['label'];
        echo '<text class="chart__lbl chart__lbl--end" x="' . $lx . '" y="' . $ly . '"'
            . ' transform="rotate(-40 ' . $lx . ' ' . $ly . ')">' . vg_h($label) . '</text>';
    }

    echo '</svg></div>';

    // 캡션 — "상위 N종이 절반" 은 데이터에서 계산한다(코드에 숫자를 박지 않는다).
    if ($pivot !== null) {
        echo '<p class="why">상위 ' . number_format($pivot + 1) . $itemUnit . '이 전체 '
            . number_format((int) $totalValue) . $unit . '의 ' . round($cumPct[$pivot], 1) . '%('
            . number_format((int) round($cumVal[$pivot])) . $unit . ')를 차지합니다.</p>';
    }
    echo '<p class="why">전체 ' . number_format($totalItems) . $itemUnit . ' 중 상위 '
        . number_format($n) . $itemUnit . '만 그렸습니다.</p>';
}
