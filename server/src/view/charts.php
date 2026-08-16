<?php
declare(strict_types=1);

/**
 * charts.php — 순수 SVG 차트 렌더. 심각도 도넛·리소스 추이 라인차트.
 *   차트 라이브러리를 들이지 않고 <svg> 를 직접 그린다. 색은 app.css 의 CSS 변수/클래스를
 *   그대로 참조하므로 팔레트를 바꾸면 차트도 같이 바뀐다.
 */

require_once __DIR__ . '/../format.php';
require_once __DIR__ . '/components.php';

/**
 * 심각도 도넛 (순수 SVG — 차트 라이브러리를 들이지 않는다).
 *   $counts: ['CRITICAL'=>3, 'HIGH'=>7, …]. 합이 0이면 회색 빈 링 + "0" 을 그린다.
 *
 * stroke-dasharray 로 원호를 그린다: 둘레를 100 으로 잡으면 dasharray 가 곧 퍼센트다.
 * 조각마다 dashoffset 을 누적해 이어 붙인다. 색은 CSS 변수(--crit 등)를 그대로 참조하므로
 * 팔레트를 바꾸면 도넛도 같이 바뀐다.
 */
function vg_sev_donut(array $counts, int $size = 132): void {
    $total = 0;
    foreach (VG_TONE_SEV as $sev => $tone) { $total += (int) ($counts[$sev] ?? 0); }

    $r = 15.9155;   // 둘레가 정확히 100 이 되는 반지름 (2πr = 100)
    echo '<div class="donut">';
    echo '<svg viewBox="0 0 42 42" width="' . $size . '" height="' . $size . '" role="img" aria-label="심각도 분포">';
    echo '<circle class="donut__track" cx="21" cy="21" r="' . $r . '" fill="none" stroke-width="4.5"></circle>';

    if ($total > 0) {
        $offset = 25;   // 12시 방향에서 시작(기본은 3시 방향)
        foreach (VG_TONE_SEV as $sev => $tone) {
            $n = (int) ($counts[$sev] ?? 0);
            if ($n === 0) { continue; }
            $pct = $n / $total * 100;
            echo '<circle class="donut__arc tone-' . $tone . '" cx="21" cy="21" r="' . $r . '"'
                . ' fill="none" stroke-width="4.5"'
                . ' stroke-dasharray="' . round($pct, 2) . ' ' . round(100 - $pct, 2) . '"'
                . ' stroke-dashoffset="' . round($offset, 2) . '">'
                . '<title>' . vg_h($sev . ' ' . $n . '건') . '</title></circle>';
            $offset -= $pct;   // 시계방향으로 이어 붙인다
        }
    }
    echo '</svg>';
    echo '<div class="donut__mid"><b>' . number_format($total) . '</b><span>전체</span></div>';
    echo '</div>';
}

/**
 * 스캔별 리소스(메모리/CPU) 추이 라인차트 — app.css 의 chart__grid/tick/lbl
 * 눈금 위에 area 채움(세로 그라데이션) + 폴리라인 + 포인트로 그린다.
 *   $scans: host.php 가 이미 들고 있는 tb_scan 행(oldest→newest 순으로 넘긴다 — 차트는 좌→우).
 *   값이 없는(구버전 에이전트) 스캔은 건너뛴다 — 0으로 이으면 실제로 없는 급락처럼 보인다.
 *   $tone: 'mem'|'cpu' — app.css 의 .chart__line.tone-* 색만 다르다.
 */
function vg_resource_trend(array $scans, string $field, string $unit, int $decimals, string $tone): void {
    $pts = [];
    foreach ($scans as $s) {
        if ($s[$field] === null || $s[$field] === '') { continue; }
        $pts[] = ['t' => (string) $s['collected_at'], 'v' => (float) $s[$field]];
    }
    if (count($pts) === 0) {
        vg_empty(['icon' => 'chart', 'title' => '그래프를 그리기엔 스캔 이력이 부족합니다.',
                  'hint'  => '메모리·CPU 값이 있는 스캔이 2건 이상 쌓이면 여기에 추이가 표시됩니다.']);
        return;
    }
    if (count($pts) === 1) {
        $when = date('n/j H:i', strtotime($pts[0]['t']));
        vg_empty(['icon' => 'chart',
                  'title' => '현재 ' . number_format($pts[0]['v'], $decimals) . $unit . ' (' . $when . ')',
                  'hint'  => '스캔이 1건뿐이라 추이선은 아직 못 그립니다. 2건 이상 쌓이면 선으로 표시됩니다.']);
        return;
    }

    $W = 720; $H = 190;
    $padL = 44; $padR = 8; $padT = 12; $padB = 26;
    $plotW = $W - $padL - $padR;
    $plotH = $H - $padT - $padB;
    $n = count($pts);

    // 관측 구간의 최소·최대로 자동 확대하면 0.6%도 차트 꼭대기에 붙어 실제 부하가 큰 것처럼
    // 보인다. 사용률 차트는 언제나 같은 의미를 갖도록 0~100% 절대 축으로 고정한다.
    $min = 0.0;
    $max = 100.0;

    $xAt = static fn(int $i): float => $padL + ($n === 1 ? 0.0 : $plotW * $i / ($n - 1));
    $yAt = static fn(float $v): float => $padT + $plotH * (1 - ($v - $min) / ($max - $min));
    $baseY = $padT + $plotH;   // area 를 닫는 바닥선(plot 하단)

    // area 채움 그라데이션 id 는 인스턴스마다 고유해야 한다 — 한 화면(host.php 리소스 탭)에
    // 이 차트가 4개 뜨는데, id 가 겹치면 브라우저가 첫 그라데이션으로만 그린다.
    static $seq = 0;
    $gradId = 'chart-grad-' . vg_h($tone) . '-' . (++$seq);

    echo '<div class="chart">';
    echo '<svg viewBox="0 0 ' . $W . ' ' . $H . '" role="img" aria-label="' . vg_h($unit) . ' 추이(스캔 ' . $n . '건)">';

    // 선 아래 area 를 채울 세로 그라데이션(선 근처 옅게 → 바닥으로 투명). stop 색은 app.css 가
    // CSS 변수(--accent/--high)로 준다 — 색 하드코딩 없이 라이트/다크 모두 계열색을 탄다.
    echo '<defs><linearGradient id="' . $gradId . '" x1="0" y1="0" x2="0" y2="1">'
        . '<stop class="chart__grad-0 tone-' . vg_h($tone) . '" offset="0"></stop>'
        . '<stop class="chart__grad-1 tone-' . vg_h($tone) . '" offset="1"></stop>'
        . '</linearGradient></defs>';

    // 눈금은 절대 축의 0%·100%만 표시한다.
    foreach ([0, 1] as $f) {
        $gy = $padT + $plotH * (1 - $f);
        $gv = $min + ($max - $min) * $f;
        echo '<line class="chart__grid" x1="' . $padL . '" y1="' . round($gy, 1) . '"'
            . ' x2="' . ($W - $padR) . '" y2="' . round($gy, 1) . '"></line>';
        echo '<text class="chart__tick" x="' . ($padL - 6) . '" y="' . round($gy + 3.5, 1) . '">'
            . number_format($gv, $decimals) . vg_h($unit) . '</text>';
    }

    $poly = [];
    foreach ($pts as $i => $p) { $poly[] = round($xAt($i), 1) . ',' . round($yAt($p['v']), 1); }

    // area — 선을 그대로 따라가다 양끝에서 바닥으로 떨어뜨려 닫는다(선 아래를 그라데이션으로 채움).
    $xFirst = round($xAt(0), 1);
    $xLast  = round($xAt($n - 1), 1);
    echo '<polygon class="chart__area" fill="url(#' . $gradId . ')" points="'
        . implode(' ', $poly) . ' ' . $xLast . ',' . round($baseY, 1)
        . ' ' . $xFirst . ',' . round($baseY, 1) . '"></polygon>';

    echo '<polyline class="chart__line tone-' . vg_h($tone) . '" points="' . implode(' ', $poly) . '"></polyline>';

    foreach ($pts as $i => $p) {
        $cx = round($xAt($i), 1); $cy = round($yAt($p['v']), 1);
        // 마지막(현재) 점은 계열색으로 채워 강조한다.
        $last = $i === $n - 1 ? ' chart__pt--last' : '';
        echo '<circle class="chart__pt tone-' . vg_h($tone) . $last . '" cx="' . $cx . '" cy="' . $cy . '" r="3">'
            . '<title>' . vg_h($p['t'] . ' · ' . number_format($p['v'], $decimals) . $unit) . '</title>'
            . '</circle>';
        // x축 라벨은 시작·끝만 — 과하게 붙이면 겹친다(작업 지침).
        // 가운데 정렬(chart__lbl)로 두면 끝 라벨은 x=W-padR 에서 절반이 viewBox 밖으로
        // 잘린다 — 위치별로 앵커를 안쪽(시작=start/끝=end)으로 튼다.
        if ($i === 0 || $i === $n - 1) {
            $edge = $i === 0 ? 'start' : 'end';
            echo '<text class="chart__lbl chart__lbl--' . $edge . '" x="' . $cx . '" y="' . ($H - 8) . '">'
                . vg_h(date('n/j H:i', strtotime($p['t']))) . '</text>';
        }
    }
    echo '</svg></div>';
}

/**
 * 가로 막대 랭킹 — "어느 자산이 / 어느 패키지가 제일 나쁜가" 를 순서로 말한다.
 *   $items: [['label'=>'ubuntu', 'value'=>2237, 'tone'=>'high', 'href'=>'/host.php?id=2'], …]
 *           'tone'·'href' 는 선택. 넘긴 순서를 그대로 쓰지 않고 값 내림차순으로 정렬한다
 *           (랭킹이라는 이름값을 호출부마다 다시 지키게 하지 않는다).
 *   $opts:  'top'(기본 8) · 'empty'(vg_empty 스펙) · 'unit'(값 뒤 단위, 기본 '')
 *
 * 여기만 SVG 가 아니라 HTML 이다(도넛·추이선은 SVG). 이유: SVG 는 폭에 맞춰 통째로 늘어나
 * 좁은 카드에 들어가면 라벨 글자까지 같이 줄어 못 읽는다(실측 — 250px 카드에서 4px 글자가 됐다).
 * 라벨이 주인공인 차트라 글자는 진짜 텍스트여야 한다: 말줄임·title·링크가 다 공짜로 따라온다.
 * 막대 폭만 값이라 인라인 width:N% 로 준다 — .riskbar/vg_meter 와 같은 규약이고 색은 톤 클래스가 준다.
 */
function vg_rank_bars(array $items, array $opts = []): void {
    $items = array_values(array_filter($items, static fn($i) => (float) ($i['value'] ?? 0) > 0));
    if (!$items) {
        vg_empty($opts['empty'] ?? ['icon' => 'chart', 'title' => '순위를 매길 데이터가 없습니다.',
                                    'hint'  => '수집이 한 번이라도 끝나면 여기에 상위 항목이 표시됩니다.']);
        return;
    }
    usort($items, static fn($a, $b) => (float) $b['value'] <=> (float) $a['value']);
    $top = max(1, (int) ($opts['top'] ?? 8));
    $items = array_slice($items, 0, $top);
    $unit = (string) ($opts['unit'] ?? '');

    $max = 0.0;
    foreach ($items as $i) { $max = max($max, (float) $i['value']); }

    echo '<div class="rank">';
    foreach ($items as $it) {
        $v     = (float) $it['value'];
        $tone  = (string) ($it['tone'] ?? 'info');
        $label = (string) ($it['label'] ?? '');
        $pct   = $max > 0 ? max(1.0, round($v / $max * 100, 2)) : 1.0;
        $href  = (string) ($it['href'] ?? '');
        $title = vg_h($label . ' · ' . number_format($v) . $unit);

        $tag = $href !== '' ? 'a' : 'div';
        echo '<' . $tag . ' class="rank__row"' . ($href !== '' ? ' href="' . vg_h($href) . '"' : '')
            . ' title="' . $title . '">';
        echo '<span class="rank__label">' . vg_h($label) . '</span>';
        echo '<span class="rank__track"><i class="rank__bar tone-' . vg_h($tone) . '" style="width:' . $pct . '%"></i></span>';
        echo '<b class="rank__value">' . vg_h(number_format($v) . $unit) . '</b>';
        echo '</' . $tag . '>';
    }
    echo '</div>';
}

/**
 * 보기 좋은 눈금 최댓값. raw 이상인 값 중 1/2/5/10 의 10^n 배수 가운데 가장 작은 것을 고른다
 * (예: 7→10, 23→50, 140→200). 0 이하면 최소 축(4)을 준다 — 변화가 전혀 없어도 축이 찌그러지지 않게.
 */
function vg_nice_max(int $raw): int {
    if ($raw <= 0) { return 4; }
    $exp = (int) floor(log10($raw));
    $base = 10 ** $exp;
    foreach ([1, 2, 5, 10] as $step) {
        $candidate = (int) ($step * $base);
        if ($candidate >= $raw) { return $candidate; }
    }
    return (int) (10 * $base);
}

/**
 * 회차별 미해결(잔존) 건수 추이. vg_resource_trend() 와 같은 SVG 패턴이지만, 사용률처럼
 * 0~100% 로 고정할 수 없는 건수라 vg_nice_max() 로 데이터 범위에 맞춘 축을 잡는다.
 *   $rounds: changes.php 의 vg_trend_load() 결과(오래된→최신 순). 'collected_at'·'unresolved'·'round' 사용.
 */
function vg_count_trend(array $rounds, string $tone = 'trend'): void {
    // collected_at 이 NULL/빈값인 회차(에이전트 파싱 실패)는 건너뛴다 — vg_resource_trend() 와
    // 같은 이유: 실제로 없는 시점을 0/오늘로 이으면 없는 데이터가 있는 것처럼 보인다.
    $pts = [];
    foreach ($rounds as $r) {
        if ($r['collected_at'] === null || $r['collected_at'] === '') { continue; }
        $pts[] = ['t' => (string) $r['collected_at'], 'v' => (int) $r['unresolved'], 'round' => (int) $r['round']];
    }
    $n = count($pts);
    if ($n === 0) {
        vg_empty(['icon' => 'chart', 'title' => '그래프를 그리기엔 회차 이력이 부족합니다.',
                  'hint'  => '스캔이 쌓이면 여기에 추이가 표시됩니다.']);
        return;
    }
    if ($n === 1) {
        $when = date('n/j H:i', strtotime($pts[0]['t']));
        vg_empty(['icon' => 'chart',
                  'title' => '현재 미해결 ' . number_format($pts[0]['v']) . '건 (' . $when . ')',
                  'hint'  => '회차가 1건뿐이라 추이선은 아직 못 그립니다. 2회차 이상 쌓이면 선으로 표시됩니다.']);
        return;
    }

    $W = 720; $H = 190;
    $padL = 44; $padR = 8; $padT = 12; $padB = 26;
    $plotW = $W - $padL - $padR;
    $plotH = $H - $padT - $padB;

    $rawMax = 0;
    foreach ($pts as $p) { $rawMax = max($rawMax, $p['v']); }
    $niceMax = vg_nice_max($rawMax);
    $min = 0.0; $max = (float) $niceMax;

    $xAt = static fn(int $i): float => $padL + $plotW * $i / ($n - 1);
    $yAt = static fn(float $v): float => $padT + $plotH * (1 - ($v - $min) / ($max - $min));
    $baseY = $padT + $plotH;

    static $seq = 0;
    $gradId = 'chart-grad-cnt-' . vg_h($tone) . '-' . (++$seq);

    echo '<div class="chart">';
    echo '<svg viewBox="0 0 ' . $W . ' ' . $H . '" role="img" aria-label="미해결 건수 추이(회차 ' . $n . '개)">';

    echo '<defs><linearGradient id="' . $gradId . '" x1="0" y1="0" x2="0" y2="1">'
        . '<stop class="chart__grad-0 tone-' . vg_h($tone) . '" offset="0"></stop>'
        . '<stop class="chart__grad-1 tone-' . vg_h($tone) . '" offset="1"></stop>'
        . '</linearGradient></defs>';

    // 눈금은 0/25/50/75/100% 다섯 자리 — vg_nice_max() 로 반올림한 값 기준.
    foreach ([0, 0.25, 0.5, 0.75, 1] as $f) {
        $gy = $padT + $plotH * (1 - $f);
        $gv = $min + ($max - $min) * $f;
        echo '<line class="chart__grid" x1="' . $padL . '" y1="' . round($gy, 1) . '"'
            . ' x2="' . ($W - $padR) . '" y2="' . round($gy, 1) . '"></line>';
        echo '<text class="chart__tick" x="' . ($padL - 6) . '" y="' . round($gy + 3.5, 1) . '">'
            . number_format((int) round($gv)) . '</text>';
    }

    $poly = [];
    foreach ($pts as $i => $p) { $poly[] = round($xAt($i), 1) . ',' . round($yAt($p['v']), 1); }

    $xFirst = round($xAt(0), 1);
    $xLast  = round($xAt($n - 1), 1);
    echo '<polygon class="chart__area" fill="url(#' . $gradId . ')" points="'
        . implode(' ', $poly) . ' ' . $xLast . ',' . round($baseY, 1)
        . ' ' . $xFirst . ',' . round($baseY, 1) . '"></polygon>';

    echo '<polyline class="chart__line tone-' . vg_h($tone) . '" points="' . implode(' ', $poly) . '"></polyline>';

    foreach ($pts as $i => $p) {
        $cx = round($xAt($i), 1); $cy = round($yAt($p['v']), 1);
        $last = $i === $n - 1 ? ' chart__pt--last' : '';
        echo '<circle class="chart__pt tone-' . vg_h($tone) . $last . '" cx="' . $cx . '" cy="' . $cy . '" r="3">'
            . '<title>' . vg_h($p['round'] . '회차 · ' . $p['t'] . ' · ' . number_format($p['v']) . '건') . '</title>'
            . '</circle>';
        if ($i === 0 || $i === $n - 1) {
            $edge = $i === 0 ? 'start' : 'end';
            echo '<text class="chart__lbl chart__lbl--' . $edge . '" x="' . $cx . '" y="' . ($H - 8) . '">'
                . vg_h(date('n/j H:i', strtotime($p['t']))) . '</text>';
        }
    }
    echo '</svg></div>';
}

/**
 * 날짜별 추이선(대시보드 30일 추세) — vg_count_trend() 와 같은 눈금·area 패턴이지만
 * x축이 **회차가 아니라 날짜**라 두 가지가 다르다:
 *   · 점(circle)은 **그날 실제로 스캔이 있었던 날에만** 찍는다. 스캔은 바뀔 때만 저장돼
 *     날짜가 듬성듬성한데, 이월(carry-forward)로 이어 그린 날까지 점을 찍으면 "그날 쟀다"는
 *     거짓 신호가 된다. 선은 끊지 않는다 — 끊으면 이번엔 "그날 0건" 으로 읽힌다.
 *   · x 라벨은 날짜(m/d)만 쓴다(시각은 하루 단위 집계에서 의미가 없다).
 *   $days: 오래된→최신 순 [['d'=>'2026-08-12', 'v'=>1001, 'scanned'=>true], …]
 */
function vg_daily_trend(array $days, string $tone = 'trend'): void {
    $pts = array_values(array_filter($days, static fn($p) => isset($p['d'], $p['v'])));
    $n = count($pts);
    if ($n < 2) {
        vg_empty(['icon' => 'chart', 'title' => '추세를 그리기엔 스캔 이력이 부족합니다.',
                  'hint'  => '서로 다른 날짜의 수집이 2건 이상 쌓이면 여기에 추세가 표시됩니다.']);
        return;
    }

    $W = 720; $H = 190;
    $padL = 44; $padR = 8; $padT = 12; $padB = 26;
    $plotW = $W - $padL - $padR;
    $plotH = $H - $padT - $padB;

    $rawMax = 0;
    foreach ($pts as $p) { $rawMax = max($rawMax, (int) $p['v']); }
    $max = (float) vg_nice_max($rawMax);

    $xAt = static fn(int $i): float => $padL + $plotW * $i / ($n - 1);
    $yAt = static fn(float $v): float => $padT + $plotH * (1 - $v / $max);
    $baseY = $padT + $plotH;

    static $seq = 0;
    $gradId = 'chart-grad-day-' . vg_h($tone) . '-' . (++$seq);

    echo '<div class="chart">';
    echo '<svg viewBox="0 0 ' . $W . ' ' . $H . '" role="img" aria-label="최근 ' . $n . '일 추세">';
    echo '<defs><linearGradient id="' . $gradId . '" x1="0" y1="0" x2="0" y2="1">'
        . '<stop class="chart__grad-0 tone-' . vg_h($tone) . '" offset="0"></stop>'
        . '<stop class="chart__grad-1 tone-' . vg_h($tone) . '" offset="1"></stop>'
        . '</linearGradient></defs>';

    foreach ([0, 0.5, 1] as $f) {
        $gy = $padT + $plotH * (1 - $f);
        echo '<line class="chart__grid" x1="' . $padL . '" y1="' . round($gy, 1) . '"'
            . ' x2="' . ($W - $padR) . '" y2="' . round($gy, 1) . '"></line>';
        echo '<text class="chart__tick" x="' . ($padL - 6) . '" y="' . round($gy + 3.5, 1) . '">'
            . number_format((int) round($max * $f)) . '</text>';
    }

    $poly = [];
    foreach ($pts as $i => $p) { $poly[] = round($xAt($i), 1) . ',' . round($yAt((float) $p['v']), 1); }

    $xFirst = round($xAt(0), 1);
    $xLast  = round($xAt($n - 1), 1);
    echo '<polygon class="chart__area" fill="url(#' . $gradId . ')" points="'
        . implode(' ', $poly) . ' ' . $xLast . ',' . round($baseY, 1)
        . ' ' . $xFirst . ',' . round($baseY, 1) . '"></polygon>';
    echo '<polyline class="chart__line tone-' . vg_h($tone) . '" points="' . implode(' ', $poly) . '"></polyline>';

    foreach ($pts as $i => $p) {
        $cx = round($xAt($i), 1); $cy = round($yAt((float) $p['v']), 1);
        if (!empty($p['scanned'])) {
            $last = $i === $n - 1 ? ' chart__pt--last' : '';
            echo '<circle class="chart__pt tone-' . vg_h($tone) . $last . '" cx="' . $cx . '" cy="' . $cy . '" r="3">'
                . '<title>' . vg_h($p['d'] . ' · ' . number_format((int) $p['v']) . '건 (이날 수집됨)') . '</title>'
                . '</circle>';
        }
        if ($i === 0 || $i === $n - 1) {
            $edge = $i === 0 ? 'start' : 'end';
            echo '<text class="chart__lbl chart__lbl--' . $edge . '" x="' . $cx . '" y="' . ($H - 8) . '">'
                . vg_h(date('n/j', strtotime((string) $p['d']))) . '</text>';
        }
    }
    echo '</svg></div>';
}

/**
 * 회차별 신규(0 기준선 위)·해결(아래) 다이버징 막대차트 — vg_count_trend() 와 같은
 * grid/lbl 눈금 패턴 위에 막대만 얹은 변형. 첫 회차(비교 대상 없는 기준선)는
 * $rounds 에서 'new'===null 이므로 자동으로 빠진다.
 *   $rounds: vg_trend_load() 결과(오래된→최신 순).
 */
function vg_change_bars(array $rounds): void {
    // 비교 대상 없는 기준 회차는 이미 'new'===null 로 걸러진다. collected_at 이 NULL/빈값인
    // 회차도(에이전트 파싱 실패) date() 가 uncaught 오류를 던지므로 같이 건너뛴다.
    $data = array_values(array_filter(
        $rounds,
        static fn($r) => $r['new'] !== null && $r['collected_at'] !== null && $r['collected_at'] !== ''
    ));
    $n = count($data);
    if ($n === 0) {
        vg_empty(['icon' => 'chart', 'title' => '비교할 회차가 아직 없습니다.',
                  'hint'  => '회차가 2개 이상 쌓이면 회차별 신규·해결이 표시됩니다.']);
        return;
    }

    $W = 720; $H = 190;
    $padL = 44; $padR = 8; $padT = 12; $padB = 26;
    $plotW = $W - $padL - $padR;
    $plotH = $H - $padT - $padB;

    $rawMax = 0;
    foreach ($data as $r) { $rawMax = max($rawMax, (int) $r['new'], (int) $r['resolved']); }
    $niceMax = vg_nice_max($rawMax);

    $zeroY = $padT + $plotH / 2;
    $yAt = static fn(float $v) => $zeroY - ($plotH / 2) * ($v / $niceMax);
    $xAt = static fn(int $i): float => $n === 1 ? $padL + $plotW / 2 : $padL + $plotW * $i / ($n - 1);

    echo '<div class="chart">';
    echo '<svg viewBox="0 0 ' . $W . ' ' . $H . '" role="img" aria-label="회차별 신규·해결(회차 ' . $n . '개)">';

    foreach ([-1, 0, 1] as $f) {
        $gy = $zeroY - ($plotH / 2) * $f;
        echo '<line class="chart__grid" x1="' . $padL . '" y1="' . round($gy, 1) . '"'
            . ' x2="' . ($W - $padR) . '" y2="' . round($gy, 1) . '"></line>';
        echo '<text class="chart__tick" x="' . ($padL - 6) . '" y="' . round($gy + 3.5, 1) . '">'
            . number_format((int) ($niceMax * $f)) . '</text>';
    }

    $barW = $n === 1 ? 24.0 : min(28.0, $plotW / $n * 0.55);
    foreach ($data as $i => $r) {
        $cx = $xAt($i);
        $new = (int) $r['new']; $res = (int) $r['resolved'];
        if ($new > 0) {
            $yTop = $yAt((float) $new);
            echo '<rect class="chart__bar tone-crit" x="' . round($cx - $barW / 2, 1) . '" y="' . round($yTop, 1) . '"'
                . ' width="' . round($barW, 1) . '" height="' . round($zeroY - $yTop, 1) . '">'
                . '<title>' . vg_h($r['round'] . '회차 · 신규 ' . number_format($new) . '건') . '</title></rect>';
        }
        if ($res > 0) {
            $yBot = $yAt((float) -$res);
            echo '<rect class="chart__bar tone-ok" x="' . round($cx - $barW / 2, 1) . '" y="' . round($zeroY, 1) . '"'
                . ' width="' . round($barW, 1) . '" height="' . round($yBot - $zeroY, 1) . '">'
                . '<title>' . vg_h($r['round'] . '회차 · 해결 ' . number_format($res) . '건') . '</title></rect>';
        }
        if ($i === 0 || $i === $n - 1) {
            $edge = $i === 0 ? 'start' : 'end';
            echo '<text class="chart__lbl chart__lbl--' . $edge . '" x="' . round($cx, 1) . '" y="' . ($H - 8) . '">'
                . vg_h(date('n/j H:i', strtotime((string) $r['collected_at']))) . '</text>';
        }
    }
    echo '</svg></div>';
}
