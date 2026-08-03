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
        vg_empty(['icon' => '📉', 'title' => '그래프를 그리기엔 스캔 이력이 부족합니다.',
                  'hint'  => '메모리·CPU 값이 있는 스캔이 2건 이상 쌓이면 여기에 추이가 표시됩니다.']);
        return;
    }
    if (count($pts) === 1) {
        $when = date('n/j H:i', strtotime($pts[0]['t']));
        vg_empty(['icon' => '📍',
                  'title' => '현재 ' . number_format($pts[0]['v'], $decimals) . $unit . ' (' . $when . ')',
                  'hint'  => '스캔이 1건뿐이라 추이선은 아직 못 그립니다. 2건 이상 쌓이면 선으로 표시됩니다.']);
        return;
    }

    $W = 720; $H = 190;
    $padL = 44; $padR = 8; $padT = 12; $padB = 26;
    $plotW = $W - $padL - $padR;
    $plotH = $H - $padT - $padB;
    $n = count($pts);

    $vals = array_column($pts, 'v');
    $min = min($vals);
    $max = max($vals);
    if ($max <= $min) { $max += 1; }   // 값이 전부 같으면 0 나눗셈 방지 — 수평선으로 그려진다

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

    // 눈금은 최소·최대만 — 값 하나로 좁게 흔들리는 계열에 중간값은 소음이다.
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
