<?php
declare(strict_types=1);

/**
 * charts_spark.php — 표 셀 스파크라인(vg_sparkline)과 자산 상세 호라이즌 밴드(vg_horizon).
 *   charts.php 에 덧붙이지 않고 새 파일로 둔 이유는 그 파일과 이 파일이 동시에 다른
 *   워커의 손을 타서 머지 충돌이 나지 않게 하기 위해서다(#assets-sparkline-column 작업지시).
 *   기존 vg_multi_trend()(charts.php)는 지우지 않는다 — 대시보드·변화 추적 탭이 그대로 쓴다.
 *
 * 왜 서버 렌더 SVG 인가: CSP 가 default-src 'self' 라 인라인 <script> 를 못 쓴다 — Chart.js 로
 *   그리는 vg_multi_trend() 와 달리 이 둘은 축·범례·툴팁이 필요 없는 단순한 형태라 SVG 로 충분하다
 *   (donut·terrain 과 같은 판단).
 */

require_once __DIR__ . '/../format.php';
require_once __DIR__ . '/components.php';   // vg_empty() — vg_horizon() 의 빈 상태

/**
 * 표 셀 스파크라인 — Tufte 의 원래 의도(표 셀 안의 미니 추세). 목록의 "14일 추세" 열이 쓴다.
 *
 *   $points : [['d'=>'Y-m-d', 'v'=>수], …] **시간순으로 이미 이월(carry-forward)돼 있어야 한다**
 *             (호출부가 만든다 — 이 함수는 그리기만 한다, N+1 방지 배치 조회는 조회층 몫).
 *   $opts   : 'unit'(현재값·aria 뒤에 붙는 단위, 기본 '') · 'label'(aria 앞에 붙는 지표 이름) ·
 *             'days'(aria 의 "N일" — 기본 14, 조회 창과 맞춘다) ·
 *             'width'(100~130 로 자른다, 기본 120) · 'height'(18~32 로 자른다, 기본 26)
 *
 * **값이 하나뿐이거나 이력이 없으면 선을 그리지 않는다** — 점 하나로는 추세를 주장할 수 없고,
 *   그렇다고 0 으로 잇는 것은 "그 전엔 취약점이 없었다"는 거짓말이 된다(vg_multi_trend 와 같은 판단).
 *   그때는 옅은 '–' 하나만 돌려준다(다른 화면의 '값 없음' 어휘 — assets/table.php 의 IP 빈 칸과 동일).
 *
 * 반환값은 **이미 이스케이프된 HTML 문자열**이다 — vg_table() 의 cell 콜백 계약(component/table.php
 *   머리주석)과 같아서 목록 화면의 'cell' => fn($r) => vg_sparkline(...) 로 바로 꽂힌다.
 */
function vg_sparkline(array $points, array $opts = []): string {
    // 값이 있는 점만 남긴다. 호출부가 이미 시간순으로 넘기므로 여기서 다시 정렬하지 않는다.
    $pts = [];
    foreach ($points as $p) {
        if (!is_array($p) || !array_key_exists('v', $p) || $p['v'] === null) { continue; }
        $pts[] = ['d' => (string) ($p['d'] ?? ''), 'v' => (float) $p['v']];
    }

    $unit  = (string) ($opts['unit'] ?? '');
    $label = (string) ($opts['label'] ?? '');
    $days  = (int) ($opts['days'] ?? 14);

    if (count($pts) < 2) {
        $why = ($days > 0 ? $days . '일 ' : '') . '추세를 그리기엔 수집 이력이 부족합니다.';
        return '<span class="why" title="' . vg_h($why) . '">–</span>';
    }

    $w = max(100, min(130, (int) ($opts['width'] ?? 120)));
    $h = max(18, min(32, (int) ($opts['height'] ?? 26)));
    $padY = 3.0;   // 위아래 여백 — 값이 축 끝에 닿아 잘리지 않게

    $n     = count($pts);
    $first = $pts[0]['v'];
    $last  = $pts[$n - 1]['v'];
    $delta = $last - $first;
    // 이 지표는 취약점·위험 건수라 **늘면 나쁘고 줄면 좋다** — 등급 색과 같은 방향으로 칠한다.
    $tone  = $delta > 0 ? 'crit' : ($delta < 0 ? 'ok' : 'muted');

    $min = $max = $pts[0]['v'];
    foreach ($pts as $p) { $min = min($min, $p['v']); $max = max($max, $p['v']); }
    $span = $max - $min;

    $xAt = static fn(int $i): float => $n === 1 ? 0.0 : $i * ($w / ($n - 1));
    // 값이 전 구간 동일하면(span=0) 가운데 직선 — 0으로 나누지 않는다.
    $yAt = static fn(float $v): float => $span > 0
        ? $h - $padY - ($v - $min) / $span * ($h - 2 * $padY)
        : $h / 2;

    $coords = [];
    foreach ($pts as $i => $p) { $coords[] = round($xAt($i), 1) . ',' . round($yAt($p['v']), 1); }
    $lastX = round($xAt($n - 1), 1);
    $lastY = round($yAt($last), 1);

    // 장식이 아니라 값이다 — aria-label 에 기간과 시작·끝 값을 그대로 적는다.
    $aria = ($label !== '' ? $label . ' ' : '') . ($days > 0 ? $days . '일 ' : '')
          . number_format($first) . $unit . ' → ' . number_format($last) . $unit;

    $svg = '<svg class="spark__svg" viewBox="0 0 ' . $w . ' ' . $h . '"'
        . ' width="' . $w . '" height="' . $h . '" role="img" aria-label="' . vg_h($aria) . '">'
        . '<polyline class="spark__line tone-' . vg_h($tone) . '" points="' . vg_h(implode(' ', $coords)) . '"></polyline>'
        . '<circle class="spark__dot tone-' . vg_h($tone) . '" cx="' . $lastX . '" cy="' . $lastY . '" r="2.2"></circle>'
        . '</svg>';

    $deltaTxt = $delta > 0 ? '▲' . number_format(abs($delta))
              : ($delta < 0 ? '▼' . number_format(abs($delta)) : '0');

    return '<span class="spark">' . $svg
        . '<b class="spark__val">' . vg_h(number_format($last) . $unit) . '</b>'
        . '<i class="spark__delta tone-' . vg_h($tone) . '">' . vg_h($deltaTxt) . '</i>'
        . '</span>';
}

/** 호라이즌 밴드가 값을 접는 겹 수 — 고정 3(작업지시). 조회부는 이 값을 몰라도 된다. */
const VG_HORIZON_BANDS = 3;

/**
 * 호라이즌 밴드 — 여러 계열이 **선으로 겹쳐 서로 가리는** vg_multi_trend() 의 대안이다.
 *   계열마다 제 줄을 갖고, 값의 크기는 y 위치가 아니라 **색 농도**로 접어 넣는다 — 그래서
 *   같은 세로 공간(줄 하나 높이)에 선 그래프보다 몇 배 정밀하게 값을 읽는다(Cabot 의 horizon chart).
 *
 *   원리: 0~$max 구간을 3겹으로 나눠, 겹마다 "그 겹에 해당하는 값만큼"을 **줄 전체 높이로
 *   접어 그리고**, 다음 겹을 그 위에 덧그린다. 값이 높을수록 더 진한 겹이 아래 겹을 완전히
 *   덮으므로, 한 지점의 색 농도만 보면 값의 크기를 읽을 수 있다. **처음 보면 읽는 법을 모르므로**
 *   카드 아래에 "색이 진할수록 값이 크다" 한 줄을 이 함수가 스스로 붙인다(작업지시 요구사항).
 *
 *   $series : vg_multi_trend() 와 같은 계약 — [['name'=>…, 'points'=>[['d'=>…,'v'=>…], …]], …]
 *             점이 2개 미만인 계열은 그린다고 뜻이 없어(선 하나도 못 그린다) 건너뛴다.
 *   $opts   : 'max'(밴드 상한값 — 0~100 사용률처럼 절대 상한이 있는 지표에 준다.
 *             생략하면 전 계열의 관측 최댓값을 쓴다) · 'unit'(값 뒤 단위) · 'empty'(vg_empty 스펙)
 */
function vg_horizon(array $series, array $opts = []): void {
    $clean = [];
    foreach ($series as $s) {
        if (!is_array($s) || empty($s['points']) || !is_array($s['points'])) { continue; }
        $pts = [];
        foreach ($s['points'] as $p) {
            if (!is_array($p) || !isset($p['d']) || $p['v'] === null) { continue; }
            $pts[(string) $p['d']] = (float) $p['v'];
        }
        if (count($pts) < 2) { continue; }   // vg_multi_trend 와 같은 최소 조건(선 하나엔 점 2개)
        $clean[] = ['name' => (string) ($s['name'] ?? ''), 'points' => $pts];
    }

    if (!$clean) {
        vg_empty($opts['empty'] ?? [
            'icon'  => 'chart',
            'title' => '추세를 그리기엔 수집 이력이 부족합니다.',
            'hint'  => '서로 다른 시점의 수집이 2건 이상 쌓이면 여기에 추세가 표시됩니다.',
        ]);
        return;
    }

    $unit = (string) ($opts['unit'] ?? '');

    $globalMax = 0.0;
    foreach ($clean as $s) { foreach ($s['points'] as $v) { $globalMax = max($globalMax, $v); } }
    $max = (float) ($opts['max'] ?? ($globalMax > 0 ? $globalMax : 1.0));
    $bandSize = $max / VG_HORIZON_BANDS;

    // 계열 하나의 그림 폭·높이. 높이가 vg_multi_trend() 한 줄의 1/4 수준이라 "같은 세로
    //   공간에 정밀도가 몇 배" 라는 작업지시 문구가 그대로 성립한다(선 그래프는 계열마다
    //   최소 8~10rem 높이가 필요했지만 이 줄은 2rem 이면 된다).
    $W = 640; $H = 34;

    echo '<div class="horizon">';
    foreach ($clean as $s) {
        $vals = array_values($s['points']);
        $n    = count($vals);
        $last = $vals[$n - 1];
        $xAt  = static fn(int $i): float => $n === 1 ? 0.0 : $i * ($W / ($n - 1));

        $aria = vg_h($s['name']) !== '' ? $s['name'] . ' ' : '';
        $aria .= '최근값 ' . number_format($last, $last == (int) $last ? 0 : 1) . $unit
               . ' · 색이 진할수록 값이 큽니다';

        echo '<div class="horizon__row">';
        echo '<span class="horizon__name" title="' . vg_h($s['name']) . '">' . vg_h($s['name']) . '</span>';
        echo '<svg class="horizon__svg" viewBox="0 0 ' . $W . ' ' . $H . '" preserveAspectRatio="none"'
            . ' role="img" aria-label="' . vg_h($aria) . '">';

        // 겹 낮은 것부터 그린다 — 뒤에 그리는(높은) 겹이 진한 색으로 아래 겹을 덮어써야
        //   "값이 클수록 진하다"가 성립한다(donut 등 이 파일의 다른 SVG와 같은 "그리는 순서가
        //   곧 겹침 순서" 원칙 — charts.php 의 vg_asset_terrain 머리주석 참조).
        for ($b = 0; $b < VG_HORIZON_BANDS; $b++) {
            $lo = $b * $bandSize;
            $pathPts = [];
            foreach ($vals as $i => $v) {
                $layer = $bandSize > 0 ? max(0.0, min($bandSize, $v - $lo)) : 0.0;
                $y = $H - ($bandSize > 0 ? $layer / $bandSize : 0.0) * $H;
                $pathPts[] = round($xAt($i), 1) . ',' . round($y, 1);
            }
            $d = 'M0,' . $H . ' L' . implode(' L', $pathPts) . ' L' . round($W, 1) . ',' . $H . ' Z';
            echo '<path class="horizon__band horizon__band--' . ($b + 1) . '" d="' . $d . '"></path>';
        }

        echo '</svg>';
        echo '<b class="horizon__val">' . vg_h(number_format($last, $last == (int) $last ? 0 : 1) . $unit) . '</b>';
        echo '</div>';
    }
    // 처음 보는 사람은 읽는 법을 모른다 — 어휘를 카드 밖(문서)이 아니라 카드 안에 못박는다.
    echo '<p class="horizon__caption why">색이 진할수록 값이 큽니다 · 겹 ' . VG_HORIZON_BANDS
        . '개로 접어 같은 공간에 더 정밀하게 그립니다.</p>';
    echo '</div>';
}
