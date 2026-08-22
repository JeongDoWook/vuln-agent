<?php
declare(strict_types=1);

/**
 * charts_dash.php — 대시보드 상단 전용 차트: 자산 순위 막대 · 처리 흐름 워터폴 · 자산별 스파크라인.
 *
 *   왜 charts.php 가 아니라 새 파일인가: 지금 여러 워커가 동시에 charts.php 에 차트를
 *   추가하는 중이라(#779 계열 작업들) 한 파일에 몰면 충돌한다 — deptree.php·format/severity.php
 *   로 화면별 헬퍼를 갈라 둔 것과 같은 판단이다.
 *
 *   이 파일이 대체하는 것: vg_asset_terrain()(아이소메트릭 지형도)과 vg_flow_funnel()(퍼널).
 *   지형도는 운영 실측에서 실패했다 — 자산 11대의 High 이상이 55~132 로 몰려 있어 블록
 *   높이차가 거의 없었고, 이름표가 앞 블록에 가려 잘렸다. 높이로 비교하는 그림 자체가
 *   이 데이터에 안 맞아서, 이름을 그림 밖 한 열에 세우는 **순위 막대**로 바꾼다.
 *
 *   서버 렌더 SVG(워터폴·스파크라인)와 HTML(순위 막대)을 섞어 쓰는 이유는 charts.php
 *   머리주석과 같다 — 라벨이 주인공인 차트는 HTML(폭이 줄어도 글자가 안 줄어든다),
 *   형태가 고정된 차트는 SVG(CSP 가 default-src 'self' 라 인라인 <script> 를 못 쓴다).
 */

require_once __DIR__ . '/../format.php';   // vg_h()
require_once __DIR__ . '/charts.php';      // vg_donut_tone() — 대시보드 로드 순서에 우연히 기대지 않는다
require_once __DIR__ . '/components.php';  // vg_empty()

/**
 * 자산 순위 막대 — "어느 자산에 High 이상이 몰려 있나" 를 순서로 말한다(vg_asset_terrain 후신).
 *
 *   $assets: [['label'=>자산 이름, 'high'=>int, 'crit'=>int, 'exposed'=>int, 'kev'=>int,
 *              'href'=>''], …]
 *            순서는 여기서 다시 잡는다(High 이상 내림차순, 동률은 KEV·이름순) — 호출부마다
 *            정렬을 다시 지키게 하지 않는다(vg_rank_bars 와 같은 규약).
 *   $opts:   'top'(세울 행 수, 기본 12) · 'empty'(vg_empty 스펙) · 'rest_href'(접힌 자산으로 가는 링크)
 *
 * 막대 안의 **더 진한 겹막대**는 그 자산의 High 이상 중 외부 노출(exposed) 건수다 — 실측상
 *   대부분 막대 전체를 덮지만, 안 덮이는 자산이 생기면 그 차이가 바로 정보다("이 자산은
 *   위험도는 높은데 밖에서는 안 닿는다"). KEV 보유 자산은 막대 끝에 테두리 원 + 건수를 얹는다
 *   (지형도의 KEV 표식과 같은 어휘 — 채운 원이 아니라 테두리 원인 것도 같은 이유:
 *   채우면 그 위에 얹는 흰 글자가 다크에서 대비가 떨어진다).
 *
 * **왜 상위 N 만 세우나**: 자산이 늘수록(dev 실측 50대 이상) 목록이 카드를 넘는다. 접는
 *   기준은 화면이 말하는 것과 같은 축(High 이상)이고, 접힌 수는 목록 아래 한 줄로 남긴다 —
 *   조용히 자르지 않는다(vg_asset_terrain 과 같은 판단).
 */
function vg_asset_rank(array $assets, array $opts = []): void {
    $items = [];
    foreach ($assets as $a) {
        if (!is_array($a)) { continue; }
        $items[] = [
            'label'   => (string) ($a['label'] ?? ''),
            'high'    => max(0, (int) ($a['high'] ?? 0)),
            'crit'    => max(0, (int) ($a['crit'] ?? 0)),
            'exposed' => max(0, (int) ($a['exposed'] ?? 0)),
            'kev'     => max(0, (int) ($a['kev'] ?? 0)),
            'href'    => (string) ($a['href'] ?? ''),
        ];
    }
    if (!$items) {
        vg_empty($opts['empty'] ?? ['icon' => 'host', 'title' => '아직 수집된 자산이 없습니다.',
                                    'hint'  => '에이전트를 --send 로 실행하면 자산이 여기에 순위로 섭니다.']);
        return;
    }

    usort($items, static fn(array $x, array $y): int
        => [$y['high'], $y['kev'], $x['label']] <=> [$x['high'], $x['kev'], $y['label']]);

    $top   = max(1, (int) ($opts['top'] ?? 12));
    $rest  = array_slice($items, $top);
    $shown = array_slice($items, 0, $top);

    $max = 0;
    foreach ($shown as $s) { $max = max($max, $s['high']); }

    echo '<div class="arank">';
    foreach ($shown as $it) {
        $pct    = $max > 0 ? max(1.0, round($it['high'] / $max * 100, 2)) : 1.0;
        // 0.6 아래로는 안 줄인다(도넛·워터폴과 같은 하한) — 건수가 있는데 안 보이면 그림이
        //   숫자와 어긋난다.
        $expPct = ($max > 0 && $it['exposed'] > 0) ? max(0.6, round($it['exposed'] / $max * 100, 2)) : 0.0;
        // 윗면 색은 지형도와 같은 규칙 — 그 자산의 최악 등급.
        $tone   = $it['crit'] > 0 ? 'crit' : ($it['high'] > 0 ? 'high' : 'ok');

        $title = $it['label'] . ' · High 이상 ' . number_format($it['high']) . '건'
               . ($it['crit'] > 0 ? ' (CRITICAL ' . number_format($it['crit']) . ')' : '')
               . ($it['exposed'] > 0 ? ' · 그중 외부 노출 ' . number_format($it['exposed']) . '건' : '')
               . ($it['kev'] > 0 ? ' · KEV ' . number_format($it['kev']) . '건' : '');

        $tag = $it['href'] !== '' ? 'a' : 'div';
        echo '<' . $tag . ' class="arank__row"' . ($it['href'] !== '' ? ' href="' . vg_h($it['href']) . '"' : '')
            . ' title="' . vg_h($title) . '">';
        echo '<span class="arank__label">' . vg_h($it['label']) . '</span>';
        echo '<span class="arank__track">';
        echo '<i class="arank__bar tone-' . vg_h($tone) . '" style="width:' . $pct . '%"></i>';
        if ($it['exposed'] > 0) {
            echo '<i class="arank__bar arank__bar--exposed tone-' . vg_h($tone) . '" style="width:' . $expPct . '%"></i>';
        }
        if ($it['kev'] > 0) {
            // 원을 막대 끝(High 이상의 위치)에 앉힌다 — 인라인 style 은 폭 계산만 예외라
            //   left:N% 대신 **막대와 같은 폭의 투명 칸을 만들고 그 안에서 오른쪽으로 붙인다**
            //   (칸 끝 = 막대 끝이므로 결과는 같다).
            echo '<span class="arank__kev-wrap" style="width:' . $pct . '%">'
                . '<span class="arank__kev">' . vg_h($it['kev'] > 99 ? '99+' : (string) $it['kev']) . '</span>'
                . '</span>';
        }
        echo '</span>';
        echo '<b class="arank__value">' . vg_h(number_format($it['high'])) . '건</b>';
        echo '</' . $tag . '>';
    }
    echo '</div>';

    if ($rest) {
        $restHigh = 0;
        foreach ($rest as $r) { $restHigh += $r['high']; }
        $href = (string) ($opts['rest_href'] ?? '');
        echo '<p class="why">외 ' . number_format(count($rest)) . '대(High 이상 '
            . number_format($restHigh) . '건)는 접었습니다 — High 이상 상위 '
            . number_format($top) . '대만 세웁니다.'
            . ($href !== '' ? ' <a href="' . vg_h($href) . '">자산 전체 →</a>' : '') . '</p>';
    }
}

/** 워터폴 칸 폭 · 칸 사이 간격 · 칸 높이 상한(px). */
const VG_WFALL_STEP_W = 64;
const VG_WFALL_GAP    = 28;
const VG_WFALL_MAX_H  = 128;

/**
 * 처리 흐름 워터폴 — 탐지 전체에서 오늘 할 일까지, 칸마다 **무엇 때문에 얼마가 빠졌는지**를
 * 사유와 함께 남긴다(vg_flow_funnel 후신 — 그건 "좁아진다"만 말했다).
 *
 *   $steps: [['label'=>…, 'value'=>int, 'tone'=>…, 'href'=>'', 'title'=>'', 'reason'=>''], …]
 *           **값은 그 칸까지의 누적 총량이다**(그 칸에서 빠진 양이 아니다) — 첫 칸이 전체,
 *           이후 칸은 앞 칸에서 하나씩 뺀 나머지다. **마지막 두 칸은 값이 같아도 된다**
 *           (한 칸이 뺀 나머지를, 다음 칸이 "그래서 남은 오늘 할 일"로 다시 말한다 — 값은
 *           같아도 하나는 "무엇을 뺐는지", 하나는 "그래서 뭐가 남았는지" 를 답하는 다른 칸이다).
 *           **첫 칸과 마지막 칸만** 0 부터 세우는 막대다. 가운데 칸들은 앞 칸 값에서 이 칸
 *           값까지 **떠 있는 막대**로 그려 얼마가 빠졌는지 높이로 보이고, 값 자리에는 그
 *           빠진 양이 `−` 를 달고 선다. 'reason' 은 그 아래 한 줄(비우면 안 그린다).
 *   $opts:  'title'(SVG 접근성 이름의 머리) · 'empty'(vg_empty 스펙)
 *
 * **세로는 로그 척도**다(log10(v+1) / log10(첫값+1)) — 42,271 대 884 를 선형으로 그리면
 *   마지막 칸이 통째로 사라진다(옛 퍼널이 두께를 로그로 그리던 것과 같은 이유).
 */
function vg_flow_waterfall(array $steps, array $opts = []): void {
    $items = [];
    foreach ($steps as $s) {
        if (!is_array($s)) { continue; }
        $items[] = [
            'label'  => (string) ($s['label'] ?? ''),
            'value'  => max(0, (int) ($s['value'] ?? 0)),
            'tone'   => vg_donut_tone((string) ($s['tone'] ?? 'muted')),
            'href'   => (string) ($s['href'] ?? ''),
            'title'  => (string) ($s['title'] ?? ''),
            'reason' => (string) ($s['reason'] ?? ''),
        ];
    }
    $n = count($items);
    if ($n < 2 || $items[0]['value'] <= 0) {
        vg_empty($opts['empty'] ?? ['icon' => 'chart', 'title' => '집계할 탐지 결과가 없습니다.',
                                    'hint'  => '수집이 한 번이라도 끝나면 여기에 처리 흐름이 표시됩니다.']);
        return;
    }

    $sw = VG_WFALL_STEP_W; $gap = VG_WFALL_GAP; $maxH = VG_WFALL_MAX_H;
    $padL = 10; $padR = 10; $padT = 30; $padB = 44;
    $W = $n * $sw + ($n - 1) * $gap + $padL + $padR;
    $baseline = $padT + $maxH;
    $H = $baseline + $padB;

    // 0건도 칸을 남긴다(log10(0+1)=0 → 기준선 위치) — "그 칸이 비었다" 는 지워야 할 정보가
    //   아니라 읽어야 할 사실이다(옛 퍼널·지형도와 같은 규칙).
    $logMax = log10($items[0]['value'] + 1);
    $yAt = static fn(int $v): float => $logMax > 0
        ? $baseline - $maxH * (log10($v + 1) / $logMax) : $baseline;

    foreach ($items as $i => &$it) {
        $it['x'] = $padL + $i * ($sw + $gap);
        $it['y'] = $yAt($it['value']);
    }
    unset($it);

    // 접근성 요약 — 감소 칸은 "얼마가 왜 빠졌는지", 나머지는 누적값을 그대로 읽는다.
    $alt = (string) ($opts['title'] ?? '처리 흐름 워터폴');
    foreach ($items as $i => $it) {
        $isEdge = $i === 0 || $i === $n - 1;
        if (!$isEdge && $i > 0) {
            $cut = $items[$i - 1]['value'] - $it['value'];
            $alt .= ' · ' . $it['label'] . ' ' . number_format($cut) . '건 제외'
                  . ($it['reason'] !== '' ? '(' . $it['reason'] . ')' : '');
        } else {
            $alt .= ' · ' . $it['label'] . ' ' . number_format($it['value']) . '건';
        }
    }

    echo '<div class="wfall">';
    echo '<svg viewBox="0 0 ' . $W . ' ' . $H . '" role="img" aria-label="' . vg_h($alt) . '">';
    echo '<line class="wfall__base" x1="' . $padL . '" y1="' . round($baseline, 1)
        . '" x2="' . ($W - $padR) . '" y2="' . round($baseline, 1) . '"></line>';

    // 연결선을 막대보다 먼저 그린다 — 막대 모서리가 그 위를 덮어야 이음매가 깔끔하다.
    for ($i = 0; $i < $n - 1; $i++) {
        $y = round($items[$i]['y'], 1);
        echo '<line class="wfall__link" x1="' . round($items[$i]['x'] + $sw, 1) . '" y1="' . $y
            . '" x2="' . round($items[$i + 1]['x'], 1) . '" y2="' . $y . '"></line>';
    }

    foreach ($items as $i => $it) {
        $isEdge = $i === 0 || $i === $n - 1;
        $prev   = $i > 0 ? $items[$i - 1] : null;

        if ($isEdge) {
            $top = $it['y'];
            $h   = max(1.5, $baseline - $it['y']);
        } else {
            $top = min($prev['y'], $it['y']);
            $h   = max(1.5, abs($it['y'] - $prev['y']));
        }
        // 가운데 칸만 "빠진 양"(−)을 말한다. 첫·마지막 칸은 자기 누적값을 그대로 말한다
        //   (마지막 칸의 값이 바로 앞 칸과 같아도 "−0" 이 아니라 그 값 자체가 맞다).
        $cut = (!$isEdge && $prev !== null) ? $prev['value'] - $it['value'] : null;

        $tag = $it['href'] !== '' ? 'a' : 'g';
        $cls = 'wfall__bar tone-' . $it['tone'] . ($i === $n - 1 ? ' wfall__bar--last' : '');
        $tip = $it['title'] !== '' ? $it['title']
             : ($cut !== null
                 ? $it['label'] . ' · ' . number_format($cut) . '건 제외' . ($it['reason'] !== '' ? '(' . $it['reason'] . ')' : '')
                 : $it['label'] . ' ' . number_format($it['value']) . '건');

        echo '<' . $tag . ' class="' . vg_h($cls) . '"'
            . ($it['href'] !== '' ? ' href="' . vg_h($it['href']) . '"' : '') . '>';
        echo '<title>' . vg_h($tip) . '</title>';
        echo '<rect class="wfall__rect" x="' . round($it['x'], 1) . '" y="' . round($top, 1)
            . '" width="' . $sw . '" height="' . round($h, 1) . '" rx="3"></rect>';

        $mx     = $it['x'] + $sw / 2;
        $valTxt = $cut !== null ? '−' . number_format($cut) : number_format($it['value']);
        echo '<text class="wfall__val" x="' . $mx . '" y="' . round($top - 8, 1) . '">' . vg_h($valTxt) . '</text>';
        echo '<text class="wfall__lbl" x="' . $mx . '" y="' . ($baseline + 16) . '">' . vg_h($it['label']) . '</text>';
        if ($it['reason'] !== '') {
            echo '<text class="wfall__reason" x="' . $mx . '" y="' . ($baseline + 29) . '">' . vg_h($it['reason']) . '</text>';
        }
        echo '</' . $tag . '>';
    }
    echo '</svg></div>';
}

/** 스파크라인 한 줄의 SVG 크기(px). */
const VG_SPARK_W = 88;
const VG_SPARK_H = 26;

/**
 * 자산별 미니 추세 — 자산마다 한 줄에 "스파크라인 + 현재값 + N일 전 대비 증감". vg_multi_trend()
 * 의 겹치는 선 5개 대신 **줄로 쪼갠다**(vg_multi_trend()는 그대로 둔다 — host.php·changes.php 가 쓴다).
 *
 *   $series: [['name'=>자산 이름, 'href'=>'', 'points'=>[['d'=>…, 'v'=>int], …]], …]
 *            points 는 **시간순(오래된→최신)** 이어야 한다 — vg_dash_trend() 의 반환 그대로.
 *   $opts:   'top'(줄 수, 기본 8) · 'unit'(값 뒤 단위) · 'compare_days'(기본 14) · 'empty'
 *
 * 비교 시점은 "정확히 N일 전"이 아니라 **가진 이력 안에서 가장 가까운 과거**다 — 수집을
 *   막 시작한 자산은 N일치가 없어서, 있는 만큼만 비교하고 그 사실을 툴팁에 남긴다(0건으로
 *   메우지 않는다 — vg_dash_trend() 의 이월 규칙과 같은 정직함).
 */
function vg_asset_sparklines(array $series, array $opts = []): void {
    $top        = max(1, (int) ($opts['top'] ?? 8));
    $unit       = (string) ($opts['unit'] ?? '');
    $cmpDaysReq = max(1, (int) ($opts['compare_days'] ?? 14));

    $clean = [];
    foreach ($series as $s) {
        if (!is_array($s) || empty($s['points']) || !is_array($s['points'])) { continue; }
        $pts = array_values($s['points']);
        if (!$pts) { continue; }
        $clean[] = ['name' => (string) ($s['name'] ?? ''), 'href' => (string) ($s['href'] ?? ''), 'points' => $pts];
    }
    if (!$clean) {
        vg_empty($opts['empty'] ?? ['icon' => 'chart', 'title' => '추세를 그리기엔 수집 이력이 부족합니다.',
                                    'hint'  => '서로 다른 날짜의 수집이 2건 이상 쌓이면 여기에 자산별 추세가 표시됩니다.']);
        return;
    }

    // 지금 제일 나쁜 자산이 위로 — 추이의 방향이 아니라 **현재 수치**로 줄을 세운다
    // (등급 도넛·순위 막대와 같은 "지금 뭐가 큰가" 축이라 화면 전체가 한 기준으로 읽힌다).
    usort($clean, static fn(array $a, array $b): int
        => end($b['points'])['v'] <=> end($a['points'])['v']);
    $clean = array_slice($clean, 0, $top);

    echo '<div class="spark-rows">';
    foreach ($clean as $s) {
        $pts   = $s['points'];
        $count = count($pts);
        $now   = (int) $pts[$count - 1]['v'];

        $cmpDays = min($cmpDaysReq, $count - 1);
        $delta   = null; $before = null;
        if ($cmpDays >= 1) {
            $before = (int) $pts[$count - 1 - $cmpDays]['v'];
            $delta  = $now - $before;
        }

        $vals = array_map(static fn($p) => (float) $p['v'], $pts);
        $minV = min($vals); $maxV = max($vals);
        $range = $maxV - $minV;
        $poly = [];
        foreach ($vals as $i => $v) {
            $x = $count > 1 ? VG_SPARK_W * $i / ($count - 1) : VG_SPARK_W / 2;
            $y = $range > 0
                ? 3 + (VG_SPARK_H - 6) * (1 - ($v - $minV) / $range)
                : VG_SPARK_H / 2;
            $poly[] = round($x, 1) . ',' . round($y, 1);
        }
        $lastPoint = explode(',', $poly[count($poly) - 1]);

        if ($delta === null) {
            $deltaTxt = '신규'; $tone = 'muted';
            $deltaTitle = '이력이 하루뿐이라 증감을 비교할 수 없습니다.';
        } else {
            $arrow = $delta > 0 ? '▲' : ($delta < 0 ? '▼' : '–');
            $deltaTxt = $arrow . number_format(abs($delta));
            $tone = $delta > 0 ? 'crit' : ($delta < 0 ? 'ok' : 'muted');
            $deltaTitle = $cmpDays . '일 전(' . number_format($before) . '건) 대비 '
                        . ($delta > 0 ? '+' : '') . number_format($delta) . '건'
                        . ($cmpDays < $cmpDaysReq ? ' · 수집 이력이 ' . $cmpDays . '일치뿐이라 그만큼만 비교' : '');
        }

        $title = $s['name'] . ' · 오늘 ' . number_format($now) . $unit . ' · ' . $deltaTitle;
        $tag   = $s['href'] !== '' ? 'a' : 'div';

        echo '<' . $tag . ' class="spark-row"' . ($s['href'] !== '' ? ' href="' . vg_h($s['href']) . '"' : '')
            . ' title="' . vg_h($title) . '">';
        echo '<span class="spark-row__label">' . vg_h($s['name']) . '</span>';
        echo '<svg class="spark-row__svg" viewBox="0 0 ' . VG_SPARK_W . ' ' . VG_SPARK_H . '" aria-hidden="true" focusable="false">';
        echo '<polyline class="spark-row__line" points="' . implode(' ', $poly) . '"></polyline>';
        echo '<circle class="spark-row__dot" cx="' . $lastPoint[0] . '" cy="' . $lastPoint[1] . '" r="2.2"></circle>';
        echo '</svg>';
        echo '<b class="spark-row__now">' . vg_h(number_format($now) . $unit) . '</b>';
        echo '<span class="spark-row__delta tone-' . $tone . '">' . vg_h($deltaTxt) . '</span>';
        echo '</' . $tag . '>';
    }
    echo '</div>';
}
