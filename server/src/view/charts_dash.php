<?php
declare(strict_types=1);

/**
 * charts_dash.php — 대시보드 상단 전용 차트: 자산 순위 막대 · 자산별 스파크라인.
 *
 *   왜 charts.php 가 아니라 새 파일인가: 지금 여러 워커가 동시에 charts.php 에 차트를
 *   추가하는 중이라(#779 계열 작업들) 한 파일에 몰면 충돌한다 — deptree.php·format/severity.php
 *   로 화면별 헬퍼를 갈라 둔 것과 같은 판단이다.
 *
 *   이 파일이 대체한 것: vg_asset_terrain()(아이소메트릭 지형도) · vg_flow_funnel()(퍼널) ·
 *   vg_flow_waterfall()(사유가 있는 워터폴, "F3(숫자 4칸)" 작업으로 걷었다 — 값 넷과 라벨뿐인
 *   자리는 SVG 도 카드도 필요 없어 dashboard/sections/summary.php 의 vg_kpi_strip() 호출로
 *   바뀌었다). 지형도는 운영 실측에서 실패했다 — 자산 11대의 High 이상이 55~132 로 몰려 있어
 *   블록 높이차가 거의 없었고, 이름표가 앞 블록에 가려 잘렸다. 높이로 비교하는 그림 자체가
 *   이 데이터에 안 맞아서, 이름을 그림 밖 한 열에 세우는 **순위 막대**로 바꾼다.
 *
 *   서버 렌더 HTML(순위 막대)인 이유는 charts.php 머리주석과 같다 — 라벨이 주인공인
 *   차트는 HTML(폭이 줄어도 글자가 안 줄어든다).
 */

require_once __DIR__ . '/../format.php';   // vg_h()
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

/** 증감 막대 한 줄의 SVG 세로 크기(viewBox 단위, 가로는 100 고정 — 아래 vg_asset_delta_bars()
 *  주석 참조). 선이 없는 막대 하나뿐이라 스파크라인(26px)보다 얇다 — 불릿·SLA 소진 막대
 *  (view/charts_bullet.php, 16px)와 같은 인라인 단 안에서 그와 같은 두께로 맞춘다. */
const VG_DELTA_BAR_H = 16;

/**
 * 자산 하나의 추세 점열에서 "지금 값 · N일 전 대비 증감" 을 뽑는다 — vg_asset_sparklines() 의
 * 렌더 루프와 dashboard/sections/trend.php 의 "변화 있는 자산만 고르기" 가 **같은 계산**을
 * 써야 화면에 그려진 증감과 걸러낸 기준이 어긋나지 않는다(둘이 따로 셈하면 조용히 갈린다).
 *
 *   $points: [['d'=>…, 'v'=>int], …] — **시간순(오래된→최신)**, 최소 1건.
 *   비교 시점은 "정확히 N일 전"이 아니라 **가진 이력 안에서 가장 가까운 과거**다 — 수집을
 *   막 시작한 자산은 N일치가 없어서, 있는 만큼만 비교한다(0건으로 메우지 않는다 —
 *   vg_dash_trend() 의 이월 규칙과 같은 정직함). 비교할 과거가 아예 없으면 delta=null.
 *   반환: ['now'=>int, 'before'=>?int, 'delta'=>?int, 'cmp_days'=>int(실제 비교에 쓴 일수)]
 */
function vg_trend_delta(array $points, int $compareDaysReq): array {
    $pts   = array_values($points);
    $count = count($pts);
    $now   = $count > 0 ? (int) $pts[$count - 1]['v'] : 0;

    $cmpDays = min(max(1, $compareDaysReq), max(0, $count - 1));
    if ($cmpDays < 1) {
        return ['now' => $now, 'before' => null, 'delta' => null, 'cmp_days' => 0];
    }
    $before = (int) $pts[$count - 1 - $cmpDays]['v'];
    return ['now' => $now, 'before' => $before, 'delta' => $now - $before, 'cmp_days' => $cmpDays];
}

/**
 * 자산별 증감 막대 — vg_asset_sparklines() 후신(2026-08-23, 스파크라인 폐지). 선 9줄이
 * "계단 한 번 오르고 평평"으로 죄다 같은 모양이라(사용자 지적) 실제로 다른 두 자산이
 * 안 튀었다 — 이 카드의 질문은 "얼마나·어느 방향으로 움직였나"인데 선은 "어떻게 생겼나"를
 * 그렸다. 그래서 모양(선)을 걷어내고 0을 세로 기준선으로 둔 **증감 막대**로 바꾼다 — 늘었으면
 * 오른쪽(빨강), 줄었으면 왼쪽(초록). vg_multi_trend() 는 그대로 둔다(host.php·changes.php 가 쓴다).
 *
 *   $series: vg_asset_sparklines() 와 같은 입력 계약 — [['name'=>자산 이름, 'href'=>'',
 *            'points'=>[['d'=>…, 'v'=>int], …]], …], points 는 시간순(오래된→최신).
 *   $opts:   'top'(줄 수 상한, 기본 8) · 'unit'(값 뒤 단위) · 'compare_days'(기본 14) · 'empty'
 *
 * **정렬을 "지금 값" 내림차순에서 "증감 절대값" 내림차순으로 바꿨다** — 이 카드가 이제
 *   "얼마나 움직였나"를 말하므로 크게 움직인 자산이 위로 와야 한다. 이력이 하루뿐이라
 *   비교 자체가 안 되는 자산(delta=null, '신규')은 움직임의 크기를 모르므로 맨 아래로 보낸다.
 *
 * **기준선 위치를 데이터에 맞춘다(정가운데 고정 아님)**. 이유는 두 가지가 겹친다 —
 *   (1) 늘어난 자산·줄어든 자산 수가 비대칭이면(운영 실측 증가 8·감소 1) 적은 쪽 폭이 대부분의
 *   줄에서 통째로 빈다. (2) 양쪽을 **같은 축척(단위당 폭)** 으로 그리려면, 절대값이 큰 쪽
 *   (운영 실측 ubuntu −262) 이 그 축척을 정해버려 반대쪽(최대 +47)이 제 몫 폭 안에서도 다
 *   눌린다(정가운데 50:50 이면 이 축척 계산에 262 가 쓰여 우측 막대가 전부 47/262≈18% 안에
 *   뭉친다). 그래서 기준선을 "증가 최대 : 감소 최대"의 비로 옮긴다 —
 *     감소쪽 폭(base) : 증가쪽 폭(100-base) = 감소 최대(maxDec) : 증가 최대(maxInc)
 *   로 두면 base = maxDec/(maxDec+maxInc)*100 이고, 이때 두 축척(폭/최대값)이 같아진다
 *   (증명: base/maxDec = (100-base)/maxInc). 즉 **각 쪽의 가장 큰 막대가 정확히 그 쪽 끝까지
 *   닿고**, 나머지는 같은 자로 잰 상대 길이로 보인다 — 어느 쪽도 뭉개지지 않는다. 한쪽 최대가
 *   0(전부 증가/전부 감소)이면 그 쪽 폭을 최소 6%만 남긴다 — 0으로 접으면 기준선이 화면
 *   끝에 붙어 "0" 이라는 개념 자체가 안 보인다.
 */
function vg_asset_delta_bars(array $series, array $opts = []): void {
    $top        = max(1, (int) ($opts['top'] ?? 8));
    $unit       = (string) ($opts['unit'] ?? '');
    $cmpDaysReq = max(1, (int) ($opts['compare_days'] ?? 14));

    $rows = [];
    foreach ($series as $s) {
        if (!is_array($s) || empty($s['points']) || !is_array($s['points'])) { continue; }
        $pts = array_values($s['points']);
        if (!$pts) { continue; }
        $d = vg_trend_delta($pts, $cmpDaysReq);
        $rows[] = [
            'name' => (string) ($s['name'] ?? ''), 'href' => (string) ($s['href'] ?? ''),
            'now' => $d['now'], 'before' => $d['before'], 'delta' => $d['delta'], 'cmp_days' => $d['cmp_days'],
        ];
    }
    if (!$rows) {
        vg_empty($opts['empty'] ?? ['icon' => 'chart', 'title' => '추세를 그리기엔 수집 이력이 부족합니다.',
                                    'hint'  => '서로 다른 날짜의 수집이 2건 이상 쌓이면 여기에 자산별 증감이 표시됩니다.']);
        return;
    }

    // 증감 절대값 내림차순(위 주석) — 신규(delta=null)는 -1 로 둬 맨 아래로 보낸다.
    usort($rows, static function (array $a, array $b): int {
        $ka = $a['delta'] === null ? -1 : abs($a['delta']);
        $kb = $b['delta'] === null ? -1 : abs($b['delta']);
        return [$kb, $b['now']] <=> [$ka, $a['now']];
    });
    $rows = array_slice($rows, 0, $top);

    $maxInc = 0; $maxDec = 0;
    foreach ($rows as $r) {
        if ($r['delta'] === null) { continue; }
        if ($r['delta'] > 0) { $maxInc = max($maxInc, $r['delta']); }
        elseif ($r['delta'] < 0) { $maxDec = max($maxDec, -$r['delta']); }
    }
    $minSide = 6.0; // 위 주석 — 한쪽이 0이어도 기준선이 화면 끝에 붙지 않게.
    if ($maxInc <= 0 && $maxDec <= 0) {
        $base = 50.0; // 그릴 증감이 하나도 없다(전부 신규) — 기준선만 가운데 보인다.
    } else {
        $base = max($minSide, min(100 - $minSide, $maxDec / ($maxDec + $maxInc) * 100));
    }
    // 단위당 폭(px 대신 viewBox 100 기준 %) — 위 주석의 "같은 축척" 계산.
    $pxLeft  = $maxDec > 0 ? $base / $maxDec : 0.0;
    $pxRight = $maxInc > 0 ? (100 - $base) / $maxInc : 0.0;

    echo '<div class="delta-rows">';
    foreach ($rows as $r) {
        $now = $r['now']; $before = $r['before']; $delta = $r['delta']; $cmpDays = $r['cmp_days'];
        $barX = $base; $barW = 0.0; $barTone = '';

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
            $barTone = $tone;
            if ($delta > 0) {
                $barW = max(0.6, round($delta * $pxRight, 2));
                $barX = $base;
            } elseif ($delta < 0) {
                $barW = max(0.6, round(-$delta * $pxLeft, 2));
                $barX = max(0.0, $base - $barW);
            }
        }

        $title = $r['name'] . ' · 오늘 ' . number_format($now) . $unit . ' · ' . $deltaTitle;
        $tag   = $r['href'] !== '' ? 'a' : 'div';

        echo '<' . $tag . ' class="delta-row"' . ($r['href'] !== '' ? ' href="' . vg_h($r['href']) . '"' : '')
            . ' title="' . vg_h($title) . '">';
        echo '<span class="delta-row__label">' . vg_h($r['name']) . '</span>';
        // preserveAspectRatio="none": 가로만 카드 폭에 맞춰 늘어난다(#797 이 스파크라인에서
        //   푼 문제와 같은 이유) — 세로는 CSS height 로 고정된다.
        echo '<svg class="delta-row__svg" viewBox="0 0 100 ' . VG_DELTA_BAR_H . '" preserveAspectRatio="none" aria-hidden="true" focusable="false">';
        if ($barW > 0) {
            echo '<rect class="delta-row__bar tone-' . vg_h($barTone) . '" x="' . round($barX, 2) . '" y="3" width="' . round($barW, 2) . '" height="' . (VG_DELTA_BAR_H - 6) . '"></rect>';
        }
        // 막대보다 나중에 그린다 — 막대가 정확히 기준선에서 시작/끝나 겹치므로, 먼저 그리면
        //   막대 밑에 깔려 안 보인다(신규처럼 막대가 없는 줄에서만 보이게 된다).
        echo '<line class="delta-row__zero" x1="' . round($base, 2) . '" y1="0" x2="' . round($base, 2) . '" y2="' . VG_DELTA_BAR_H . '"></line>';
        echo '</svg>';
        echo '<b class="delta-row__now">' . vg_h(number_format($now) . $unit) . '</b>';
        echo '<span class="delta-row__delta tone-' . $tone . '">' . vg_h($deltaTxt) . '</span>';
        echo '</' . $tag . '>';
    }
    echo '</div>';
}
