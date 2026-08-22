<?php
declare(strict_types=1);

/**
 * charts.php — 차트 렌더. 색은 전부 app.css 의 토큰을 참조하므로 팔레트를 바꾸면 차트도 따라온다.
 *   ① 형태가 고정된 차트(중앙 총계 도넛·순위 막대·다이버징 막대·자산 지형도·처리 흐름 퍼널)는
 *      <svg> 를 직접 그린다.
 *   ② 축·범례·툴팁이 필요한 일반 차트(계열별 추세)는 vg_chart() 로 Chart.js(vendor/) 에 넘긴다.
 *   ②의 색·다크 대응은 assets/js/chart-kit.js 한 곳이 갖는다(파일 아래 주석 참조).
 */

require_once __DIR__ . '/../format.php';
require_once __DIR__ . '/components.php';
// vg_chart_assets() 가 vg_asset() 을 쓴다. 로드 순서에 우연히 얹히지 않도록 명시한다
//   (#271 때 view.php 를 쪼개며 format.php 의존을 선언하지 않아 겪은 그 문제).
require_once __DIR__ . '/layout.php';

/**
 * 톤 어휘 → 도넛 조각·스와치 색. app.css 의 토큰 이름과 1:1 이다(새 색을 만들지 않는다).
 *   cat1..cat6 은 의미가 없는 범주용 팔레트(--cat-N)고, cat6 은 언제나 "기타" 자리다.
 *   어휘 밖 값은 muted 로 눕힌다 — vg_badge()·vg_legend() 와 같은 규칙.
 */
const VG_DONUT_TONES = [
    'crit', 'high', 'med', 'low', 'ok', 'accent', 'purple', 'info', 'muted',
    'cat1', 'cat2', 'cat3', 'cat4', 'cat5', 'cat6',
];

function vg_donut_tone(string $tone): string {
    return in_array($tone, VG_DONUT_TONES, true) ? $tone : 'muted';
}

/**
 * 도넛 옆 **직접 라벨 목록** 한 벌(스와치 · 라벨 · 값). vg_donut_kpi() 가 조각 목록을 그릴 때
 * 쓰고, **도넛으로 그릴 수 없는 희소한 수치**를 도넛 옆에 세울 때도 같은 함수를 쓴다.
 *
 *   희소한 값(전체 대비 0.x%)은 도넛으로 그리면 거짓말이 된다 — 둘 다 그리면 고리가 통째로
 *   한 색이고, 큰 쪽을 arc=false 로 빼면 조각이 하나만 남아 **꽉 찬 원**(=100%)이 된다.
 *   그렇다고 카드 격자로 되돌리면 같은 줄에 어휘가 둘이 된다(도넛 옆에 네모 카드). 그래서
 *   그림은 포기하되 **어휘는 도넛 목록 그대로** 쓴다 — 같은 스와치·같은 행·같은 링크 계약.
 *
 *   $items: [['label'=>…, 'value'=>int, 'tone'=>…, 'href'=>…, 'selected'=>bool, 'title'=>…], …]
 *   $opts:  'caption' — 목록 위에 붙는 짧은 제목(무엇들의 묶음인지). 도넛의 목록은 옆의 고리가
 *           이미 말해 주므로 안 쓰고, 홀로 서는 목록만 쓴다.
 *           'caption_title' — 그 제목의 툴팁(왜 그림이 아닌지 같은 한 문장). 제목 줄에 풀어
 *           쓰면 좁은 칸에서 두 줄이 되어 옆 도넛과 시선 높이가 어긋난다.
 */
function vg_donut_list(array $items, array $opts = []): void {
    echo '<div class="donut-kpi__list">';
    $caption = (string) ($opts['caption'] ?? '');
    if ($caption !== '') {
        $capTitle = (string) ($opts['caption_title'] ?? '');
        echo '<span class="donut-kpi__caption"'
            . ($capTitle !== '' ? ' title="' . vg_h($capTitle) . '"' : '') . '>'
            . vg_h($caption) . '</span>';
    }
    foreach ($items as $s) {
        if (!is_array($s)) { continue; }
        $label = (string) ($s['label'] ?? '');
        $value = (int) ($s['value'] ?? 0);
        $tone  = vg_donut_tone((string) ($s['tone'] ?? 'muted'));
        $href  = (string) ($s['href'] ?? '');
        $title = (string) ($s['title'] ?? ($label . ' ' . number_format($value)));
        $tag   = $href !== '' ? 'a' : 'div';
        $cls   = 'donut-kpi__seg' . ($value === 0 ? ' donut-kpi__seg--zero' : '')
               . (!empty($s['selected']) ? ' is-selected' : '');
        echo '<' . $tag . ' class="' . vg_h($cls) . '"'
            . ($href !== '' ? ' href="' . vg_h($href) . '"' : '')
            . ' title="' . vg_h($title) . '">'
            . '<i class="tone-' . vg_h($tone) . '"></i>'
            . '<span>' . vg_h($label) . '</span>'
            . '<b>' . number_format($value) . '</b>'
            . '</' . $tag . '>';
    }
    echo '</div>';
}

/**
 * **자기 분모를 가진 미니 고리** 목록 — 값마다 한 줄, 줄마다 작은 도넛 하나.
 *
 *   한 고리에 못 담는 값들을 고리 어휘로 세우는 자리다. vg_donut_kpi() 는 조각들이 **한
 *   모집단**을 나눠 가질 때만 쓸 수 있다 — 모집단이 서로 다른 값을 한 고리에 넣으면 합이
 *   거짓말이 된다(자산 상세 '등급 밖의 신호': KEV·외부노출은 tb_finding, 소켓은 tb_exposure,
 *   설정은 tb_cce_finding). 그렇다고 목록만 세우면 옆 카드의 도넛과 어휘도 높이도 안 맞는다.
 *   그래서 **고리를 값 수만큼 쪼갠다** — 각 고리는 자기 분모만 그리므로 어떤 합도 주장하지 않고,
 *   화면에는 옆 카드와 같은 원형 어휘가 선다.
 *
 *   $items: [['label'=>…, 'value'=>int, 'total'=>int, 'denom'=>'전체 취약점',
 *             'tone'=>…, 'href'=>…, 'title'=>…], …]
 *           'total' 이 0이면 고리를 안 채운다(비율을 주장할 근거가 없다 — 값은 그대로 보인다).
 *   $opts:  'size' — 고리 지름(px, 기본 32).
 */
function vg_ratio_rings(array $items, array $opts = []): void {
    $size = max(24, (int) ($opts['size'] ?? 32));
    $r    = 15.9155;   // 둘레가 정확히 100 인 반지름 — dasharray 가 곧 퍼센트다

    echo '<div class="ring-rows">';
    foreach ($items as $it) {
        if (!is_array($it)) { continue; }
        $label = (string) ($it['label'] ?? '');
        $value = max(0, (int) ($it['value'] ?? 0));
        $total = max(0, (int) ($it['total'] ?? 0));
        $denom = (string) ($it['denom'] ?? '');
        $tone  = vg_donut_tone((string) ($it['tone'] ?? 'muted'));
        $href  = (string) ($it['href'] ?? '');
        // 분모가 값보다 작을 수는 없지만(부분/전체), 집계 시점이 어긋나도 고리가 넘치지 않게 자른다.
        $pct   = $total > 0 ? min(100.0, $value / $total * 100) : 0.0;

        // 분모 줄 — 비율은 여기가 말한다(32px 고리 안에는 숫자가 안 들어간다).
        $ratio = $total > 0
            ? $denom . ' ' . number_format($total) . '건의 ' . number_format($pct, 1) . '%'
            : $denom . ' 집계 없음';
        $title = (string) ($it['title'] ?? ($label . ' ' . number_format($value) . ' · ' . $ratio));

        $tag = $href !== '' ? 'a' : 'div';
        $cls = 'ring-row' . ($value === 0 ? ' ring-row--zero' : '');
        echo '<' . $tag . ' class="' . $cls . '"'
            . ($href !== '' ? ' href="' . vg_h($href) . '"' : '')
            . ' title="' . vg_h($title) . '">';

        echo '<span class="ring">'
            . '<svg viewBox="0 0 42 42" width="' . $size . '" height="' . $size . '"'
            . ' role="img" aria-label="' . vg_h($label . ' — ' . $ratio) . '">'
            . '<circle class="donut__track" cx="21" cy="21" r="' . $r . '" fill="none" stroke-width="6"></circle>';
        if ($pct > 0) {
            // 0.6 아래로는 안 줄인다 — 1건짜리 고리가 아예 안 보이면 그림이 숫자와 어긋난다.
            $len = max(0.6, $pct);
            echo '<circle class="donut__arc tone-' . vg_h($tone) . '" cx="21" cy="21" r="' . $r . '"'
                . ' fill="none" stroke-width="6" stroke-linecap="round"'
                . ' stroke-dasharray="' . round($len, 2) . ' ' . round(100 - $len, 2) . '"'
                . ' stroke-dashoffset="25"></circle>';
        }
        echo '</svg></span>';

        echo '<span class="ring-row__text">'
            . '<span class="ring-row__label">' . vg_h($label) . '</span>'
            . '<span class="ring-row__den">' . vg_h($ratio) . '</span>'
            . '</span>'
            . '<b class="ring-row__val">' . number_format($value) . '</b>';

        echo '</' . $tag . '>';
    }
    echo '</div>';
}

/**
 * 중앙 총계 도넛 KPI — 순수 SVG(차트 라이브러리를 들이지 않는다). 왼쪽 도넛 + 오른쪽 조각 목록.
 *
 *   $title    : 접근성 이름(SVG 의 aria-label). **눈에 보이는 제목은 그리지 않는다** —
 *               감싸는 카드의 <strong> 이 이미 갖고 있어서 두 번 적으면 같은 문구가 겹친다.
 *   $segments : [['label'=>'HIGH', 'value'=>968, 'tone'=>'high',
 *                 'href'=>'…', 'selected'=>bool, 'title'=>'…', 'arc'=>bool], …]
 *               값이 0 인 조각은 **목록에는 남기고 호(arc)만 그리지 않는다** — "그 등급이
 *               0건" 은 지워야 할 정보가 아니라 읽어야 할 사실이다(0건 = 안전 아님).
 *               'arc'=>false 는 같은 처리를 **건수와 무관하게** 건다 — 한 조각이 고리를
 *               통째로 먹어 나머지가 실오라기가 될 때 쓴다(심각도의 LOW: 운영 실측
 *               LOW 38,797 : HIGH 962 라 고리의 89%가 회색 한 덩어리였다). 숫자를 지우는
 *               게 아니라 **그림에서만 빼는 것**이라 목록 행은 그대로 남는다.
 *   $opts     : 'center'(중앙 숫자 — 기본은 **호로 그린 것의 합**) · 'center_label'(기본 '전체'
 *               — 목록 툴팁의 비율 분모 이름으로도 쓰인다) ·
 *               'href'(도넛 자체를 링크로) · 'size'(px, 기본 132) ·
 *               'max_segments'(상위 N + '기타' 로 접는다 — 0 이면 접지 않는다) ·
 *               'none'(호로 그릴 게 0 일 때 고리 대신 세울 뱃지 — ['label'=>…, 'tone'=>…].
 *                안 주면 예전처럼 빈 고리 + 중앙 숫자다)
 *
 * **조각 사이에 2px 간격을 둔다.** --high 와 --med 는 맞닿으면 색차가 정상 시야 10.4 ·
 *   색각이상 6.1 로 권장치(15)에 한참 못 미쳐 한 덩어리로 읽힌다. 토큰 값은 바꿀 수 없으므로
 *   (전 화면이 그 색에 의존한다) **형태**로 가른다 — 간격 + 오른쪽 직접 라벨.
 *   간격은 viewBox(42)를 실제 렌더 폭($size)으로 환산해 낸다. `.donut svg` 에는 width:100% 가
 *   없어(그건 `.chart svg` 규칙이다) 렌더 폭이 곧 $size 라 이 환산이 정확하다.
 */
function vg_donut_kpi(string $title, array $segments, array $opts = []): void {
    $size = max(72, (int) ($opts['size'] ?? 132));

    // 조각 정규화. 음수는 받지 않는다 — 도넛은 구성비라 음수가 뜻을 못 갖는다.
    $segs = [];
    foreach ($segments as $s) {
        if (!is_array($s)) { continue; }
        $segs[] = [
            'label'    => (string) ($s['label'] ?? ''),
            'value'    => max(0, (int) ($s['value'] ?? 0)),
            'tone'     => vg_donut_tone((string) ($s['tone'] ?? 'muted')),
            'href'     => (string) ($s['href'] ?? ''),
            'selected' => !empty($s['selected']),
            'title'    => (string) ($s['title'] ?? ''),
            // 기본은 true — 'arc' 를 모르는 기존 호출부는 예전과 똑같이 그려진다.
            'arc'      => !array_key_exists('arc', $s) || (bool) $s['arc'],
        ];
    }

    // 상위 N + 기타 — 범주가 많은 도넛(생태계 분포 등)이 색만 다른 실오라기가 되지 않게.
    //   '기타' 는 언제나 --cat-6 슬롯이다(app.css 범주형 팔레트 주석의 계약).
    $maxSeg = max(0, (int) ($opts['max_segments'] ?? 0));
    if ($maxSeg > 0 && count($segs) > $maxSeg) {
        usort($segs, static fn(array $a, array $b): int => $b['value'] <=> $a['value']);
        $rest = array_slice($segs, $maxSeg);
        $segs = array_slice($segs, 0, $maxSeg);
        $restSum = 0;
        foreach ($rest as $r) { $restSum += $r['value']; }
        $segs[] = ['label' => '기타', 'value' => $restSum, 'tone' => 'cat6',
                   'href' => '', 'selected' => false, 'arc' => true,
                   'title' => '나머지 ' . number_format(count($rest)) . '종 합계'];
    }

    // 두 합을 따로 센다. $total 은 목록이 말하는 **전체**, $arcTotal 은 고리가 실제로 그린 것.
    //   중앙 숫자는 $arcTotal 이어야 한다 — 그림과 숫자가 어긋나면 둘 다 못 믿게 된다.
    //   'arc'=>false 가 하나도 없으면 두 값이 같아서 기존 호출부의 화면은 그대로다.
    $total    = 0;
    $arcTotal = 0;
    $drawn    = 0;
    foreach ($segs as $s) {
        $total += $s['value'];
        if ($s['arc'] && $s['value'] > 0) { $arcTotal += $s['value']; $drawn++; }
    }

    $center      = (string) ($opts['center'] ?? number_format($arcTotal));
    $centerLabel = (string) ($opts['center_label'] ?? '전체');
    $href        = (string) ($opts['href'] ?? '');
    // 고리가 통째로 비면 "고장난 화면" 으로 읽힌다. 부를 때 'none' 을 준 도넛만 상태로 바꾼다.
    $none        = $arcTotal === 0 && is_array($opts['none'] ?? null) ? $opts['none'] : null;

    // 2px 을 viewBox 단위로. 조각이 하나뿐이면 간격을 두지 않는다 — 끊긴 고리가 된다.
    $gap = $drawn > 1 ? min(3.0, 2.0 * 42.0 / $size) : 0.0;
    $r   = 15.9155;   // 둘레가 정확히 100 이 되는 반지름 (2πr = 100) — dasharray 가 곧 퍼센트다

    echo '<div class="donut-kpi">';

    $figTag = $href !== '' ? 'a' : 'div';
    echo '<' . $figTag . ' class="donut donut--kpi' . ($none !== null ? ' donut--none' : '') . '"'
        . ($href !== '' ? ' href="' . vg_h($href) . '"' : '') . '>';
    if ($none !== null) {
        // 그릴 게 없을 때는 빈 고리 대신 상태를 세운다. 값은 오른쪽 목록이 그대로 갖고 있다.
        echo vg_badge((string) ($none['label'] ?? '표시할 항목 없음'),
                      (string) ($none['tone'] ?? 'ok'),
                      (string) ($none['title'] ?? $title));
    } else {
        echo '<svg viewBox="0 0 42 42" width="' . $size . '" height="' . $size . '"'
            . ' role="img" aria-label="' . vg_h($title) . '">';
        echo '<circle class="donut__track" cx="21" cy="21" r="' . $r . '" fill="none" stroke-width="4.5"></circle>';
        if ($arcTotal > 0) {
            $offset = 25;   // 12시 방향에서 시작(원의 기본 시작점은 3시 방향)
            foreach ($segs as $s) {
                if (!$s['arc'] || $s['value'] <= 0) { continue; }
                $pct = $s['value'] / $arcTotal * 100;
                // 간격만큼 짧게 그린다(위치는 그대로 — offset 은 원래 몫만큼 밀어야 이어 붙는다).
                //   0.6 아래로는 안 줄인다: 1건짜리 조각이 아예 사라지면 그림이 목록과 어긋난다.
                $len = max(0.6, $pct - $gap);
                echo '<circle class="donut__arc tone-' . vg_h($s['tone']) . '" cx="21" cy="21" r="' . $r . '"'
                    . ' fill="none" stroke-width="4.5"'
                    . ' stroke-dasharray="' . round($len, 2) . ' ' . round(100 - $len, 2) . '"'
                    . ' stroke-dashoffset="' . round($offset, 2) . '">'
                    . '<title>' . vg_h($s['label'] . ' ' . number_format($s['value'])
                        . ' (' . $centerLabel . '의 ' . number_format($pct, 1) . '%)') . '</title></circle>';
                $offset -= $pct;   // 시계방향으로 이어 붙인다
            }
        }
        echo '</svg>';
        // 라벨이 숫자 위에 온다 — 큰 숫자가 먼저 읽히고, 그게 무엇인지는 바로 위에서 받는다.
        //   자릿수가 많으면(천단위 구분 포함 6자 이상) 고리 안쪽 구멍보다 넓어져 링 위로 걸친다.
        $midCls = 'donut__mid' . (mb_strlen($center) >= 6 ? ' donut__mid--long' : '');
        echo '<div class="' . $midCls . '"><span>' . vg_h($centerLabel) . '</span><b>' . vg_h($center) . '</b></div>';
    }
    echo '</' . $figTag . '>';

    // 직접 라벨 — 색만으로 조각을 식별하게 두지 않는다(색각이상·흑백 인쇄·인접 색 문제).
    //   행 마크업은 vg_donut_list() 하나가 갖는다(도넛 없이 서는 목록과 같은 어휘여야 한다).
    $rows = [];
    foreach ($segs as $s) {
        // 비율의 분모를 조각마다 맞춘다 — 호로 그린 조각은 고리와 같은 분모($arcTotal),
        //   그림에서 뺀 조각은 전체($total). 한 분모로 통일하면 "고리의 20%인데 툴팁은 2%"
        //   처럼 그림과 글자가 어긋난다.
        $tip  = $s['title'] !== '' ? $s['title']
              : ($s['arc']
                  ? $s['label'] . ' ' . number_format($s['value'])
                    . ($arcTotal > 0 ? ' (' . $centerLabel . '의 '
                        . number_format($s['value'] / $arcTotal * 100, 1) . '%)' : '')
                  : $s['label'] . ' ' . number_format($s['value'])
                    . ($total > 0 ? ' (전체의 ' . number_format($s['value'] / $total * 100, 1) . '%)' : '')
                    . ' · 도넛에는 그리지 않는다');
        $rows[] = ['label' => $s['label'], 'value' => $s['value'], 'tone' => $s['tone'],
                   'href' => $s['href'], 'selected' => $s['selected'], 'title' => $tip];
    }
    vg_donut_list($rows);

    echo '</div>';
}

/**
 * 심각도 도넛 — vg_donut_kpi() 로 그린다(도넛 구현은 이 저장소에 한 벌만 둔다).
 *   $counts: ['CRITICAL'=>3, 'HIGH'=>7, …].
 *   $opts:   'title'(aria-label, 기본 '심각도 분포') · 'href'(도넛 자체를 링크로) ·
 *            'seg'(등급마다 href/selected/title 을 얹는 콜백 — fn(string $sev, int $n): array).
 *            나머지 키는 vg_donut_kpi 로 그대로 넘어간다.
 *
 * **고리는 조치 대상(CRITICAL·HIGH·MEDIUM)만 그린다.** LOW 는 목록에만 남는다(숫자는 안 지운다).
 *   운영 실측이 LOW 38,797 : HIGH 962 : MEDIUM 3,927 : CRITICAL 0 이라 같이 그리면 고리의
 *   89%가 회색 한 덩어리가 되고 조치할 등급이 실오라기가 됐다. 추세 차트가 이미 같은 이유로
 *   C·H·M 만 그린다(#137) — 그때 "전체 구성은 도넛이 맡는다"고 미뤄둔 판단을 여기서 잇는다.
 *   중앙 숫자도 따라서 **조치 대상 합**이다 — 전체 건수는 목록의 LOW 행과 화면 상단 KPI 가 갖는다.
 *
 * 심각도가 아닌 도넛(판정 PASS/FAIL·노출 범위·SBOM 생태계/라이선스)은 이 규칙과 무관하다 —
 *   LOW 축이 없어서 뺄 것이 없다. 그쪽은 vg_donut_kpi 를 직접 부른다.
 */
function vg_sev_donut(array $counts, int $size = 132, array $opts = []): void {
    $seg   = $opts['seg'] ?? null;
    $title = (string) ($opts['title'] ?? '심각도 분포');
    unset($opts['seg'], $opts['title']);

    $segments = [];
    foreach (VG_TONE_SEV as $sev => $tone) {
        $n     = (int) ($counts[$sev] ?? 0);
        $extra = $seg !== null ? (array) $seg($sev, $n) : [];
        // 왼쪽(호출부가 준 href·selected·title)이 이기고, 오른쪽은 이 함수가 정하는 계약이다.
        $segments[] = $extra + ['tone' => $tone, 'label' => $sev, 'value' => $n, 'arc' => $sev !== 'LOW'];
    }

    vg_donut_kpi($title, $segments, $opts + [
        'size'         => $size,
        'center_label' => '조치 대상',
        'none'         => ['label' => '조치 대상 없음', 'tone' => 'ok',
                           'title' => 'CRITICAL·HIGH·MEDIUM 이 0건이라 고리를 그리지 않습니다'
                                    . ' · 등급별 건수는 오른쪽 목록에 있습니다'],
    ]);
}

/**
 * 노출·실행 상태(runtime_status)의 어휘 정본 — [라벨, 톤, 고리에 그리는가].
 *
 *   순서가 곧 노출 강도다(밖에서 닿는 것 → 안에서 도는 것 → 안 도는 것 → 모르는 것).
 *   고리에는 **실제로 노출·실행 중인 것만** 그린다. '설치만 됨' 이 압도적이라(dev 실측
 *   162,100 : 나머지 42,977) 같이 그리면 고리의 79%가 한 색 덩어리가 되고, '방화벽 차단'·
 *   '상태 미상' 도 같은 이유로 뺀다 — 심각도 도넛이 LOW 를 빼는 것과 같은 처방이다.
 *   **숫자는 지우지 않는다**: 뺀 상태도 목록에 건수로 남고 링크도 산다.
 *
 *   톤은 vg_status_badge() 의 뱃지 색과 굳이 맞추지 않는다 — 저기는 값 하나를 뱃지로 말하는
 *   자리고 여기는 여덟 값이 **한 목록에서 서로 갈려야** 하는 자리다(인접 스와치 색차 문제).
 *   '방화벽 차단' 이 ok(초록)인 것도 그래서다: info(파랑)로 뒀더니 바로 윗줄 '사용 중'(accent)과
 *   rgb(37,99,224) : rgb(49,130,246) 으로 사실상 같은 색이었다(브라우저 실측). 노출 축에서
 *   '밖에서 못 닿는다' 는 실제로 안전한 쪽이라 초록이 뜻과도 맞는다.
 */
const VG_RUNTIME_DONUT = [
    'EXTERNAL'  => ['외부 노출',         'crit',   true],
    'LAN'       => ['로컬 세그먼트 노출', 'purple', true],
    'LISTENING' => ['수신 대기',          'high',   true],
    'RUNNING'   => ['실행 중',            'med',    true],
    'LOADED'    => ['사용 중',            'accent', true],
    'FILTERED'  => ['방화벽 차단',        'ok',     false],
    'INSTALLED' => ['설치만 됨',          'low',    false],
    '미상'      => ['상태 미상',          'muted',  false],
];

/**
 * 노출·실행 상태 도넛 — 대시보드와 탐지 결과가 **같은 함수·같은 어휘**로 그린다.
 *   같은 축(무엇이 밖에서 닿는가)을 화면마다 다른 라벨·다른 색으로 그리면 두 화면의 숫자를
 *   이어서 읽을 수 없다. 어휘는 위 VG_RUNTIME_DONUT 하나가 갖는다.
 *
 *   $runtime: [상태키 => 건수]. **넘긴 키만** 그린다 — 화면마다 세는 상태의 폭이 다르다
 *             (대시보드는 네 상태 + '미상', 탐지 결과는 툴바 필터와 같은 일곱 상태 + '미상').
 *   $opts:    'seg' — fn(string $key, int $n): array 로 href/selected/title 을 얹는다
 *             (심각도 도넛과 같은 계약). 나머지 키는 vg_donut_kpi 로 그대로 넘어간다.
 */
function vg_runtime_donut(array $runtime, int $size = 132, array $opts = []): void {
    $seg   = $opts['seg'] ?? null;
    $title = (string) ($opts['title'] ?? '노출·실행 상태 구성');
    unset($opts['seg'], $opts['title']);

    $segments = [];
    $live     = 0;
    foreach (VG_RUNTIME_DONUT as $key => [$label, $tone, $arc]) {
        if (!array_key_exists($key, $runtime)) { continue; }
        $n = (int) $runtime[$key];
        if ($arc) { $live += $n; }
        $extra = $seg !== null ? (array) $seg($key, $n) : [];
        // 왼쪽(호출부가 준 href·selected·title)이 이기고, 오른쪽은 이 함수가 정하는 계약이다.
        $segments[] = $extra + ['tone' => $tone, 'label' => $label, 'value' => $n, 'arc' => $arc];
    }

    vg_donut_kpi($title, $segments, $opts + [
        'size'         => $size,
        'center'       => number_format($live),
        'center_label' => '노출·실행 중',
        'none'         => ['label' => '노출·실행 중 없음', 'tone' => 'ok',
                           'title' => '외부 노출·수신 대기·실행 중이 0건이라 고리를 그리지 않습니다'
                                    . ' · 상태별 건수는 오른쪽 목록에 있습니다'],
    ]);
}

/**
 * 임의 판정 분포 도넛(PASS/FAIL/NA 등) — 심각도처럼 어휘가 고정돼 있지 않은 화면들이 쓴다
 *   (control.php 의 PASS/FAIL/판정불가, cce-rule.php 등).
 *   $segments: [['tone'=>'crit', 'label'=>'FAIL', 'n'=>3], …] — 'n' 은 옛 계약이라 그대로 받는다.
 */
function vg_result_donut(array $segments, int $size = 132, string $alt = '판정 분포'): void {
    $out = [];
    foreach ($segments as $seg) {
        $out[] = [
            'tone'  => (string) ($seg['tone'] ?? 'muted'),
            'label' => (string) ($seg['label'] ?? ''),
            'value' => (int) ($seg['value'] ?? $seg['n'] ?? 0),
        ];
    }
    vg_donut_kpi($alt, $out, ['size' => $size]);
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
 * 회차별 신규(0 기준선 위)·해결(아래) 다이버징 막대차트 — 이 파일에 남은 마지막 SVG
 * 눈금 차트다(grid/tick/lbl 규칙을 쓰는 곳도 여기뿐). 첫 회차(비교 대상 없는 기준선)는
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

/* ==========================================================================
 * 아이소메트릭 자산 지형도 · 처리 흐름 퍼널 — 대시보드 상단의 두 그림.
 *
 * 왜 여기 있나: 이 파일의 헬퍼 14개 중 7개가 도넛 변형이라 화면이 달라져도 같은 그림으로
 *   읽혔다(사용자 지적: "원형 도표밖에 없으니 안 이쁘네"). 형태를 **딱 둘** 더한다 —
 *   "어느 자산이 얼마나 나쁜가"(지형도)와 "무엇까지 좁혀지나"(퍼널). 도넛은 구성비를
 *   묻는 자리에 그대로 남는다(등급 구성 · 노출·실행).
 * 왜 서버 렌더 SVG 인가: CSP 가 default-src 'self' 라 인라인 <script> 가 아예 안 돈다
 *   (deptree.php·도넛과 같은 이유). 3D 라이브러리도 쓰지 않는다 — 아이소메트릭은
 *   폴리곤 좌표 계산과 <path> 세 장이면 끝난다.
 * 색은 여기서 정하지 않는다: 면마다 클래스를 주고 명도차는 app.css 가 color-mix() 로 낸다
 *   (하드코딩 hex 로 어둡게 하면 다크에서 면이 배경에 잠긴다).
 * ========================================================================== */

/** 지형도 격자 — 타일 반폭·반높이(2:1 아이소메트릭)와 한 줄에 세우는 블록 수. */
const VG_TERRAIN_TW   = 54;
const VG_TERRAIN_TH   = 27;
const VG_TERRAIN_COLS = 4;
/** 기둥 높이 = 밑값 + 비율 × 폭. 밑값이 있어야 0건 자산도 블록으로 보인다(바닥 얼룩이 아니라). */
const VG_TERRAIN_BASE = 26;
const VG_TERRAIN_SPAN = 104;
/**
 * 이름표 최대 글자 수와 그만큼 잡아 두는 좌우 여백(px).
 *   한 줄 안에서 이웃 이름표끼리는 2×TW(108px) 떨어져 있으므로 이름표 하나가 68px(≈14자,
 *   9px 글꼴) 을 넘지 않으면 서로 겹치지 않는다. 여백은 맨 왼쪽·맨 오른쪽 이름표가
 *   viewBox 밖으로 잘리지 않게 하는 몫이다(블록보다 이름표가 넓다).
 */
const VG_TERRAIN_NAME_MAX = 14;
const VG_TERRAIN_NAME_PAD = 34;

/**
 * 자산 지형도 — 자산 하나가 아이소메트릭 블록 하나. **높이 = High 이상 건수**, 윗면 색 =
 * 그 자산의 최악 등급, 윗면의 붉은 원 = KEV 보유 건수.
 *
 *   $assets: [['label'=>자산 이름, 'high'=>int, 'crit'=>int, 'kev'=>int, 'href'=>''], …]
 *            순서는 여기서 다시 잡는다(High 이상 내림차순) — 호출부마다 정렬을 다시 지키게
 *            하지 않는다(vg_rank_bars 와 같은 규약).
 *   $opts:   'top'(세울 블록 수, 기본 12) · 'empty'(vg_empty 스펙) ·
 *            'rest_href'(접힌 자산으로 가는 링크)
 *
 * **왜 상위 N 만 세우나**: 지금은 자산이 11대지만 50대가 되면 격자가 카드를 넘는다. 접는
 *   기준은 화면이 말하는 것과 같은 축(High 이상)이고, 접힌 수는 그림 아래 한 줄로 남긴다 —
 *   조용히 자르지 않는다(tests/ui_lint.sh 4번 검사가 목록에 거는 규칙과 같은 판단).
 *
 * **그리는 순서가 곧 겹침 순서다** — 뒤(row+col 작은 것)부터 앞으로 그린다. 뒤집으면 앞
 *   블록이 뒷 블록에 먹힌다. 배치는 행 우선(가장 나쁜 자산이 뒤-왼쪽)이라 **큰 블록이 늘
 *   뒤에 선다** — 앞줄이 더 낮으므로 윗면과 숫자가 가려지지 않는다(높이가 내림차순이라
 *   구조적으로 그렇다). 이름표만 마지막에 한 번에 그린다(블록 면 위로 올라오게).
 */
function vg_asset_terrain(array $assets, array $opts = []): void {
    $items = [];
    foreach ($assets as $a) {
        if (!is_array($a)) { continue; }
        $items[] = [
            'label' => (string) ($a['label'] ?? ''),
            'high'  => max(0, (int) ($a['high'] ?? 0)),
            'crit'  => max(0, (int) ($a['crit'] ?? 0)),
            'kev'   => max(0, (int) ($a['kev'] ?? 0)),
            'href'  => (string) ($a['href'] ?? ''),
        ];
    }
    if (!$items) {
        vg_empty($opts['empty'] ?? ['icon' => 'host', 'title' => '아직 수집된 자산이 없습니다.',
                                    'hint'  => '에이전트를 --send 로 실행하면 자산이 여기에 블록으로 섭니다.']);
        return;
    }

    usort($items, static fn(array $x, array $y): int
        => [$y['high'], $y['kev'], $x['label']] <=> [$x['high'], $x['kev'], $y['label']]);

    $top   = max(1, (int) ($opts['top'] ?? 12));
    $rest  = array_slice($items, $top);
    $shown = array_slice($items, 0, $top);

    $maxH = 0;
    foreach ($shown as $s) { $maxH = max($maxH, $s['high']); }

    // 좌표는 원점(0,0) 기준으로 잡고, 다 그린 뒤 실제 차지한 범위로 viewBox 를 낸다 —
    //   자산이 2대든 12대든 그림이 카드 안에서 제 크기로 선다(빈 여백을 그리지 않는다).
    $blocks = [];
    foreach ($shown as $i => $s) {
        $row = intdiv($i, VG_TERRAIN_COLS);
        $col = $i % VG_TERRAIN_COLS;
        $h   = VG_TERRAIN_BASE + ($maxH > 0 ? (int) round($s['high'] / $maxH * VG_TERRAIN_SPAN) : 0);
        $blocks[] = $s + [
            'x'     => ($col - $row) * VG_TERRAIN_TW,
            'y'     => ($col + $row) * VG_TERRAIN_TH,
            'h'     => $h,
            'depth' => $row + $col,
            // 윗면 색은 그 자산의 최악 등급이다. KEV 는 등급과 독립이라 색이 아니라 표식이 말한다.
            'tone'  => $s['crit'] > 0 ? 'crit' : ($s['high'] > 0 ? 'high' : 'ok'),
        ];
    }
    usort($blocks, static fn(array $x, array $y): int => $x['depth'] <=> $y['depth']);

    $tw = VG_TERRAIN_TW;
    $th = VG_TERRAIN_TH;
    $minX = $maxX = $minY = $maxY = 0.0;
    foreach ($blocks as $k => $b) {
        $l = $b['x'] - $tw - VG_TERRAIN_NAME_PAD;                   // 이름표가 블록보다 넓을 수 있다
        $r = $b['x'] + $tw + VG_TERRAIN_NAME_PAD;
        $t = $b['y'] - $th - $b['h'] - 6;                           // 윗면 위 꼭짓점
        $u = $b['y'] + $th + 16;                                    // 이름표 한 줄
        if ($k === 0) { $minX = $l; $maxX = $r; $minY = $t; $maxY = $u; }
        $minX = min($minX, $l); $maxX = max($maxX, $r);
        $minY = min($minY, $t); $maxY = max($maxY, $u);
    }

    $kevHosts = 0;
    foreach ($shown as $s) { if ($s['kev'] > 0) { $kevHosts++; } }
    $alt = '자산 지형도 · 블록 ' . count($shown) . '개'
         . ' · 블록 높이는 High 이상 건수(최대 ' . number_format($maxH) . '건)'
         . ' · KEV 보유 자산 ' . $kevHosts . '대'
         . ($rest ? ' · 나머지 ' . count($rest) . '대는 접힘' : '');

    echo '<div class="terrain">';
    echo '<svg viewBox="' . round($minX, 1) . ' ' . round($minY, 1) . ' '
        . round(max(1.0, $maxX - $minX), 1) . ' ' . round(max(1.0, $maxY - $minY), 1) . '"'
        . ' role="img" aria-label="' . vg_h($alt) . '">';

    foreach ($blocks as $b) {
        $x = $b['x']; $y = $b['y']; $h = $b['h'];
        $tag = $b['href'] !== '' ? 'a' : 'g';
        echo '<' . $tag . ' class="terrain__block tone-' . vg_h($b['tone']) . '"'
            . ($b['href'] !== '' ? ' href="' . vg_h($b['href']) . '"' : '') . '>';
        echo '<title>' . vg_h($b['label'] . ' · High 이상 ' . number_format($b['high']) . '건'
            . ($b['crit'] > 0 ? ' (CRITICAL ' . number_format($b['crit']) . ')' : '')
            . ($b['kev'] > 0 ? ' · KEV ' . number_format($b['kev']) . '건' : '')) . '</title>';
        // 왼쪽·오른쪽 면을 먼저, 윗면을 나중에 — 한 블록 안에서도 위가 앞이다.
        echo '<path class="terrain__face terrain__left" d="'
            . 'M' . ($x - $tw) . ' ' . ($y - $h)
            . 'L' . $x . ' ' . ($y + $th - $h)
            . 'L' . $x . ' ' . ($y + $th)
            . 'L' . ($x - $tw) . ' ' . $y . 'Z"></path>';
        echo '<path class="terrain__face terrain__right" d="'
            . 'M' . ($x + $tw) . ' ' . ($y - $h)
            . 'L' . $x . ' ' . ($y + $th - $h)
            . 'L' . $x . ' ' . ($y + $th)
            . 'L' . ($x + $tw) . ' ' . $y . 'Z"></path>';
        echo '<path class="terrain__face terrain__top" d="'
            . 'M' . $x . ' ' . ($y - $th - $h)
            . 'L' . ($x + $tw) . ' ' . ($y - $h)
            . 'L' . $x . ' ' . ($y + $th - $h)
            . 'L' . ($x - $tw) . ' ' . ($y - $h) . 'Z"></path>';
        // 값과 KEV 표식은 **윗면 안쪽**에 앉힌다. 머리 위로 띄우면 자기 블록을 벗어나
        //   뒷 블록의 윗면에 얹힌다 — 높이가 비슷한 자산이 이웃하면(실측 dev: 12대가 전부
        //   90건) 표식이 남의 지붕 한가운데에 박힌다. 윗면 다이아몬드는 108×54 라
        //   위쪽 삼각형(중심에서 13px 위, 폭 56px)에 지름 18px 표식이 그대로 들어간다.
        echo '<text class="terrain__val" x="' . $x . '" y="' . ($y - $h + ($b['kev'] > 0 ? 7 : 0)) . '">'
            . vg_h(number_format($b['high'])) . '</text>';
        if ($b['kev'] > 0) {
            $ky = $y - $h - 13;
            echo '<circle class="terrain__kev" cx="' . $x . '" cy="' . $ky . '" r="9"></circle>';
            echo '<text class="terrain__kevn" x="' . $x . '" y="' . $ky . '">'
                . vg_h($b['kev'] > 99 ? '99+' : (string) $b['kev']) . '</text>';
        }
        echo '</' . $tag . '>';
    }

    // 이름표는 **전부 마지막에** 그린다 — 다이아몬드가 평면을 빈틈없이 덮어서 어디에 놓든
    //   앞 블록의 면에 걸린다. 순서로 위에 올리고, 글자 테두리(paint-order)로 어느 면
    //   위에서도 읽히게 한다. 전체 이름은 블록의 <title> 이 갖는다.
    foreach ($blocks as $b) {
        $name = mb_strlen($b['label']) > VG_TERRAIN_NAME_MAX
              ? mb_substr($b['label'], 0, VG_TERRAIN_NAME_MAX - 1) . '…' : $b['label'];
        echo '<text class="terrain__name" x="' . $b['x'] . '" y="' . ($b['y'] + $th + 12) . '">'
            . vg_h($name) . '</text>';
    }
    echo '</svg></div>';

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

/** 퍼널 좌표 — 단계 띠 폭 · 단계 사이 사다리꼴 폭 · 가장 두꺼운 띠. */
const VG_FLOW_STEP_W = 64;
const VG_FLOW_LINK_W = 54;
const VG_FLOW_MAX_T  = 132;

/**
 * 처리 흐름 퍼널 — 앞 단계를 포함관계로 좁혀 가는 띠. 단계마다 값·라벨·"앞 단계 대비
 * 남는 비율"을 글자로 적는다.
 *
 *   $steps: [['label'=>…, 'value'=>int, 'tone'=>…, 'href'=>'', 'title'=>''], …]
 *           **첫 단계가 가장 큰 모집단**이어야 한다 — 뒤 단계는 앞 단계의 부분집합이라는
 *           전제 위에 그린 그림이라, 부분집합이 아니게 되면 형태 자체가 거짓말이 된다.
 *   $opts:  'title'(SVG 접근성 이름의 머리)
 *
 * **두께는 로그 척도**다(log10(v+1) / log10(첫값+1)). 선형으로 그리면 44,349 대 3 에서
 *   뒤 세 칸이 1px 실선이 되어 사라진다 — 도넛에서 LOW 를 빼는 것과 같은 문제인데, 여기서는
 *   칸을 뺄 수가 없다(포함관계의 마지막 칸이 곧 "오늘 할 일" 이다). 비율을 눈으로 재는
 *   그림이 아니라 **좁혀지는 관계**를 보는 그림이므로 로그가 정직하다 — 진짜 비율은
 *   칸마다 글자로 적는다.
 */
function vg_flow_funnel(array $steps, array $opts = []): void {
    $items = [];
    foreach ($steps as $s) {
        if (!is_array($s)) { continue; }
        $items[] = [
            'label' => (string) ($s['label'] ?? ''),
            'value' => max(0, (int) ($s['value'] ?? 0)),
            'tone'  => vg_donut_tone((string) ($s['tone'] ?? 'muted')),
            'href'  => (string) ($s['href'] ?? ''),
            'title' => (string) ($s['title'] ?? ''),
        ];
    }
    if (!$items) { return; }

    $n    = count($items);
    $base = log10($items[0]['value'] + 1);
    $sw   = VG_FLOW_STEP_W;
    $lw   = VG_FLOW_LINK_W;
    $W    = $n * $sw + ($n - 1) * $lw + 12;
    $cy   = 10 + VG_FLOW_MAX_T / 2;
    $H    = 208;

    foreach ($items as $i => &$it) {
        // 0건도 띠를 남긴다 — "그 칸이 비었다" 는 지워야 할 정보가 아니라 읽어야 할 사실이다.
        $t = $base > 0 ? VG_FLOW_MAX_T * (log10($it['value'] + 1) / $base) : VG_FLOW_MAX_T;
        $it['t'] = max(5.0, $t);
        $it['x'] = 6 + $i * ($sw + $lw);
        // 0건이면 색을 걷는다(옛 퍼널 타일과 같은 규칙) — 0 은 지금 볼 것이 없다는 뜻이다.
        if ($it['value'] === 0) { $it['tone'] = 'muted'; }
    }
    unset($it);

    $alt = (string) ($opts['title'] ?? '처리 흐름');
    foreach ($items as $it) { $alt .= ' · ' . $it['label'] . ' ' . number_format($it['value']) . '건'; }

    echo '<div class="flow">';
    echo '<svg viewBox="0 0 ' . $W . ' ' . $H . '" role="img" aria-label="' . vg_h($alt) . '">';

    foreach ($items as $i => $it) {
        $tag  = $it['href'] !== '' ? 'a' : 'g';
        $prev = $i > 0 ? $items[$i - 1] : null;
        $pct  = $prev !== null && $prev['value'] > 0 ? $it['value'] / $prev['value'] * 100 : null;
        $cls  = 'flow__step tone-' . $it['tone']
              . ($i === $n - 1 ? ' flow__step--last' : '')
              . ($it['value'] === 0 ? ' flow__step--zero' : '');
        $tip  = $it['title'] !== '' ? $it['title'] : $it['label'] . ' ' . number_format($it['value']) . '건';
        if ($pct !== null) { $tip .= ' · 앞 단계 대비 ' . number_format($pct, 1) . '%'; }

        echo '<' . $tag . ' class="' . vg_h($cls) . '"'
            . ($it['href'] !== '' ? ' href="' . vg_h($it['href']) . '"' : '') . '>';
        echo '<title>' . vg_h($tip) . '</title>';
        // 앞 단계에서 이 단계로 좁혀지는 사다리꼴 — 이 단계의 색을 옅게 깔아 흐름의 방향을 준다.
        if ($prev !== null) {
            $x1 = $prev['x'] + $sw;
            $x2 = $it['x'];
            echo '<path class="flow__link" d="'
                . 'M' . $x1 . ' ' . round($cy - $prev['t'] / 2, 1)
                . 'L' . $x2 . ' ' . round($cy - $it['t'] / 2, 1)
                . 'L' . $x2 . ' ' . round($cy + $it['t'] / 2, 1)
                . 'L' . $x1 . ' ' . round($cy + $prev['t'] / 2, 1) . 'Z"></path>';
        }
        echo '<rect class="flow__band" x="' . $it['x'] . '" y="' . round($cy - $it['t'] / 2, 1)
            . '" width="' . $sw . '" height="' . round($it['t'], 1) . '" rx="3"></rect>';

        $mx = $it['x'] + $sw / 2;
        echo '<text class="flow__val" x="' . $mx . '" y="172">' . vg_h(number_format($it['value'])) . '</text>';
        echo '<text class="flow__lbl" x="' . $mx . '" y="188">' . vg_h($it['label']) . '</text>';
        echo '<text class="flow__pct" x="' . $mx . '" y="201">'
            . vg_h($pct === null ? '기준' : '앞 대비 ' . number_format($pct, 1) . '%') . '</text>';
        echo '</' . $tag . '>';
    }
    echo '</svg></div>';
}

/* ==========================================================================
 * Chart.js 기반 차트 — 위 SVG 차트들이 못 그리는 형태(범주형 도넛·다계열 막대 등)용.
 *
 * 왜 라이브러리인가: 위 함수들은 "심각도 도넛" 처럼 **형태가 고정된** 차트다. 축·범례·툴팁·
 *   반응형이 필요한 일반 차트를 SVG 로 계속 늘리면 그때부터는 우리가 차트 라이브러리를
 *   직접 만드는 셈이 된다. Chart.js(MIT, 208KB·gzip 70KB)를 vendor 로 들인다.
 * 왜 CDN 이 아닌가: 대상 환경(주요정보통신기반시설·전자금융)은 폐쇄망이 흔해 CDN 을 물면
 *   그 환경에서 화면이 통째로 깨진다. flatpickr(host.php)가 이미 같은 방식이다.
 * 왜 헬퍼 하나인가: 팔레트·격자색·툴팁·다크 대응이 화면마다 갈라지지 않게 하기 위해서다.
 *   색은 assets/js/chart-kit.js 한 곳에서만 정하고, 화면은 데이터와 형태만 말한다.
 * ========================================================================== */

/**
 * 차트 자산(vendor + chart-kit)을 이 페이지에 붙인다. **차트를 그리는 화면만** 부른다 —
 *   전 화면에 70KB 를 물리지 않기 위해 layout.php 에 넣지 않았다.
 *   호출 위치는 vg_header() 직후(본문 시작 지점)다. chart-kit.js 는 defer 라 문서 순서대로
 *   실행되고, vendor 는 동기 로드라 그 전에 window.Chart 가 준비된다(host.php 의 flatpickr 와 같은 순서).
 *   여러 번 불러도 한 번만 나간다.
 */
function vg_chart_assets(): void {
    static $emitted = false;
    if ($emitted) {
        return;
    }
    $emitted = true;
    echo '<script src="' . vg_asset('/assets/vendor/chartjs/chart.umd.js') . '"></script>' . "\n";
    echo '<script src="' . vg_asset('/assets/js/chart-kit.js') . '" defer></script>' . "\n";
}

/**
 * 차트 하나를 그린다. 실제 렌더는 chart-kit.js 가 한다 — 여기서는 사양을 data 속성에 실어
 *   넘길 뿐이다(CSP 가 default-src 'self' 라 인라인 <script> 를 못 쓴다).
 *
 * $type  : 'doughnut'|'bar'|'line' … (Chart.js 타입)
 * $data  : ['labels' => [...], 'datasets' => [['label'=>…, 'data'=>[…]], …]]
 *          색을 주지 않으면 chart-kit 이 범주형 팔레트(--cat-1..6)를 순서대로 배정한다.
 *          심각도처럼 의미가 고정된 색을 직접 줄 때는 데이터셋에 'vgKeepColors' => true 를 함께 준다.
 * $opts  : ['size' => 'sm'|'md'|'lg', 'alt' => 대체 텍스트, 'options' => Chart.js options 덮어쓰기]
 *
 * 높이는 클래스로만 준다(인라인 style 금지 — app.css 가 크기를 소유한다).
 * <canvas> 안의 글은 캔버스를 못 그리는 환경에서 읽히는 대체 텍스트다.
 */
function vg_chart(string $type, array $data, array $opts = []): void {
    // 자산(vendor + chart-kit)은 여기서 붙인다 — 차트를 그리는 화면만 70KB 를 물게 하되,
    //   화면마다 "부르는 걸 잊어 캔버스가 빈 채로 뜨는" 실수를 구조적으로 없앤다. 멱등이다.
    vg_chart_assets();

    $sizes = ['sm' => 'chart-js--sm', 'md' => 'chart-js--md', 'lg' => 'chart-js--lg'];
    $size  = $sizes[(string) ($opts['size'] ?? 'md')] ?? $sizes['md'];
    $alt   = (string) ($opts['alt'] ?? '차트');

    $spec = ['type' => $type, 'data' => $data];
    if (!empty($opts['options'])) {
        $spec['options'] = $opts['options'];
    }
    $json = json_encode($spec, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

    echo '<div class="chart-js ' . $size . '">'
        . '<canvas role="img" aria-label="' . vg_h($alt) . '" data-vg-chart="' . vg_h((string) $json) . '">'
        . vg_h($alt) . '</canvas></div>';
}

/**
 * 자산(계열)별 멀티라인 추세 — Chart.js `line` 에 위임한다.
 *
 * 왜 SVG 가 아닌가: 계열이 여럿이면 범례·공통 x 툴팁·축이 필요하고, 그걸 SVG 로 계속 늘리면
 *   우리가 차트 라이브러리를 직접 만드는 셈이 된다(이 파일 아래 Chart.js 절의 판단과 같다).
 *
 *   $series : [['name' => 'ubuntu-01', 'points' => [['d' => '8/20', 'v' => 412], …]], …]
 *             'd' 는 **x축 라벨 문자열**이다(표시할 모양 그대로 넘긴다). 계열마다 점 개수가
 *             달라도 라벨로 맞춰 꽂으므로, 빠진 라벨은 null 이 되어 선이 그 구간만 이어진다
 *             (spanGaps). **없는 날을 0 으로 떨구지 않는다** — 이 스키마는 "바뀔 때만 스냅샷"
 *             이라 0 으로 이으면 "취약점이 사라졌다"는 거짓말이 된다(이월은 호출부의 몫이다).
 *   $opts   : 'unit'(툴팁 값 뒤에 붙는 단위) · 'max_series'(기본 5 — 넘으면 상위 N + '기타') ·
 *             'y_max'(y 축 상한 고정 — 사용률처럼 0~100 이 절대 의미를 갖는 값에 준다) ·
 *             'size'('sm'|'md'|'lg') · 'alt'(대체 텍스트) · 'fold'(false 면 접지 않고 자른다)
 *
 * 규모가 크게 다른 계열을 한 차트에 쌓으면 작은 계열이 1px 실선이 된다(PR #137 의 실측:
 *   LOW 2,198 : CRITICAL 2). 그래서 **계열은 상위 N 으로 제한**하고, 전체 구성은 도넛
 *   (vg_donut_kpi)이 맡는다. 호출부는 추세에 LOW 를 섞지 않는다.
 */
function vg_multi_trend(array $series, array $opts = []): void {
    $unit  = (string) ($opts['unit'] ?? '');
    $max   = max(1, (int) ($opts['max_series'] ?? 5));
    $fold  = !isset($opts['fold']) || (bool) $opts['fold'];

    // 점이 없는 계열은 애초에 그릴 것이 없다.
    $clean = [];
    foreach ($series as $s) {
        if (!is_array($s) || empty($s['points']) || !is_array($s['points'])) { continue; }
        $pts = [];
        foreach ($s['points'] as $p) {
            if (!is_array($p) || !isset($p['d'])) { continue; }
            $pts[(string) $p['d']] = (float) ($p['v'] ?? 0);
        }
        if (!$pts) { continue; }
        $clean[] = ['name' => (string) ($s['name'] ?? ''), 'points' => $pts];
    }

    // x 라벨 — 계열들이 준 순서를 처음 나온 순으로 이어 붙인다(정렬하지 않는다:
    //   '8/9' 와 '8/20' 처럼 표시용 문자열은 사전순이 시간순과 다르다).
    $labels = [];
    foreach ($clean as $s) {
        foreach (array_keys($s['points']) as $d) {
            if (!isset($labels[$d])) { $labels[$d] = true; }
        }
    }
    $labels = array_keys($labels);

    if (!$clean || count($labels) < 2) {
        vg_empty($opts['empty'] ?? [
            'icon'  => 'chart',
            'title' => '추세를 그리기엔 수집 이력이 부족합니다.',
            'hint'  => '서로 다른 시점의 수집이 2건 이상 쌓이면 여기에 추세가 표시됩니다.',
        ]);
        return;
    }

    // 계열 순서 = 마지막 시점의 값이 큰 순. "지금 누가 제일 나쁜가" 가 범례의 순서가 된다.
    $lastOf = static function (array $pts) use ($labels): float {
        for ($i = count($labels) - 1; $i >= 0; $i--) {
            if (isset($pts[$labels[$i]])) { return $pts[$labels[$i]]; }
        }
        return 0.0;
    };
    usort($clean, static fn(array $a, array $b): int => $lastOf($b['points']) <=> $lastOf($a['points']));

    // 상위 N + '기타'. '기타' 는 --cat-6 고정 슬롯이라 vgCat 으로 못박는다 — max_series 를
    //   바꿔도 "기타 = 회색" 이 흔들리지 않게(색이 의미를 갖는 유일한 자리다).
    $others = [];
    if (count($clean) > $max) {
        $others = array_slice($clean, $max);
        $clean  = array_slice($clean, 0, $max);
    }
    if ($others && $fold) {
        $sum = [];
        foreach ($others as $o) {
            foreach ($o['points'] as $d => $v) { $sum[$d] = ($sum[$d] ?? 0.0) + $v; }
        }
        $clean[] = ['name' => '기타 ' . number_format(count($others)) . '개', 'points' => $sum, 'cat' => 6];
    }

    $lastIdx = count($labels) - 1;
    $datasets = [];
    foreach ($clean as $s) {
        $data = [];
        foreach ($labels as $d) { $data[] = array_key_exists($d, $s['points']) ? $s['points'][$d] : null; }
        // 점 마커는 기본으로 숨기고 **마지막 점만** 남긴다 — 30일치 점이 전부 찍히면
        //   시선을 점이 가져가 정작 선의 방향이 안 읽힌다(현행 화면의 실제 지적).
        $radius = array_fill(0, count($labels), 0);
        $radius[$lastIdx] = 3.5;
        $ds = [
            'label'            => $s['name'],
            'data'             => $data,
            'borderWidth'      => 2,
            'tension'          => 0.25,
            'fill'             => false,
            'spanGaps'         => true,
            'pointRadius'      => $radius,
            'pointHoverRadius' => 4.5,
            'pointHitRadius'   => 8,
        ];
        if (isset($s['cat'])) { $ds['vgCat'] = (int) $s['cat']; }
        $datasets[] = $ds;
    }

    $yScale = ['beginAtZero' => true];
    if (isset($opts['y_max'])) { $yScale['max'] = (float) $opts['y_max']; }

    $options = [
        // 범례는 Chart.js 기본 범례를 상단에 둔다 — 계열 이름이 곧 자산 이름이라 왼쪽 정렬.
        'plugins'     => ['legend' => ['position' => 'top', 'align' => 'start']],
        // 한 x 지점의 모든 계열을 한 툴팁에 모은다 — 계열이 여럿일 때 선마다 겨누게 하면 못 읽는다.
        'interaction' => ['mode' => 'index', 'intersect' => false],
        'scales'      => [
            'y' => $yScale,
            // 라벨이 30개면 x축이 글자로 메워진다. 개수를 줄이고 눕히지 않는다(기울인 글자는 못 읽는다).
            'x' => ['ticks' => ['autoSkip' => true, 'maxTicksLimit' => 8, 'maxRotation' => 0]],
        ],
        // 값 뒤에 붙는 단위. Chart.js 는 콜백(함수)으로 받지만 CSP 상 인라인 <script> 를 못 쓰므로
        //   문자열로 넘기고 chart-kit.js 가 콜백으로 바꿔 끼운다.
        'vgUnit'      => $unit,
    ];

    vg_chart('line', ['labels' => $labels, 'datasets' => $datasets], [
        'size'    => (string) ($opts['size'] ?? 'md'),
        'alt'     => (string) ($opts['alt'] ?? ('계열 ' . count($datasets) . '개 추세')),
        'options' => $options,
    ]);
}
