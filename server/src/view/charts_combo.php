<?php
declare(strict_types=1);

/**
 * charts_combo.php — 위험 조합(vg_risk_combo): 노출(exposed) · 벤더 미수정(no_fix) · KEV(in_kev)
 *   세 조건의 겹침을 벤 다이어그램으로 보여준다. charts.php 에 안 붙이는 이유는 동시에 여러
 *   워커가 그 파일을 건드리고 있어서다 — 새 파일로 분리해 코드 충돌을 피한다.
 *
 *   왜 도넛이 아니라 벤인가: 셋은 서로 독립이고(부분집합 관계가 아니다) 동시에 겹친다 —
 *   도넛(구성비)은 조각이 겹치면 안 되므로 이 셋을 담을 수 없다(vg_ratio_donuts 의 판단과
 *   같은 이유로 값마다 제 고리를 그리는 대신, 여기서는 **겹침 자체**가 이야기의 핵심이라
 *   벤 다이어그램을 쓴다). 값에 비례한 면적(오일러 다이어그램)은 계산이 과하다 — 이 카드가
 *   말하려는 것은 "이만큼 겹친다" 는 사실과 실제 건수지 정확한 면적비가 아니다.
 */

require_once __DIR__ . '/components.php';

/**
 * $counts: ['total'=>, 'exposed'=>, 'no_fix'=>, 'kev'=>,
 *           'exposed_nofix'=>, 'exposed_kev'=>, 'nofix_kev'=>, 'all3'=>,
 *           'only_exposed'=>, 'only_nofix'=>, 'only_kev'=>,
 *           'exposed_nofix_only'=>, 'exposed_kev_only'=>, 'nofix_kev_only'=>]
 *          전부 findings/queries/cve.php 의 한 쿼리(SUM(a=1 AND b=1) 표현식들)에서 나온 값이다.
 *          여기서 다시 곱집합을 셈하지 않는다 — 이미 계산된 값을 어떻게 그릴지만 정한다.
 *          raw(exposed/exposed_nofix/all3 …)는 겹침을 포함한 순수 교집합 — 헤드라인·목록이
 *          "전체 몇 건"을 말할 때 쓴다. only_ 로 시작하거나 _only 로 끝나는 키는 **배타**
 *          조합(벤 다이어그램의 실제 면적)이라 SVG 를 그릴 때만 쓴다. 이 둘을 섞으면 단독
 *          칸에 겹침이 포함된 값이 찍혀 이중 계산된다 — 이 함수가 고치는 사고가 바로 그것이다.
 * $opts:  'links' => [region_key => href] — 실제로 그 조합으로 필터할 수 있는 키만 채운다.
 *         키가 없으면(또는 빈 문자열이면) 그 칸은 링크 없이 값만 보인다.
 */
function vg_risk_combo(array $counts, array $opts = []): void {
    // raw — 헤드라인·접근성 목록(겹침을 포함한 순수 교집합)
    $a   = max(0, (int) ($counts['exposed'] ?? 0));
    $b   = max(0, (int) ($counts['no_fix'] ?? 0));
    $c   = max(0, (int) ($counts['kev'] ?? 0));
    $ab  = max(0, (int) ($counts['exposed_nofix'] ?? 0));
    $ac  = max(0, (int) ($counts['exposed_kev'] ?? 0));
    $bc  = max(0, (int) ($counts['nofix_kev'] ?? 0));
    $abc = max(0, (int) ($counts['all3'] ?? 0));

    // exclusive — 벤 다이어그램 SVG 전용(단독·겹침 칸이 서로 겹치지 않는 배타값)
    $onlyA  = max(0, (int) ($counts['only_exposed'] ?? 0));
    $onlyB  = max(0, (int) ($counts['only_nofix'] ?? 0));
    $onlyC  = max(0, (int) ($counts['only_kev'] ?? 0));
    $onlyAb = max(0, (int) ($counts['exposed_nofix_only'] ?? 0));
    $onlyAc = max(0, (int) ($counts['exposed_kev_only'] ?? 0));
    $onlyBc = max(0, (int) ($counts['nofix_kev_only'] ?? 0));

    $links = (array) ($opts['links'] ?? []);
    $hrefFor = static fn(string $key): string => (string) ($links[$key] ?? '');

    // 가장 큰 겹침 — **두 조건짜리 조합 중에서만** 고른다. 셋 다(abc)는 정의상 어느 둘의
    //   교집합보다 클 수 없다(조건을 하나 더 걸수록 집합은 작아지거나 같다) — 그래서 애초에
    //   후보에서 뺀다. 동률이면 먼저 나온 조합을 유지한다(강한 부등호 비교).
    $pairs = [
        ['key' => 'exposed_nofix', 'label' => '노출 + 미수정', 'value' => $ab],
        ['key' => 'exposed_kev',   'label' => '노출 + KEV',   'value' => $ac],
        ['key' => 'nofix_kev',     'label' => '미수정 + KEV', 'value' => $bc],
    ];
    $winner = $pairs[0];
    foreach ($pairs as $p) {
        if ($p['value'] > $winner['value']) { $winner = $p; }
    }

    // 결론 한 줄 — 문장을 코드에 박지 않고 값에서 계산한다. KEV 가 실제로 외부에도 노출돼
    //   있는지(2026-08 실측처럼 0일 수도, 아닐 수도 있다)를 먼저 말하고, 지금 가장 급한
    //   조합을 이어 말한다.
    if ($c === 0) {
        $kevPart = 'KEV 로 등재된 취약점은 없고';
    } elseif ($ac === 0) {
        $kevPart = 'KEV ' . number_format($c) . '건은 외부에 노출되어 있지 않고';
    } else {
        $kevPart = 'KEV ' . number_format($c) . '건 중 ' . number_format($ac) . '건은 외부에도 노출되어 있고';
    }
    $conclusion = $kevPart . ', 지금 가장 급한 조합은 ' . $winner['label'] . ' '
                . number_format($winner['value']) . '건입니다.';

    echo '<div class="risk-combo">';

    // 헤드라인 — 가장 큰 겹침을 큰 숫자로 세운다(0 이어도 그대로 적는다 — 비어 보이지 않게).
    $winHref = $hrefFor($winner['key']);
    $winTag  = $winHref !== '' ? 'a' : 'div';
    echo '<' . $winTag . ' class="risk-combo__hero"'
        . ($winHref !== '' ? ' href="' . vg_h($winHref) . '"' : '') . '>'
        . '<b>' . number_format($winner['value']) . '</b>'
        . '<span>' . vg_h($winner['label']) . '</span>'
        . '</' . $winTag . '>';

    // 벤 다이어그램 — 460px 이하에서는 app.css 가 이 블록을 숨기고 아래 목록만 남긴다.
    // 반드시 배타값(only*)을 넘긴다 — raw 교집합을 넘기면 단독 칸이 겹침을 이중 계산한다.
    echo '<div class="risk-combo__viz">'
        . vg_risk_combo_svg($onlyA, $onlyB, $onlyC, $onlyAb, $onlyAc, $onlyBc, $abc) . '</div>';

    // 접근성·좁은 화면 대체 목록 — 그림과 같은 값, 가능한 조합만 링크한다.
    $rows = [
        ['key' => 'exposed',       'label' => '노출',         'value' => $a,   'tone' => 'crit'],
        ['key' => 'no_fix',        'label' => '벤더 미수정',   'value' => $b,   'tone' => 'high'],
        ['key' => 'kev',           'label' => 'KEV',          'value' => $c,   'tone' => 'purple'],
        ['key' => 'exposed_nofix', 'label' => '노출 ∩ 미수정', 'value' => $ab,  'tone' => ''],
        ['key' => 'exposed_kev',   'label' => '노출 ∩ KEV',   'value' => $ac,  'tone' => ''],
        ['key' => 'nofix_kev',     'label' => '미수정 ∩ KEV', 'value' => $bc,  'tone' => ''],
        ['key' => 'all3',          'label' => '셋 다',        'value' => $abc, 'tone' => ''],
    ];
    echo '<ul class="risk-combo__list">';
    foreach ($rows as $row) {
        $href = $hrefFor((string) $row['key']);
        $tone = (string) $row['tone'];
        $inner = ($tone !== '' ? '<i class="tone-' . vg_h($tone) . '"></i>' : '')
            . '<span>' . vg_h((string) $row['label']) . '</span>'
            . '<b>' . number_format((int) $row['value']) . '</b>';
        $cls = 'risk-combo__row' . ((int) $row['value'] === 0 ? ' risk-combo__row--zero' : '');
        echo '<li class="' . vg_h($cls) . '">';
        // 링크 유무와 무관하게 **같은 클래스**로 감싼다 — flex 정렬(라벨 왼쪽·값 오른쪽)이
        //   태그 종류에 따라 갈리면 링크 없는 줄(미수정 ∩ KEV·셋 다)만 값이 라벨에 붙어 보인다.
        echo $href !== ''
            ? '<a class="risk-combo__row-inner" href="' . vg_h($href) . '">' . $inner . '</a>'
            : '<span class="risk-combo__row-inner">' . $inner . '</span>';
        echo '</li>';
    }
    echo '</ul>';

    echo '<p class="risk-combo__note">' . vg_h($conclusion) . '</p>';
    echo '</div>';
}

/**
 * 원 세 개짜리 벤 다이어그램 SVG. 고정 배치(값에 면적을 맞추지 않는다) — 좌표는 정삼각형
 * (원 지름과 중심 간 거리가 같다)이라 세 조건이 항상 대칭으로, 항상 같은 자리에 겹친다.
 * 단독 영역(오직 그 조건만)에는 이름표 + 값을, 겹치는 칸은 좁아서 값만 적는다 —
 * 어느 쪽이든 **0 이면 "0" 이라고 그대로 적는다**(비워 두면 "그림이 고장났다"로 읽힌다).
 *
 * 인자는 전부 **배타값**이어야 한다 — $a 는 "노출만"(미수정도 KEV 도 아님), $ab 는
 * "노출+미수정만"(KEV 는 아님) 식이다. 겹침을 포함한 원값을 넘기면 단독 칸이 옆 겹침 칸을
 * 이중 계산한다(호출부 vg_risk_combo 참고).
 */
function vg_risk_combo_svg(int $a, int $b, int $c, int $ab, int $ac, int $bc, int $abc): string {
    $fmt  = static fn(int $n): string => number_format($n);
    $aria = '노출만 ' . $fmt($a) . '건 · 벤더 미수정만 ' . $fmt($b) . '건 · KEV 만 ' . $fmt($c) . '건'
          . ' · 노출과 미수정만 ' . $fmt($ab) . '건 · 노출과 KEV 만 ' . $fmt($ac) . '건'
          . ' · 미수정과 KEV 만 ' . $fmt($bc) . '건 · 셋 다 ' . $fmt($abc) . '건';

    $svg  = '<svg viewBox="0 0 220 210" role="img" aria-label="' . vg_h($aria) . '">';
    $svg .= '<circle class="venn-circle tone-crit"   cx="80"  cy="78"  r="60"></circle>';
    $svg .= '<circle class="venn-circle tone-high"   cx="140" cy="78"  r="60"></circle>';
    $svg .= '<circle class="venn-circle tone-purple" cx="110" cy="130" r="60"></circle>';

    $svg .= vg_venn_label(55, 46, '노출', $a);
    $svg .= vg_venn_label(165, 46, '미수정', $b);
    $svg .= vg_venn_label(110, 176, 'KEV', $c);
    $svg .= vg_venn_value(110, 47, $ab);   // 노출 ∩ 미수정
    $svg .= vg_venn_value(68, 118, $ac);   // 노출 ∩ KEV
    $svg .= vg_venn_value(152, 118, $bc);  // 미수정 ∩ KEV
    $svg .= vg_venn_value(110, 98, $abc);  // 셋 다
    $svg .= '</svg>';
    return $svg;
}

// 단독 영역 — 조건 이름 한 줄 + 값 한 줄.
function vg_venn_label(float $x, float $y, string $label, int $value): string {
    // <g> 는 두 <text> 를 한 덩어리로 묶기만 한다 — 스타일은 자식 클래스가 갖는다.
    //   래퍼에 클래스를 달면 app.css 에 정의 없는 죽은 클래스가 된다(ui_lint 가 잡는다).
    return '<g>'
        . '<text x="' . $x . '" y="' . $y . '" class="venn-text__label">' . vg_h($label) . '</text>'
        . '<text x="' . $x . '" y="' . ($y + 17) . '" class="venn-text__value">' . number_format($value) . '</text>'
        . '</g>';
}

// 겹치는 영역 — 칸이 좁아 값만 적는다(이름은 카드 아래 목록·헤드라인이 이미 말한다).
function vg_venn_value(float $x, float $y, int $value): string {
    return '<text x="' . $x . '" y="' . $y . '" class="venn-text__value venn-text__value--overlap">'
        . number_format($value) . '</text>';
}
