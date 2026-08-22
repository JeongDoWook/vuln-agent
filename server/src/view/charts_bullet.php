<?php
declare(strict_types=1);

/**
 * charts_bullet.php — 불릿 그래프(Stephen Few) · 조치 기한 소진 막대.
 *   charts.php 에 덧붙이지 않고 새 파일로 뗀 이유: 컴플라이언스 계열 5화면(compliance.php·
 *   control_mapping.php·control.php·kisa-u.php·cce-rule.php)에 동시에 걸치는 작업이라
 *   charts.php(1000줄대) 를 같이 건드리면 병렬로 도는 다른 워커와 매 줄이 충돌한다.
 *
 *   vg_bullet() 는 vg_meter()(format/badge.php)의 확장판이다 — 값 막대 하나만 보이던 미터에
 *   배경 등급 밴드(양호/주의/미흡)와 목표선(세로 눈금)을 더해 "목표 대비 지금 어디쯤인가"를
 *   한 줄로 답한다. 원형 게이지 대신 불릿을 쓰는 이유는 초기 요청 그대로다 — 같은 정보를
 *   더 적은 자리에 담고, 여러 통제를 세로로 나란히 비교할 수 있다.
 *
 *   **판정은 여기서 하지 않는다.** 값·목표·막대 색(tone)은 전부 호출부가 넘긴다 — 이 화면들의
 *   판정 SSOT 는 여전히 server/src/compliance/policy.php(vg_compliance_status 등)다. 이 파일이
 *   그 판정을 다시 계산하면 화면마다 기준이 갈릴 위험이 생긴다(SRP: 그리기만 한다).
 */

require_once __DIR__ . '/../format.php';   // vg_h

/**
 * 목표 대비 한 줄 — 불릿 그래프. vg_meter() 와 같은 자리에 드롭인으로 쓸 수 있게 앞 세 인자
 * (tone, value, label)의 순서를 vg_meter(tone, pct, label) 와 맞췄다(호출부 diff를 최소로).
 *
 *   $tone   : 값 막대 색 — crit/high/med/low/ok(meter 와 같은 톤 어휘). 판정은 호출부의 몫이다
 *             (예: vg_compliance_status() 결과) — 여기서 값·목표를 비교해 새로 판정하지 않는다.
 *   $value  : 현재값(0..$max, 기본 %).
 *   $target : 목표선 위치(0..$max) — 굵은 세로 눈금으로 그린다.
 *   $label  : title/aria-label. vg_meter 와 같은 계약(화면에 보이는 글자가 아니라 마우스/스크린리더용).
 *   $opts   : 'max'   — 축 최댓값(기본 100).
 *             'bands' — 배경 등급 밴드 경계 [cut1, cut2](0..max, vg_bullet_bands() 로 만든다).
 *                       생략하면 배경 밴드 없이 막대 + 목표선만 그린다.
 *             'na'    — 판정 불가(값 자체가 없다). true 면 막대·밴드·목표선을 그리지 않고
 *                       문구만 남긴다 — 근거 없는 값을 0%로 그리면 없는 사실을 만들어내는
 *                       것이다(패치관리 통제처럼 이력이 짧아 판정 자체가 안 되는 대상이 실제로 있다).
 *             'na_label' — 기본 '판정 불가 — 근거 없음'.
 *
 * 서버 렌더 SVG 다(CSP default-src 'self' — 인라인 <script> 없이 돈다, charts.php 의 다른
 * 차트와 같은 이유). 밴드·막대·목표선은 전부 SVG 도형 속성(x/width)으로 배치한다 — PHP 안
 * 인라인 스타일 속성은 폭 계산(width:N%) 한 줄만 예외로 두는 저장소 규칙(tests/ui_lint.sh
 * 검사 2번) 이 있는데, SVG 도형의 x/width 속성은 그 속성 자체를 아예 안 쓰므로 규칙 밖이다.
 */
function vg_bullet(string $tone, float $value, float $target, ?string $label = null, array $opts = []): string {
    $attr = ($label !== null && $label !== '')
        ? ' title="' . vg_h($label) . '" aria-label="' . vg_h($label) . '"'
        : '';

    if (!empty($opts['na'])) {
        // 문구는 "근거 없음" 을 앞에 둔다 — compliance.php 는 예전에 통제 4종이 전부 같은
        //   '· 판정 불가 N건' 캡션을 달고 있어 "체크 안 됐다" 목록처럼 읽혔던 걸 걷어낸 화면이고
        //   (tests/smoke.sh 837행이 'class="why">판정 불가' 로 시작하는 문구의 재발을 막는다),
        //   그 뱃지는 이미 '판정 불가' 라고 말한다 — 여기서는 "왜"(근거 없음)를 먼저 보인다.
        $naLabel = (string) ($opts['na_label'] ?? '근거 없음 — 판정 불가');
        return '<div class="bullet bullet--na"' . $attr . '><span class="why">' . vg_h($naLabel) . '</span></div>';
    }

    $max  = max(0.0001, (float) ($opts['max'] ?? 100.0));
    $vPct = max(0.0, min(100.0, $value / $max * 100));
    $tPct = max(0.0, min(100.0, $target / $max * 100));

    $bandsSvg = '';
    $bands = $opts['bands'] ?? null;
    if (is_array($bands) && count($bands) === 2) {
        $c1 = max(0.0, min(100.0, (float) $bands[0] / $max * 100));
        $c2 = max($c1, min(100.0, (float) $bands[1] / $max * 100));
        // 양호(왼쪽, 값이 낮을수록 좋다는 이 화면들의 공통 축 — 미준수율·위반율) → 주의 → 미흡.
        $bandsSvg = '<rect class="bullet__band bullet__band--good" x="0" y="0" width="' . round($c1, 2) . '" height="16"></rect>'
            . '<rect class="bullet__band bullet__band--warn" x="' . round($c1, 2) . '" y="0" width="' . round($c2 - $c1, 2) . '" height="16"></rect>'
            . '<rect class="bullet__band bullet__band--poor" x="' . round($c2, 2) . '" y="0" width="' . round(100 - $c2, 2) . '" height="16"></rect>';
    }

    // 목표선 폭 1(백분율 축) — 0·100 끝에 걸려도 항상 온전히 보이게 안쪽으로 살짝 당긴다.
    $tx = max(0.0, min(99.0, $tPct - 0.5));

    // 밴드 트랙(16 높이) 안에 값 막대(6 높이, 위아래 5씩 여백)를 가늘게 띄운다 — 막대가
    // 트랙과 같은 높이면 막대 밑에 깔린 밴드가 완전히 가려져 등급 3단이 안 보인다
    // (실측: 10=10 이던 첫 구현에서 막대가 밴드를 덮어 초록·노랑이 안 보였다).
    return '<div class="bullet"' . $attr . '>'
        . '<svg class="bullet__svg" viewBox="0 0 100 16" preserveAspectRatio="none" role="img"'
        . ' aria-label="' . vg_h((string) $label) . '">'
        . $bandsSvg
        . '<rect class="bullet__bar tone-' . vg_h($tone) . '" x="0" y="5" width="' . round($vPct, 2) . '" height="6"></rect>'
        . '<rect class="bullet__target" x="' . round($tx, 2) . '" y="0" width="1" height="16"></rect>'
        . '</svg></div>';
}

/**
 * 부분준수 컷라인(건수, tb_setting 의 compliance.partial_max)을 이 막대의 분모에 맞춰
 * 배경 밴드 경계(0~100, %)로 바꾼다. 95% 같은 목표치를 새로 만들지 않는다 — 이미 판정에
 * 쓰는 컷라인을 그대로 백분율로 환산할 뿐이다(compliance/policy.php 가 SSOT).
 *
 * 경계는 정수 컷라인의 **중간점**이다 — partial_max=5 면 5건까지 부분준수·6건부터 미준수이므로
 * 경계를 5.5건에 둔다(정수 컷라인 어느 쪽도 밴드 접점에 걸치지 않는다). 0건(양호)과 1건
 * (부분준수 시작)의 경계도 같은 방식으로 0.5건에 둔다.
 *
 * **밴드 폭에 최소값(4%)을 둔다.** 분모가 큰 통제(예: 조치 대상 800여 건)는 실제 컷라인이
 * 0.6%대로 나와 양호·주의 밴드가 그림에서 통째로 사라진다(실측: 패치관리 통제) — 등급
 * 3단을 보이자는 이 함수의 목적 자체가 무너진다. vg_donut_kpi()·vg_ratio_rings() 가 1건짜리
 * 조각을 0.6% 밑으로 줄이지 않는 것과 같은 처방이다 — 정확한 컷라인은 막대 자체의 색(tone)과
 * title/aria-label 의 정확한 수치가 여전히 말한다. 밴드는 "대략 어느 자리인가"를 보이는
 * 눈금일 뿐이라, 최소 폭을 줘도 값을 왜곡하지 않는다.
 *
 * $denom 이 0 이면 애초에 비율을 못 그린다 — 호출부가 그 경우 vg_bullet() 자체를 안 부른다는
 * 계약이라(vg_meter() 를 쓰던 기존 화면들도 분모 0 이면 게이지를 안 그렸다) 여기서는 밴드
 * 폭 0으로만 방어한다.
 */
function vg_bullet_bands(int $partialMax, int $denom): array {
    if ($denom <= 0) { return [0.0, 0.0]; }
    $c1 = max(0.5 / $denom * 100, 4.0);
    $c2 = max(($partialMax + 0.5) / $denom * 100, $c1 + 4.0);
    return [$c1, min(96.0, $c2)];
}

/**
 * vg_sla_burn() — 등급별(KEV/CRITICAL/HIGH) 조치 기한 소진. 기한 안(초록)·초과(빨강)을
 * 한 줄에 쌓고 오른쪽에 초과율을 적는다.
 *
 * 기준일은 새로 정하지 않는다 — vg_compliance_load_patch()(server/src/compliance/patch.php)가
 * 이미 계산해 돌려주는 buckets 를 그대로 그린다. 그 계산의 "최초 발견 시각"은 finding_sla.php
 * 와 같은 축(스캔 수신시각 기준 최초 발견)이다 — 화면마다 기준이 갈리면 그게 버그다(초기
 * 요청의 지적). CVE 공개일 기준이 아니다: 우리가 언제 그 자산에서 처음 봤는지가 조치 기한의
 * 출발점이다(공개일 기준이면 배포 전부터 조치 시계가 돌게 된다).
 *
 * 판정 불가(이력이 SLA 보다 짧아 위반 여부를 셀 방법이 없는 건, patch.php 의 'unjudged')는
 * 막대에 섞지 않는다 — 0건 초과로 그리면 데이터가 모자라서 나온 결과를 조치를 잘해서 나온
 * 결과처럼 보고하게 된다(patch.php 의 "허위 안심" 원칙과 동일). 판정 가능한 건
 * (targets - unjudged)만으로 막대를 채우고, 판정 불가 건수는 옆에 글자로만 남긴다.
 *
 *   $buckets: vg_compliance_load_patch() 결과의 'buckets'(KEV/CRITICAL/HIGH 각각
 *             label/sla_days/targets/violations/unjudged 를 가진 배열) 그대로.
 */
function vg_sla_burn(array $buckets): void {
    echo '<div class="sla-burn">';
    foreach ($buckets as $b) {
        if (!is_array($b)) { continue; }
        $targets    = (int) ($b['targets'] ?? 0);
        $violations = (int) ($b['violations'] ?? 0);
        $unjudged   = (int) ($b['unjudged'] ?? 0);
        $judged     = $targets - $unjudged;
        $label      = (string) ($b['label'] ?? '');
        $slaDays    = (int) ($b['sla_days'] ?? 0);

        echo '<div class="sla-burn__row">';
        echo '<span class="sla-burn__label">' . vg_h($label)
            . '<span class="why"> · ' . $slaDays . '일</span></span>';

        if ($judged <= 0) {
            // 문구는 "근거 없음" 을 앞에 둔다 — vg_bullet() 의 판정 불가 문구와 같은 이유
            //   (compliance.php 는 통제 4종이 전부 같은 '· 판정 불가 N건' 캡션을 달던 걸 걷어낸
            //   화면이라, tests/smoke.sh 837행이 'class="why">판정 불가' 로 시작하는 문구의
            //   재발을 막는다).
            $why = $targets === 0 ? '조치 대상 없음' : '근거 없음 — 판정 불가';
            $whyTitle = $targets === 0 ? '' : ' title="' . vg_h('조치 대상 ' . number_format($targets)
                . '건 모두 이력이 ' . $slaDays . '일보다 짧아 기한 초과 여부를 셀 수 없습니다') . '"';
            echo '<span class="sla-burn__track sla-burn__track--empty"><span class="why"' . $whyTitle . '>'
                . vg_h($why) . '</span></span>';
        } else {
            $overPct = min(100.0, $violations / $judged * 100);
            $okPct   = 100.0 - $overPct;
            $title = $label . ' · 기한 안 ' . number_format($judged - $violations) . '건'
                . ' · 기한 초과 ' . number_format($violations) . '건'
                . '(판정 가능 ' . number_format($judged) . '건 중)';
            echo '<svg class="sla-burn__bar" viewBox="0 0 100 10" preserveAspectRatio="none" role="img"'
                . ' aria-label="' . vg_h($title) . '">';
            if ($okPct > 0) {
                echo '<rect class="sla-burn__seg tone-ok" x="0" y="0" width="' . round($okPct, 2) . '" height="10"></rect>';
            }
            if ($overPct > 0) {
                echo '<rect class="sla-burn__seg tone-crit" x="' . round($okPct, 2) . '" y="0" width="' . round($overPct, 2) . '" height="10"></rect>';
            }
            echo '</svg>';
            echo '<b class="sla-burn__pct">' . number_format($overPct, 0) . '% 초과</b>';
            if ($unjudged > 0) {
                echo '<span class="why sla-burn__na">판정 불가 ' . number_format($unjudged) . '건 별도</span>';
            }
        }
        echo '</div>';
    }
    echo '</div>';
}
