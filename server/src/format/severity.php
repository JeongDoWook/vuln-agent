<?php
declare(strict_types=1);

/**
 * format/severity.php — 심각도 어휘와 CVSS.
 *   "이 취약점이 얼마나 나쁜가"를 말하는 것들 전부: 톤 매핑 · 뱃지 · 행 클래스 · 등급별 건수/막대와,
 *   그 등급의 출처인 CVSS(점수 구간 · 벡터 해독).
 *   색은 CSS 의 .tone-* 이 정한다. PHP 는 "어떤 톤인가" 만 고른다.
 *   뱃지를 쓰는 모든 화면(심각도·런타임상태·피드상태·노출범위·자산상태)이 이 어휘를 공유한다.
 */

const VG_TONE_SEV = ['CRITICAL' => 'crit', 'HIGH' => 'high', 'MEDIUM' => 'med', 'LOW' => 'low'];

/** 심각도(CRITICAL/HIGH/MEDIUM/LOW) 뱃지. */
function vg_sev_badge(string $sev): string {
    return vg_badge($sev, vg_sev_tone($sev));
}

/** 심각도 → 톤 클래스명. KPI 카드도 같은 톤을 쓴다. */
function vg_sev_tone(string $sev): string {
    return VG_TONE_SEV[$sev] ?? 'muted';
}

/* CVSS 기본점수 → 심각도 구간(NVD v3 기준). cves.php 에만 있었는데 cve.php 도 쓰게 돼 공용으로. */
const VG_SEV_RANGES = [
    'critical' => [9.0, 10.0],
    'high'     => [7.0, 8.9],
    'medium'   => [4.0, 6.9],
    'low'      => [0.1, 3.9],
];

/** CVSS 점수 → 심각도 라벨(소문자). 점수가 없으면 빈 문자열. */
function vg_cvss_sev(?string $cvss): string {
    if ($cvss === null || $cvss === '') { return ''; }
    $v = (float) $cvss;
    foreach (VG_SEV_RANGES as $name => [$lo, $hi]) {
        if ($v >= $lo && $v <= $hi) { return $name; }
    }
    return '';
}

/* CVSS v3 벡터 해독표. 점수 하나로는 "원격인지 로컬인지, 인증이 필요한지" 를 알 수 없다.
 * 벡터가 그걸 말한다 — 같은 9.8 이라도 AV:N/PR:N 이면 인터넷에서 무인증 공격이 가능하다는 뜻.
 * 축약키만 담는다(v2 벡터는 키가 달라 해독 안 되고, 그대로 원문만 보여준다). */
const VG_CVSS_METRICS = [
    'AV' => ['label' => '공격 경로',   'v' => ['N' => '네트워크', 'A' => '인접 네트워크', 'L' => '로컬', 'P' => '물리']],
    'AC' => ['label' => '공격 복잡도', 'v' => ['L' => '낮음', 'H' => '높음']],
    'PR' => ['label' => '필요 권한',   'v' => ['N' => '불필요', 'L' => '일반 사용자', 'H' => '관리자']],
    'UI' => ['label' => '사용자 개입', 'v' => ['N' => '불필요', 'R' => '필요']],
    'S'  => ['label' => '범위 변경',   'v' => ['U' => '없음', 'C' => '있음']],
    'C'  => ['label' => '기밀성 영향', 'v' => ['H' => '높음', 'L' => '낮음', 'N' => '없음']],
    'I'  => ['label' => '무결성 영향', 'v' => ['H' => '높음', 'L' => '낮음', 'N' => '없음']],
    'A'  => ['label' => '가용성 영향', 'v' => ['H' => '높음', 'L' => '낮음', 'N' => '없음']],
];

/**
 * CVSS 벡터 문자열 → [['label'=>'공격 경로','value'=>'네트워크','danger'=>true], …]
 * 해독 못하는 키(v2 벡터 등)는 건너뛴다 — 빈 배열이면 호출부가 원문만 보여준다.
 * 'danger' 는 "공격자에게 유리한 값"(원격·무인증·개입불필요·영향높음) — UI 가 붉게 강조한다.
 */
function vg_cvss_vector_parts(?string $vector): array {
    if ($vector === null || $vector === '') { return []; }
    $worst = ['AV' => 'N', 'AC' => 'L', 'PR' => 'N', 'UI' => 'N', 'S' => 'C', 'C' => 'H', 'I' => 'H', 'A' => 'H'];
    $out = [];
    foreach (explode('/', $vector) as $part) {
        $kv = explode(':', $part, 2);
        if (count($kv) !== 2) { continue; }
        [$k, $v] = $kv;
        if (!isset(VG_CVSS_METRICS[$k]['v'][$v])) { continue; }   // CVSS:3.1 접두나 v2 키는 여기서 걸러진다
        $out[] = [
            'label'  => VG_CVSS_METRICS[$k]['label'],
            'value'  => VG_CVSS_METRICS[$k]['v'][$v],
            'danger' => ($worst[$k] ?? null) === $v,
        ];
    }
    return $out;
}

/**
 * 표의 <tr> 심각도 클래스. CSS 가 왼쪽 띠(+상위 등급은 옅은 배경)로 칠한다.
 * vg_table 의 'row_class' 에 심각도를 뽑아 넘긴다:
 *     'row_class' => fn($r) => vg_sev_row((string) $r['severity'])
 * 심각도가 어느 컬럼에 있는지는 표마다 다르고(base_severity), CVSS 에서 파생시키는
 * 표(cves.php)도 있어서, 컬럼명을 추측하지 않고 호출부가 문자열로 건네게 한다.
 * 어휘에 없는 값이면 빈 문자열 — 클래스 없는 평범한 행이 된다.
 */
function vg_sev_row(?string $sev): string {
    return isset(VG_TONE_SEV[(string) $sev]) ? 'sev-' . VG_TONE_SEV[(string) $sev] : '';
}

/**
 * 심각도별 건수 뱃지 묶음. 0건인 등급은 생략하고, 전부 0이면 '–'.
 *   $href 를 주면 각 뱃지를 링크로 만든다(자산관리: 등급별 취약점 목록으로).
 *   대시보드 · 자산관리 · 호스트 스캔이력이 공유한다.
 */
function vg_sev_counts(array $counts, ?callable $href = null): string {
    $out = [];
    foreach (VG_TONE_SEV as $sev => $tone) {
        $n = (int) ($counts[$sev] ?? 0);
        if ($n === 0) {
            continue;
        }
        $attr = 'class="badge tone-' . $tone . '" title="' . vg_h($sev) . '"';
        $out[] = $href !== null
            ? '<a ' . $attr . ' href="' . vg_h($href($sev)) . '">' . $n . '</a>'
            : '<span ' . $attr . '>' . $n . '</span>';
    }
    return $out ? implode(' ', $out) : '<span class="why">–</span>';
}

/** 지금 조치할 등급. LOW 는 여기 없다 — 그림(도넛·막대)은 이 셋만 그린다. */
const VG_SEV_ACTIONABLE = ['CRITICAL', 'HIGH', 'MEDIUM'];

/** 이 분포의 조치 대상 건수 합(CRITICAL+HIGH+MEDIUM). */
function vg_sev_actionable(array $counts): int {
    $n = 0;
    foreach (VG_SEV_ACTIONABLE as $sev) { $n += (int) ($counts[$sev] ?? 0); }
    return $n;
}

/**
 * 표 전체의 공통 척도 — 조치 대상 합이 가장 큰 행의 값. vg_sev_bar() 의 $scale 로 넘긴다.
 *   $countsList: [분포, 분포, …] (예: $sevByContainer, $sevByScan — 키는 안 본다)
 */
function vg_sev_bar_scale(array $countsList): int {
    $max = 0;
    foreach ($countsList as $c) {
        if (is_array($c)) { $max = max($max, vg_sev_actionable($c)); }
    }
    return $max;
}

/**
 * 심각도 구성 막대(가로 누적). 숫자 뱃지만 있으면 호스트끼리 "누가 더 나쁜지"를
 * 머리로 더해야 한다 — 막대는 그걸 눈으로 보게 한다. 뱃지와 같이 쓴다(색만으로 말하지 않게).
 * 폭 계산(width:N%)은 app.css 로 옮길 수 없는 값이라 인라인 style 예외에 해당한다.
 *
 * **조치 대상(CRITICAL·HIGH·MEDIUM)만 그린다.** LOW 는 바에서 빠지고 표의 LOW 열이 계속 갖는다 —
 *   운영 실측이 한 컨테이너에서 HIGH 14 : LOW 895 라 같이 그리면 색 세그먼트가 1px 이 돼
 *   분포가 아예 안 읽혔다(도넛과 같은 이유·같은 처방 — vg_sev_donut 주석).
 *
 * $scale: 표 전체의 공통 분모(vg_sev_bar_scale()). 0 이면 자기 합을 분모로 쓴다.
 *   **행마다 자기 합으로 잡으면 HIGH 14뿐인 행과 HIGH 34뿐인 행이 똑같이 꽉 찬 바가 되어
 *   비교가 안 된다.** 가로 랭킹 막대(vg_rank_bars)가 최댓값을 100%로 잡는 것과 같은 방식이다.
 *
 * 조치 대상이 0인 행은 빈 바 대신 'LOW만' 로 둔다 — 빈 회색 바는 "데이터 없음"으로 오독된다.
 *   LOW 도 0이면 빈 문자열이라, 호출부가 '판정된 취약점 없음' 같은 자기 문구를 그대로 쓴다.
 */
function vg_sev_bar(array $counts, int $scale = 0): string {
    $sum = vg_sev_actionable($counts);
    if ($sum === 0) {
        $low = (int) ($counts['LOW'] ?? 0);
        return $low > 0
            ? '<span class="why" title="' . vg_h('LOW ' . number_format($low)
                . '건 · 조치 대상(CRITICAL·HIGH·MEDIUM) 없음') . '">LOW만</span>'
            : '';
    }

    // 공통 척도가 자기 합보다 작을 수는 없지만(최댓값이므로), 호출부가 안 주면 자기 합으로 눕는다.
    $denom = max($scale, $sum);
    $parts = [];
    $out   = '';
    foreach (VG_SEV_ACTIONABLE as $sev) {
        $n = (int) ($counts[$sev] ?? 0);
        if ($n === 0) { continue; }
        $parts[] = $sev . ' ' . number_format($n);
        $pct = round($n / $denom * 100, 2);
        $out .= '<i class="tone-' . vg_sev_tone($sev) . '" style="width:' . $pct . '%" title="'
              . vg_h($sev . ' ' . number_format($n) . '건') . '"></i>';
    }
    $low = (int) ($counts['LOW'] ?? 0);
    $tip = '조치 대상 ' . number_format($sum) . '건 (' . implode(' · ', $parts) . ')'
         . ($low > 0 ? ' · LOW ' . number_format($low) . '건은 바에서 제외' : '')
         . ($scale > 0 ? ' · 바 길이는 최다 행(' . number_format($denom) . '건) 대비' : '');
    return '<span class="riskbar" title="' . vg_h($tip) . '">' . $out . '</span>';
}
