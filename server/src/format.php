<?php
declare(strict_types=1);

/**
 * format.php — 순수 포맷/변환 헬퍼. 입력값 → 이스케이프된 문자열(또는 배열), side-effect 없음.
 *   echo 하지 않는다 — DB·세션·파일시스템에 안 닿는다. 그래서 서버 없이 단위테스트가 가능하다.
 *   레이아웃·테이블 렌더(echo 하는 것들)는 view.php 에 남는다. view.php 가 이 파일을 require 한다.
 */

function vg_h(?string $s): string {
    return htmlspecialchars((string) $s, ENT_QUOTES, 'UTF-8');
}

/* --- 톤 어휘 --------------------------------------------------------------
 * 색은 CSS 의 .tone-* 이 정한다. PHP 는 "어떤 톤인가" 만 고른다.
 * 뱃지를 쓰는 모든 화면(심각도·런타임상태·피드상태·노출범위·자산상태)이 이 어휘를 공유한다. */

const VG_TONE_SEV = ['CRITICAL' => 'crit', 'HIGH' => 'high', 'MEDIUM' => 'med', 'LOW' => 'low'];

/** 임의의 라벨을 톤 뱃지로. $label 은 여기서 이스케이프한다. */
function vg_badge(string $label, string $tone = 'muted', string $title = ''): string {
    return '<span class="badge tone-' . vg_h($tone) . '"'
        . ($title !== '' ? ' title="' . vg_h($title) . '"' : '')
        . '>' . vg_h($label) . '</span>';
}

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

// 런타임 상태(EXTERNAL/LISTENING/RUNNING/LOADED/INSTALLED)
function vg_status_label(?string $s): string {
    $m = ['EXTERNAL' => '외부노출', 'LISTENING' => '로컬리스닝', 'RUNNING' => '실행중', 'LOADED' => '사용중', 'INSTALLED' => '설치만'];
    return $m[$s ?? ''] ?? (string) $s;
}
function vg_status_badge(?string $s): string {
    $tone = ['EXTERNAL' => 'crit', 'LISTENING' => 'high', 'RUNNING' => 'med', 'LOADED' => 'purple', 'INSTALLED' => 'muted'];
    return vg_badge(vg_status_label($s), $tone[$s ?? ''] ?? 'muted');
}

/* 수집 상태 판정 기준(분). 에이전트 기본 스케줄이 매시간이라 3시간까지는 정상으로 본다.
 *   자산관리 목록(assets.php)과 호스트 상세(host.php) 히어로가 공유한다. */
const VG_STALE_MIN   = 180;        // 3시간 초과 → 지연
const VG_OFFLINE_MIN = 10080;      // 7일 초과 → 오프라인

/** 최신 수집 경과시간(분)으로 수집 상태 뱃지. 스캔이 없으면(null) '수집없음'. */
function vg_asset_state($ageMin): string {
    if ($ageMin === null) { return vg_badge('수집없음', 'muted'); }
    $m = (int) $ageMin;
    if ($m > VG_OFFLINE_MIN) { return vg_badge('오프라인', 'crit'); }
    if ($m > VG_STALE_MIN)   { return vg_badge('지연', 'high'); }
    return vg_badge('정상', 'ok');
}

/**
 * 에이전트 자기계측 셀 — 실행당 리소스 발자국(담당자 안심용).
 *   피크 메모리는 프로세스 트리 전체 최댓값, CPU 는 자식 포함 실제 점유(벽시계 아님).
 *   값이 없으면(구버전 에이전트·측정 불가) 대시. 옛 스캔은 컬럼이 비어 있는 게 정상이다.
 */
function vg_resource_mem($mb): string {
    if ($mb === null || $mb === '') { return '<span class="why">–</span>'; }
    return number_format((float) $mb, 0) . '<span class="why">MB</span>';
}
function vg_resource_cpu($sec): string {
    if ($sec === null || $sec === '') { return '<span class="why">–</span>'; }
    return vg_h(number_format((float) $sec, 1)) . '<span class="why">s</span>';
}

/**
 * EPSS 셀 — 악용확률과 백분위를 함께.
 *
 * 확률만 보면 크기 감이 안 온다. EPSS 는 절대다수가 1% 미만이라 "2.7%" 도 실은 상위권이다.
 * FIRST 가 같이 주는 백분위(epss_percentile)를 "상위 N%" 로 뒤집어 붙여 맥락을 준다.
 *   epss=0.02719, percentile=0.97281  →  "2.7% 상위 2.7%"
 * 값이 없으면(1999년대 CVE 등 FIRST 가 점수를 안 매기는 건) 대시.
 */
function vg_epss_cell($epss, $percentile = null): string {
    if ($epss === null || $epss === '') {
        return '<span class="why">–</span>';
    }
    $out = vg_h(number_format((float) $epss * 100, 1)) . '%';
    if ($percentile !== null && $percentile !== '') {
        $top = (1.0 - (float) $percentile) * 100;
        if ($top < 0.01) { $top = 0.01; }   // percentile=1.0 이 "상위 0%" 로 보이지 않게
        $dec = $top < 1 ? 2 : ($top < 10 ? 1 : 0);
        $out .= ' <span class="why">상위 ' . vg_h(number_format($top, $dec)) . '%</span>';
    }
    return $out;
}

// 긴 텍스트 말줄임 + 툴팁(title 에 원문). 안 잘리면 그냥 이스케이프만.
function vg_trunc(?string $text, int $len = 72): string {
    $text = (string) $text;
    $cut = mb_strimwidth($text, 0, $len, '…');
    if ($cut === $text) {
        return vg_h($text);
    }
    return '<span class="trunc" title="' . vg_h($text) . '">' . vg_h($cut) . '</span>';
}

/**
 * 도움말 툴팁. 본문에 늘어놓으면 화면이 무거워지는 부연설명을 아이콘 뒤로 보낸다.
 * 네이티브 title 을 쓴다 — 스크린리더도 읽고, JS 도 필요 없다.
 */
function vg_help(string $text): string {
    return '<span class="help" title="' . vg_h($text) . '" tabindex="0" role="note">?</span>';
}
