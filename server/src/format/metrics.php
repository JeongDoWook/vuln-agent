<?php
declare(strict_types=1);

/**
 * format/metrics.php — 수치 셀. 값 하나를 "크기 감이 오는 문자열"로 바꾼다.
 *   악용확률(EPSS)과 에이전트 자기계측(메모리·CPU·사용률)이 여기 있다.
 *   값이 없으면 전부 대시(–) 하나로 통일한다 — 0 과 "모름"은 다른 사실이다.
 */

/* EPSS(악용확률 0~1) → 게이지 톤 구간. packages.php 최고 EPSS 셀에서 쓴다.
 * CVSS→심각도(VG_SEV_RANGES)와 같은 성격의 분류 기준이라 매직 넘버 대신 이름있는 상수로 둔다.
 * 큰 값부터 위에 두고 순서대로 맞춰본다(vg_epss_tone). */
const VG_EPSS_RANGES = ['high' => 0.5, 'med' => 0.1];

/** EPSS 확률(0~1) → 게이지 톤 라벨. 가장 높은 구간부터 맞춰보고, 아무 데도 안 걸리면 low. */
function vg_epss_tone(float $epss): string {
    foreach (VG_EPSS_RANGES as $tone => $min) {
        if ($epss >= $min) { return $tone; }
    }
    return 'low';
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
 * 리소스 사용률(%) 셀 — 호스트 스펙(메모리 총량·CPU 코어수) 대비 퍼센트.
 *   host.php 리소스 탭·대시보드 함대 카드 양쪽에서 쓴다. 스펙 미수집 스캔은 null.
 */
function vg_resource_pct(?float $pct): string {
    if ($pct === null) { return '<span class="why">–</span>'; }
    return number_format($pct, 1) . '<span class="why">%</span>';
}

/** 한 번의 에이전트 실행이 차지한 호스트 메모리 비율. 잘못된 누적 계측값은 제외한다. */
function vg_agent_mem_pct($peakMb, $totalMb): ?float {
    if ($peakMb === null || $peakMb === '' || $totalMb === null || $totalMb === '' || (float) $totalMb <= 0) {
        return null;
    }
    $pct = (float) $peakMb / (float) $totalMb * 100;
    return $pct >= 0 && $pct <= 100 ? $pct : null;
}

/** 실행 시간 동안 에이전트 프로세스 트리가 사용한 전체 CPU 용량 비율. */
function vg_agent_cpu_pct($cpuSeconds, $elapsedSeconds, $cores): ?float {
    if ($cpuSeconds === null || $cpuSeconds === '' || $elapsedSeconds === null || $elapsedSeconds === ''
        || $cores === null || $cores === '' || (float) $elapsedSeconds <= 0 || (float) $cores <= 0) {
        return null;
    }
    $pct = (float) $cpuSeconds / ((float) $elapsedSeconds * (float) $cores) * 100;
    // 한 호스트의 전체 코어 용량을 분모로 삼았으므로 100% 초과는 과거 누적 cgroup 계측값이다.
    return $pct >= 0 && $pct <= 100 ? $pct : null;
}
