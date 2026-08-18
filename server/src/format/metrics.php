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
 * EPSS 값 — 평문(뱃지·태그 없이). 모달·툴팁처럼 HTML 을 못 싣는 자리에서 쓴다.
 *   값이 없으면(1999년대 CVE 등 FIRST 가 점수를 안 매기는 건) 대시.
 */
function vg_epss_pct($epss): string {
    if ($epss === null || $epss === '') { return '–'; }
    return number_format((float) $epss * 100, 1) . '%';
}

/**
 * EPSS 셀 — **악용확률 하나만** 쓴다.
 *
 * 예전엔 백분위를 "상위 N%" 로 뒤집어 나란히 붙였다("2.7% 상위 2.7%") — 확률만으론 크기 감이
 * 안 온다는 이유였다. 그런데 한 칸에 뜻이 다른 두 수가 서면 사용자는 어느 쪽을 읽어야 할지
 * 모른다(실제 피드백: "머야 이게"). 하나만 남긴다.
 *
 * 남긴 쪽이 확률인 이유: **화면과 정렬이 같은 값을 말해야 한다.** 목록은 전부 `c.epss DESC`
 * 로 줄을 세우고(host·container·package·cves), 게이지 톤(VG_EPSS_RANGES)도, export 의
 * `epss` 필드도 확률이다. 여기만 백분위를 보이면 "정렬 기준이 화면에 없는" 표가 된다.
 * 백분위가 필요한 자리는 따로 있다 — cves.php 의 'EPSS 상위 1%' 필터와 cve.php 상세의
 * 'EPSS 백분위' 항목이 그 값을 이름을 붙여 보여준다.
 *
 * $percentile 은 받기만 하고 그리지 않는다 — 호출부 8곳의 시그니처를 그대로 두기 위한 것이다.
 */
function vg_epss_cell($epss, $percentile = null): string {
    if ($epss === null || $epss === '') {
        return '<span class="why">–</span>';
    }
    return vg_h(vg_epss_pct($epss));
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
