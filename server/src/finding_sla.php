<?php
declare(strict_types=1);

/**
 * finding_sla.php — 탐지 결과 한 건의 **조치 기한(SLA)** 계산.
 *
 *   기한 일수는 새로 정하지 않는다: 설정(tb_setting)의 KEV/CRITICAL/HIGH 조치 기한을
 *   compliance.php 의 vg_compliance_policy() 로 그대로 읽는다 — 같은 숫자를 두 곳에 두면
 *   컴플라이언스 화면과 목록 화면이 서로 다른 날짜를 말하기 시작한다(DRY).
 *
 *   기준일은 그 조합의 **최초 발견 시각**이다. tb_finding 은 스캔마다 행이 새로 생기므로
 *   (uq_find 가 scan_id 를 포함한다) 최초 시각은 컬럼이 아니라 집계로만 나온다 —
 *   compliance.php 가 쓰는 것과 같은 GROUP BY 를, 여기서는 **목록 한 페이지분**으로만 좁혀 돈다.
 *
 *   경과일은 SQL 의 DATEDIFF 로 센다. PHP strtotime()/타임존 불일치와, 파싱 실패 시 false 가
 *   산술에서 0(1970년)으로 축약돼 무조건 기한 초과가 되는 문제를 둘 다 없앤다
 *   (compliance.php 가 같은 이유로 같은 선택을 했다).
 */

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/compliance.php';        // vg_compliance_policy — SLA 기준일의 정본
require_once __DIR__ . '/format.php';            // vg_badge, vg_finding_status_label
require_once __DIR__ . '/finding_status.php';    // vg_finding_status_key — 조치 상태와 같은 자연키

/**
 * 이 판정에 걸리는 기한(일). MEDIUM·LOW 는 기한이 없다(null) — 설정에 값 자체가 없다.
 *   KEV 등재면 등급보다 KEV 기한이 우선한다(가장 급한 것이 기준).
 */
function vg_finding_sla_days(bool $inKev, string $severity, array $policy): ?int {
    if ($inKev) { return (int) $policy['kev']; }
    if ($severity === 'CRITICAL') { return (int) $policy['crit']; }
    if ($severity === 'HIGH')     { return (int) $policy['high']; }
    return null;
}

/**
 * 최초 발견 시각을 되짚을 구간(일) = 가장 긴 기한 + 여유일.
 *   절대 일수로 두지 않는다: 기한을 늘려 놓고 구간이 그대로면 경과일이 구간에서 잘려
 *   초과가 검출되지 않는다(compliance.php 의 VG_COMPLIANCE_HISTORY_MARGIN_DAYS 주석과 같은 이유).
 */
function vg_finding_sla_lookback_days(array $policy): int {
    return max((int) $policy['kev'], (int) $policy['crit'], (int) $policy['high']) + (int) $policy['margin'];
}

/**
 * 목록 한 페이지분의 최초 발견 경과일을 한 번에 읽는다(N+1 방지).
 *   $keys = [[host_id, 컨테이너이름, cve_id, 패키지명], …]
 *   → vg_finding_status_key() 와 같은 키의 맵: ['first_seen' => 'Y-m-d H:i:s', 'days' => int]
 *
 *   세 축(host_id·cve_id·package_name)을 IN 으로 좁혀 idx_find_cve 를 타게 하고, 정확한
 *   조합 대조는 반환 직전 키 맵으로 한다(remediation_note.php 와 같은 방식). 구간 밖의
 *   오래된 스캔은 조인 단계에서 잘라낸다 — 그보다 오래 지속된 판정은 어차피 기한 초과 확정이라
 *   정확한 최초 시각까지 알 필요가 없다.
 */
function vg_finding_first_seen_map(PDO $pdo, array $keys, int $lookbackDays): array {
    if (!$keys) { return []; }

    $hostIds = []; $cves = []; $packages = [];
    foreach ($keys as $k) {
        $hostIds[(int) $k[0]] = true;
        $cves[(string) $k[2]] = true;
        $packages[(string) $k[3]] = true;
    }
    $hostIds = array_keys($hostIds); $cves = array_keys($cves); $packages = array_keys($packages);
    $ph = static fn(array $a): string => implode(',', array_fill(0, count($a), '?'));

    $st = $pdo->prepare(
        "SELECT s2.host_id, COALESCE(c2.cid, '') AS cid, f2.cve_id, f2.package_name,
                MIN(COALESCE(s2.received_at, s2.collected_at)) AS first_seen,
                DATEDIFF(NOW(), MIN(COALESCE(s2.received_at, s2.collected_at))) AS days_since
           FROM tb_finding f2
           JOIN tb_scan s2 ON s2.scan_id = f2.scan_id AND s2.is_deleted = 0
           LEFT JOIN tb_container c2 ON c2.container_id = f2.container_id
          WHERE f2.is_deleted = 0
            AND f2.cve_id IN (" . $ph($cves) . ")
            AND f2.package_name IN (" . $ph($packages) . ")
            AND s2.host_id IN (" . $ph($hostIds) . ")
            AND COALESCE(s2.received_at, s2.collected_at) >= DATE_SUB(NOW(), INTERVAL ? DAY)
          GROUP BY s2.host_id, cid, f2.cve_id, f2.package_name"
    );
    $st->execute(array_merge($cves, $packages, $hostIds, [$lookbackDays]));

    $map = [];
    foreach ($st->fetchAll() as $r) {
        if ($r['first_seen'] === null) { continue; }
        $map[vg_finding_status_key((int) $r['host_id'], (string) $r['cid'],
                                   (string) $r['cve_id'], (string) $r['package_name'])] = [
            'first_seen' => (string) $r['first_seen'],
            'days'       => (int) $r['days_since'],
        ];
    }

    $wanted = [];
    foreach ($keys as $k) {
        $key = vg_finding_status_key((int) $k[0], $k[1], (string) $k[2], (string) $k[3]);
        if (isset($map[$key])) { $wanted[$key] = $map[$key]; }
    }
    return $wanted;
}

/**
 * 남은 일수 칸의 HTML. 상태가 완료·예외면 세지 않는다 — 끝난 일에 남은 기한은 없다.
 *   최초 시각을 못 찾으면 '–' 로 두고 "기한 내" 라고 말하지 않는다(모르는 것은 모른다고 적는다).
 *   $daysSince 는 SQL DATEDIFF 결과다(vg_finding_first_seen_map).
 */
function vg_finding_due_cell(?int $daysSince, ?int $slaDays, ?string $status): string {
    if ($slaDays === null) {
        return '<span class="why" title="MEDIUM·LOW 는 조치 기한 설정이 없습니다">—</span>';
    }
    if ($status === 'DONE' || $status === 'EXCEPTED') {
        return '<span class="why" title="' . vg_h(vg_finding_status_label($status))
             . ' 처리된 항목은 기한을 세지 않습니다">—</span>';
    }
    if ($daysSince === null) {
        return '<span class="why" title="최초 발견 시각을 확인할 수 없습니다('
             . '보유한 스캔 이력이 짧으면 되짚을 수 없습니다)">–</span>';
    }
    $left = $slaDays - $daysSince;
    $title = '기한 ' . $slaDays . '일 · 최초 발견 후 ' . max(0, $daysSince) . '일 경과';
    if ($left < 0) {
        return vg_badge(number_format(-$left) . '일 초과', 'crit', $title);
    }
    // 기한이 코앞인 것과 여유 있는 것을 같은 색으로 두지 않는다 — 목록에서 훑을 때 그 차이가
    //   곧 조치 순서다. 경계는 기한의 1/4(설정을 바꿔도 비율이 따라간다).
    $tone = $left <= max(1, (int) floor($slaDays / 4)) ? 'high' : 'muted';
    return vg_badge('D-' . number_format($left), $tone, $title);
}
