<?php
declare(strict_types=1);

/**
 * vendorerrata.php — RHEL 계열 벤더 권고(errata) **판정**(매처가 쓴다).
 *   수집(fetch·OVAL 파싱·저장)은 feeds/rhoval.php 가 한다 — 매처가 HTTP·XML 계층을 끌고 오지
 *   않도록 책임을 갈랐다(SRP). 데비안 트래커(debtracker.php)와 같은 구조다.
 *
 * 왜 필요한가: RHEL 계열도 **백포트**한다(업스트림 버전은 그대로, 릴리스만 올린다).
 *   버전 비교만으로는 "이미 고쳐짐"과 "진짜 취약"을 구분할 수 없다.
 *   예전엔 이 근거를 에이전트가 대상 서버에서 긁어왔다(dnf updateinfo → tb_applied_errata).
 *   그건 debsecan 과 같은 안티패턴이라 중앙 수집으로 옮긴다.
 *
 * 판정: 설치 EVR 이 그 CVE 의 조치 EVR 이상이면 **이미 패치됨**(억제 근거).
 */

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/vercmp.php';    // vg_ver_cmp — rpm EVR 비교(epoch·(none) 처리 포함)
require_once __DIR__ . '/distro.php';    // vg_is_os_manager

/** os_id → OVAL 을 제공하는 벤더. 없으면 null(= 이 경로로 판정하지 않는다). */
function vg_errata_vendor(?string $osId): ?string
{
    switch (strtolower(trim((string) $osId))) {
        case 'rhel':
        case 'redhat':
        case 'centos':    return 'redhat';      // UBI·CentOS Stream 도 RHEL 패키지다
        case 'almalinux': return 'almalinux';
        // rocky 는 OSV(Rocky Linux:N)가 조치 버전을 이미 준다 → 중복 수집하지 않는다.
        default:          return null;
    }
}

/** 설치 EVR 에서 마이너 스트림 토큰을 뽑는다: 3.0.7-24.el9_2 → el9_2 (없으면 빈 문자열). */
function vg_errata_stream(string $evr): string
{
    return preg_match('/\.(el\d+(?:_\d+)?)/i', $evr, $m) === 1 ? strtolower($m[1]) : '';
}

/**
 * 이 CVE 가 이 설치 빌드에서 이미 고쳐졌는가.
 *   같은 (패키지, CVE) 라도 마이너 릴리스마다 조치 EVR 이 다르다(el9_2 · el9_4 …).
 *   **설치본과 같은 스트림의 조치안**을 우선 보고, 없으면 전체에서 가장 높은 조치안과 비교한다.
 *   후자는 보수적이다 — 억제를 덜 하게 되어 오탐이 남을지언정 미탐은 만들지 않는다.
 * @param list<array{evr:string,advisory:string}> $fixes
 * @return string|null 억제 근거(권고 ID + 버전) 또는 null(아직 취약)
 */
function vg_errata_is_fixed(string $installedEvr, array $fixes): ?string
{
    if (!$fixes || $installedEvr === '') { return null; }

    $stream = vg_errata_stream($installedEvr);
    $pool   = [];
    if ($stream !== '') {
        foreach ($fixes as $f) {
            if (vg_errata_stream((string) $f['evr']) === $stream) { $pool[] = $f; }
        }
    }
    if (!$pool) { $pool = $fixes; }

    $best = $pool[0];
    foreach ($pool as $f) {
        if (vg_ver_cmp((string) $f['evr'], (string) $best['evr'], 'rpm') > 0) { $best = $f; }
    }

    if (vg_ver_cmp($installedEvr, (string) $best['evr'], 'rpm') >= 0) {
        return sprintf('%s 가 이 빌드에서 고침 (설치 %s ≥ 조치 %s)',
                       (string) ($best['advisory'] ?: '벤더 권고'), $installedEvr, (string) $best['evr']);
    }
    return null;
}

/**
 * 이 스캔의 호스트·컨테이너 중 RHEL 계열 대상에 벤더 권고를 적용해 "이미 고쳐짐" 맵을 만든다.
 *   반환: container_id => [패키지 => [cve_id => 근거]]   (호스트는 0)
 *   에이전트 errata(tb_applied_errata)와 **같은 모양**이라 매처의 기존 억제 경로를 그대로 탄다.
 *   데이터가 없으면 빈 배열 → 억제하지 않는다(수집 실패와 "취약점 0"은 구분 불가).
 */
function vg_vendor_errata_evidence(PDO $pdo, int $scanId, ?string $hostOsId, ?string $hostOsVersion): array
{
    // 1) 대상별 (벤더, 메이저) — 호스트(0) + RHEL 계열 컨테이너.
    $targets = [];
    $major = static function (?string $v): string {
        return preg_match('/^(\d+)/', trim((string) $v), $m) === 1 ? $m[1] : '';
    };

    $hv = vg_errata_vendor($hostOsId);
    $hm = $major($hostOsVersion);
    if ($hv !== null && $hm !== '') { $targets[0] = [$hv, $hm]; }

    $cs = $pdo->prepare('SELECT id, os_id, os_version FROM tb_containers WHERE scan_id = ?');
    $cs->execute([$scanId]);
    foreach ($cs->fetchAll() as $c) {
        $v = vg_errata_vendor((string) $c['os_id']);
        $m = $major((string) $c['os_version']);
        if ($v !== null && $m !== '') { $targets[(int) $c['id']] = [$v, $m]; }
    }
    if (!$targets) { return []; }

    // 2) 필요한 (벤더, 메이저) 의 권고만 읽는다.
    //    **키별로 한 번만 읽는다(정적 캐시).** 재매칭은 한 프로세스에서 스캔을 전부 도는데,
    //    스캔마다 24만 행을 다시 읽으면 30초 실행제한에 걸린다(데비안 트래커에서 실제로 겪었다).
    static $cache = [];

    $byKey   = [];
    $missing = [];
    foreach (array_unique(array_map(static fn($t) => $t[0] . '|' . $t[1], $targets)) as $key) {
        if (isset($cache[$key])) { $byKey[$key] = $cache[$key]; } else { $missing[] = $key; }
    }

    if ($missing) {
        $where = [];
        $args  = [];
        foreach ($missing as $key) {
            [$v, $m] = explode('|', $key, 2);
            $where[] = '(vendor = ? AND release_major = ?)';
            $args[]  = $v;
            $args[]  = $m;
        }
        $st = $pdo->prepare(
            'SELECT vendor, release_major, pkg_name, cve_id, fixed_evr, advisory
               FROM tb_vendor_errata
              WHERE is_deleted = 0 AND (' . implode(' OR ', $where) . ')'
        );
        $st->execute($args);
        foreach ($missing as $key) { $cache[$key] = []; }
        foreach ($st->fetchAll() as $r) {
            $cache[$r['vendor'] . '|' . $r['release_major']][$r['pkg_name']][$r['cve_id']][] = [
                'evr'      => (string) $r['fixed_evr'],
                'advisory' => (string) ($r['advisory'] ?? ''),
            ];
        }
        foreach ($missing as $key) { $byKey[$key] = $cache[$key]; }
    }
    if (!array_filter($byKey)) { return []; }

    // 3) 각 대상의 rpm 패키지를 그 대상의 권고와 대조.
    $ids = array_keys($targets);
    $in  = implode(',', array_fill(0, count($ids), '?'));
    $ps  = $pdo->prepare(
        "SELECT container_id, name, version
           FROM tb_packages
          WHERE scan_id = ? AND manager = 'rpm' AND container_id IN ($in)"
    );
    $ps->execute(array_merge([$scanId], $ids));

    $out = [];
    foreach ($ps->fetchAll() as $p) {
        $ctrId = (int) $p['container_id'];
        [$vendor, $rel] = $targets[$ctrId] ?? [null, null];
        if ($vendor === null) { continue; }

        $byCve = $byKey[$vendor . '|' . $rel][(string) $p['name']] ?? null;
        if (!$byCve) { continue; }

        foreach ($byCve as $cve => $fixes) {
            $why = vg_errata_is_fixed((string) $p['version'], $fixes);
            if ($why !== null) { $out[$ctrId][(string) $p['name']][(string) $cve] = $why; }
        }
    }
    return $out;
}
