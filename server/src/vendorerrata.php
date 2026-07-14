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
        // Oracle Linux 는 OSV 에 아예 없다 → ELSA OVAL 이 **유일한** 판정 소스다.
        //   (실측 deskmini: ol 9.7 컨테이너의 패키지 117개에 findings 가 0 이었다 — 통째로 미탐)
        case 'ol':
        case 'oraclelinux': return 'oracle';
        // rocky 는 OSV(Rocky Linux:N)가 조치 버전을 이미 준다 → 중복 수집하지 않는다.
        default:          return null;
    }
}

/**
 * 바이너리 패키지 → **컴포넌트(소스 패키지)** 이름.
 *   Red Hat 은 취약점 상태를 컴포넌트 단위로 매긴다(bzip2). 설치된 건 바이너리(bzip2-libs)라
 *   그대로 물으면 0건이 나온다 — 소스 rpm 이름에서 버전을 떼어 컴포넌트를 얻는다.
 *   예: "bzip2-1.0.6-26.el8.src.rpm" → "bzip2"
 *   소스 정보가 없으면(에이전트 구버전) 바이너리 이름으로 대체한다.
 */
function vg_rpm_component(?string $sourceRpm, string $binName): string
{
    $s = trim((string) $sourceRpm);
    if ($s === '') { return $binName; }

    $s = preg_replace('/\.src\.rpm$/i', '', $s);                 // 확장자 제거
    // 뒤에서부터 "-버전-릴리스" 두 조각을 떼면 이름이 남는다(이름에도 '-' 가 들어갈 수 있다).
    if (preg_match('/^(.+)-[^-]+-[^-]+$/', (string) $s, $m) === 1) { return $m[1]; }
    return (string) $s !== '' ? (string) $s : $binName;
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
 * "아직 안 고쳐진" CVE 후보 — 수정본이 없어 **조치할 수 없는** 취약점.
 *   반환: container_id => [바이너리패키지 => [cve_id => ['state'=>fix_state, 'cvss'=>float|null]]]
 *
 *   Red Hat 은 컴포넌트(bzip2) 단위로 상태를 매기므로, 그 컴포넌트로 빌드된 **설치된 바이너리
 *   전부**(bzip2-libs …)에 펼친다(Trivy 와 같은 방식).
 *   수정본이 나온 CVE 는 여기서 제외한다 — 그건 OVAL(tb_vendor_errata)이 판정한다.
 */
function vg_vendor_unfixed_candidates(PDO $pdo, int $scanId, ?string $hostOsId, ?string $hostOsVersion): array
{
    $targets = vg_vendor_errata_targets($pdo, $scanId, $hostOsId, $hostOsVersion);
    if (!$targets) { return []; }

    // 대상의 rpm 패키지 → 컴포넌트
    $ids = array_keys($targets);
    $in  = implode(',', array_fill(0, count($ids), '?'));
    $ps  = $pdo->prepare(
        "SELECT container_id, name, source_pkg
           FROM tb_packages
          WHERE scan_id = ? AND manager = 'rpm' AND container_id IN ($in)"
    );
    $ps->execute(array_merge([$scanId], $ids));
    $pkgs = $ps->fetchAll();
    if (!$pkgs) { return []; }

    $comps = [];   // 컴포넌트 => true
    foreach ($pkgs as $p) {
        $comps[vg_rpm_component((string) $p['source_pkg'], (string) $p['name'])] = true;
    }
    $comps = array_values(array_filter(array_keys($comps)));
    if (!$comps) { return []; }

    // 대상(벤더·메이저)별로, 설치된 컴포넌트의 미수정 CVE 만 읽는다.
    $byKey = [];
    foreach (array_unique(array_map(static fn($t) => $t[0] . '|' . $t[1], $targets)) as $key) {
        [$v, $m] = explode('|', $key, 2);
        foreach (array_chunk($comps, 500) as $chunk) {
            $inC = implode(',', array_fill(0, count($chunk), '?'));
            $st  = $pdo->prepare(
                "SELECT component, cve_id, fix_state, cvss
                   FROM tb_vendor_unfixed
                  WHERE is_deleted = 0 AND vendor = ? AND release_major = ? AND component IN ($inC)
                    AND fix_state IN ('Affected','Fix deferred','Will not fix','Under investigation','Out of support scope')"
            );
            $st->execute(array_merge([$v, $m], $chunk));
            foreach ($st->fetchAll() as $r) {
                $byKey[$key][$r['component']][$r['cve_id']] = [
                    'state' => (string) $r['fix_state'],
                    'cvss'  => $r['cvss'] !== null ? (float) $r['cvss'] : null,
                ];
            }
        }
    }
    if (!$byKey) { return []; }

    // 컴포넌트 상태를 그 컴포넌트의 설치 바이너리들에 펼친다.
    $out = [];
    foreach ($pkgs as $p) {
        $ctrId = (int) $p['container_id'];
        [$vendor, $rel] = $targets[$ctrId] ?? [null, null];
        if ($vendor === null) { continue; }

        $comp = vg_rpm_component((string) $p['source_pkg'], (string) $p['name']);
        foreach ($byKey[$vendor . '|' . $rel][$comp] ?? [] as $cve => $info) {
            $out[$ctrId][(string) $p['name']][(string) $cve] = $info;
        }
    }
    return $out;
}

/** 이 스캔의 판정 대상: container_id => [벤더, 메이저]. 호스트는 0. (권고·미수정 공용) */
function vg_vendor_errata_targets(PDO $pdo, int $scanId, ?string $hostOsId, ?string $hostOsVersion): array
{
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
    return $targets;
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
    $targets = vg_vendor_errata_targets($pdo, $scanId, $hostOsId, $hostOsVersion);
    if (!$targets) { return []; }

    // 2) 이 스캔의 rpm 패키지를 먼저 읽는다 — 권고는 **그 패키지들 것만** 조회한다.
    //    예전엔 (벤더, 메이저) 전량을 배열에 올렸다. RHEL 8·9 를 함께 받으니 50만 행이 되어
    //    운영에서 메모리 512MB 를 넘겨 죽었다. 스캔 하나가 보는 rpm 은 수백 개뿐이다.
    $ids = array_keys($targets);
    $in  = implode(',', array_fill(0, count($ids), '?'));
    $ps  = $pdo->prepare(
        "SELECT container_id, name, version
           FROM tb_packages
          WHERE scan_id = ? AND manager = 'rpm' AND container_id IN ($in)"
    );
    $ps->execute(array_merge([$scanId], $ids));
    $pkgs = $ps->fetchAll();
    if (!$pkgs) { return []; }

    $names = [];
    foreach ($pkgs as $p) { $names[(string) $p['name']] = true; }
    $names = array_keys($names);

    // 3) 대상(벤더·메이저)별로, 설치된 패키지 이름에 해당하는 권고만 읽는다.
    $byKey = [];
    foreach (array_unique(array_map(static fn($t) => $t[0] . '|' . $t[1], $targets)) as $key) {
        [$v, $m] = explode('|', $key, 2);
        $byKey[$key] = [];
        foreach (array_chunk($names, 500) as $chunk) {
            $inN = implode(',', array_fill(0, count($chunk), '?'));
            $st  = $pdo->prepare(
                "SELECT pkg_name, cve_id, fixed_evr, advisory
                   FROM tb_vendor_errata
                  WHERE is_deleted = 0 AND vendor = ? AND release_major = ? AND pkg_name IN ($inN)"
            );
            $st->execute(array_merge([$v, $m], $chunk));
            foreach ($st->fetchAll() as $r) {
                $byKey[$key][$r['pkg_name']][$r['cve_id']][] = [
                    'evr'      => (string) $r['fixed_evr'],
                    'advisory' => (string) ($r['advisory'] ?? ''),
                ];
            }
        }
    }
    if (!array_filter($byKey)) { return []; }

    // 4) 각 대상의 rpm 패키지를 그 대상의 권고와 대조.
    $out = [];
    foreach ($pkgs as $p) {
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
