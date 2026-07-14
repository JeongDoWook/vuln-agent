<?php
declare(strict_types=1);

/**
 * debtracker.php — 데비안 보안 트래커 **판정**(매처가 쓴다).
 *   수집(fetch·파싱·저장)은 feeds/debtracker.php 가 한다 — 매처가 HTTP 계층을 끌고 오지 않도록
 *   책임을 갈랐다(SRP). 이 파일은 DB 에 이미 있는 트래커 데이터로 "아직 취약한가"만 답한다.
 *
 * 왜 필요한가: 데비안은 보안패치를 **백포트**한다(버전을 안 올리고 고친다). 버전 비교만으로는
 *   "이미 고쳐짐"과 "진짜 취약"을 구분할 수 없어 오탐이 대량으로 남는다
 *   (실측 raspberrypi5-00: HIGH 160 중 73건이 그 오탐이었다).
 *   예전엔 대상 서버에 debsecan 을 깔아 판정을 받아왔지만, 에이전트는 사실만 모으고 판정 지식은
 *   중앙이 갖는 게 정석이다(폐쇄망 서버엔 apt 설치조차 못 한다).
 *
 * 판정 규칙은 debsecan 원본(/usr/bin/debsecan · Vulnerability.is_vulnerable)과 동일하다.
 */

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/vercmp.php';   // vg_ver_cmp — 데비안 버전 비교(문자열 비교로는 epoch·틸드에서 틀린다)

/**
 * 이 패키지가 이 CVE 에 **아직 취약한가**.
 *   · 바이너리 항목: 설치 바이너리 버전 < fixed  (fixed 가 비면 아직 수정본 없음 → 취약)
 *   · 소스   항목: 설치 소스 버전 < fixed 이고, 예외 버전 목록에 없을 것
 */
function vg_debtracker_is_vulnerable(array $row, string $binName, string $binVer, string $srcName, string $srcVer): bool {
    $fixed = trim((string) ($row['fixed'] ?? ''));

    if ((int) ($row['is_binary'] ?? 0) === 1) {
        if (($row['pkg'] ?? '') !== $binName) { return false; }
        return $fixed === '' ? true : vg_ver_cmp($binVer, $fixed, 'dpkg') < 0;
    }

    if (($row['pkg'] ?? '') !== $srcName) { return false; }
    $others = array_values(array_filter(explode(' ', trim((string) ($row['others'] ?? '')))));
    if ($others && in_array($srcVer, $others, true)) { return false; }
    return $fixed === '' ? true : vg_ver_cmp($srcVer, $fixed, 'dpkg') < 0;
}

/**
 * 이 스캔의 **호스트와 데비안 컨테이너**에 트래커를 적용해 "아직 취약" 맵을 만든다.
 *   반환: container_id => [바이너리패키지명 => [cve_id => true]]   (호스트는 0)
 *   에이전트 debsecan(tb_debsecan)과 같은 모양이라 매처의 기존 억제 경로를 그대로 탄다.
 *
 * **컨테이너에도 적용하는 이유**: 예전 규칙은 "컨테이너를 호스트 근거로 억제하지 말 것" 이었다.
 *   그건 근거(debsecan·errata)를 **호스트에서 수집**하던 시절의 이야기다 — 호스트의 상태를
 *   컨테이너에 적용하면 실제 취약점을 숨긴다(미탐). 지금 트래커는 호스트 상태가 아니라
 *   **"그 배포판 릴리스의 사실"** 이고, 컨테이너의 os_id/os_version 으로 그 컨테이너의
 *   릴리스 데이터를 골라 그 안의 패키지 버전과 대조한다 → 호스트가 새는 경로가 없다.
 *
 *   트래커 데이터가 없으면 빈 배열 → 매처는 억제하지 않는다(수집 실패와 "취약점 0"은 구분 불가).
 */
function vg_debtracker_evidence(PDO $pdo, int $scanId, string $hostCodename): array {
    // 1) 판정 대상별 릴리스 코드명 — 호스트(0) + 데비안 컨테이너.
    $relOf = [];
    if ($hostCodename !== '') { $relOf[0] = $hostCodename; }

    $cs = $pdo->prepare('SELECT id, os_id, os_version FROM tb_containers WHERE scan_id = ?');
    $cs->execute([$scanId]);
    foreach ($cs->fetchAll() as $c) {
        if (strtolower((string) $c['os_id']) !== 'debian') { continue; }   // 우분투는 OSV 경로가 덮는다
        $code = vg_debian_codename((string) $c['os_version']);
        if ($code !== '') { $relOf[(int) $c['id']] = $code; }
    }
    if (!$relOf) { return []; }

    // 2) 필요한 릴리스의 트래커 행만 읽는다.
    $codes = array_values(array_unique($relOf));
    $in    = implode(',', array_fill(0, count($codes), '?'));
    $st    = $pdo->prepare(
        "SELECT release_codename, pkg_name, is_binary, cve_id, fixed_version, other_versions
           FROM tb_debian_tracker WHERE release_codename IN ($in) AND is_deleted = 0"
    );
    $st->execute($codes);

    $byRelPkg = [];   // 코드명 => 패키지 => 행들
    foreach ($st->fetchAll() as $r) {
        $byRelPkg[(string) $r['release_codename']][(string) $r['pkg_name']][] = [
            'pkg'       => (string) $r['pkg_name'],
            'is_binary' => (int) $r['is_binary'],
            'cve'       => (string) $r['cve_id'],
            'fixed'     => (string) ($r['fixed_version'] ?? ''),
            'others'    => (string) ($r['other_versions'] ?? ''),
        ];
    }
    if (!$byRelPkg) { return []; }

    // 3) 각 대상의 dpkg 패키지를 그 대상의 릴리스 데이터와 대조.
    $ids = array_keys($relOf);
    $inC = implode(',', array_fill(0, count($ids), '?'));
    $ps  = $pdo->prepare(
        "SELECT container_id, name, source_pkg, version, source_version
           FROM tb_packages
          WHERE scan_id = ? AND manager = 'dpkg' AND container_id IN ($inC)"
    );
    $ps->execute(array_merge([$scanId], $ids));

    $out = [];
    foreach ($ps->fetchAll() as $p) {
        $ctrId = (int) $p['container_id'];
        $rows  = $byRelPkg[$relOf[$ctrId] ?? ''] ?? null;
        if (!$rows) { continue; }

        $bin    = (string) $p['name'];
        $binVer = (string) $p['version'];
        $src    = (string) ($p['source_pkg'] ?: $p['name']);
        $srcVer = (string) ($p['source_version'] ?: $p['version']);

        foreach (array_unique([$bin, $src]) as $key) {
            foreach ($rows[$key] ?? [] as $row) {
                if (vg_debtracker_is_vulnerable($row, $bin, $binVer, $src, $srcVer)) {
                    $out[$ctrId][$bin][$row['cve']] = true;
                }
            }
        }
    }
    return $out;
}
