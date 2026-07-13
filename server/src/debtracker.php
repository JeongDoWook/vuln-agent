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
 * 이 스캔의 호스트 패키지에 트래커를 적용해 "아직 취약" 맵을 만든다.
 *   반환: 바이너리패키지명 => [cve_id => true] — 에이전트 debsecan(tb_debsecan)과 **같은 모양**이라
 *   매처의 기존 억제 경로를 그대로 태운다(누가 계산했는지만 다르다).
 *   트래커 데이터가 없으면 빈 배열 → 매처는 억제하지 않는다(수집 실패와 "취약점 0"은 구분 불가).
 */
function vg_debtracker_evidence(PDO $pdo, int $scanId, string $codename): array {
    if ($codename === '') { return []; }

    $st = $pdo->prepare(
        'SELECT pkg_name, is_binary, cve_id, fixed_version, other_versions
           FROM tb_debian_tracker WHERE release_codename = ? AND is_deleted = 0'
    );
    $st->execute([$codename]);

    $byPkg = [];
    foreach ($st->fetchAll() as $r) {
        $byPkg[$r['pkg_name']][] = [
            'pkg'       => (string) $r['pkg_name'],
            'is_binary' => (int) $r['is_binary'],
            'cve'       => (string) $r['cve_id'],
            'fixed'     => (string) ($r['fixed_version'] ?? ''),
            'others'    => (string) ($r['other_versions'] ?? ''),
        ];
    }
    if (!$byPkg) { return []; }

    // 호스트(container_id=0)의 dpkg 패키지만 본다 — 컨테이너를 호스트 근거로 판정하면 미탐이다.
    $ps = $pdo->prepare(
        "SELECT name, source_pkg, version, source_version
           FROM tb_packages
          WHERE scan_id = ? AND container_id = 0 AND manager = 'dpkg'"
    );
    $ps->execute([$scanId]);

    $out = [];
    foreach ($ps->fetchAll() as $p) {
        $bin    = (string) $p['name'];
        $binVer = (string) $p['version'];
        $src    = (string) ($p['source_pkg'] ?: $p['name']);
        $srcVer = (string) ($p['source_version'] ?: $p['version']);

        foreach (array_unique([$bin, $src]) as $key) {
            foreach ($byPkg[$key] ?? [] as $row) {
                if (vg_debtracker_is_vulnerable($row, $bin, $binVer, $src, $srcVer)) {
                    $out[$bin][$row['cve']] = true;
                }
            }
        }
    }
    return $out;
}
