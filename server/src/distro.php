<?php
declare(strict_types=1);

/**
 * distro.php — 배포판 식별 → 생태계(ecosystem) 매핑.
 *
 * feeds(수집)와 matcher(매칭)가 **같은 기준**으로 판단해야 하므로 한 곳에 둔다.
 * 수집 때 'Ubuntu:24.04' 로 저장한 행을, 매칭 때 다른 규칙으로 읽으면 어긋난다.
 */

if (!function_exists('vg_pkg_ecosystem')) {
    /**
     * 이 패키지가 속한 생태계 — 패키지 매니저로 정한다.
     *   rpm/dpkg → 호스트 배포판('Rocky Linux:9')
     *   pip/npm/gem/composer → 언어 생태계(OSV 표기)
     * 언어 패키지를 배포판 생태계로 조회하면 안 되고(그 반대도), 섞이면 이름만 같은
     * 엉뚱한 CVE 가 붙는다(예: OS 의 curl 과 npm 의 curl).
     */
    function vg_pkg_ecosystem(string $manager, ?string $hostEco): ?string
    {
        switch (strtolower($manager)) {
            case 'pip':      return 'PyPI';
            case 'npm':      return 'npm';
            case 'gem':      return 'RubyGems';
            case 'composer': return 'Packagist';
            default:         return $hostEco;   // rpm / dpkg → 배포판
        }
    }

    /** OS 패키지 매니저인가(rpm/dpkg). 아니면 언어 패키지. */
    function vg_is_os_manager(string $manager): bool
    {
        $m = strtolower($manager);
        return $m === 'rpm' || $m === 'dpkg';
    }
}

if (!function_exists('vg_eco_matches')) {
    /**
     * tb_cve_affected_packages.ecosystem 은 두 표기가 섞여 있다:
     *   · 배포판 형식 'Ubuntu:24.04' / 'Rocky Linux:9'  — OSV 커넥터가 쓴다(조치안이 배포판 EVR).
     *   · 패키지 계열 'rpm' / 'deb' / 'generic'         — 초기 스키마·시드의 표기.
     * 이 행이 지금 호스트에 해당하는지 판정한다.
     */
    function vg_eco_matches(?string $rowEco, ?string $hostEco, string $family): bool
    {
        $e = trim((string) $rowEco);
        if ($e === '') { return true; }              // 정보 없음 → 판단 보류(통과)
        $l = strtolower($e);
        if ($l === 'generic') { return true; }
        if ($l === 'rpm' || $l === 'deb') { return $l === strtolower($family); }
        // 배포판 형식 — 접두 일치(OSV 는 'Ubuntu:24.04:LTS' 처럼 접미사를 붙이기도 한다)
        return $hostEco !== null && strncasecmp($e, $hostEco, strlen($hostEco)) === 0;
    }

    /**
     * 이 행의 fixed_version 을 **설치 버전과 직접 비교해도 되는가**.
     * 배포판 형식 행만 참 — OSV 배포판 생태계의 조치안은 배포판 EVR 이라 EVR 끼리 비교된다.
     * 'rpm'/'deb'/'generic' 행의 조치안은 업스트림 버전일 수 있다(예: nginx 1.21.0).
     * 배포판 EVR(1:1.20.1-14.el9_2)과 섞어 비교하면 epoch 때문에 "설치가 더 최신"이 되어
     * 취약한 패키지를 패치됨으로 오억제한다(미탐) → 그런 행은 버전 판정을 하지 않는다.
     */
    function vg_eco_is_distro(?string $rowEco): bool
    {
        $l = strtolower(trim((string) $rowEco));
        return $l !== '' && $l !== 'generic' && $l !== 'rpm' && $l !== 'deb';
    }
}

if (!function_exists('vg_osv_ecosystem')) {
    // 배포판(os_id + version) → OSV ecosystem 문자열. 미지원이면 null.
    function vg_osv_ecosystem(?string $osId, ?string $osVer): ?string
    {
        $osId = strtolower(trim((string) $osId));
        $ver  = trim((string) $osVer);
        preg_match('/^\d+(\.\d+)?/', $ver, $m);
        $major = isset($m[0]) ? (int) $m[0] : 0;
        switch ($osId) {
            case 'debian':               return $major ? "Debian:$major" : null;
            case 'ubuntu':               return $ver !== '' ? "Ubuntu:$ver" : null;
            case 'rocky': case 'rockylinux': return $major ? "Rocky Linux:$major" : null;
            case 'almalinux':            return $major ? "AlmaLinux:$major" : null;
            case 'rhel': case 'redhat':  return $major ? "Red Hat:$major" : null;
            default:                     return null;
        }
    }
}
