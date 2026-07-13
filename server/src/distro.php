<?php
declare(strict_types=1);

/**
 * distro.php — 배포판 식별 → 생태계(ecosystem) 매핑.
 *
 * feeds(수집)와 matcher(매칭)가 **같은 기준**으로 판단해야 하므로 한 곳에 둔다.
 * 수집 때 'Ubuntu:24.04' 로 저장한 행을, 매칭 때 다른 규칙으로 읽으면 어긋난다.
 */

if (!function_exists('vg_distro_unsupported')) {
    /**
     * 이 배포판을 CVE 피드(OSV)가 지원하지 않는가?
     *
     * 지원하지 않으면 매칭 후보 자체가 없어 **취약점이 0건으로 뜬다.** 운영자는 "안전하다"고
     * 읽는다 — 침묵하는 미탐이다. 그래서 화면에 명시적으로 알려야 한다.
     *
     * OSV 공식 생태계 목록(osv-vulnerabilities.storage.googleapis.com/ecosystems.txt) 기준
     * OS 배포판: AlmaLinux · Alpine · Azure Linux · Chainguard · Debian · Mageia · Red Hat ·
     * Rocky Linux · SUSE · openSUSE · Ubuntu · Wolfi.
     * **Amazon Linux · Oracle Linux · CentOS 는 목록에 없다**(2026-07 확인. Amazon Linux 로
     * 질의하면 OSV 가 INVALID_ARGUMENT 를 돌려준다).
     *
     * @return string|null 미지원이면 사람이 읽을 사유, 지원하면 null
     */
    function vg_distro_unsupported(?string $osId, ?string $osVer): ?string
    {
        $id = strtolower(trim((string) $osId));
        if ($id === '') { return null; }                 // 배포판 자체를 모름 → 별도로 다룬다
        if (vg_osv_ecosystem($osId, $osVer) !== null) { return null; }

        // 이름을 아는 미지원 배포판은 구체적으로 알려준다(자체 피드가 따로 있다).
        $known = [
            'amzn'   => 'Amazon Linux — OSV 미지원(자체 ALAS 피드 필요)',
            'ol'     => 'Oracle Linux — OSV 미지원(자체 ELSA 피드 필요)',
            'centos' => 'CentOS — OSV 미지원',
        ];
        if (isset($known[$id])) { return $known[$id]; }

        return sprintf('%s %s — CVE 피드(OSV)가 지원하지 않는 배포판', $osId, (string) $osVer);
    }
}

if (!function_exists('vg_container_unjudgeable')) {
    /**
     * 이 컨테이너의 취약점 0건이 "안전"이 아니라 "판정 불가"인가 — 그 사유.
     *
     * 두 가지 이유로 0건이 나온다. 둘 다 침묵하면 운영자는 "안전하다"고 읽는다.
     *   1) 피드가 모르는 배포판(Oracle Linux 등) → 매칭 후보 자체가 없다.
     *   2) **패키지 DB 가 없는 이미지** → 무엇이 깔렸는지 알 수 없다.
     *      운영 실측: Calico(Tigera) 이미지 9개가 여기 해당한다. RHEL 기반인데 rpm DB 를
     *      지우고 빌드해서 /var/lib/rpm 이 아예 없다. rhel 은 OSV **지원** 배포판이라
     *      1)번 경고에도 안 걸려, 지금까지 CVE 0건으로 조용히 지나갔다.
     *
     * @param  string|null $mgr       에이전트가 읽어낸 패키지 매니저(못 읽었으면 빈 값)
     * @param  int         $pkgCount  수집된 패키지 수
     * @return string|null 판정 가능하면 null
     */
    function vg_container_unjudgeable(?string $osId, ?string $osVer, ?string $mgr, int $pkgCount): ?string
    {
        if (trim((string) $mgr) === '' || $pkgCount === 0) {
            return '패키지 DB 가 없는 이미지 — 무엇이 깔렸는지 알 수 없어 판정 불가'
                 . ' (rpm/dpkg DB 를 지우고 빌드한 이미지. 이미지 제공처의 SBOM 이 필요하다)';
        }
        return vg_distro_unsupported($osId, $osVer);
    }
}

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
            // Go 바이너리에서 뽑은 의존 모듈(buildinfo). OSV 의 Go 생태계로 그대로 조회된다.
            case 'go':       return 'Go';
            // 패키지 DB 도 Go 도 없는 이미지에서 바이너리 버전을 뽑아낸 것(nginx 등).
            //   OSV 의 Bitnami 생태계가 업스트림 앱을 커버한다(BIT-nginx-… 는 CVE 를 alias 로 단다).
            case 'upstream': return 'Bitnami';
            default:         return $hostEco;   // rpm / dpkg → 배포판
        }
    }

    /**
     * 이 패키지가 **배포판 저장소** 것인가? (서드파티 PPA/Docker/NodeSource·수동설치가 아닌가)
     *
     * 왜 필요한가: 배포판 기준 억제(debsecan·errata·changelog)는 "배포판 트래커에 없으면
     * 이미 수정됨"으로 본다. 서드파티 패키지는 애초에 트래커에 없으므로, 그대로 두면
     * **진짜 취약점을 숨기는 미탐**이 된다.
     *
     * 판정은 apt 의 Origin 라벨(o=Debian / o=Docker / o=LP-PPA-…)로 한다. URL 로 보면
     * 사내 미러(mirror.company.com)가 서드파티로 오판된다.
     *
     * **정보가 없으면(구 에이전트, origin=null) 배포판으로 간주한다.** 그러지 않으면 아직
     * 업데이트 안 된 호스트의 억제가 통째로 사라져 오탐이 폭증한다.
     */
    function vg_is_distro_pkg(?string $origin, ?string $osId): bool
    {
        $o = trim((string) $origin);
        if ($o === '') { return true; }                 // 정보 없음 → 종전대로(억제 유지)
        $ou = strtoupper($o);
        if ($ou === 'UNKNOWN') { return true; }         // 매핑 실패 → 판단 보류(억제 유지)
        if ($ou === 'LOCAL')   { return false; }        // 어느 저장소에도 없음 = 수동 .deb 설치

        $os = strtolower((string) $osId);
        // dpkg: 라벨이 배포판 것인가. rpm: VENDOR 문자열에 배포판 벤더명이 들어 있는가.
        switch ($os) {
            case 'debian':    return stripos($o, 'Debian') !== false;
            case 'ubuntu':    return stripos($o, 'Ubuntu') !== false;
            case 'rocky':     return stripos($o, 'Rocky')  !== false;
            case 'almalinux': return stripos($o, 'AlmaLinux') !== false;
            case 'rhel':
            case 'redhat':    return stripos($o, 'Red Hat') !== false;
            case 'alpine':    return stripos($o, 'Alpine') !== false;
            default:          return true;              // 모르는 배포판 → 판단 보류
        }
    }

    /** OS 패키지 매니저인가(rpm/dpkg/apk). 아니면 언어 패키지. apk 는 알파인 컨테이너에서 흔하다. */
    function vg_is_os_manager(string $manager): bool
    {
        $m = strtolower($manager);
        return $m === 'rpm' || $m === 'dpkg' || $m === 'apk';
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
            // 알파인은 컨테이너에서 흔하다. OSV 표기는 'Alpine:v3.19' (마이너까지, v 접두).
            case 'alpine':
                return preg_match('/^(\d+\.\d+)/', $ver, $mm) ? "Alpine:v{$mm[1]}" : null;
            case 'rocky': case 'rockylinux': return $major ? "Rocky Linux:$major" : null;
            case 'almalinux':            return $major ? "AlmaLinux:$major" : null;
            case 'rhel': case 'redhat':  return $major ? "Red Hat:$major" : null;
            default:                     return null;
        }
    }
}
