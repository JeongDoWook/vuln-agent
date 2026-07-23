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
        // Oracle Linux 는 여기 없다 — ELSA OVAL 을 직접 받아 판정한다(rhoval 커넥터).
        $known = [
            'amzn'   => 'Amazon Linux — OSV 미지원(자체 ALAS 피드 필요)',
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
            case 'maven':    return 'Maven';
            case 'nuget':    return 'NuGet';
            case 'cargo':    return 'crates.io';
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

    /**
     * 이 커널 패키지가 **지금 실행 중인 그 커널**인가(uname -r 과 대조).
     *
     * 한 호스트에 커널 이미지가 여러 개 깔린다 — 옛 커널(롤백용), 다른 기종용(라즈베리 v8/2712).
     * 그중 **실제로 실행되는 건 하나**뿐이고, 나머지는 부팅해야 활성화된다. 커널 CVE 를 설치된
     * 이미지 전부에 매달면 같은 목록이 4번 중복된다(실측: LOW 2,808건 = 702 × 4).
     * 업계 표준(Vuls 등)도 커널은 uname 으로 구동 버전을 잡아 그것만 판정한다.
     *
     *   dpkg : 패키지 이름에 버전이 박힌다 → linux-image-6.18.34+rpt-rpi-2712 == "linux-image-" + uname -r
     *   rpm  : 이름은 kernel/kernel-core 뿐이고 버전이 따로다 → uname -r 이 설치 버전으로 시작하는가
     *          (uname 엔 아키가 붙는다: 5.14.0-503.el9.x86_64 ← 버전 5.14.0-503.el9)
     */
    function vg_is_running_kernel_pkg(string $name, string $version, ?string $running): bool
    {
        $r = trim((string) $running);
        if ($r === '' || !vg_is_kernel_code_pkg($name)) { return false; }

        if (strcasecmp($name, 'linux-image-' . $r) === 0) { return true; }          // dpkg

        $v = trim($version);
        return $v !== '' && strncasecmp($r, $v, strlen($v)) === 0;                   // rpm
    }

    /**
     * 데비안 VERSION_ID → 릴리스 코드명. 보안 트래커는 코드명으로 데이터를 준다.
     *   에이전트는 /etc/os-release 의 VERSION_ID(11·12·13…)를 보내므로 여기서 옮긴다.
     *   모르는 버전이면 빈 문자열 → 호출자는 억제를 하지 않는다(모르면 안 지운다).
     */
    function vg_debian_codename(?string $osVersion): string
    {
        $v = trim((string) $osVersion);
        if ($v === '') { return ''; }
        $major = explode('.', $v)[0];
        return [
            '10' => 'buster',
            '11' => 'bullseye',
            '12' => 'bookworm',
            '13' => 'trixie',
            '14' => 'forky',
        ][$major] ?? '';
    }

    /**
     * 커널 소스 패키지인가(데비안 `linux` / RHEL `kernel`).
     *   이 소스에서 나온 CVE 는 **커널 코드**의 취약점이다 — 같은 소스로 빌드됐다는 이유만으로
     *   헤더·빌드도구·메타패키지에까지 매달면 안 된다(vg_is_kernel_code_pkg 와 짝).
     */
    function vg_is_kernel_source(?string $src): bool
    {
        $s = strtolower(trim((string) $src));
        return $s === 'linux' || $s === 'kernel' || $s === 'kernel-uek';
    }

    /**
     * 실제 커널 코드를 담은 바이너리 패키지인가.
     *
     * 커널 소스 하나에서 바이너리가 20개 넘게 나온다. 그중 취약한 코드가 들어 있는 건
     * **커널 이미지뿐**이고, 나머지는 컴파일용 헤더(`linux-headers-*`, `linux-libc-dev`)·
     * 빌드스크립트(`linux-kbuild-*`)·의존성 메타(`linux-base-*`)라 실행되지 않는다.
     *
     * 실측(raspberrypi5-00): `source_pkg = linux` 인 패키지가 21개였고, 커널 CVE 369건이
     * 전부에 곱해져 **LOW 7,925건**이 됐다. 실제 커널 이미지는 그중 6개뿐이다.
     * 억제(증거 기반)가 아니라 **매칭 범위 교정**이다 — 헤더엔 취약 코드가 없으므로 미탐이 아니다.
     */
    function vg_is_kernel_code_pkg(string $name): bool
    {
        $n = strtolower($name);
        // dpkg: **버전이 이름에 박힌 것만** 진짜 이미지다 — linux-image-6.18.34+rpt-rpi-2712.
        //   버전 없는 linux-image-rpi-2712 / linux-image-amd64 는 진짜 이미지를 끌어오는
        //   의존성 메타패키지라 커널 코드가 없다(실측: 이 둘에 CVE 738건이 붙어 있었다).
        return preg_match('/^linux-image-\d/', $n) === 1
            || $n === 'kernel'                            // rpm
            || str_starts_with($n, 'kernel-core')
            || str_starts_with($n, 'kernel-modules')
            || str_starts_with($n, 'kernel-uek');
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
            // Wolfi는 롤링 배포판이라 VERSION_ID(예: 20230201)를 ecosystem에 붙이지 않는다.
            // OSV 공식 ecosystem 이름은 항상 "Wolfi"다.
            case 'wolfi':                return 'Wolfi';
            case 'rocky': case 'rockylinux': return $major ? "Rocky Linux:$major" : null;
            case 'almalinux':            return $major ? "AlmaLinux:$major" : null;
            case 'rhel': case 'redhat':  return $major ? "Red Hat:$major" : null;
            // Oracle Linux 는 OSV 에 없다. 우리가 ELSA OVAL 을 직접 받아 이 표기로 카탈로그에 넣는다
            //   (rhoval 커넥터). 이 매핑이 없으면 매처가 "생태계 미지원" 으로 보고 컨테이너 패키지를
            //   통째로 건너뛴다 — 실측(deskmini): ol 9.7 컨테이너 117개 패키지에 findings 0 이었다.
            case 'ol': case 'oraclelinux': return $major ? "Oracle Linux:$major" : null;
            default:                     return null;
        }
    }
}
