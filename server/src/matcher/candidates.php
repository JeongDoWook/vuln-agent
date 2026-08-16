<?php
declare(strict_types=1);

/**
 * matcher/candidates.php — **패키지 하나** 단위의 준비 작업 두 가지.
 *   ① vg_match_pkg_candidates: 이 패키지에 붙는 후보 CVE 를 모은다(생태계 판정 → name/source_pkg
 *      매칭 → 벤더 미수정 병합). 곧 "패키지↔CVE 조인" 이고 이 제품의 매칭 그 자체다.
 *   ② vg_match_pkg_context: 그 패키지의 모든 CVE 에 공통인 맥락(재시작·재부팅 필요, 커널 실행
 *      여부, 서드파티 여부, 런타임 노출)을 한 번만 계산한다.
 *   둘을 한 파일에 둔 이유: 같은 패키지 루프 1회전의 앞뒤이고, 둘 다 "CVE 별 판정 전에
 *   패키지 단위로 한 번" 이라는 같은 계약을 공유한다. 실제 판정은 matcher/decide.php 가 한다.
 *
 * matcher.php 가 require 한다.
 */

if (!function_exists('vg_match_pkg_candidates')) {
    /**
     * 한 패키지의 후보 CVE 를 모은다: 생태계 판정 → name/source_pkg 매칭 → 벤더 미수정 후보 병합.
     *   빈 배열을 반환하면 "이 패키지는 매칭 대상이 없다"는 뜻이다(배포판 미지원 또는 후보 CVE
     *   없음, 두 경우를 호출부가 구분하지 않고 그대로 건너뛰므로 합쳐도 무방하다).
     */
    function vg_match_pkg_candidates(
        array $p, ?array $ctr, string $mgr, int $ctrId,
        ?string $hostEco, string $family, array $affected, array $unfixed
    ): array {
        // 이 패키지가 속한 생태계 — OS 패키지는 배포판, 언어 패키지는 PyPI/npm/RubyGems/Packagist.
        //   섞이면 이름만 같은 엉뚱한 CVE 가 붙는다(OS 의 curl vs npm 의 curl).
        //   컨테이너 패키지는 **그 컨테이너의 배포판** 기준이다(호스트와 다를 수 있다).
        $baseEco = $ctr !== null ? $ctr['eco'] : $hostEco;
        $pkgFam  = $ctr !== null ? $ctr['family'] : $family;
        $pkgEco  = vg_pkg_ecosystem($mgr, $baseEco);
        // 컨테이너 배포판이 OSV 미지원이면 **배포판 패키지는** 판단 근거가 없다 → 매칭 안 한다(추측 금지).
        //   단 언어 패키지(Go/PyPI/npm…)는 배포판과 무관하다. 여기서 같이 버리면,
        //   배포판이 미지원이라는 이유로 Go 의존성 취약점을 통째로 놓친다(미탐).
        if ($ctr !== null && $baseEco === null && vg_is_os_manager($mgr)) { return []; }

        // pkg.name 또는 source_pkg 로 후보 CVE 수집.
        //   비교 버전은 매칭된 키에 맞춘다 — OSV 의 deb 조치안은 **소스 버전** 기준이라
        //   source_pkg 로 매칭됐으면 source_version 과 비교해야 한다(binNMU: 1.2.3-4+b1).
        $cands = [];   // cve => ['cvss'=>, 'fixed'=>, 'cmpver'=>]
        foreach ([[$p['name'], $p['version']], [$p['source_pkg'], $p['source_version'] ?: $p['version']]] as [$key, $cmpVer]) {
            if (!$key || !isset($affected[$key])) { continue; }
            // 커널 CVE 는 **커널 코드가 든 바이너리**에만 해당한다.
            //   커널 소스(linux/kernel) 하나에서 헤더·빌드도구·메타패키지가 20개 넘게 나오는데,
            //   source_pkg 가 같다는 이유로 커널 CVE 전량이 거기에도 매달렸다.
            //   실측(raspberrypi5-00): linux 소스 패키지 21개 × CVE 369건 = LOW 7,925건이 오탐.
            if (vg_is_os_manager($mgr) && vg_is_kernel_source($key) && !vg_is_kernel_code_pkg((string) $p['name'])) {
                continue;
            }
            foreach ($affected[$key] as $row) {
                // 생태계 필터 — 남의 배포판/생태계 행이 이름만 같다고 붙던 것을 막는다.
                //   OS 패키지는 배포판 행만, 언어 패키지는 자기 생태계(PyPI 등) 행만 받는다.
                if (!vg_eco_matches($row['eco'] ?? null, $pkgEco, $pkgFam)) { continue; }
                // 언어 패키지는 'rpm'/'deb' 계열 표기 행과 무관하다(계열 토큰은 OS 전용).
                if (!vg_is_os_manager($mgr) && !vg_eco_is_distro($row['eco'] ?? null)) { continue; }

                // 조치안을 설치 버전과 직접 비교해도 되는 행인지(=배포판 EVR 인지) 표시.
                $fixed = vg_eco_is_distro($row['eco'] ?? null) ? $row['fixed'] : null;

                $cve = $row['cve'];
                if (!isset($cands[$cve]) || ($cands[$cve]['fixed'] === null && $fixed !== null)) {
                    $cands[$cve] = ['cvss' => $row['cvss'], 'fixed' => $fixed, 'cmpver' => (string) $cmpVer];
                }
            }
        }

        // 벤더가 **아직 안 고친** CVE — 수정본이 없어 조치할 수 없다(OVAL 엔 RHSA=수정본만 있다).
        //   실측(UBI8): Trivy 523건 중 514건이 이것이었다. 이건 오탐이 아니라 미탐이었다.
        //   조치안이 없으므로 버전 비교 억제가 걸리지 않고, no_fix 로 표시해 화면에서
        //   "지금 고칠 수 있는 것" 과 분리한다 — 섞으면 조치 불가 500건이 고칠 수 있는 9건을 덮는다.
        foreach ($unfixed[$ctrId][$p['name']] ?? [] as $cve => $info) {
            if (isset($cands[$cve])) { continue; }               // 수정본이 있으면 그쪽이 우선
            $cands[$cve] = [
                'cvss'   => $info['cvss'],
                'fixed'  => null,
                'cmpver' => (string) $p['version'],
                'no_fix' => (string) $info['state'],
            ];
        }

        return $cands;
    }

    /**
     * 한 패키지의 판정 맥락을 모은다: 재시작/재부팅 필요 신호, 커널 실행 여부, 서드파티 판정,
     *   런타임 노출 상태(리스닝·실행·로드). 이 값들은 이 패키지에 매달린 **모든 CVE 에 공통**이라
     *   (CVE 별로 다시 계산할 필요가 없어) 패키지 루프에서 한 번만 구한다.
     */
    function vg_match_pkg_context(
        array $p, ?array $ctr, int $ctrId, string $mgr, array $scan,
        string $runningKernel, bool $runningKernelPresent,
        array $loadMap, array $procRunningPkgs, array $procLoadedPkgs, array $stale
    ): array {
        // 재시작 필요 — 이 패키지의 옛 라이브러리를 물고 있는 프로세스가 있나.
        //   있으면 어떤 억제 근거가 있어도 억제하지 않는다(그 프로세스는 여전히 취약).
        //   컨테이너 패키지엔 적용하지 않는다(호스트 프로세스 기준 신호라서).
        $staleEv = $ctr !== null ? null
            : ($stale[$p['name']] ?? ($p['source_pkg'] ? ($stale[$p['source_pkg']] ?? null) : null));

        // 억제 근거(changelog·errata·debsecan)는 전부 **호스트** 상태다. 컨테이너 CVE 를
        //   호스트 근거로 억제하면 실제 취약점을 숨기는 미탐이 된다 → 컨테이너는 제외한다.
        //   (버전 비교는 그 컨테이너의 패키지 버전으로 하는 것이라 컨테이너에도 유효하다.)
        // 커널: 패치했어도 **재부팅 전까지는 옛 커널이 돈다** → 억제하면 미탐이다.
        //   (라이브러리의 "재시작 필요"와 같은 문제. 조치는 프로세스 재시작이 아니라 재부팅.)
        $isKernelPkg = $ctr === null && vg_is_kernel_code_pkg((string) $p['name']);
        $kernelPending = $isKernelPkg && (int) ($scan['kernel_reboot_needed'] ?? 0) === 1;

        // 실행 중이 아닌 커널 이미지 — 부팅해야 활성화된다. 커널 CVE 를 설치된 이미지 전부에
        //   매달면 같은 목록이 몇 번씩 중복된다(실측 raspberrypi5-00: 702건 × 이미지 4개 = 2,808).
        //   업계 표준(Vuls 등)대로 uname 으로 잡은 **구동 커널**만 판정한다.
        //   단, 실행 중인 커널의 패키지가 목록에 없으면(그 커널만 제거된 드문 경우) 아무것도
        //   억제하지 않는다 — 그러면 커널 CVE 가 통째로 사라져 미탐이 된다.
        $kernelNotRunning = $isKernelPkg && $runningKernelPresent
            && !vg_is_running_kernel_pkg((string) $p['name'], (string) $p['version'], $runningKernel);

        // 서드파티 저장소(PPA·Docker·NodeSource) 패키지 / 수동 .deb 설치는 배포판 트래커에
        //   아예 없다. 배포판 기준 억제(debsecan·errata·changelog)는 "트래커에 없으면 이미
        //   수정됨"으로 보므로, 그대로 두면 진짜 취약점을 숨긴다(미탐) → 억제하지 않는다.
        //   버전 억제도 막는다: 배포판 조치안(EVR)과 서드파티 버전은 체계가 다르다
        //   (예: docker-ce-cli 5:27.0.3-1~debian.12 vs 배포판 EVR).
        $osForOrigin = $ctr !== null ? ($ctr['os'] ?: null) : ($scan['os_id'] ?? null);
        $isDistroPkg = !vg_is_os_manager($mgr)      // 언어 패키지는 이 판정과 무관
            || vg_is_distro_pkg($p['origin'] ?? null, $osForOrigin);

        $hostEvidenceOk = ($ctr === null) && $isDistroPkg;

        // 런타임 상태 신호 (exposures=포트, processes=실행/로드).
        //   **자기 것만 본다** — 맵이 container_id 로 갈려 있어 호스트 신호가 컨테이너로
        //   새지 않는다(호스트 nginx 의 외부노출이 컨테이너 openssl 로 넘어가면 오탐).
        //   에이전트가 컨테이너 런타임을 못 보낸 경우엔 맵이 비어 예전처럼 INSTALLED(LOW) 로
        //   떨어진다 — 옛 에이전트와도 호환된다.
        $le        = $loadMap[$ctrId][$p['name']] ?? ($loadMap[$ctrId][$p['source_pkg']] ?? null);
        $running   = isset($procRunningPkgs[$ctrId][$p['name']]) || ($p['source_pkg'] && isset($procRunningPkgs[$ctrId][$p['source_pkg']]));
        $pkgLoaded = isset($procLoadedPkgs[$ctrId][$p['name']]) || ($p['source_pkg'] && isset($procLoadedPkgs[$ctrId][$p['source_pkg']]));
        $exposed   = $le !== null && ($le['scope'] ?? '') === 'EXTERNAL';
        $loaded    = $le !== null || $pkgLoaded;   // 리스닝 프로세스 로드 or 일반 프로세스 로드
        $scope     = $le['scope'] ?? null;

        return [
            'staleEv'          => $staleEv,
            'isKernelPkg'      => $isKernelPkg,
            'kernelPending'    => $kernelPending,
            'kernelNotRunning' => $kernelNotRunning,
            'isDistroPkg'      => $isDistroPkg,
            'hostEvidenceOk'   => $hostEvidenceOk,
            'le'               => $le,
            'running'          => $running,
            'pkgLoaded'        => $pkgLoaded,
            'exposed'          => $exposed,
            'loaded'           => $loaded,
            'scope'            => $scope,
        ];
    }
}
