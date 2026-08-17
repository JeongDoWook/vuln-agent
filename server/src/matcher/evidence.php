<?php
declare(strict_types=1);

/**
 * matcher/evidence.php — 억제 게이트가 **읽을 근거를 모으는** 층(적재만, 판정 없음).
 *   ①changelog 백포트 ②배포판 트래커/OVAL ③벤더 errata ④벤더 미수정 목록,
 *   그리고 억제를 취소시키는 신호(재시작 필요) · 구동 커널의 업스트림 수정 여부.
 *   **무엇이 무엇을 막는지는 여기서 정하지 않는다** — 그 순서·조건은 matcher/decide.php 가 갖는다.
 *   근거의 대상별 분리(호스트 0 / 컨테이너 >0)는 미탐·오탐이 갈리는 자리라 그대로 둔다.
 *
 * matcher.php 가 require 한다(debtracker/ubuntuoval/vendorerrata/kernelcve 는 matcher.php 가 먼저 로드).
 */

if (!function_exists('vg_load_suppression_evidence')) {
    /**
     * 오탐 억제 근거(②changelog·③errata·④debsecan) + 억제취소 신호(재시작 필요) 를 모은다.
     * 전부 이 스캔의 **호스트** 상태다 — 컨테이너 CVE 를 호스트 근거로 억제하면 실제 취약점을
     * 숨기는 미탐이 되므로, 컨테이너 배제는 호출부(vg_match_scan)의 책임으로 남겨둔다.
     */
    function vg_load_suppression_evidence(PDO $pdo, int $scanId, ?string $osId, ?string $osVersion = null): array {
        // 백포트 근거: 패키지 changelog 에 명시된 CVE(=그 빌드에 이미 수정됨).
        //   package_name => [cve_id => evidence(changelog 줄)]
        $backport = [];
        $bpStmt = $pdo->prepare('SELECT package_name, cve_id, evidence FROM tb_pkg_changelog_cve WHERE scan_id = ?');
        $bpStmt->execute([$scanId]);
        foreach ($bpStmt->fetchAll() as $r) {
            $backport[$r['package_name']][$r['cve_id']] = $r['evidence'];
        }

        // 재시작 필요: 패치됐지만 프로세스가 옛 라이브러리(.so)를 메모리에 물고 있는 패키지.
        //   package_name => 근거(lib 경로). 이게 있으면 "이미 패치됨" 억제를 하면 안 된다 —
        //   그 프로세스는 여전히 옛(취약한) 코드를 실행 중이기 때문이다.
        $stale = [];
        $slStmt = $pdo->prepare('SELECT package_name, comm, lib_path FROM tb_stale_lib WHERE scan_id = ?');
        $slStmt->execute([$scanId]);
        foreach ($slStmt->fetchAll() as $r) {
            if (!isset($stale[$r['package_name']])) {
                $stale[$r['package_name']] = trim(($r['comm'] ?? '') . ' → ' . ($r['lib_path'] ?? ''));
            }
        }

        // debsecan(데비안 보안 트래커) 판정: "이 설치 버전에 아직 해당하는 CVE" 목록.
        //   errata 와 방향이 반대다 — errata 는 고쳐진 것을, debsecan 은 남아 있는 것을 준다.
        //   따라서 **여기 없는 deb CVE 는 백포트로 이미 수정된 것**(오탐)이라 억제한다.
        //   안전장치 두 겹:
        //     (1) os_id=debian 일 때만. debsecan 은 데비안 전용이라 우분투에서 돌리면 부정확하고,
        //         잘못 믿으면 미탐이 된다(우분투는 OSV 의 USN 경로로 이미 커버된다).
        //     (2) 목록이 비어 있으면(수집 실패·미설치) 억제하지 않는다 — 실패와 "취약점 0"을
        //         구분할 수 없어서, 믿었다가는 전부 억제해 버린다.
        //   맵은 **판정 대상별**로 갈린다: container_id => [패키지 => [cve => true]] (호스트는 0).
        //   호스트의 debsecan 을 컨테이너에 적용하면 미탐이므로 섞이지 않게 키로 분리한다.
        $agentDs = [];
        $dsStmt = $pdo->prepare('SELECT cve_id, package_name FROM tb_debsecan WHERE scan_id = ?');
        $dsStmt->execute([$scanId]);
        foreach ($dsStmt->fetchAll() as $r) {
            $agentDs[$r['package_name']][$r['cve_id']] = true;
        }

        // 중앙 판정(tb_debian_tracker) — 에이전트는 사실만 모으고 판정 지식은 중앙이 갖는다.
        //   호스트뿐 아니라 **데비안 컨테이너**도 여기서 판정한다. 예전의 "컨테이너는 억제 금지"
        //   규칙은 근거를 **호스트에서 수집**하던 시절 것이다(호스트 상태가 컨테이너로 새면 미탐).
        //   트래커는 호스트 상태가 아니라 "그 릴리스의 사실" 이고, 컨테이너는 자기 릴리스 데이터로
        //   자기 패키지 버전을 대조한다 → 샐 경로가 없다. 컨테이너 오탐이 그대로 방치돼 있었다.
        $debsecan = vg_debtracker_evidence(
            $pdo, $scanId,
            strtolower((string) $osId) === 'debian' ? vg_debian_codename($osVersion) : ''
        );
        // 에이전트가 debsecan 을 보냈으면 호스트는 그 실측을 우선한다(현장 상태 그대로).
        if ($agentDs !== [] && strtolower((string) $osId) === 'debian') {
            $debsecan[0] = $agentDs;
        }
        $trackerLabel = [];
        foreach ($debsecan as $ctrId => $map) { $trackerLabel[(int) $ctrId] = '데비안 보안 트래커'; }

        // 우분투도 같은 축을 갖는다(tb_ubuntu_oval). 데비안엔 트래커, RHEL 엔 OVAL 이 있는데
        //   우분투만 벤더 판정이 없어 백포트 오탐이 그대로 남았다(실측: 억제 765건 —
        //   비슷한 규모의 데비안 호스트는 4,135건). 맵 모양이 같아 같은 억제 경로를 탄다.
        //   대상(호스트·컨테이너)이 겹치지 않는다 — 한 대상의 OS 는 하나다.
        foreach (vg_ubuntu_evidence(
            $pdo, $scanId,
            strtolower((string) $osId) === 'ubuntu' ? vg_ubuntu_codename($osVersion) : ''
        ) as $ctrId => $map) {
            $debsecan[(int) $ctrId]     = $map;
            $trackerLabel[(int) $ctrId] = '우분투 보안 OVAL';
        }

        // 대상별로 켠다 — 목록이 비어 있으면(수집 실패·트래커 미수집) 그 대상은 억제하지 않는다.
        //   실패와 "취약점 0" 을 구분할 수 없어서, 믿었다가는 전부 억제해 버린다.
        $useDebsecan = [];
        foreach ($debsecan as $ctrId => $map) {
            $useDebsecan[(int) $ctrId] = $map !== [];
        }

        // 적용된 벤더 권고(errata) 근거: 벤더가 "이 CVE 는 이 설치 빌드에서 고쳤다"고 확인한 것.
        //   changelog(핵심 13개 패키지 하드코딩)와 달리 시스템 전체를 덮는다.
        //   package_name => [cve_id => evidence(설치 NEVRA)]
        $errata = [];
        $erStmt = $pdo->prepare('SELECT package_name, cve_id, evidence FROM tb_applied_errata WHERE scan_id = ?');
        $erStmt->execute([$scanId]);
        foreach ($erStmt->fetchAll() as $r) {
            $errata[$r['package_name']][$r['cve_id']] = $r['evidence'];
        }

        // 중앙이 받은 벤더 권고(OVAL) — RHEL 계열의 백포트 판정. 데비안 트래커의 rpm 판이다.
        //   에이전트의 dnf updateinfo(위 tb_applied_errata)와 달리 대상 서버에서 아무것도 긁지 않고,
        //   **컨테이너까지** 판정한다(자기 벤더·자기 메이저 릴리스의 권고와 대조).
        //   데이터가 없으면 빈 배열 → 억제하지 않는다.
        $vendorErrata = vg_vendor_errata_evidence($pdo, $scanId, $osId, $osVersion);

        // 벤더가 **아직 안 고친** CVE(조치 불가). OVAL 엔 수정본(RHSA)만 있어 이 경로가 없으면
        //   그 CVE 들이 통째로 안 보인다(미탐). 실측 UBI8: Trivy 523건 중 514건이 이것이었다.
        $unfixed = vg_vendor_unfixed_candidates($pdo, $scanId, $osId, $osVersion);

        return [
            'backport'     => $backport,
            'stale'        => $stale,
            'debsecan'     => $debsecan,
            'useDebsecan'  => $useDebsecan,
            'trackerLabel' => $trackerLabel,
            'errata'       => $errata,
            'vendorErrata' => $vendorErrata,
            'unfixed'      => $unfixed,
        ];
    }

    /**
     * 구동 커널(uname -r) 파악 + 그 커널 버전에 대한 업스트림(kernel.org CNA) 수정 여부 판정.
     *   배포판 EVR 이 아니라 uname 버전으로 본다 — 배포판 트래커/OVAL 관할 밖(라즈베리·자체빌드)
     *   커널만 여기서 담당한다(호출부 vg_match_scan 의 커널 CNA 억제 참고).
     */
    function vg_match_load_kernel_context(PDO $pdo, array $packages, array $affected, array $scan): array {
        // 구동 커널의 패키지가 실제로 설치 목록에 있을 때만 "나머지는 안 돈다"고 판단한다.
        //   (없으면 판단 보류 → 아무것도 억제하지 않는다. 잘못 억제하면 커널 CVE 가 통째로 사라진다.)
        $runningKernel        = (string) ($scan['running_kernel'] ?? '');
        $runningKernelPresent = false;
        if ($runningKernel !== '') {
            foreach ($packages as $rp) {
                if ((int) ($rp['container_id'] ?? 0) !== 0) { continue; }   // 호스트 패키지만
                if (vg_is_running_kernel_pkg((string) $rp['name'], (string) $rp['version'], $runningKernel)) {
                    $runningKernelPresent = true;
                    break;
                }
            }
        }

        // 대상은 이 스캔의 커널 후보 CVE 뿐 — 전량 적재하면 매처 메모리가 또 터진다.
        $kernelCves = [];
        foreach ($affected as $key => $rows) {
            if (!vg_is_kernel_source((string) $key) && !vg_is_kernel_code_pkg((string) $key)) { continue; }
            foreach ($rows as $r) { $kernelCves[(string) $r['cve']] = true; }
        }
        $kernelFixed = vg_kernel_fixed_set($pdo, $runningKernel, array_keys($kernelCves));

        return [
            'runningKernel'        => $runningKernel,
            'runningKernelPresent' => $runningKernelPresent,
            'kernelFixed'          => $kernelFixed,
        ];
    }
}
