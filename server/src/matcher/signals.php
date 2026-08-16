<?php
declare(strict_types=1);

/**
 * matcher/signals.php — 한 스캔이 수집한 **원시 신호**를 배열로 읽는다(읽기 전용).
 *   스캔 메타(OS·커널) · 컨테이너 · 패키지 · 노출(로드맵) · 실행 프로세스.
 *   판정은 하지 않는다 — "무엇이 관측됐나"까지가 이 파일의 책임이고,
 *   그것으로 무엇을 결론지을지는 matcher/candidates.php·decide.php 가 한다.
 *
 * matcher.php 가 require 한다(vg_scope_rank 를 쓰므로 matcher/classify.php 뒤에 온다).
 */

if (!function_exists('vg_load_scan_signals')) {
    /**
     * 스캔이 수집한 원시 신호를 배열로 읽어온다: 스캔 메타(OS/커널) · 컨테이너 ·
     * 패키지 · 노출(exposures→로드맵) · 실행 프로세스. 전부 읽기 전용(side-effect 없음).
     *   loadMap/procRunningPkgs/procLoadedPkgs 는 **컨테이너별로 갈린다**(container_id, 0=호스트).
     *   한 덩어리로 합치면 호스트 신호가 컨테이너로 새어(혹은 그 반대로) 오판한다.
     */
    function vg_load_scan_signals(PDO $pdo, int $scanId): array {
        // 이 스캔의 배포판 → 생태계. 수집(feeds)이 'Ubuntu:24.04' 로 태깅한 것과 같은 기준.
        $sc = $pdo->prepare('SELECT s.host_id, s.os_id, s.os_version, s.package_family,
                                    s.running_kernel, s.kernel_latest, s.kernel_reboot_needed
                               FROM tb_scan s
                               JOIN tb_host h ON h.host_id = s.host_id AND h.is_deleted = 0
                              WHERE s.scan_id = ?');
        $sc->execute([$scanId]);
        $scan = $sc->fetch() ?: [];
        $hostEco = vg_osv_ecosystem($scan['os_id'] ?? null, $scan['os_version'] ?? null);
        $family  = (string) ($scan['package_family'] ?? '');

        // 컨테이너 — 호스트와 OS 가 다를 수 있다(호스트 Rocky + 컨테이너 Debian).
        //   그래서 컨테이너 패키지의 생태계는 **그 컨테이너의 OS** 로 판정해야 한다.
        $ctrs = [];   // container_id => ['eco'=>, 'family'=>, 'cid'=>]
        $cs = $pdo->prepare('SELECT container_id, cid, os_id, os_version, manager FROM tb_container WHERE scan_id = ?');
        $cs->execute([$scanId]);
        foreach ($cs->fetchAll() as $c) {
            $mgr = (string) ($c['manager'] ?? '');
            $ctrs[(int) $c['container_id']] = [
                'cid'    => (string) $c['cid'],
                'os'     => (string) ($c['os_id'] ?? ''),   // 출처 판정에 쓴다(배포판이 호스트와 다름)
                'eco'    => vg_osv_ecosystem($c['os_id'], $c['os_version']),
                'family' => $mgr === 'dpkg' ? 'deb' : ($mgr === 'rpm' ? 'rpm' : $mgr),
            ];
        }

        // 패키지 (호스트: container_id=0, 컨테이너: >0)
        $stmt = $pdo->prepare('SELECT container_id, manager, name, source_pkg, version, source_version, origin FROM tb_package WHERE scan_id = ?');
        $stmt->execute([$scanId]);
        $packages = $stmt->fetchAll();

        // 노출 → 패키지별 최악(worst) 로드 상태 맵.
        //   **컨테이너별로 따로 담는다**(container_id, 0=호스트). 한 덩어리로 합치면 호스트 nginx 의
        //   외부노출이 컨테이너 openssl 로 새어 EXTERNAL 로 오판한다(오탐).
        $stmt = $pdo->prepare('SELECT container_id, proc, proto, port, scope, exe_pkg, loaded_pkgs FROM tb_exposure WHERE scan_id = ?');
        $stmt->execute([$scanId]);
        $loadMap = []; // ctrId => pkgName => ['rank','scope','proc','port']
        foreach ($stmt->fetchAll() as $e) {
            $c = (int) $e['container_id'];
            $names = [];
            if (!empty($e['exe_pkg']) && $e['exe_pkg'] !== 'UNPACKAGED') {
                $names[] = $e['exe_pkg'];
            }
            if (!empty($e['loaded_pkgs'])) {
                foreach (explode(',', (string) $e['loaded_pkgs']) as $n) {
                    $n = trim($n);
                    if ($n !== '') { $names[] = $n; }
                }
            }
            $rank = vg_scope_rank($e['scope']);
            foreach (array_unique($names) as $n) {
                if (!isset($loadMap[$c][$n]) || $rank > $loadMap[$c][$n]['rank']) {
                    $loadMap[$c][$n] = ['rank' => $rank, 'scope' => $e['scope'], 'proc' => $e['proc'], 'port' => (int) $e['port']];
                }
            }
        }

        // 실행 프로세스 → 실행중(exe_pkg) / 사용중(loaded_pkgs) 패키지 집합 (컨테이너별).
        //   procRunningPkgs/procLoadedPkgs 는 "컨테이너별" 집합(ctrId => 패키지명 => true)이다.
        //   개별 패키지가 여기 속하는지는 호출부에서 isset() 으로 조회해 패키지별 bool 을 만든다 —
        //   vg_classify() 의 패키지별 bool 파라미터($pkgLoaded)와 이름이 겹치지 않도록 Pkgs 접미사로 구분한다.
        $procRunningPkgs = []; $procLoadedPkgs = [];
        $stmt = $pdo->prepare('SELECT container_id, exe_pkg, loaded_pkgs FROM tb_process WHERE scan_id = ?');
        $stmt->execute([$scanId]);
        foreach ($stmt->fetchAll() as $pr) {
            $c = (int) $pr['container_id'];
            if (!empty($pr['exe_pkg']) && $pr['exe_pkg'] !== 'UNPACKAGED') {
                $procRunningPkgs[$c][$pr['exe_pkg']] = true;
            }
            if (!empty($pr['loaded_pkgs'])) {
                foreach (explode(',', (string) $pr['loaded_pkgs']) as $n) {
                    $n = trim($n);
                    if ($n !== '') { $procLoadedPkgs[$c][$n] = true; }
                }
            }
        }

        return [
            'scan'            => $scan,
            'hostEco'         => $hostEco,
            'family'          => $family,
            'ctrs'            => $ctrs,
            'packages'        => $packages,
            'loadMap'         => $loadMap,
            'procRunningPkgs' => $procRunningPkgs,
            'procLoadedPkgs'  => $procLoadedPkgs,
        ];
    }
}
