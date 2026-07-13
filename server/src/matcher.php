<?php
declare(strict_types=1);

/**
 * matcher.php — 수집된 packages + exposures 를 CVE 와 조인해 우선순위를 매긴다.
 *   규칙(CONTEXT §7): 외부노출(EXTERNAL) + 로드됨 + KEV = CRITICAL.
 *   설치만 됨 → LOW, 로드·내부 → MEDIUM, 외부노출 → HIGH, +KEV 시 한 단계 상향.
 *   각 판정에 "왜"(근거)를 남긴다(설명가능성).
 */

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/vercmp.php';   // vg_ver_cmp — dpkg/rpm 버전 비교
require_once __DIR__ . '/distro.php';   // vg_osv_ecosystem — 수집과 동일 기준

if (!function_exists('vg_scope_rank')) {
    // 노출 범위 위험도 (클수록 위험)
    function vg_scope_rank(?string $s): int {
        switch ($s) {
            case 'EXTERNAL': return 3;
            case 'BOUND':    return 2;
            // FILTERED: 전체 인터페이스에 떠 있지만 방화벽이 그 포트를 막아 외부에서 못 닿는다.
            //   (에이전트가 firewalld/ufw 의 허용 포트와 대조해 판정) → LOCAL 과 같은 무게.
            case 'FILTERED':
            case 'LOCAL':    return 1;
            default:         return 0;
        }
    }

    // 런타임 상태 판정 + 등급 + 근거.
    //   상태 강도: EXTERNAL(외부노출) > LISTENING(로컬리스닝) > RUNNING(실행중) > LOADED(사용중) > INSTALLED(설치만)
    //   레벨: 설치1 / 실행·로드·로컬리스닝2 / 외부노출3, KEV 시 +1(최대 CRITICAL).
    //   반환: [status, severity, rationale]
    //   $pkgLoaded: 이 패키지가 "리스닝 중이 아닌" 실행 프로세스에 라이브러리로 로드됐는가(패키지 1개 기준 bool).
    //     호출부의 procLoadedPkgs(컨테이너별 로드 패키지 집합, 배열)와 이름이 겹치지 않도록 구분한다 —
    //     예전엔 둘 다 $procLoaded 라 배열/bool 이 이름만 보고 헷갈렸다.
    function vg_classify(?array $le, bool $running, bool $pkgLoaded, bool $inKev, string $pkg): array {
        if ($le && ($le['scope'] ?? '') === 'EXTERNAL') {
            $status = 'EXTERNAL'; $level = 3;
            $base = sprintf('외부노출(%s:%d 가 %s 사용)', $le['proc'] ?? '?', $le['port'] ?? 0, $pkg);
        } elseif ($le && ($le['scope'] ?? '') === 'FILTERED') {
            // 전체 인터페이스 바인딩이지만 방화벽이 막고 있다 → 외부노출 아님.
            //   이 판정이 없으면 방화벽 뒤의 내부 서비스가 전부 HIGH/CRITICAL 로 뜬다(오탐).
            $status = 'FILTERED'; $level = 2;
            $base = sprintf('방화벽 차단(%s:%d — 리스닝이지만 외부 도달 불가)', $le['proc'] ?? '?', $le['port'] ?? 0);
        } elseif ($le) {
            $status = 'LISTENING'; $level = 2;
            $base = sprintf('로컬 리스닝(%s:%d, scope=%s)', $le['proc'] ?? '?', $le['port'] ?? 0, $le['scope'] ?? '-');
        } elseif ($running) {
            $status = 'RUNNING'; $level = 2;
            $base = '실행 중(포트 미개방)';
        } elseif ($pkgLoaded) {
            $status = 'LOADED'; $level = 2;
            $base = '사용 중(실행 프로세스가 라이브러리 로드)';
        } else {
            $status = 'INSTALLED'; $level = 1;
            $base = '설치만 됨(실행/로드 프로세스 없음)';
        }
        if ($inKev && $level < 4) {
            $level++;
        }
        $sev = [1 => 'LOW', 2 => 'MEDIUM', 3 => 'HIGH', 4 => 'CRITICAL'][$level];
        $why = $base . ($inKev ? ' · CISA KEV 등재' : '') . ' → ' . $sev;
        return [$status, $sev, $why];
    }

    /**
     * 스캔이 수집한 원시 신호를 배열로 읽어온다: 스캔 메타(OS/커널) · 컨테이너 ·
     * 패키지 · 노출(exposures→로드맵) · 실행 프로세스. 전부 읽기 전용(side-effect 없음).
     *   loadMap/procRunningPkgs/procLoadedPkgs 는 **컨테이너별로 갈린다**(container_id, 0=호스트).
     *   한 덩어리로 합치면 호스트 신호가 컨테이너로 새어(혹은 그 반대로) 오판한다.
     */
    function vg_load_scan_signals(PDO $pdo, int $scanId): array {
        // 이 스캔의 배포판 → 생태계. 수집(feeds)이 'Ubuntu:24.04' 로 태깅한 것과 같은 기준.
        $sc = $pdo->prepare('SELECT os_id, os_version, package_family,
                                    running_kernel, kernel_latest, kernel_reboot_needed
                               FROM tb_scans WHERE id = ?');
        $sc->execute([$scanId]);
        $scan = $sc->fetch() ?: [];
        $hostEco = vg_osv_ecosystem($scan['os_id'] ?? null, $scan['os_version'] ?? null);
        $family  = (string) ($scan['package_family'] ?? '');

        // 컨테이너 — 호스트와 OS 가 다를 수 있다(호스트 Rocky + 컨테이너 Debian).
        //   그래서 컨테이너 패키지의 생태계는 **그 컨테이너의 OS** 로 판정해야 한다.
        $ctrs = [];   // container_id => ['eco'=>, 'family'=>, 'cid'=>]
        $cs = $pdo->prepare('SELECT id, cid, os_id, os_version, manager FROM tb_containers WHERE scan_id = ?');
        $cs->execute([$scanId]);
        foreach ($cs->fetchAll() as $c) {
            $mgr = (string) ($c['manager'] ?? '');
            $ctrs[(int) $c['id']] = [
                'cid'    => (string) $c['cid'],
                'os'     => (string) ($c['os_id'] ?? ''),   // 출처 판정에 쓴다(배포판이 호스트와 다름)
                'eco'    => vg_osv_ecosystem($c['os_id'], $c['os_version']),
                'family' => $mgr === 'dpkg' ? 'deb' : ($mgr === 'rpm' ? 'rpm' : $mgr),
            ];
        }

        // 패키지 (호스트: container_id=0, 컨테이너: >0)
        $stmt = $pdo->prepare('SELECT container_id, manager, name, source_pkg, version, source_version, origin FROM tb_packages WHERE scan_id = ?');
        $stmt->execute([$scanId]);
        $packages = $stmt->fetchAll();

        // 노출 → 패키지별 최악(worst) 로드 상태 맵.
        //   **컨테이너별로 따로 담는다**(container_id, 0=호스트). 한 덩어리로 합치면 호스트 nginx 의
        //   외부노출이 컨테이너 openssl 로 새어 EXTERNAL 로 오판한다(오탐).
        $stmt = $pdo->prepare('SELECT container_id, proc, port, scope, exe_pkg, loaded_pkgs FROM tb_exposures WHERE scan_id = ?');
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
        $stmt = $pdo->prepare('SELECT container_id, exe_pkg, loaded_pkgs FROM tb_processes WHERE scan_id = ?');
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

    /**
     * CVE 카탈로그(스캔과 무관, 전역): KEV 등재 집합 + 영향 패키지 인덱스.
     */
    function vg_load_cve_catalog(PDO $pdo): array {
        // KEV 집합
        $kev = [];
        foreach ($pdo->query('SELECT cve_id FROM tb_kev_catalog')->fetchAll() as $r) {
            $kev[$r['cve_id']] = true;
        }

        // 영향 패키지 인덱스: package_name => [ {cve, eco, fixed, cvss} … ]
        //   ecosystem/fixed_version 을 함께 읽는다. 예전엔 이름만 보고 CVE 를 매달아
        //   (1) 다른 배포판의 행이 붙고 (2) 이미 상위 버전인데도 취약으로 떴다.
        $affected = [];
        $capStmt = $pdo->query(
            'SELECT a.cve_id, a.package_name, a.ecosystem, a.fixed_version, c.cvss
             FROM tb_cve_affected_packages a
             LEFT JOIN tb_cves c ON c.cve_id = a.cve_id'
        );
        foreach ($capStmt->fetchAll() as $r) {
            $affected[$r['package_name']][] = [
                'cve'   => $r['cve_id'],
                'eco'   => $r['ecosystem'],
                'fixed' => $r['fixed_version'],
                'cvss'  => $r['cvss'],
            ];
        }

        return ['kev' => $kev, 'affected' => $affected];
    }

    /**
     * 오탐 억제 근거(②changelog·③errata·④debsecan) + 억제취소 신호(재시작 필요) 를 모은다.
     * 전부 이 스캔의 **호스트** 상태다 — 컨테이너 CVE 를 호스트 근거로 억제하면 실제 취약점을
     * 숨기는 미탐이 되므로, 컨테이너 배제는 호출부(vg_match_scan)의 책임으로 남겨둔다.
     */
    function vg_load_suppression_evidence(PDO $pdo, int $scanId, ?string $osId): array {
        // 백포트 근거: 패키지 changelog 에 명시된 CVE(=그 빌드에 이미 수정됨).
        //   package_name => [cve_id => evidence(changelog 줄)]
        $backport = [];
        $bpStmt = $pdo->prepare('SELECT package_name, cve_id, evidence FROM tb_pkg_changelog_cves WHERE scan_id = ?');
        $bpStmt->execute([$scanId]);
        foreach ($bpStmt->fetchAll() as $r) {
            $backport[$r['package_name']][$r['cve_id']] = $r['evidence'];
        }

        // 재시작 필요: 패치됐지만 프로세스가 옛 라이브러리(.so)를 메모리에 물고 있는 패키지.
        //   package_name => 근거(lib 경로). 이게 있으면 "이미 패치됨" 억제를 하면 안 된다 —
        //   그 프로세스는 여전히 옛(취약한) 코드를 실행 중이기 때문이다.
        $stale = [];
        $slStmt = $pdo->prepare('SELECT package_name, comm, lib_path FROM tb_stale_libs WHERE scan_id = ?');
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
        $debsecan = [];
        $dsStmt = $pdo->prepare('SELECT cve_id, package_name FROM tb_debsecan WHERE scan_id = ?');
        $dsStmt->execute([$scanId]);
        foreach ($dsStmt->fetchAll() as $r) {
            $debsecan[$r['package_name']][$r['cve_id']] = true;
        }
        $useDebsecan = $debsecan !== [] && strtolower((string) $osId) === 'debian';

        // 적용된 벤더 권고(errata) 근거: 벤더가 "이 CVE 는 이 설치 빌드에서 고쳤다"고 확인한 것.
        //   changelog(핵심 13개 패키지 하드코딩)와 달리 시스템 전체를 덮는다.
        //   package_name => [cve_id => evidence(설치 NEVRA)]
        $errata = [];
        $erStmt = $pdo->prepare('SELECT package_name, cve_id, evidence FROM tb_applied_errata WHERE scan_id = ?');
        $erStmt->execute([$scanId]);
        foreach ($erStmt->fetchAll() as $r) {
            $errata[$r['package_name']][$r['cve_id']] = $r['evidence'];
        }

        return [
            'backport'    => $backport,
            'stale'       => $stale,
            'debsecan'    => $debsecan,
            'useDebsecan' => $useDebsecan,
            'errata'      => $errata,
        ];
    }

    /**
     * 한 스캔에 대해 매칭 수행 → findings 재계산. 반환: 등급별 카운트.
     */
    function vg_match_scan(PDO $pdo, int $scanId): array {
        $sig = vg_load_scan_signals($pdo, $scanId);
        $scan            = $sig['scan'];
        $hostEco         = $sig['hostEco'];
        $family          = $sig['family'];
        $ctrs            = $sig['ctrs'];
        $packages        = $sig['packages'];
        $loadMap         = $sig['loadMap'];
        $procRunningPkgs = $sig['procRunningPkgs'];
        $procLoadedPkgs  = $sig['procLoadedPkgs'];

        $catalog  = vg_load_cve_catalog($pdo);
        $kev      = $catalog['kev'];
        $affected = $catalog['affected'];

        $sup         = vg_load_suppression_evidence($pdo, $scanId, $scan['os_id'] ?? null);
        $backport    = $sup['backport'];
        $stale       = $sup['stale'];
        $debsecan    = $sup['debsecan'];
        $useDebsecan = $sup['useDebsecan'];
        $errata      = $sup['errata'];

        // 재계산은 원자적으로(자체 트랜잭션). 스케줄러 사이드카와 동시 재매칭 시
        // DELETE↔INSERT 경합으로 유니크키 충돌이 나던 것을 방지.
        $ownTx = !$pdo->inTransaction();
        if ($ownTx) { $pdo->beginTransaction(); }
        try {

        // 기존 findings 삭제 후 재삽입. INSERT 는 멱등(동시성 대비).
        $pdo->prepare('DELETE FROM tb_findings WHERE scan_id = ?')->execute([$scanId]);
        $ins = $pdo->prepare(
            'INSERT INTO tb_findings
               (scan_id, container_id, cve_id, package_name, installed_version, loaded, exposed,
                exposure_scope, runtime_status, in_kev, needs_restart, cvss, severity, rationale)
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
             ON DUPLICATE KEY UPDATE
               installed_version=VALUES(installed_version), loaded=VALUES(loaded),
               exposed=VALUES(exposed), exposure_scope=VALUES(exposure_scope),
               runtime_status=VALUES(runtime_status), in_kev=VALUES(in_kev),
               needs_restart=VALUES(needs_restart), cvss=VALUES(cvss),
               severity=VALUES(severity), rationale=VALUES(rationale)'
        );

        // 억제(백포트)된 건은 tb_findings 가 아니라 여기로 — 위험 집계에서 자동 제외.
        $pdo->prepare('DELETE FROM tb_suppressed_findings WHERE scan_id = ?')->execute([$scanId]);
        $insSupp = $pdo->prepare(
            'INSERT INTO tb_suppressed_findings
               (scan_id, cve_id, package_name, installed_version, in_kev, cvss, base_severity, suppress_reason)
             VALUES (?,?,?,?,?,?,?,?)
             ON DUPLICATE KEY UPDATE
               installed_version=VALUES(installed_version), in_kev=VALUES(in_kev), cvss=VALUES(cvss),
               base_severity=VALUES(base_severity), suppress_reason=VALUES(suppress_reason)'
        );

        $counts = ['CRITICAL' => 0, 'HIGH' => 0, 'MEDIUM' => 0, 'LOW' => 0, 'SUPPRESSED' => 0];
        $seen = [];

        foreach ($packages as $p) {
            $mgr   = (string) ($p['manager'] ?? 'dpkg');
            $ctrId = (int) ($p['container_id'] ?? 0);
            $ctr   = $ctrId > 0 ? ($ctrs[$ctrId] ?? null) : null;

            // 이 패키지가 속한 생태계 — OS 패키지는 배포판, 언어 패키지는 PyPI/npm/RubyGems/Packagist.
            //   섞이면 이름만 같은 엉뚱한 CVE 가 붙는다(OS 의 curl vs npm 의 curl).
            //   컨테이너 패키지는 **그 컨테이너의 배포판** 기준이다(호스트와 다를 수 있다).
            $baseEco = $ctr !== null ? $ctr['eco'] : $hostEco;
            $pkgFam  = $ctr !== null ? $ctr['family'] : $family;
            $pkgEco  = vg_pkg_ecosystem($mgr, $baseEco);
            // 컨테이너 배포판이 OSV 미지원이면 **배포판 패키지는** 판단 근거가 없다 → 매칭 안 한다(추측 금지).
            //   단 언어 패키지(Go/PyPI/npm…)는 배포판과 무관하다. 여기서 같이 버리면,
            //   배포판이 미지원이라는 이유로 Go 의존성 취약점을 통째로 놓친다(미탐).
            if ($ctr !== null && $baseEco === null && vg_is_os_manager($mgr)) { continue; }

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
            if (!$cands) {
                continue;
            }

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

            foreach ($cands as $cveId => $cand) {
                $cvss = $cand['cvss'];
                // 컨테이너별로 따로 센다 — 호스트의 openssl 과 컨테이너의 openssl 은 별개 취약점이다.
                $key = $ctrId . '|' . $cveId . '|' . $p['name'];
                if (isset($seen[$key])) { continue; }
                $seen[$key] = true;

                $inKev = isset($kev[$cveId]);
                [$status, $sev, $why] = vg_classify($le, $running, $pkgLoaded, $inKev, $p['name']);

                // 옛 라이브러리가 메모리에 상주하면 "패치됨"이라도 억제하지 않는다(재시작 전까지 취약).
                $canSuppress = ($staleEv === null);
                if ($staleEv !== null) {
                    $why .= ' · 재시작 필요(패치됐지만 옛 라이브러리 사용 중: ' . $staleEv . ')';
                }
                // 커널이 패치됐지만 재부팅 전이면, 설치 버전으로 억제하면 안 된다(옛 커널이 실행 중).
                if ($kernelPending) {
                    $canSuppress = false;
                    $why .= sprintf(' · 재부팅 필요(설치 %s / 실행 중 %s — 패치된 커널이 아직 안 올라옴)',
                                    (string) ($scan['kernel_latest'] ?? '?'),
                                    (string) ($scan['running_kernel'] ?? '?'));
                }

                // 서드파티 패키지는 배포판 조치안과 버전 체계가 달라 "설치 ≥ 조치" 비교도 못 믿는다.
                //   억제하지 않고 근거에 출처를 남겨, 사람이 판단할 수 있게 한다.
                if (!$isDistroPkg) {
                    $canSuppress = false;
                    $why .= sprintf(' · 서드파티 저장소(%s) 패키지 — 배포판 조치안과 버전 체계가 달라 자동 판정 불가',
                                    (string) ($p['origin'] ?? '출처 미상'));
                }

                // 버전 억제: 설치 버전이 조치 버전 이상이면 이미 패치된 것.
                //   배포판 규칙(epoch·릴리스·틸드)대로 비교한다 — vg_ver_cmp.
                //   fixed 가 비어 있으면(피드가 조치안을 안 준 경우) 판단하지 않고 남긴다.
                $fixed = $cand['fixed'];
                if ($canSuppress && $fixed !== null && $fixed !== '' && $cand['cmpver'] !== ''
                    && vg_ver_cmp($cand['cmpver'], (string) $fixed, $mgr) >= 0) {
                    $insSupp->execute([
                        $scanId, $cveId, $p['name'], $p['version'],
                        $inKev ? 1 : 0, $cvss, $sev,
                        sprintf('설치 %s ≥ 조치 %s → 이미 패치됨', $cand['cmpver'], $fixed),
                    ]);
                    $counts['SUPPRESSED']++;
                    continue;
                }

                // debsecan 억제: 데비안 트래커가 이 패키지의 이 CVE 를 "아직 취약"으로 보지 않았다면
                //   백포트로 이미 고쳐진 것이다(트래커는 데비안 패치 상태를 반영한다).
                if ($canSuppress && $hostEvidenceOk && $useDebsecan && vg_is_os_manager($mgr)
                    && !isset($debsecan[$p['name']][$cveId])) {
                    $insSupp->execute([
                        $scanId, $cveId, $p['name'], $p['version'],
                        $inKev ? 1 : 0, $cvss, $sev,
                        '데비안 보안 트래커(debsecan)가 ' . $p['name'] . ' 의 ' . $cveId
                        . ' 를 해당 없음으로 판정 → 백포트로 이미 수정됨',
                    ]);
                    $counts['SUPPRESSED']++;
                    continue;
                }

                // errata 억제: 벤더 보안권고가 이 설치 빌드에서 해당 CVE 를 고쳤다고 확인해 준 경우.
                //   버전이 낮아 보여도(백포트) 이미 패치된 것 → 실제 위험에서 제외.
                $erEv = $errata[$p['name']][$cveId]
                    ?? ($p['source_pkg'] ? ($errata[$p['source_pkg']][$cveId] ?? null) : null);
                if ($canSuppress && $hostEvidenceOk && $erEv !== null) {
                    $reason = $p['name'] . ' 에 적용된 벤더 보안권고가 ' . $cveId . ' 를 고침(백포트) → 이미 패치됨';
                    if (is_string($erEv) && $erEv !== '') { $reason .= ' · ' . $erEv; }
                    $insSupp->execute([
                        $scanId, $cveId, $p['name'], $p['version'],
                        $inKev ? 1 : 0, $cvss, $sev, $reason,
                    ]);
                    $counts['SUPPRESSED']++;
                    continue;
                }

                // 백포트 억제: 이 빌드의 changelog 에 해당 CVE 수정 기록이 있으면
                //   버전이 낮아 보여도 이미 패치된 것 → 실제 위험에서 제외(오탐 제거).
                $bpEv = $backport[$p['name']][$cveId]
                    ?? ($p['source_pkg'] ? ($backport[$p['source_pkg']][$cveId] ?? null) : null);
                if ($canSuppress && $hostEvidenceOk && $bpEv !== null) {
                    $reason = $p['name'] . ' changelog 에 ' . $cveId . ' 수정 기록(백포트) → 버전이 낮아 보여도 패치됨';
                    if (is_string($bpEv) && $bpEv !== '') { $reason .= ' · ' . $bpEv; }
                    $insSupp->execute([
                        $scanId, $cveId, $p['name'], $p['version'],
                        $inKev ? 1 : 0, $cvss, $sev, $reason,
                    ]);
                    $counts['SUPPRESSED']++;
                    continue;
                }

                $counts[$sev]++;
                $ins->execute([
                    $scanId, $ctrId, $cveId, $p['name'], $p['version'],
                    $loaded ? 1 : 0, $exposed ? 1 : 0, $scope, $status, $inKev ? 1 : 0,
                    ($staleEv !== null || $kernelPending) ? 1 : 0, $cvss, $sev, $why,
                ]);
            }
        }

            if ($ownTx) { $pdo->commit(); }
            return $counts;
        } catch (Throwable $e) {
            if ($ownTx && $pdo->inTransaction()) { $pdo->rollBack(); }
            throw $e;
        }
    }
}
