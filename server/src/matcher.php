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
    function vg_classify(?array $le, bool $running, bool $procLoaded, bool $inKev, string $pkg): array {
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
        } elseif ($procLoaded) {
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
     * 한 스캔에 대해 매칭 수행 → findings 재계산. 반환: 등급별 카운트.
     */
    function vg_match_scan(PDO $pdo, int $scanId): array {
        // 이 스캔의 배포판 → 생태계. 수집(feeds)이 'Ubuntu:24.04' 로 태깅한 것과 같은 기준.
        $sc = $pdo->prepare('SELECT os_id, os_version, package_family FROM tb_scans WHERE id = ?');
        $sc->execute([$scanId]);
        $scan = $sc->fetch() ?: [];
        $hostEco = vg_osv_ecosystem($scan['os_id'] ?? null, $scan['os_version'] ?? null);
        $family  = (string) ($scan['package_family'] ?? '');

        // 패키지
        $stmt = $pdo->prepare('SELECT manager, name, source_pkg, version, source_version FROM tb_packages WHERE scan_id = ?');
        $stmt->execute([$scanId]);
        $packages = $stmt->fetchAll();

        // 노출 → 패키지별 최악(worst) 로드 상태 맵
        $stmt = $pdo->prepare('SELECT proc, port, scope, exe_pkg, loaded_pkgs FROM tb_exposures WHERE scan_id = ?');
        $stmt->execute([$scanId]);
        $loadMap = []; // pkgName => ['rank','scope','proc','port']
        foreach ($stmt->fetchAll() as $e) {
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
                if (!isset($loadMap[$n]) || $rank > $loadMap[$n]['rank']) {
                    $loadMap[$n] = ['rank' => $rank, 'scope' => $e['scope'], 'proc' => $e['proc'], 'port' => (int) $e['port']];
                }
            }
        }

        // 실행 프로세스 → 실행중(exe_pkg) / 사용중(loaded_pkgs) 패키지 집합
        $procRunning = []; $procLoaded = [];
        $stmt = $pdo->prepare('SELECT exe_pkg, loaded_pkgs FROM tb_processes WHERE scan_id = ?');
        $stmt->execute([$scanId]);
        foreach ($stmt->fetchAll() as $pr) {
            if (!empty($pr['exe_pkg']) && $pr['exe_pkg'] !== 'UNPACKAGED') {
                $procRunning[$pr['exe_pkg']] = true;
            }
            if (!empty($pr['loaded_pkgs'])) {
                foreach (explode(',', (string) $pr['loaded_pkgs']) as $n) {
                    $n = trim($n);
                    if ($n !== '') { $procLoaded[$n] = true; }
                }
            }
        }

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

        // 적용된 벤더 권고(errata) 근거: 벤더가 "이 CVE 는 이 설치 빌드에서 고쳤다"고 확인한 것.
        //   changelog(핵심 13개 패키지 하드코딩)와 달리 시스템 전체를 덮는다.
        //   package_name => [cve_id => evidence(설치 NEVRA)]
        $errata = [];
        $erStmt = $pdo->prepare('SELECT package_name, cve_id, evidence FROM tb_applied_errata WHERE scan_id = ?');
        $erStmt->execute([$scanId]);
        foreach ($erStmt->fetchAll() as $r) {
            $errata[$r['package_name']][$r['cve_id']] = $r['evidence'];
        }

        // 재계산은 원자적으로(자체 트랜잭션). 스케줄러 사이드카와 동시 재매칭 시
        // DELETE↔INSERT 경합으로 유니크키 충돌이 나던 것을 방지.
        $ownTx = !$pdo->inTransaction();
        if ($ownTx) { $pdo->beginTransaction(); }
        try {

        // 기존 findings 삭제 후 재삽입. INSERT 는 멱등(동시성 대비).
        $pdo->prepare('DELETE FROM tb_findings WHERE scan_id = ?')->execute([$scanId]);
        $ins = $pdo->prepare(
            'INSERT INTO tb_findings
               (scan_id, cve_id, package_name, installed_version, loaded, exposed,
                exposure_scope, runtime_status, in_kev, needs_restart, cvss, severity, rationale)
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
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
            $mgr = (string) ($p['manager'] ?? 'dpkg');

            // pkg.name 또는 source_pkg 로 후보 CVE 수집.
            //   비교 버전은 매칭된 키에 맞춘다 — OSV 의 deb 조치안은 **소스 버전** 기준이라
            //   source_pkg 로 매칭됐으면 source_version 과 비교해야 한다(binNMU: 1.2.3-4+b1).
            $cands = [];   // cve => ['cvss'=>, 'fixed'=>, 'cmpver'=>]
            foreach ([[$p['name'], $p['version']], [$p['source_pkg'], $p['source_version'] ?: $p['version']]] as [$key, $cmpVer]) {
                if (!$key || !isset($affected[$key])) { continue; }
                foreach ($affected[$key] as $row) {
                    // 생태계 필터 — 남의 배포판 행이 이름만 같다고 붙던 것을 막는다.
                    if (!vg_eco_matches($row['eco'] ?? null, $hostEco, $family)) { continue; }

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
            $staleEv = $stale[$p['name']] ?? ($p['source_pkg'] ? ($stale[$p['source_pkg']] ?? null) : null);

            // 런타임 상태 신호 (exposures=포트, processes=실행/로드)
            $le      = $loadMap[$p['name']] ?? ($loadMap[$p['source_pkg']] ?? null);
            $running = isset($procRunning[$p['name']]) || ($p['source_pkg'] && isset($procRunning[$p['source_pkg']]));
            $pLoaded = isset($procLoaded[$p['name']]) || ($p['source_pkg'] && isset($procLoaded[$p['source_pkg']]));
            $exposed = $le !== null && ($le['scope'] ?? '') === 'EXTERNAL';
            $loaded  = $le !== null || $pLoaded;   // 리스닝 프로세스 로드 or 일반 프로세스 로드
            $scope   = $le['scope'] ?? null;

            foreach ($cands as $cveId => $cand) {
                $cvss = $cand['cvss'];
                $key = $cveId . '|' . $p['name'];
                if (isset($seen[$key])) { continue; }
                $seen[$key] = true;

                $inKev = isset($kev[$cveId]);
                [$status, $sev, $why] = vg_classify($le, $running, $pLoaded, $inKev, $p['name']);

                // 옛 라이브러리가 메모리에 상주하면 "패치됨"이라도 억제하지 않는다(재시작 전까지 취약).
                $canSuppress = ($staleEv === null);
                if ($staleEv !== null) {
                    $why .= ' · 재시작 필요(패치됐지만 옛 라이브러리 사용 중: ' . $staleEv . ')';
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

                // errata 억제: 벤더 보안권고가 이 설치 빌드에서 해당 CVE 를 고쳤다고 확인해 준 경우.
                //   버전이 낮아 보여도(백포트) 이미 패치된 것 → 실제 위험에서 제외.
                $erEv = $errata[$p['name']][$cveId]
                    ?? ($p['source_pkg'] ? ($errata[$p['source_pkg']][$cveId] ?? null) : null);
                if ($canSuppress && $erEv !== null) {
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
                if ($canSuppress && $bpEv !== null) {
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
                    $scanId, $cveId, $p['name'], $p['version'],
                    $loaded ? 1 : 0, $exposed ? 1 : 0, $scope, $status, $inKev ? 1 : 0,
                    $staleEv !== null ? 1 : 0, $cvss, $sev, $why,
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
