<?php
declare(strict_types=1);

/**
 * matcher.php — 수집된 packages + exposures 를 CVE 와 조인해 우선순위를 매긴다.
 *   규칙(CONTEXT §7): 외부노출(EXTERNAL) + 로드됨 + KEV = CRITICAL.
 *   설치만 됨 → LOW, 로드·내부 → MEDIUM, 외부노출 → HIGH, +KEV 시 한 단계 상향.
 *   각 판정에 "왜"(근거)를 남긴다(설명가능성).
 */

require_once __DIR__ . '/db.php';

if (!function_exists('vg_scope_rank')) {
    // 노출 범위 위험도 (클수록 위험)
    function vg_scope_rank(?string $s): int {
        switch ($s) {
            case 'EXTERNAL': return 3;
            case 'BOUND':    return 2;
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
        // 패키지
        $stmt = $pdo->prepare('SELECT name, source_pkg, version FROM tb_packages WHERE scan_id = ?');
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

        // 영향 패키지 인덱스: package_name => [cve_id => cvss]
        $affected = [];
        $capStmt = $pdo->query(
            'SELECT a.cve_id, a.package_name, c.cvss
             FROM tb_cve_affected_packages a
             LEFT JOIN tb_cves c ON c.cve_id = a.cve_id'
        );
        foreach ($capStmt->fetchAll() as $r) {
            $affected[$r['package_name']][$r['cve_id']] = $r['cvss'];
        }

        // 백포트 근거: 패키지 changelog 에 명시된 CVE(=그 빌드에 이미 수정됨).
        //   package_name => [cve_id => evidence(changelog 줄)]
        $backport = [];
        $bpStmt = $pdo->prepare('SELECT package_name, cve_id, evidence FROM tb_pkg_changelog_cves WHERE scan_id = ?');
        $bpStmt->execute([$scanId]);
        foreach ($bpStmt->fetchAll() as $r) {
            $backport[$r['package_name']][$r['cve_id']] = $r['evidence'];
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
                exposure_scope, runtime_status, in_kev, cvss, severity, rationale)
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
             ON DUPLICATE KEY UPDATE
               installed_version=VALUES(installed_version), loaded=VALUES(loaded),
               exposed=VALUES(exposed), exposure_scope=VALUES(exposure_scope),
               runtime_status=VALUES(runtime_status), in_kev=VALUES(in_kev), cvss=VALUES(cvss),
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
            // pkg.name 또는 source_pkg 로 후보 CVE 수집
            $cands = [];
            foreach ([$p['name'], $p['source_pkg']] as $key) {
                if ($key && isset($affected[$key])) {
                    foreach ($affected[$key] as $cve => $cvss) {
                        $cands[$cve] = $cvss;
                    }
                }
            }
            if (!$cands) {
                continue;
            }

            // 런타임 상태 신호 (exposures=포트, processes=실행/로드)
            $le      = $loadMap[$p['name']] ?? ($loadMap[$p['source_pkg']] ?? null);
            $running = isset($procRunning[$p['name']]) || ($p['source_pkg'] && isset($procRunning[$p['source_pkg']]));
            $pLoaded = isset($procLoaded[$p['name']]) || ($p['source_pkg'] && isset($procLoaded[$p['source_pkg']]));
            $exposed = $le !== null && ($le['scope'] ?? '') === 'EXTERNAL';
            $loaded  = $le !== null || $pLoaded;   // 리스닝 프로세스 로드 or 일반 프로세스 로드
            $scope   = $le['scope'] ?? null;

            foreach ($cands as $cveId => $cvss) {
                $key = $cveId . '|' . $p['name'];
                if (isset($seen[$key])) { continue; }
                $seen[$key] = true;

                $inKev = isset($kev[$cveId]);
                [$status, $sev, $why] = vg_classify($le, $running, $pLoaded, $inKev, $p['name']);

                // 백포트 억제: 이 빌드의 changelog 에 해당 CVE 수정 기록이 있으면
                //   버전이 낮아 보여도 이미 패치된 것 → 실제 위험에서 제외(오탐 제거).
                $bpEv = $backport[$p['name']][$cveId]
                    ?? ($p['source_pkg'] ? ($backport[$p['source_pkg']][$cveId] ?? null) : null);
                if ($bpEv !== null) {
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
                    $cvss, $sev, $why,
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
