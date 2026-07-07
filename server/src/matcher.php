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

    // 등급 + 근거 계산 (레벨: 설치1 / 로드2 / 외부노출3, KEV 시 +1, 최대 CRITICAL)
    function vg_severity(bool $loaded, ?string $scope, bool $exposed, bool $inKev, ?array $load, string $pkg): array {
        $level = 1;
        if ($exposed) {
            $level = 3;
            $base = sprintf('외부노출(%s:%d 가 %s 로드)', $load['proc'] ?? '?', $load['port'] ?? 0, $pkg);
        } elseif ($loaded) {
            $level = 2;
            $base = sprintf('로드됨·내부(%s, scope=%s)', $load['proc'] ?? '?', $scope ?? '-');
        } else {
            $base = '설치만 됨(로드 프로세스 없음)';
        }
        if ($inKev && $level < 4) {
            $level++;
        }
        $map = [1 => 'LOW', 2 => 'MEDIUM', 3 => 'HIGH', 4 => 'CRITICAL'];
        $sev = $map[$level];
        $why = $base . ($inKev ? ' · CISA KEV 등재' : '') . ' → ' . $sev;
        return [$sev, $why];
    }

    /**
     * 한 스캔에 대해 매칭 수행 → findings 재계산. 반환: 등급별 카운트.
     */
    function vg_match_scan(PDO $pdo, int $scanId): array {
        // 패키지
        $stmt = $pdo->prepare('SELECT name, source_pkg, version FROM packages WHERE scan_id = ?');
        $stmt->execute([$scanId]);
        $packages = $stmt->fetchAll();

        // 노출 → 패키지별 최악(worst) 로드 상태 맵
        $stmt = $pdo->prepare('SELECT proc, port, scope, exe_pkg, loaded_pkgs FROM exposures WHERE scan_id = ?');
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

        // KEV 집합
        $kev = [];
        foreach ($pdo->query('SELECT cve_id FROM kev_catalog')->fetchAll() as $r) {
            $kev[$r['cve_id']] = true;
        }

        // 영향 패키지 인덱스: package_name => [cve_id => cvss]
        $affected = [];
        $capStmt = $pdo->query(
            'SELECT a.cve_id, a.package_name, c.cvss
             FROM cve_affected_packages a
             LEFT JOIN cves c ON c.cve_id = a.cve_id'
        );
        foreach ($capStmt->fetchAll() as $r) {
            $affected[$r['package_name']][$r['cve_id']] = $r['cvss'];
        }

        // 재계산: 기존 findings 삭제 후 재삽입
        $pdo->prepare('DELETE FROM findings WHERE scan_id = ?')->execute([$scanId]);
        $ins = $pdo->prepare(
            'INSERT INTO findings
               (scan_id, cve_id, package_name, installed_version, loaded, exposed,
                exposure_scope, in_kev, cvss, severity, rationale)
             VALUES (?,?,?,?,?,?,?,?,?,?,?)'
        );

        $counts = ['CRITICAL' => 0, 'HIGH' => 0, 'MEDIUM' => 0, 'LOW' => 0];
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

            // 로드 상태
            $load    = $loadMap[$p['name']] ?? ($loadMap[$p['source_pkg']] ?? null);
            $loaded  = $load !== null;
            $scope   = $load['scope'] ?? null;
            $exposed = $loaded && $scope === 'EXTERNAL';

            foreach ($cands as $cveId => $cvss) {
                $key = $cveId . '|' . $p['name'];
                if (isset($seen[$key])) { continue; }
                $seen[$key] = true;

                $inKev = isset($kev[$cveId]);
                [$sev, $why] = vg_severity($loaded, $scope, $exposed, $inKev, $load, $p['name']);
                $counts[$sev]++;

                $ins->execute([
                    $scanId, $cveId, $p['name'], $p['version'],
                    $loaded ? 1 : 0, $exposed ? 1 : 0, $scope, $inKev ? 1 : 0,
                    $cvss, $sev, $why,
                ]);
            }
        }
        return $counts;
    }
}
