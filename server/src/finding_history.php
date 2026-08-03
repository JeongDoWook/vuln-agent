<?php
declare(strict_types=1);

/**
 * finding_history.php — 특정 (호스트, 컨테이너, CVE, 패키지) 조합의 스캔별 이력 조회.
 *   tb_finding/tb_suppressed_finding 은 스캔마다 삭제되지 않고 전부 남아있으므로
 *   새 수집·새 스키마 없이 조회만으로 타임라인을 만들 수 있다(host.php/finding_history.php 주석 참조).
 *
 *   컨테이너 주의: tb_container.container_id 는 **스캔마다 새로 생기는 행**의 PK 라, 같은 컨테이너라도
 *   스캔이 바뀌면 값이 달라진다(호스트 자신은 container_id=0 으로 고정이라 문제없음). 그래서 여기서는
 *   링크로 받은 container_id 를 그 컨테이너의 이름(cid 문자열)으로 먼저 바꾼 뒤, 스캔마다 그 이름으로
 *   다시 컨테이너 행을 찾아 finding/suppressed 를 조인한다 — 숫자 container_id 를 스캔 간에 그대로
 *   비교하면 안 된다.
 */

require_once __DIR__ . '/db.php';

/**
 * @return array<int, array{
 *   scan_id: int, collected_at: ?string, status: string,
 *   severity: ?string, version: ?string, reason: ?string
 * }>
 */
function vg_finding_history(PDO $pdo, int $hostId, int $containerId, string $cveId, string $packageName): array {
    if ($containerId > 0) {
        $st = $pdo->prepare('SELECT cid FROM tb_container WHERE container_id = ? AND is_deleted = 0');
        $st->execute([$containerId]);
        $containerCid = $st->fetchColumn();
        $containerCid = $containerCid !== false ? (string) $containerCid : null;
    } else {
        $containerCid = null;
    }

    if ($containerId > 0 && $containerCid !== null) {
        $sql = "SELECT s.scan_id, s.collected_at, c2.container_id AS resolved_container_id,
                       f.severity AS finding_severity, f.rationale AS finding_rationale,
                       f.installed_version AS finding_version,
                       sf.base_severity AS supp_severity, sf.suppress_reason AS supp_reason,
                       sf.installed_version AS supp_version,
                       (p.package_id IS NOT NULL) AS pkg_present
                  FROM tb_scan s
                  LEFT JOIN tb_container c2
                    ON c2.scan_id = s.scan_id AND c2.cid = ? AND c2.is_deleted = 0
                  LEFT JOIN tb_finding f
                    ON f.scan_id = s.scan_id AND f.container_id = c2.container_id
                   AND f.cve_id = ? AND f.package_name = ? AND f.is_deleted = 0
                  LEFT JOIN tb_suppressed_finding sf
                    ON sf.scan_id = s.scan_id AND sf.container_id = c2.container_id
                   AND sf.cve_id = ? AND sf.package_name = ? AND sf.is_deleted = 0
                  LEFT JOIN tb_package p
                    ON p.scan_id = s.scan_id AND p.container_id = c2.container_id
                   AND p.name = ? AND p.is_deleted = 0
                 WHERE s.host_id = ?
                 ORDER BY s.scan_id";
        $params = [$containerCid, $cveId, $packageName, $cveId, $packageName, $packageName, $hostId];
    } else {
        // containerId=0(호스트 자신) 이거나, 링크의 container_id 가 이미 삭제돼 이름을 못 찾은 경우.
        //   후자는 origin 스캔조차 못 맞출 수 있지만, 확신 없는 매칭을 억지로 만들지 않는다(YAGNI).
        $cid = $containerId > 0 ? $containerId : 0;
        $sql = "SELECT s.scan_id, s.collected_at, NULL AS resolved_container_id,
                       f.severity AS finding_severity, f.rationale AS finding_rationale,
                       f.installed_version AS finding_version,
                       sf.base_severity AS supp_severity, sf.suppress_reason AS supp_reason,
                       sf.installed_version AS supp_version,
                       (p.package_id IS NOT NULL) AS pkg_present
                  FROM tb_scan s
                  LEFT JOIN tb_finding f
                    ON f.scan_id = s.scan_id AND f.container_id = ?
                   AND f.cve_id = ? AND f.package_name = ? AND f.is_deleted = 0
                  LEFT JOIN tb_suppressed_finding sf
                    ON sf.scan_id = s.scan_id AND sf.container_id = ?
                   AND sf.cve_id = ? AND sf.package_name = ? AND sf.is_deleted = 0
                  LEFT JOIN tb_package p
                    ON p.scan_id = s.scan_id AND p.container_id = ?
                   AND p.name = ? AND p.is_deleted = 0
                 WHERE s.host_id = ?
                 ORDER BY s.scan_id";
        $params = [$cid, $cveId, $packageName, $cid, $cveId, $packageName, $cid, $packageName, $hostId];
    }

    $st = $pdo->prepare($sql);
    $st->execute($params);

    $rows = [];
    foreach ($st->fetchAll() as $r) {
        if ($r['finding_severity'] !== null) {
            $status   = 'FOUND';
            $severity = (string) $r['finding_severity'];
            $version  = $r['finding_version'];
            $reason   = $r['finding_rationale'];
        } elseif ($r['supp_severity'] !== null) {
            $status   = 'SUPPRESSED';
            $severity = (string) $r['supp_severity'];
            $version  = $r['supp_version'];
            $reason   = $r['supp_reason'];
        } elseif ($containerId > 0 && $r['resolved_container_id'] === null) {
            $status   = 'NO_CONTAINER';
            $severity = null;
            $version  = null;
            $reason   = null;
        } elseif ((int) $r['pkg_present'] === 1) {
            $status   = 'PACKAGE_ONLY';
            $severity = null;
            $version  = null;
            $reason   = null;
        } else {
            $status   = 'NONE';
            $severity = null;
            $version  = null;
            $reason   = null;
        }

        $rows[] = [
            'scan_id'      => (int) $r['scan_id'],
            'collected_at' => $r['collected_at'],
            'status'       => $status,
            'severity'     => $severity,
            'version'      => $version,
            'reason'       => $reason,
        ];
    }

    return $rows;
}
