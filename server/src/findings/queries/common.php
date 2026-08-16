<?php
declare(strict_types=1);

/**
 * findings/queries/common.php — 세 탭이 공유하는 것만: 대상 집합과 탭 머리 건수.
 *   대상 스캔 집합(호스트별 최신 스캔)은 어느 탭이든 첫 재료이고, 탭 머리 뱃지는 지금 탭이
 *   아닌 유형까지 세야 하므로 특정 탭에 둘 수 없다. 탭 고유 조회는 옆 파일들이 갖는다.
 */

/** 호스트별 최신 스캔 (삭제된 호스트 제외) — 통합 뷰의 대상 스캔 집합. */
function vg_findings_load_hosts(PDO $pdo): array {
    return $pdo->query(
        'SELECT h.host_id, h.fqdn, h.os_id, h.os_version, t.mid AS scan_id
           FROM tb_host h
           JOIN ' . vg_latest_scan_subq() . ' t ON t.host_id = h.host_id
          WHERE h.is_deleted = 0
          ORDER BY h.last_seen DESC, h.fqdn'
    )->fetchAll();
}

/**
 * 최신 스캔에 딸린 컨테이너 — "판정 불가" 경고의 대상이다.
 *   CVE 탭 전용이라 다른 탭에서는 호출하지 않는다(안 쓰는 집계를 매 요청에 붙이지 않는다).
 */
function vg_findings_load_containers(PDO $pdo): array {
    return $pdo->query(
        'SELECT h.fqdn, c.cid, c.os_id, c.os_version, c.manager,
                CASE WHEN EXISTS (
                    SELECT 1 FROM tb_package p
                     WHERE p.scan_id = c.scan_id AND p.container_id = c.container_id
                ) THEN 1 ELSE c.pkg_count END AS pkg_count
           FROM tb_container c
           JOIN tb_scan s ON s.scan_id = c.scan_id
           JOIN tb_host h ON h.host_id = s.host_id
           JOIN ' . vg_latest_scan_subq() . ' t ON t.mid = s.scan_id
          WHERE h.is_deleted = 0
          ORDER BY h.fqdn, c.cid'
    )->fetchAll();
}

/**
 * 지금 탭이 아닌 유형의 건수 — 탭 머리에 붙는 요약이다. 각각 인덱스 선두(scan_id) 범위
 *   COUNT 하나뿐이라 값싸다(현재 탭 것은 이미 집계됐으므로 null 이 아니면 다시 세지 않는다).
 */
function vg_findings_type_counts(PDO $pdo, array $scanIds, array $typeCounts): array {
    $in = implode(',', array_fill(0, count($scanIds), '?'));
    if ($typeCounts['cve'] === null) {
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM tb_finding WHERE scan_id IN ($in)");
        $stmt->execute($scanIds);
        $typeCounts['cve'] = (int) $stmt->fetchColumn();
    }
    if ($typeCounts['cce'] === null) {
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM tb_cce_finding WHERE scan_id IN ($in) AND result = 'FAIL'");
        $stmt->execute($scanIds);
        $typeCounts['cce'] = (int) $stmt->fetchColumn();
    }
    if ($typeCounts['exposure'] === null) {
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM tb_exposure WHERE scan_id IN ($in)");
        $stmt->execute($scanIds);
        $typeCounts['exposure'] = (int) $stmt->fetchColumn();
    }
    return $typeCounts;
}
