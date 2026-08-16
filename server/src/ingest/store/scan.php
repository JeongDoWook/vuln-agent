<?php
declare(strict_types=1);

/**
 * ingest/store/scan.php — 스캔 스냅샷(tb_scan)과 실행 기록(tb_scan_run·tb_collection_stage).
 *
 *   내용이 같으면 새 스냅샷을 만들지 않고 기존 행의 수집시각·실행 자원값만 갱신한다
 *   (vg_ingest_store_scan_touch). 달라졌을 때만 새 행을 만든다(vg_ingest_store_scan_insert).
 *   반면 "실행했다는 사실"(tb_scan_run)과 수집기 완전성(tb_collection_stage)은 스냅샷
 *   재사용 여부와 무관하게 항상 남는다 — 그래서 두 분기 밖에서 호출된다.
 */

/**
 * 동일 스냅샷 재전송 — 새 행을 만들지 않고 수집시각과 이번 실행의 자원값만 덮어쓴다.
 *   호스트 생존 신호는 tb_host.last_seen 이 이미 갱신했으므로 잃는 정보가 없다.
 *   그 결과 스캔 목록 자체가 "변경 시점" 목록이 된다(changes.php 의 비교도 더 정확해진다).
 */
function vg_ingest_store_scan_touch(PDO $pdo, int $scanId, $collectedAt, $meta): void
{
    $pdo->prepare(
        'UPDATE tb_scan SET collected_at = :ca, agent_version = :av, schedule = :sch,
                                 elapsed_seconds = :el,
                                 peak_rss_mb = :pk, cpu_seconds = :cpu,
                                 mem_total_mb = :mem, cpu_cores = :cores WHERE scan_id = :sid'
    )->execute([
        ':ca' => $collectedAt,
        ':av' => ($meta['agent_version'] ?? '') ?: null,
        ':sch' => ($meta['schedule'] ?? '') ?: null,
        ':el' => isset($meta['elapsed_seconds']) ? (int) $meta['elapsed_seconds'] : null,
        ':pk' => isset($meta['peak_rss_mb']) ? (float) $meta['peak_rss_mb'] : null,
        ':cpu' => isset($meta['cpu_seconds']) ? (float) $meta['cpu_seconds'] : null,
        ':mem' => isset($meta['mem_total_mb']) ? (float) $meta['mem_total_mb'] : null,
        ':cores' => isset($meta['nproc']) ? (int) $meta['nproc'] : null,
        ':sid' => $scanId,
    ]);
}

/** 새 스냅샷 1행. 반환값 scan_id 에 이후의 모든 벌크 삽입이 매달린다. */
function vg_ingest_store_scan_insert(
    PDO $pdo,
    int $hostId,
    $collectedAt,
    $meta,
    $vm,
    $sys,
    string $runningKernel,
    string $kernelLatest,
    $kernelReboot,
    string $contentHash,
    int $pkgCount,
    int $expCount,
    string $raw
): int {
    $stmt = $pdo->prepare(
        'INSERT INTO tb_scan
            (host_id, collected_at, agent_version, schedule, elapsed_seconds, peak_rss_mb, cpu_seconds,
             mem_total_mb, cpu_cores,
             os_id, os_version, kernel, running_kernel, kernel_latest, kernel_reboot_needed,
             cpe, package_family, content_hash,
             package_count, exposure_count, raw_json)
         VALUES
            (:h, :ca, :av, :sch, :el, :pk, :cpu, :mem, :cores, :osid, :osver, :kern, :rk, :kl, :krn, :cpe, :fam, :hash, :pc, :ec, :raw)'
    );
    $stmt->execute([
        ':h'     => $hostId,
        ':ca'    => $collectedAt,
        ':av'    => ($meta['agent_version'] ?? '') ?: null,
        ':sch'   => ($meta['schedule'] ?? '') ?: null,
        ':el'    => isset($meta['elapsed_seconds']) ? (int) $meta['elapsed_seconds'] : null,
        ':pk'    => isset($meta['peak_rss_mb']) ? (float) $meta['peak_rss_mb'] : null,
        ':cpu'   => isset($meta['cpu_seconds']) ? (float) $meta['cpu_seconds'] : null,
        ':mem'   => isset($meta['mem_total_mb']) ? (float) $meta['mem_total_mb'] : null,
        ':cores' => isset($meta['nproc']) ? (int) $meta['nproc'] : null,
        ':osid'  => ($vm['distro_id'] ?? '') ?: null,
        ':osver' => ($vm['distro_version'] ?? '') ?: null,
        ':kern'  => ($sys['kernel_release'] ?? ($sys['kernel'] ?? '')) ?: null,
        ':rk'    => $runningKernel ?: null,
        ':kl'    => $kernelLatest ?: null,
        ':krn'   => $kernelReboot,
        ':cpe'   => ($vm['cpe_name'] ?? '') ?: null,
        ':fam'   => ($vm['package_family'] ?? '') ?: null,
        ':hash'  => $contentHash,
        ':pc'    => $pkgCount,
        ':ec'    => $expCount,
        ':raw'   => $raw,
    ]);
    return (int) $pdo->lastInsertId();
}

/** 동일 스냅샷 재전송이어도 수집기 완전성은 최신 상태로 갱신한다. */
function vg_ingest_store_stages(PDO $pdo, int $scanId, array $collectionStages): void
{
    $stage = $pdo->prepare('INSERT INTO tb_collection_stage (scan_id,stage_code,status,item_count) VALUES (?,?,?,?) ON DUPLICATE KEY UPDATE status=VALUES(status),item_count=VALUES(item_count),created_at=NOW()');
    foreach ($collectionStages as $r) { $stage->execute([$scanId, $r[0], $r[1], $r[2]]); }
}

/** 수집 결과가 같아 기존 스냅샷을 재사용하더라도 실행 사실과 실행별 자원값은 항상 남긴다. */
function vg_ingest_store_scan_run(
    PDO $pdo,
    int $hostId,
    int $scanId,
    $collectedAt,
    bool $unchanged,
    int $pkgCount,
    int $expCount,
    $meta
): void {
    $pdo->prepare(
        'INSERT INTO tb_scan_run
            (host_id, scan_id, collected_at, content_changed, package_count, exposure_count,
             agent_version, schedule, elapsed_seconds, peak_rss_mb, cpu_seconds, mem_total_mb, cpu_cores)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
    )->execute([
        $hostId, $scanId, $collectedAt, $unchanged ? 0 : 1, $pkgCount, $expCount,
        ($meta['agent_version'] ?? '') ?: null,
        ($meta['schedule'] ?? '') ?: null,
        isset($meta['elapsed_seconds']) ? (int) $meta['elapsed_seconds'] : null,
        isset($meta['peak_rss_mb']) ? (float) $meta['peak_rss_mb'] : null,
        isset($meta['cpu_seconds']) ? (float) $meta['cpu_seconds'] : null,
        isset($meta['mem_total_mb']) ? (float) $meta['mem_total_mb'] : null,
        isset($meta['nproc']) ? (int) $meta['nproc'] : null,
    ]);
}
