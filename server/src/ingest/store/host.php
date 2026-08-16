<?php
declare(strict_types=1);

/**
 * ingest/store/host.php — 저장의 첫 두 걸음: 호스트 upsert 와 직전 스냅샷 조회.
 *   host_id 를 확보하고(뒤따르는 모든 삽입이 이 값에 매달린다), 직전 스캔의 content_hash 를
 *   읽어 "이번 수집이 달라졌는가"를 판정할 재료를 준다.
 *   트랜잭션은 호출부(vg_ingest_store)가 이미 열어 뒀다 — 여기서 열지도 닫지도 않는다.
 */

/** 호스트 upsert (fqdn 유니크). LAST_INSERT_ID 트릭으로 기존 host_id 회수. */
function vg_ingest_store_host_upsert(PDO $pdo, string $fqdn, $vm, $remoteIp): int
{
    $stmt = $pdo->prepare(
        'INSERT INTO tb_host (fqdn, hostname, os_id, os_version, first_seen, last_seen, last_seen_ip)
         VALUES (:fqdn, :hn, :osid, :osver, NOW(), NOW(), :ip)
         ON DUPLICATE KEY UPDATE
            hostname     = VALUES(hostname),
            os_id        = VALUES(os_id),
            os_version   = VALUES(os_version),
            last_seen    = NOW(),
            last_seen_ip = VALUES(last_seen_ip),
            host_id      = LAST_INSERT_ID(host_id)'
    );
    $stmt->execute([
        ':fqdn'  => $fqdn,
        ':hn'    => $fqdn,
        ':osid'  => ($vm['distro_id'] ?? '') ?: null,
        ':osver' => ($vm['distro_version'] ?? '') ?: null,
        ':ip'    => $remoteIp,
    ]);
    return (int) $pdo->lastInsertId();
}

/** 직전 스캔 1행(scan_id, content_hash). 없으면 null — 첫 수집이라는 뜻이다. */
function vg_ingest_store_prev_scan(PDO $pdo, int $hostId): ?array
{
    $q = $pdo->prepare('SELECT scan_id, content_hash FROM tb_scan WHERE host_id = ? ORDER BY scan_id DESC LIMIT 1');
    $q->execute([$hostId]);
    return $q->fetch() ?: null;
}
