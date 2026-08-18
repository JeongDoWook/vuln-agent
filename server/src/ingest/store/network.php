<?php
declare(strict_types=1);

/**
 * ingest/store/network.php — 호스트가 가진 IPv4·라우팅을 각각 tb_host_address·tb_host_route 에
 *   누적한다. 자산 탐색(발견 IP)이 "이미 아는 자산인가"를 판단하는 좌변이 앞의 테이블이고,
 *   세그먼트 맵(망 구조 화면)이 대역·게이트웨이를 그리는 원천이 뒤의 테이블이다.
 *
 *   ⚠ 사라진 행은 지우지 않는다 — last_seen 이 오래된 채로 남는 것이 정답이다
 *     (소프트삭제 관례). DHCP 로 잠깐 주소가 바뀐 것과 자산이 사라진 것을 여기서 구분할 수 없다.
 *   트랜잭션은 호출부(vg_ingest_store)가 이미 열어 뒀다 — 여기서 열지도 닫지도 않는다.
 */

/**
 * 호스트 IP upsert. $addrRows = [[iface|null, ip], ...] (vg_ingest_parse_host_addresses 반환형)
 * 유니크 키 (host_id, ip) — 있으면 last_seen 만, 없으면 first_seen/last_seen 둘 다 새로.
 */
function vg_ingest_store_host_addresses(PDO $pdo, int $hostId, array $addrRows): int
{
    if ($addrRows === []) { return 0; }

    $ins = $pdo->prepare(
        'INSERT INTO tb_host_address (host_id, ip, iface, first_seen, last_seen)
              VALUES (?, ?, ?, NOW(), NOW())
         ON DUPLICATE KEY UPDATE
            iface      = VALUES(iface),
            last_seen  = NOW(),
            is_deleted = 0,
            deleted_at = NULL'
    );
    $n = 0;
    foreach ($addrRows as $r) {
        $ins->execute([$hostId, $r[1], $r[0]]);
        $n++;
    }
    return $n;
}

/**
 * 파싱된 라우팅(vg_ingest_parse_host_routes 반환형: {gateway, subnets})을 tb_host_route 에
 * 누적한다. 기본 게이트웨이는 cidr='0.0.0.0/0' 행으로, 직결 서브넷은 gateway_ip=NULL 행으로 쌓는다.
 * 유니크 키 (host_id, cidr) — 있으면 last_seen 만, 없으면 first_seen/last_seen 둘 다 새로.
 *
 * ⚠ 사라진 라우팅 행도 지우지 않는다 — tb_host_address 와 같은 소프트삭제 관례다.
 */
function vg_ingest_store_host_routes(PDO $pdo, int $hostId, array $parsedRoutes): int
{
    $rows = [];
    $gw = $parsedRoutes['gateway'] ?? null;
    if (is_array($gw) && !empty($gw['ip'])) {
        $rows[] = ['0.0.0.0/0', (string) $gw['ip'], $gw['iface'] ?? null];
    }
    foreach ((array) ($parsedRoutes['subnets'] ?? []) as $s) {
        if (empty($s['cidr'])) { continue; }
        $rows[] = [(string) $s['cidr'], null, $s['iface'] ?? null];
    }
    if ($rows === []) { return 0; }

    $ins = $pdo->prepare(
        'INSERT INTO tb_host_route (host_id, cidr, gateway_ip, iface, first_seen, last_seen)
              VALUES (?, ?, ?, ?, NOW(), NOW())
         ON DUPLICATE KEY UPDATE
            gateway_ip = VALUES(gateway_ip),
            iface      = VALUES(iface),
            last_seen  = NOW(),
            is_deleted = 0,
            deleted_at = NULL'
    );
    $n = 0;
    foreach ($rows as $r) {
        $ins->execute([$hostId, $r[0], $r[1], $r[2]]);
        $n++;
    }
    return $n;
}
