<?php
declare(strict_types=1);

// PHP 한도는 **반드시 이 프로세스가 도는 컨테이너의 mem_limit 보다 낮아야** 한다 — 높으면
//   PHP 가 자기 한도에 닿기 전에 cgroup 이 SIGKILL 해서 잡히는 오류 없이 즉사한다
//   (bin/sync.php 상단 주석의 2026-07 스케줄러 실측). 이 스크립트도 web 컨테이너에서
//   돌므로(mem_limit 768m) sync.php·backfill_host_address.php 와 같은 512M 으로 맞춘다. raw_json 은
//   호스트당 한 건씩만 읽고 바로 버려서 실제 사용량은 이보다 훨씬 낮다.
ini_set('memory_limit', '512M');

/**
 * backfill_host_route.php — 기존 스캔의 raw_json 에서 라우팅(net.routes)을 뽑아
 *   tb_host_route 를 채운다. 세그먼트 맵(망 구조 화면)이 대역·게이트웨이를 그리는 원천이다.
 *
 *   에이전트는 예전부터 `ip route`(없으면 `route -n`) 원문을 보내 왔지만, 그 값은
 *   tb_scan.raw_json 안에만 있고 어떤 테이블로도 파싱되지 않았다. 지금부터 들어오는 수집은
 *   ingest.php 가 저장하지만, **이미 수집된 자산은 백필하지 않으면 라우팅이 없어 세그먼트
 *   맵에서 대역을 못 찾는다.**
 *
 *   호스트별 **최신 스캔 1건**만 본다 — 옛 스캔의 옛 라우팅을 되살릴 이유가 없다.
 *   저장은 ingest 와 같은 upsert(vg_ingest_store_host_routes)를 쓰므로 몇 번을 돌려도 멱등하고,
 *   중단되면 마지막에 출력된 --start-host-id 로 이어서 실행하면 된다.
 *
 *   ⚠ backfill_host_address.php 가 겪은 실패를 반복하지 않는다: 호스트별 최신 스캔의
 *     raw_json 을 **정렬 쿼리에 얹지 않는다**(운영에서 `1038 Out of sort memory` 로 즉사했다,
 *     #653). ① 정렬에는 작은 컬럼(scan_id)만 올리고 ② 큰 컬럼은 그 한 건을 PK 로 따로 읽는다.
 *
 *   사용:
 *     php bin/backfill_host_route.php                    # 전체
 *     php bin/backfill_host_route.php --start-host-id=42  # 중단 지점부터 재개
 *     php bin/backfill_host_route.php --limit=10          # 앞 10개 호스트만(시험용)
 *     php bin/backfill_host_route.php --dry-run           # 저장 없이 파싱 결과만 출력
 *
 *   종료코드: 0 정상 / 1 내부오류 / 2 인자오류
 */

require __DIR__ . '/../src/db.php';
require __DIR__ . '/../src/ingest_parse.php';            // vg_ingest_parse_host_routes
require __DIR__ . '/../src/ingest/store/network.php';    // vg_ingest_store_host_routes

// ─── 인자 파싱 ──────────────────────────────────────────────────────────
$opts = getopt('', ['start-host-id::', 'limit::', 'dry-run']);
if ($opts === false) {
    fwrite(STDERR, "인자를 해석하지 못했습니다. 사용법은 파일 상단 주석 참고.\n");
    exit(2);
}
foreach (array_slice($argv, 1) as $a) {
    if (!preg_match('/^--(start-host-id=\d+|limit=\d+|dry-run)$/', $a)) {
        fwrite(STDERR, "알 수 없는 인자: {$a}\n");
        exit(2);
    }
}
$startHostId = max(0, (int) ($opts['start-host-id'] ?? 0));
$limit       = isset($opts['limit']) ? max(1, (int) $opts['limit']) : 0;   // 0 = 제한 없음
$dryRun      = array_key_exists('dry-run', $opts);

try {
    $pdo = vg_pdo();

    // 대상 호스트 목록만 먼저 뽑는다(raw_json 은 여기서 안 읽는다 — 다 들고 있으면 메모리가 터진다).
    $sql = 'SELECT host_id, fqdn FROM tb_host WHERE host_id >= ? AND is_deleted = 0 ORDER BY host_id';
    if ($limit > 0) { $sql .= ' LIMIT ' . $limit; }   // 정수 캐스팅된 값 — LIMIT 은 바인딩 불가
    $q = $pdo->prepare($sql);
    $q->execute([$startHostId]);
    $hosts = $q->fetchAll();

    $total = count($hosts);
    fwrite(STDOUT, sprintf(
        "호스트 라우팅 백필 시작. 대상 %d개 호스트 (host_id >= %d)%s\n",
        $total, $startHostId, $dryRun ? ' · 예행연습(저장 안 함)' : ''
    ));
    if ($total === 0) { exit(0); }

    // 호스트별 최신 스캔 1건의 raw_json — **두 단계로 나눠 읽는다**(위 주석 참고).
    $scanIdQ = $pdo->prepare(
        'SELECT scan_id FROM tb_scan WHERE host_id = ? ORDER BY scan_id DESC LIMIT 1'
    );
    $rawQ = $pdo->prepare(
        'SELECT raw_json FROM tb_scan WHERE scan_id = ?'
    );

    $done = 0; $withGw = 0; $withSubnet = 0; $rowsTotal = 0; $noScan = 0; $noRoute = 0;
    $lastId = $startHostId;
    $t0 = time();

    foreach ($hosts as $h) {
        $hostId = (int) $h['host_id'];
        $lastId = $hostId;
        $done++;

        $scanIdQ->execute([$hostId]);
        $scanId = $scanIdQ->fetchColumn();
        $raw = '';
        if ($scanId !== false) {
            $rawQ->execute([(int) $scanId]);
            $raw = (string) ($rawQ->fetchColumn() ?: '');
            $rawQ->closeCursor();   // 버퍼된 결과에 raw_json 이 그대로 남는다 — 바로 놓는다
        }
        if ($raw === '') {
            $noScan++;
        } else {
            $data = json_decode($raw, true);
            $routeText = is_array($data) ? (string) ($data['net']['routes'] ?? '') : '';
            $parsed = $routeText !== '' ? vg_ingest_parse_host_routes($routeText) : ['gateway' => null, 'subnets' => []];
            $rowCount = (int) ($parsed['gateway'] !== null) + count($parsed['subnets']);

            if ($rowCount === 0) {
                $noRoute++;
            } else {
                if (!$dryRun) {
                    $pdo->beginTransaction();
                    vg_ingest_store_host_routes($pdo, $hostId, $parsed);
                    $pdo->commit();
                }
                if ($parsed['gateway'] !== null) { $withGw++; }
                if ($parsed['subnets'] !== []) { $withSubnet++; }
                $rowsTotal += $rowCount;
                fwrite(STDOUT, sprintf(
                    "  [%d/%d] host_id=%d %s → gw=%s 서브넷=%s\n",
                    $done, $total, $hostId, (string) $h['fqdn'],
                    $parsed['gateway'] !== null ? $parsed['gateway']['ip'] : '없음',
                    implode(',', array_column($parsed['subnets'], 'cidr')) ?: '없음'
                ));
            }
            unset($data, $raw);   // raw_json 은 수십 MB 도 된다 — 호스트마다 바로 놓는다
        }

        if ($done % 50 === 0) {
            fwrite(STDOUT, sprintf(
                "  … %d/%d 처리 · 게이트웨이 확보 %d · 서브넷 확보 %d · %d행 · %d초 · 메모리 %.0fMB\n",
                $done, $total, $withGw, $withSubnet, $rowsTotal, max(1, time() - $t0), memory_get_usage(true) / 1048576
            ));
        }
    }

    fwrite(STDOUT, sprintf(
        "완료. 호스트 %d개 처리 · 게이트웨이 확보 %d · 서브넷 확보 %d(%d행) · 스캔없음 %d · 라우팅없음 %d · %d초\n",
        $done, $withGw, $withSubnet, $rowsTotal, $noScan, $noRoute, max(1, time() - $t0)
    ));
    exit(0);
} catch (Throwable $e) {
    if (isset($pdo) && $pdo->inTransaction()) { $pdo->rollBack(); }
    fwrite(STDERR, '실패: ' . $e->getMessage() . "\n");
    fwrite(STDERR, sprintf("재개하려면: php bin/backfill_host_route.php --start-host-id=%d\n", $lastId ?? $startHostId));
    exit(1);
}
