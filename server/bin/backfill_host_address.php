<?php
declare(strict_types=1);

// PHP 한도는 **반드시 이 프로세스가 도는 컨테이너의 mem_limit 보다 낮아야** 한다 — 높으면
//   PHP 가 자기 한도에 닿기 전에 cgroup 이 SIGKILL 해서 잡히는 오류 없이 즉사한다
//   (bin/sync.php 상단 주석의 2026-07 스케줄러 실측). 이 스크립트도 web 컨테이너에서
//   돌므로(mem_limit 768m) sync.php 와 같은 512M 으로 맞춘다. raw_json 은 호스트당
//   한 건씩만 읽고 바로 버려서 실제 사용량은 이보다 훨씬 낮다.
ini_set('memory_limit', '512M');

/**
 * backfill_host_address.php — 기존 스캔의 raw_json 에서 호스트 IPv4 를 뽑아 tb_host_address 를 채운다.
 *
 *   에이전트는 예전부터 `ip -o addr` / `ifconfig -a` 원문을 보내 왔지만, 그 값은 tb_scan.raw_json
 *   안에만 있고 어떤 테이블로도 파싱되지 않았다. 지금부터 들어오는 수집은 ingest.php 가 저장하지만,
 *   **이미 수집된 자산은 백필하지 않으면 IP 가 없어 전부 "매칭 안 됨"(= 섀도우 IT)으로 뜬다.**
 *
 *   호스트별 **최신 스캔 1건**만 본다 — 옛 스캔의 옛 IP 를 되살릴 이유가 없다.
 *   저장은 ingest 와 같은 upsert(vg_ingest_store_host_addresses)를 쓰므로 몇 번을 돌려도 멱등하고,
 *   중단되면 마지막에 출력된 --start-host-id 로 이어서 실행하면 된다.
 *
 *   사용:
 *     php bin/backfill_host_address.php                    # 전체
 *     php bin/backfill_host_address.php --start-host-id=42 # 중단 지점부터 재개
 *     php bin/backfill_host_address.php --limit=10         # 앞 10개 호스트만(시험용)
 *     php bin/backfill_host_address.php --dry-run          # 저장 없이 파싱 결과만 출력
 *
 *   종료코드: 0 정상 / 1 내부오류 / 2 인자오류
 */

require __DIR__ . '/../src/db.php';
require __DIR__ . '/../src/ingest_parse.php';            // vg_ingest_parse_host_addresses
require __DIR__ . '/../src/ingest/store/network.php';    // vg_ingest_store_host_addresses

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
        "호스트 IP 백필 시작. 대상 %d개 호스트 (host_id >= %d)%s\n",
        $total, $startHostId, $dryRun ? ' · 예행연습(저장 안 함)' : ''
    ));
    if ($total === 0) { exit(0); }

    // 호스트별 최신 스캔 1건의 raw_json.
    $scanQ = $pdo->prepare(
        'SELECT scan_id, raw_json FROM tb_scan WHERE host_id = ? ORDER BY scan_id DESC LIMIT 1'
    );

    $done = 0; $withIp = 0; $rowsTotal = 0; $noScan = 0; $noIface = 0; $lastId = $startHostId;
    $t0 = time();

    foreach ($hosts as $h) {
        $hostId = (int) $h['host_id'];
        $lastId = $hostId;
        $done++;

        $scanQ->execute([$hostId]);
        $scan = $scanQ->fetch();
        if (!$scan || (string) $scan['raw_json'] === '') {
            $noScan++;
        } else {
            $data = json_decode((string) $scan['raw_json'], true);
            $iface = is_array($data) ? (string) ($data['net']['interfaces'] ?? '') : '';
            $rows  = $iface !== '' ? vg_ingest_parse_host_addresses($iface) : [];
            if ($rows === []) {
                $noIface++;
            } else {
                if (!$dryRun) {
                    $pdo->beginTransaction();
                    vg_ingest_store_host_addresses($pdo, $hostId, $rows);
                    $pdo->commit();
                }
                $withIp++;
                $rowsTotal += count($rows);
                fwrite(STDOUT, sprintf(
                    "  [%d/%d] host_id=%d %s → %s\n",
                    $done, $total, $hostId, (string) $h['fqdn'],
                    implode(', ', array_map(static fn($r) => ($r[0] ?? '?') . '=' . $r[1], $rows))
                ));
            }
            unset($data, $scan);   // raw_json 은 수십 MB 도 된다 — 호스트마다 바로 놓는다
        }

        if ($done % 50 === 0) {
            fwrite(STDOUT, sprintf(
                "  … %d/%d 처리 · IP 확보 %d호스트 %d행 · %d초 · 메모리 %.0fMB\n",
                $done, $total, $withIp, $rowsTotal, max(1, time() - $t0), memory_get_usage(true) / 1048576
            ));
        }
    }

    fwrite(STDOUT, sprintf(
        "완료. 호스트 %d개 처리 · IP 확보 %d개(%d행) · 스캔없음 %d · IP미확인 %d · %d초\n",
        $done, $withIp, $rowsTotal, $noScan, $noIface, max(1, time() - $t0)
    ));
    exit(0);
} catch (Throwable $e) {
    if (isset($pdo) && $pdo->inTransaction()) { $pdo->rollBack(); }
    fwrite(STDERR, '실패: ' . $e->getMessage() . "\n");
    fwrite(STDERR, sprintf("재개하려면: php bin/backfill_host_address.php --start-host-id=%d\n", $lastId ?? $startHostId));
    exit(1);
}
