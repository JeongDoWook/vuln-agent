<?php
declare(strict_types=1);

require_once __DIR__ . '/../src/schedule.php';

$healthFile = getenv('SCHEDULER_HEALTH_FILE') ?: '/tmp/vulnagent-scheduler-health.json';
$staleSeconds = max(1, (int) (getenv('SCHEDULER_STALE_SECONDS') ?: 600));

$readHealth = static function () use ($healthFile): array {
    $raw = @file_get_contents($healthFile);
    if ($raw === false) { return []; }
    $decoded = json_decode($raw, true);
    return is_array($decoded) ? $decoded : [];
};
$writeHealth = static function (array $state) use ($healthFile): void {
    $tmp = $healthFile . '.tmp.' . getmypid();
    $json = json_encode($state, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    if ($json === false || @file_put_contents($tmp, $json . "\n", LOCK_EX) === false || !@rename($tmp, $healthFile)) {
        @unlink($tmp);
        throw new RuntimeException('scheduler health state 기록 실패: ' . $healthFile);
    }
};

// Compose healthcheck/운영자가 같은 JSON 판정을 소비한다. DB나 connector 코드는 로드하지 않는다.
if (($argv[1] ?? '') === '--health') {
    $state = $readHealth();
    $health = vg_scheduler_health_status($state, null, $staleSeconds);
    fwrite(STDOUT, json_encode($state + $health, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n");
    exit($health['healthy'] ? 0 : 1);
}

// SIGKILL/OOM cannot run the shutdown handler. The long-lived Compose shell calls
// this command after wait(2) reports a non-zero child exit, before starting another tick.
if (($argv[1] ?? '') === '--record-exit') {
    $exitCode = isset($argv[2]) ? (int) $argv[2] : 0;
    if ($exitCode <= 0) {
        fwrite(STDERR, "--record-exit requires a positive exit code\n");
        exit(2);
    }
    $writeHealth(vg_scheduler_record_exit($readHealth(), $exitCode));
    exit(0);
}

$state = $readHealth();
$state['last_started_at'] = date(DATE_ATOM);
$state['running'] = true;
$state['last_message'] = 'scheduler tick started';
$writeHealth($state);

$finished = false;
$finish = static function (bool $success, string $message) use (&$finished, &$state, $writeHealth): void {
    $now = date(DATE_ATOM);
    $state['running'] = false;
    $state['last_message'] = $message;
    if ($success) {
        $state['last_success_at'] = $now;
    } else {
        $state['last_failure_at'] = $now;
        $state['last_failure_message'] = $message;
    }
    $writeHealth($state);
    $finished = true;
};
register_shutdown_function(static function () use (&$finished, &$state, $writeHealth): void {
    if ($finished) { return; }
    $error = error_get_last();
    $message = $error ? ($error['message'] . ' at ' . basename($error['file']) . ':' . $error['line']) : 'scheduler tick terminated unexpectedly';
    $state['running'] = false;
    $state['last_message'] = $message;
    $state['last_failure_at'] = date(DATE_ATOM);
    $state['last_failure_message'] = $message;
    try { $writeHealth($state); } catch (Throwable $ignored) { error_log($ignored->getMessage()); }
});

// PHP 한도는 **반드시 이 프로세스가 도는 컨테이너의 mem_limit 보다 낮아야** 한다.
//   여기는 scheduler 컨테이너(deploy/compose.common.yml: mem_limit 1g) → 768M.
//   높으면(예전: PHP 1024M vs 컨테이너 384m) PHP 가 자기 한도에 닿기 전에 cgroup 이 SIGKILL 하고,
//   그러면 잡히는 PHP 오류가 없어 vg_feed_run() 의 catch 가 못 돈다 → 로그가 'running' 으로 굳고
//   6시간 뒤 vg_feed_reap_stale() 이 마감한 것만 화면에 error 로 보인다.
//   실측(2026-07): RHEL OVAL(52만 행 + 대용량 XML)은 384m 한도에서 schedule 실행이 실패하고
//   `docker inspect vulnagent-scheduler` 가 Memory=402653184(384m)·OOMKilled=true 를 보인다.
//   같은 커넥터가 web 컨테이너(768m)에서 도는 수동 실행에서는 매번 성공했다 — 피크는 384M~768M 사이.
//   compose.common.yml 의 scheduler mem_limit 을 내리면 이 값도 함께 내려야 한다(짝).
ini_set('memory_limit', '768M');

/**
 * scheduler.php — 예약된(enabled + due) 피드 커넥터를 실행한다.
 *   스케줄러 사이드카 컨테이너가 1분마다 호출(compose.yml).
 *   피드가 실제로 뭔가를 수집했으면 호스트별 최신 2건 스캔을 재매칭한다(vg_rematch_scan_ids).
 */

require __DIR__ . '/../src/feeds.php';
require __DIR__ . '/../src/matcher.php';
require __DIR__ . '/../src/license_summary.php';   // vg_rebuild_license_summary
require __DIR__ . '/../src/compliance.php';        // vg_compliance_take_snapshot
require __DIR__ . '/../src/discovery.php';         // vg_discovery_reap_stale / vg_discovery_run_pending

$pdo = vg_pdo();

// 죽은 실행이 'running' 으로 굳어 있으면 정리한다(UI 가 영원히 실행중으로 보인다).
$reaped = vg_feed_reap_stale($pdo);
if ($reaped > 0) {
    fwrite(STDOUT, '[' . date('c') . "] 중단된 실행 {$reaped}건 정리\n");
}

// 라이선스 요약은 OSV 게이트/due 커넥터 유무와 무관하게 무조건 실행한다 — 라이선스 데이터는
//   OSV 가 아니라 에이전트 ingest 로만 들어오므로, OSV upserted>0 조건이나 아래 "due 커넥터
//   없음" 조기 종료에 묶이면 OSV 가 0건이거나 미등록인 기간 내내 language-packages.php 의
//   KPI 카드가 영원히 0으로 보인다(실측 확인됨). 스케줄러는 1분마다 도는 구간이라 여기서
//   매번 갱신해도 최신 데이터를 반영한다.
vg_rebuild_license_summary($pdo);

// 컴플라이언스 판정 스냅샷 — 하루 1건. 라이선스 요약과 같은 이유로 due 커넥터 유무와 무관하게
//   여기(조기 종료 앞)에서 판정한다 — 커넥터가 없는 날에도 증적은 남아야 한다.
//   판정은 무겁고(전 호스트 집계) 하루 한 번이면 충분하므로, 오늘 것이 이미 있으면 건너뛴다.
//   UPSERT 라 게이트를 뚫고 두 번 돌아도 행이 늘지 않는다(같은 날짜 = 항상 1건).
//   판정 기준은 화면과 같은 vg_compliance_policy()(tb_setting 반영)를 쓴다 — 스케줄러만
//   상수를 쓰면 설정을 바꾼 조직에서 화면과 증적의 기준이 갈라진다(증적 오염).
try {
    if (!vg_compliance_snapshot_exists($pdo)) {
        $snap = vg_compliance_take_snapshot($pdo, null, vg_compliance_policy());
        $parts = [];
        foreach ($snap as $key => $c) {
            $parts[] = $key . '=' . $c['total'] . ($c['unjudged'] > 0 ? '(판정불가 ' . $c['unjudged'] . ')' : '');
        }
        fwrite(STDOUT, '[' . date('c') . '] 컴플라이언스 스냅샷 적재 (' . implode(' · ', $parts) . ")\n");
    }
} catch (Throwable $e) {
    // 스냅샷 실패가 피드 실행을 막지 않게 한다 — 조용히 넘기지는 않는다.
    fwrite(STDOUT, '[' . date('c') . '] 컴플라이언스 스냅샷 실패: ' . $e->getMessage() . "\n");
    error_log('[compliance] 스냅샷 실패: ' . $e->getMessage());
}

// 자산 탐색 — 화면이 만든 pending run 을 여기서 집행한다. 이 호출이 없으면 "지금 스캔" 은
//   pending 행만 만들고 영원히 실행되지 않는다(bin/discover.php --pending 을 부르는 곳이 없었다).
//   ★ due 커넥터 유무와 무관해야 하므로 라이선스 요약과 같이 조기 종료 **앞**에 둔다.
//   ★ 한 틱이 집행할 run 수·시간에 상한이 있다(vg_discovery_run_pending 기본 1건·45초) —
//     스캔이 길어져도 아래 피드 수집이 밀리지 않게 한다. 남은 pending 은 다음 틱이 집는다.
//   ★ 스캔 실패는 tb_discovery_run.status='failed' 로 끝난다. 여기서 예외를 밖으로 던지면
//     compose 의 rc!=0 경로가 스케줄러 전체를 불건강으로 기록하므로, 스캔 하나의 실패로
//     그렇게 만들지 않는다(피드 수집은 아직 시작도 안 했다).
try {
    $reapedRuns = vg_discovery_reap_stale($pdo);
    if ($reapedRuns > 0) {
        fwrite(STDOUT, '[' . date('c') . "] 중단된 자산 탐색 {$reapedRuns}건 정리\n");
    }
    $disc = vg_discovery_run_pending($pdo);
    if ($disc['executed'] > 0 || $disc['skipped'] > 0 || $disc['deferred'] > 0) {
        foreach ($disc['results'] as $r) {
            fwrite(STDOUT, '[' . date('c') . '] 자산 탐색 run ' . $r['run_id'] . ' ['
                . (string) ($r['cidr'] ?? '') . '] '
                . (!empty($r['ok'])
                    ? sprintf('완료 — 살아있음 %d · 열린포트 %d · %.2fs', $r['ip_alive'], $r['open_total'], $r['elapsed'])
                    : '실패 — ' . (string) ($r['error'] ?? ''))
                . "\n");
        }
        fwrite(STDOUT, '[' . date('c') . "] 자산 탐색 집행 {$disc['ok']}건 성공 · {$disc['failed']}건 실패"
            . " · 건너뜀 {$disc['skipped']} · 다음 틱으로 {$disc['deferred']}\n");
    }
} catch (Throwable $e) {
    fwrite(STDOUT, '[' . date('c') . '] 자산 탐색 집행 실패: ' . $e->getMessage() . "\n");
    error_log('[discovery] 스케줄러 집행 실패: ' . $e->getMessage());
}

$due = vg_feed_due($pdo);
if (!$due) {
    fwrite(STDOUT, '[' . date('c') . "] due 커넥터 없음\n");
    $finish(true, 'scheduler tick succeeded: no due connector');
    exit(0);
}

$ok = 0; $okIds = []; $upserted = 0;
$failedMessages = [];
foreach ($due as $id) {
    $r = vg_feed_run($pdo, $id, 'schedule');
    fwrite(STDOUT, '[' . date('c') . "] connector #$id → " . ($r['ok'] ? "ok ({$r['upserted']} upserted)" : "error: {$r['error']}") . "\n");
    if (!empty($r['ok'])) { $ok++; $okIds[] = $id; $upserted += (int) ($r['upserted'] ?? 0); }
    else { $failedMessages[] = "connector #$id: " . (string) ($r['error'] ?? 'unknown error'); }
}

// 성공 여부가 아니라 **실제 수집분**을 기준으로 재매칭한다. 커넥터가 ok 이기만 하면 돌리던
//   예전 코드는 `ok (0 upserted)` 뒤에도 전체 재매칭을 걸어 binlog 만 불렸다(달라진 게 없는데).
if ($upserted > 0) {
    $scans = vg_rematch_scan_ids($pdo);
    foreach ($scans as $sid) { vg_match_scan($pdo, $sid); }
    fwrite(STDOUT, '[' . date('c') . "] 재매칭 완료 (" . count($scans) . " 스캔)\n");

    // OSV 를 수집했으면 조치안(fixed_version)을 이어서 보강한다.
    //   querybatch 응답엔 fixed 가 없어 findings 의 '조치' 칸이 비어버린다.
    //   findings 를 읽으므로 반드시 재매칭 뒤에 부른다.
    if (vg_feed_has_type($pdo, $okIds, 'osv')) {
        $s = vg_osv_enrich_fixed($pdo);
        fwrite(STDOUT, '[' . date('c') . "] OSV 조치안 보강 — 대상 {$s['targets']}종 · 조회 {$s['queried']} · 채움 {$s['filled']} · 건너뜀 {$s['skipped']}\n");
        // OSV 로 affected_packages 가 바뀌었으니 packages.php 요약을 다시 만든다.
        if ($s['filled'] > 0) {
            vg_load_cve_catalog($pdo, [], true);
            foreach ($scans as $sid) { vg_match_scan($pdo, (int) $sid); }
        }
        vg_rebuild_package_summary($pdo);
        fwrite(STDOUT, '[' . date('c') . "] packages 요약 재빌드 완료\n");
    }
} else {
    // 조용히 건너뛰지 않는다 — 왜 재매칭이 안 돌았는지 로그로 드러나야 한다.
    fwrite(STDOUT, '[' . date('c') . "] 수집 0건 (커넥터 성공 {$ok}/" . count($due) . ") — 재매칭 생략\n");
}

if ($failedMessages) {
    $message = implode('; ', $failedMessages);
    $finish(false, $message);
    exit(1);
}
$finish(true, "scheduler tick succeeded: connectors {$ok}/" . count($due));
