<?php
declare(strict_types=1);

// PHP 한도는 **반드시 이 프로세스가 도는 컨테이너의 mem_limit 보다 낮아야** 한다.
//   여기는 scheduler 컨테이너(deploy/compose.common.yml: mem_limit 1g) → 768M.
//   높으면(예전: PHP 1024M vs 컨테이너 384m) PHP 가 자기 한도에 닿기 전에 cgroup 이 SIGKILL 하고,
//   그러면 잡히는 PHP 오류가 없어 vg_feed_run() 의 catch 가 못 돈다 → 로그가 'running' 으로 굳고
//   6시간 뒤 vg_feed_reap_stale() 이 마감한 것만 화면에 error 로 보인다.
//   실측(2026-07): RHEL OVAL(52만 행 + 대용량 XML)이 schedule 로만 6일 연속 실패했고
//   `docker inspect vulnagent-scheduler` 가 Memory=402653184(384m)·OOMKilled=true 였다.
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

$pdo = vg_pdo();

// 죽은 실행이 'running' 으로 굳어 있으면 정리한다(UI 가 영원히 실행중으로 보인다).
$reaped = vg_feed_reap_stale($pdo);
if ($reaped > 0) {
    fwrite(STDOUT, '[' . date('c') . "] 중단된 실행 {$reaped}건 정리\n");
}

$due = vg_feed_due($pdo);
if (!$due) {
    fwrite(STDOUT, '[' . date('c') . "] due 커넥터 없음\n");
    exit(0);
}

$ok = 0; $okIds = []; $upserted = 0;
foreach ($due as $id) {
    $r = vg_feed_run($pdo, $id, 'schedule');
    fwrite(STDOUT, '[' . date('c') . "] connector #$id → " . ($r['ok'] ? "ok ({$r['upserted']} upserted)" : "error: {$r['error']}") . "\n");
    if (!empty($r['ok'])) { $ok++; $okIds[] = $id; $upserted += (int) ($r['upserted'] ?? 0); }
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
