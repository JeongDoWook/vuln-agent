<?php
declare(strict_types=1);

ini_set('memory_limit', '1024M'); // 대량 피드 처리 여유(Oracle OVAL 은 236MB XML & 49만 행 — 512M 로는 죽는다)

/**
 * scheduler.php — 예약된(enabled + due) 피드 커넥터를 실행한다.
 *   스케줄러 사이드카 컨테이너가 1분마다 호출(compose.yml).
 *   피드 수집으로 CVE/KEV 가 갱신되면 전체 스캔을 재매칭한다.
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

$ok = 0; $okIds = [];
foreach ($due as $id) {
    $r = vg_feed_run($pdo, $id, 'schedule');
    fwrite(STDOUT, '[' . date('c') . "] connector #$id → " . ($r['ok'] ? "ok ({$r['upserted']} upserted)" : "error: {$r['error']}") . "\n");
    if (!empty($r['ok'])) { $ok++; $okIds[] = $id; }
}

if ($ok > 0) {
    $scans = array_map('intval', $pdo->query('SELECT id FROM tb_scans')->fetchAll(PDO::FETCH_COLUMN));
    foreach ($scans as $sid) { vg_match_scan($pdo, $sid); }
    fwrite(STDOUT, '[' . date('c') . "] 재매칭 완료 (" . count($scans) . " 스캔)\n");

    // OSV 를 수집했으면 조치안(fixed_version)을 이어서 보강한다.
    //   querybatch 응답엔 fixed 가 없어 findings 의 '조치' 칸이 비어버린다.
    //   findings 를 읽으므로 반드시 재매칭 뒤에 부른다.
    if (vg_feed_has_type($pdo, $okIds, 'osv')) {
        $s = vg_osv_enrich_fixed($pdo);
        fwrite(STDOUT, '[' . date('c') . "] OSV 조치안 보강 — 대상 {$s['targets']}종 · 조회 {$s['queried']} · 채움 {$s['filled']} · 건너뜀 {$s['skipped']}\n");
        // OSV 로 affected_packages 가 바뀌었으니 packages.php 요약을 다시 만든다.
        vg_rebuild_package_summary($pdo);
        fwrite(STDOUT, '[' . date('c') . "] packages 요약 재빌드 완료\n");
    }
}
