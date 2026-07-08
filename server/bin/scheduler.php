<?php
declare(strict_types=1);

ini_set('memory_limit', '512M'); // 대량 피드(OSV/EPSS) 처리 여유

/**
 * scheduler.php — 예약된(enabled + due) 피드 커넥터를 실행한다.
 *   스케줄러 사이드카 컨테이너가 1분마다 호출(compose.yml).
 *   피드 수집으로 CVE/KEV 가 갱신되면 전체 스캔을 재매칭한다.
 */

require __DIR__ . '/../src/feeds.php';
require __DIR__ . '/../src/matcher.php';

$pdo = vg_pdo();
$due = vg_feed_due($pdo);
if (!$due) {
    fwrite(STDOUT, '[' . date('c') . "] due 커넥터 없음\n");
    exit(0);
}

$ok = 0;
foreach ($due as $id) {
    $r = vg_feed_run($pdo, $id, 'schedule');
    fwrite(STDOUT, '[' . date('c') . "] connector #$id → " . ($r['ok'] ? "ok ({$r['upserted']} upserted)" : "error: {$r['error']}") . "\n");
    if (!empty($r['ok'])) { $ok++; }
}

if ($ok > 0) {
    $scans = array_map('intval', $pdo->query('SELECT id FROM tb_scans')->fetchAll(PDO::FETCH_COLUMN));
    foreach ($scans as $sid) { vg_match_scan($pdo, $sid); }
    fwrite(STDOUT, '[' . date('c') . "] 재매칭 완료 (" . count($scans) . " 스캔)\n");
}
