<?php
declare(strict_types=1);

ini_set('memory_limit', '512M'); // 대량 피드(OSV/EPSS) 처리 여유

/**
 * sync.php — 커넥터 1건을 즉시 실행(수동). 사용: php sync.php <connector_id>
 *   실행 후 전체 스캔 재매칭.
 */

require __DIR__ . '/../src/feeds.php';
require __DIR__ . '/../src/matcher.php';

$id = (int) ($argv[1] ?? 0);
if ($id <= 0) {
    fwrite(STDERR, "사용법: php sync.php <connector_id>\n");
    exit(2);
}

$pdo = vg_pdo();
$r = vg_feed_run($pdo, $id, 'manual');
fwrite(STDOUT, json_encode($r, JSON_UNESCAPED_UNICODE) . "\n");

if (!empty($r['ok'])) {
    foreach (array_map('intval', $pdo->query('SELECT id FROM tb_scans')->fetchAll(PDO::FETCH_COLUMN)) as $sid) {
        vg_match_scan($pdo, $sid);
    }
    fwrite(STDOUT, "재매칭 완료\n");

    // OSV 면 조치안(fixed_version)까지 이어서 보강한다. findings 를 읽으므로 재매칭 뒤에.
    if (vg_feed_has_type($pdo, [$id], 'osv')) {
        $s = vg_osv_enrich_fixed($pdo);
        fwrite(STDOUT, "OSV 조치안 보강 — 대상 {$s['targets']}종 · 조회 {$s['queried']} · 채움 {$s['filled']} · 건너뜀 {$s['skipped']}\n");
    }
}
exit(empty($r['ok']) ? 1 : 0);
