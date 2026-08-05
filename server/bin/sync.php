<?php
declare(strict_types=1);

// PHP 한도는 **반드시 이 프로세스가 도는 컨테이너의 mem_limit 보다 낮아야** 한다 — 높으면
//   PHP 가 자기 한도에 닿기 전에 cgroup 이 SIGKILL 해서 잡히는 오류 없이 즉사하고,
//   vg_feed_run() 의 catch 가 못 돌아 로그가 'running' 으로 굳는다(2026-07 스케줄러 사고).
//   sync.php 는 web 컨테이너에서 돈다(README: `docker compose exec web php bin/sync.php <id>`,
//   mem_limit 768m) → 같은 컨테이너에서 같은 vg_feed_run() 을 부르는 UI 수동실행
//   (server/src/connector_actions.php)과 동일하게 512M 으로 맞춘다.
ini_set('memory_limit', '512M');

/**
 * sync.php — 커넥터 1건을 즉시 실행(수동). 사용: php sync.php <connector_id>
 *   실제로 수집분이 있으면 호스트별 최신 2건 스캔을 재매칭한다(vg_rematch_scan_ids).
 */

require __DIR__ . '/../src/feeds.php';
require __DIR__ . '/../src/matcher.php';
require __DIR__ . '/../src/license_summary.php';   // vg_rebuild_license_summary

$id = (int) ($argv[1] ?? 0);
if ($id <= 0) {
    fwrite(STDERR, "사용법: php sync.php <connector_id>\n");
    exit(2);
}

$pdo = vg_pdo();
$r = vg_feed_run($pdo, $id, 'manual');
fwrite(STDOUT, json_encode($r, JSON_UNESCAPED_UNICODE) . "\n");

// 성공 여부가 아니라 **실제 수집분**이 기준이다 — 0건 수집이면 재계산할 근거가 없다.
if (!empty($r['ok']) && (int) $r['upserted'] > 0) {
    $scans = vg_rematch_scan_ids($pdo);
    foreach ($scans as $sid) { vg_match_scan($pdo, $sid); }
    fwrite(STDOUT, '재매칭 완료 (' . count($scans) . " 스캔)\n");

    // OSV 면 조치안(fixed_version)까지 이어서 보강한다. findings 를 읽으므로 재매칭 뒤에.
    if (vg_feed_has_type($pdo, [$id], 'osv')) {
        $s = vg_osv_enrich_fixed($pdo);
        fwrite(STDOUT, "OSV 조치안 보강 — 대상 {$s['targets']}종 · 조회 {$s['queried']} · 채움 {$s['filled']} · 건너뜀 {$s['skipped']}\n");
        // OSV 로 affected_packages 가 바뀌었으니 packages.php 요약을 다시 만든다.
        if ($s['filled'] > 0) {
            vg_load_cve_catalog($pdo, [], true);
            foreach ($scans as $sid) { vg_match_scan($pdo, (int) $sid); }
        }
        vg_rebuild_package_summary($pdo);
        vg_rebuild_license_summary($pdo);
        fwrite(STDOUT, "packages 요약 재빌드 완료\n");
    }
} elseif (!empty($r['ok'])) {
    // 조용히 건너뛰지 않는다 — 왜 재매칭이 안 돌았는지 로그로 드러나야 한다.
    fwrite(STDOUT, "수집 0건 — 재매칭 생략\n");
}
exit(empty($r['ok']) ? 1 : 0);
