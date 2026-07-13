<?php
declare(strict_types=1);

/**
 * backfill_advisory_cves.php — 기존 tb_advisories.cve_ids CSV 를 tb_advisory_cves 정션으로
 *   1회 백필한다. 정규화 마이그레이션(db/migrations/20260713192700_advisory_cves.sql)으로
 *   정션 테이블을 만든 뒤, 이 스크립트로 기존 행의 CSV 를 채워 넣는다.
 *
 *   이후로는 이 스크립트가 다시 필요 없다 — 쓰기 경로(feeds/kisa.php 의 vg_upsert_advisory·
 *   vg_advisory_fill_content, bin/rebuild_advisory_cveids.php)가 매번 vg_sync_advisory_cves 로
 *   정션을 함께 갱신한다.
 *
 *   네트워크를 쓰지 않는다. DB 에 이미 있는 cve_ids 값만 읽어 반영하므로 몇 초면 끝나고,
 *   몇 번을 돌려도 멱등하다(정션의 UNIQUE(advisory_id,cve_id) + soft-delete 동기화).
 *
 *   사용:
 *     php bin/backfill_advisory_cves.php            # 실제 적용
 *     php bin/backfill_advisory_cves.php --dry-run  # 대상 건수만 출력
 */

require __DIR__ . '/../src/feeds.php';

$opts   = getopt('', ['dry-run']);
$dryRun = array_key_exists('dry-run', $opts);

$pdo  = vg_pdo();
$rows = $pdo->query('SELECT id, cve_ids FROM tb_advisories WHERE is_deleted = 0 ORDER BY id')
            ->fetchAll(PDO::FETCH_ASSOC);

fwrite(STDOUT, sprintf("대상 %d건%s\n", count($rows), $dryRun ? ' (dry-run)' : ''));

$synced = 0; $withCves = 0;
foreach ($rows as $r) {
    // CSV 형식검증은 vg_extract_cve_ids 가 겸한다 — 잘린 조각·오탈자는 여기서도 걸러진다.
    $ids = vg_extract_cve_ids((string) $r['cve_ids']);
    if ($ids) { $withCves++; }
    if ($dryRun) { continue; }
    vg_sync_advisory_cves($pdo, (int) $r['id'], $ids);
    $synced++;
}

fwrite(STDOUT, sprintf(
    "%s CVE 있는 공지 %d건%s\n",
    $dryRun ? '예정:' : '완료.', $withCves, $dryRun ? '' : " · 동기화 {$synced}건"
));
exit(0);
