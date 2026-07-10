<?php
declare(strict_types=1);

ini_set('memory_limit', '512M');

/**
 * enrich_osv.php — OSV 조치안(fixed_version) 지연 보강을 수동으로 1회 실행.
 *
 *   로직은 vg_osv_enrich_fixed() 에 있다(feeds.php). scheduler.php · sync.php 가
 *   OSV 수집 + 재매칭 뒤에 같은 함수를 자동으로 부르므로, 이 스크립트는 점검·보충용이다.
 *   fixed 가 이미 있는 패키지는 대상에서 빠져 몇 번을 돌려도 멱등하다.
 *
 *   사용: php bin/enrich_osv.php
 */

require __DIR__ . '/../src/feeds.php';

$pdo = vg_pdo();
$s   = vg_osv_enrich_fixed($pdo, static function (string $line): void {
    fwrite(STDOUT, $line . "\n");
});

if ($s['targets'] === 0) {
    fwrite(STDOUT, '[' . date('c') . "] 보강할 패키지 없음(모두 조치 확보 또는 findings 없음)\n");
    exit(0);
}
fwrite(STDOUT, sprintf(
    "[%s] 대상 %d종 · 조회 %d패키지 · 조치 %d건 채움 · %d건 건너뜀\n",
    date('c'), $s['targets'], $s['queried'], $s['filled'], $s['skipped']
));
