<?php
declare(strict_types=1);

/**
 * backfill_nvd.php — NVD 전체 CVE(약 36만건) 1회성 백필.
 *
 *   주기 커넥터(VgNvdConnector)는 "최근 N일 수정분"만 본다. 그래서 커넥터를 아무리
 *   돌려도 과거 이력은 채워지지 않는다. 여기서 한 번 전부 끌어온다.
 *
 *   NVD 는 날짜 필터 없이도 startIndex 로 끝까지 페이징된다(실측: startIndex=360000 → 200).
 *   따라서 120일 창을 1999년부터 순회할 필요가 없다.
 *
 *   [소요 시간] 오래 걸린다. NVD 는 API 키가 있어도 50~60KB/s 밖에 주지 않고 전체
 *   응답이 1GB 를 넘는다(실측 2026-07-09). 페이지 500건 기준 약 730페이지,
 *   페이지당 40~50초 → 전체 6시간 안팎. 페이지를 키워도 대역폭이 병목이라 같다.
 *   백그라운드로 돌리고(nohup / docker exec -d) 진행 로그를 지켜보는 것을 권한다.
 *
 *   vg_upsert_cve 가 COALESCE 갱신이라 몇 번을 돌려도 멱등하다. 중단되면 마지막에
 *   출력된 --start-index 로 이어서 실행하면 된다. 메모리는 페이지 단위로 해제돼
 *   36만건을 훑어도 40MB 안팎으로 일정하다(실측).
 *
 *   API 키는 DB(tb_feed_connectors.connection_json.api_key)에서 읽는다. 코드·저장소에
 *   키를 두지 않는다. 키가 있으면 요청 간격 1초, 없으면 6초로 자동 조절된다.
 *
 *   사용:
 *     php bin/backfill_nvd.php                    # 전체
 *     php bin/backfill_nvd.php --start-index=40000 # 중단 지점부터 재개
 *     php bin/backfill_nvd.php --max-pages=2       # 앞 2페이지만(시험용)
 */

require __DIR__ . '/../src/feeds.php';

$opts     = getopt('', ['start-index::', 'max-pages::']);
$startIdx = max(0, (int) ($opts['start-index'] ?? 0));
$maxPages = isset($opts['max-pages']) ? max(1, (int) $opts['max-pages']) : 0;   // 0 = 제한 없음

$pdo = vg_pdo();

// 커넥터 레코드에서 url·api_key 를 가져온다(없으면 기본 URL, 키 없이 동작).
$row  = $pdo->query("SELECT connection_json FROM tb_feed_connectors WHERE connector_type='nvd' AND is_deleted=0 LIMIT 1")
            ->fetchColumn();
$conn = $row ? vg_json_col($row) : [];

$hasKey = trim((string) ($conn['api_key'] ?? '')) !== '';
fwrite(STDOUT, sprintf(
    "NVD 전체 백필 시작. startIndex=%d · API키 %s (요청 간격 %s초)\n",
    $startIdx,
    $hasKey ? '있음' : '없음',
    $hasKey ? '1' : '6'
));

$pages = 0;
$t0    = time();

$onPage = function (int $next, int $total, int $fetched) use (&$pages, $maxPages, $t0): bool {
    $pages++;
    $done = min($next, $total);
    $pct  = $total > 0 ? round($done / $total * 100, 1) : 0.0;
    $el   = max(1, time() - $t0);
    fwrite(STDOUT, sprintf(
        "  %d/%d (%.1f%%) · %d페이지 · %d초 · 메모리 %.0fMB\n",
        $done, $total, $pct, $pages, $el, memory_get_peak_usage(true) / 1048576
    ));
    if ($maxPages > 0 && $pages >= $maxPages) {
        fwrite(STDOUT, "  --max-pages 도달 → 중단. 재개: --start-index=$next\n");
        return false;   // 루프 중단
    }
    return true;
};

try {
    $res = vg_nvd_sync($pdo, $conn, [], $startIdx, $onPage);
} catch (Throwable $e) {
    fwrite(STDERR, "실패: " . $e->getMessage() . "\n");
    fwrite(STDERR, "재개하려면 위 진행 로그의 마지막 인덱스로: --start-index=<N>\n");
    exit(1);
}

$sec = max(1, time() - $t0);
fwrite(STDOUT, sprintf(
    "완료. 수신 %d건 · upsert %d건 · 전체 %d건 · %d초 · 최대 메모리 %.0fMB\n",
    $res['fetched'], $res['upserted'], $res['total'], $sec, memory_get_peak_usage(true) / 1048576
));
exit(0);
