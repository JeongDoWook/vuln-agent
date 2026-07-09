<?php
declare(strict_types=1);

/**
 * backfill_kisa_content.php — 이미 저장된 공지의 본문(content)을 1회성으로 채운다.
 *
 *   커넥터는 이제 신규 공지를 저장할 때 본문까지 긁는다. 하지만 그 전에 쌓인
 *   2천여 건은 content 가 NULL 이다. 여기서 상세 페이지를 순회해 채운다.
 *
 *   vg_advisory_fill_content 가 "content 가 이미 있으면 요청조차 안 함"이라
 *   몇 번을 돌려도 멱등하다. 중단 후 재실행하면 남은 것부터 이어서 처리한다.
 *
 *   보호나라에 부담을 주지 않도록 요청 간 간격을 둔다(기본 300ms).
 *
 *   사용:
 *     php bin/backfill_kisa_content.php               # 남은 전부
 *     php bin/backfill_kisa_content.php --limit=20    # 앞 20건만(시험용)
 *     php bin/backfill_kisa_content.php --sleep-ms=800
 */

require __DIR__ . '/../src/feeds.php';

$opts     = getopt('', ['limit::', 'sleep-ms::']);
$limit    = isset($opts['limit']) ? max(1, (int) $opts['limit']) : 0;   // 0 = 전부
$sleepUs  = (isset($opts['sleep-ms']) ? max(0, (int) $opts['sleep-ms']) : 300) * 1000;

$pdo = vg_pdo();

$sql = 'SELECT id, url FROM tb_advisories
        WHERE is_deleted = 0 AND content IS NULL AND url LIKE "%boho.or.kr%"
        ORDER BY published DESC, id DESC';
if ($limit > 0) { $sql .= ' LIMIT ' . $limit; }

$rows  = $pdo->query($sql)->fetchAll(PDO::FETCH_ASSOC);
$total = count($rows);
if ($total === 0) {
    fwrite(STDOUT, "채울 공지가 없습니다(모두 수집됨).\n");
    exit(0);
}

fwrite(STDOUT, "대상 {$total}건. 요청 간격 " . ($sleepUs / 1000) . "ms\n");

$done = 0; $skip = 0; $fail = 0;
foreach ($rows as $i => $row) {
    $n = $i + 1;
    try {
        if (vg_advisory_fill_content($pdo, (string) $row['url'])) {
            $done++;
        } else {
            $skip++;   // 이미 채워졌거나 대상 아님
        }
    } catch (Throwable $e) {
        $fail++;
        fwrite(STDERR, "[{$n}/{$total}] 실패 id={$row['id']}: " . $e->getMessage() . "\n");
    }
    if ($n % 50 === 0 || $n === $total) {
        fwrite(STDOUT, "  진행 {$n}/{$total} · 저장 {$done} · 스킵 {$skip} · 실패 {$fail}\n");
    }
    if ($sleepUs > 0 && $n < $total) { usleep($sleepUs); }
}

fwrite(STDOUT, "완료. 저장 {$done} · 스킵 {$skip} · 실패 {$fail}\n");
exit($fail > 0 && $done === 0 ? 1 : 0);
