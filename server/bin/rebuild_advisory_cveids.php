<?php
declare(strict_types=1);

/**
 * rebuild_advisory_cveids.php — 저장된 제목·본문에서 cve_ids 를 다시 계산한다.
 *
 *   왜 필요한가: cve_ids 가 varchar(512) 였고 코드가 500자에서 잘라 저장했다. 그래서
 *     - 마지막 CVE 가 조각났고("CVE-2"), 상세 페이지 링크가 깨졌다(운영 114건)
 *     - CVE 가 많은 공지는 대부분 버려졌다(263개 중 36개만 저장)
 *     - 원문 오탈자(CVE-0215-8451 등)가 그대로 남았다(운영 3건)
 *
 *   네트워크를 쓰지 않는다. 이미 DB 에 있는 content/title 만 다시 읽어 계산하므로
 *   보호나라에 부담이 없고 몇 초면 끝난다. 몇 번을 돌려도 멱등하다.
 *
 *   선행 조건: tb_advisories.cve_ids 가 TEXT 여야 한다(db/06-advisories.sql).
 *
 *   사용:
 *     php bin/rebuild_advisory_cveids.php            # 실제 적용
 *     php bin/rebuild_advisory_cveids.php --dry-run  # 바뀔 내용만 출력
 */

require __DIR__ . '/../src/feeds.php';

$opts   = getopt('', ['dry-run']);
$dryRun = array_key_exists('dry-run', $opts);

$pdo  = vg_pdo();
$rows = $pdo->query('SELECT id, title, content, cve_ids FROM tb_advisories WHERE is_deleted = 0 ORDER BY id')
            ->fetchAll(PDO::FETCH_ASSOC);

fwrite(STDOUT, sprintf("대상 %d건%s\n", count($rows), $dryRun ? ' (dry-run)' : ''));

$upd = $pdo->prepare('UPDATE tb_advisories SET cve_ids = ? WHERE id = ?');
$changed = 0; $grew = 0; $cleaned = 0;

foreach ($rows as $r) {
    $ids = vg_extract_cve_ids((string) $r['title'] . "\n" . (string) $r['content']);
    $new = $ids ? implode(',', $ids) : null;
    $old = $r['cve_ids'] !== null && $r['cve_ids'] !== '' ? (string) $r['cve_ids'] : null;

    if ($new === $old) { continue; }
    $changed++;

    $oldN = $old === null ? 0 : substr_count($old, ',') + 1;
    $newN = count($ids);
    if ($newN > $oldN) { $grew++; }

    // 잘린 조각이나 오탈자가 있었는지
    foreach (($old === null ? [] : explode(',', $old)) as $tok) {
        if (!vg_is_cve_id(trim($tok))) { $cleaned++; break; }
    }

    if ($dryRun) {
        fwrite(STDOUT, sprintf("  id=%-6s %d개 → %d개\n", $r['id'], $oldN, $newN));
    } else {
        $upd->execute([$new, (int) $r['id']]);
        foreach ($ids as $cve) { vg_upsert_cve($pdo, $cve, null, null, null); }
    }
}

fwrite(STDOUT, sprintf(
    "%s 변경 %d건 · CVE 늘어난 공지 %d건 · 손상된 값이 있던 공지 %d건\n",
    $dryRun ? '예정:' : '완료.', $changed, $grew, $cleaned
));
exit(0);
