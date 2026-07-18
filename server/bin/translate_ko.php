<?php
declare(strict_types=1);

/**
 * translate_ko.php — tb_cves.summary / tb_kev_catalog.note 를 LibreTranslate 로 한글 번역해
 *   summary_ko / note_ko 에 채운다(1회성 배치 + 재실행 가능한 증분 처리).
 *
 *   대상은 항상 "원문은 있고 번역은 아직 없는" 행뿐이다(summary_ko/note_ko IS NULL). 번역에
 *   실패한 행은 컬럼을 NULL 로 남겨두므로 다음 실행에서 자연히 다시 대상이 된다 — 별도의
 *   실패 추적이 필요 없다. 원문이 나중에 갱신돼도 재번역은 하지 않는다(이번 스코프 밖 —
 *   YAGNI, CLAUDE.md/.initial-prompt 참고).
 *
 *   스케줄러(bin/scheduler.php)에는 일부러 얹지 않았다 — 번역 1건이 최대 30초까지 걸릴 수
 *   있어(vg_translate_ko 타임아웃), 그걸 스케줄러의 1분 주기 루프 안에 넣으면 신규 CVE 가
 *   몰릴 때 다음 피드 수집 주기를 통째로 지연시킨다. 대신 독립 스크립트로 두고 cron/수동으로
 *   돌린다(과설계 금지).
 *
 *   사용:
 *     php bin/translate_ko.php                # 남은 전부
 *     php bin/translate_ko.php --limit=50      # 앞 50건만(시험용)
 *     php bin/translate_ko.php --sleep-ms=500  # 요청 간격(기본 200ms) — 자체 호스팅이라 여유있게
 */

require __DIR__ . '/../src/db.php';
require __DIR__ . '/../src/translate.php';

$opts    = getopt('', ['limit::', 'sleep-ms::']);
$limit   = isset($opts['limit']) ? max(1, (int) $opts['limit']) : 0;   // 0 = 전부
$sleepUs = (isset($opts['sleep-ms']) ? max(0, (int) $opts['sleep-ms']) : 200) * 1000;

$pdo = vg_pdo();

/** @return array{done:int,skip:int} */
function vg_translate_ko_batch(PDO $pdo, string $table, string $idCol, string $srcCol, string $dstCol, int $limit, int $sleepUs): array {
    $sql = "SELECT {$idCol} AS id, {$srcCol} AS src FROM {$table} WHERE {$srcCol} IS NOT NULL AND {$dstCol} IS NULL";
    if ($limit > 0) { $sql .= ' LIMIT ' . $limit; }
    $rows  = $pdo->query($sql)->fetchAll(PDO::FETCH_ASSOC);
    $total = count($rows);
    if ($total === 0) {
        fwrite(STDOUT, "[{$table}] 번역할 행이 없습니다.\n");
        return ['done' => 0, 'skip' => 0];
    }

    fwrite(STDOUT, "[{$table}] 대상 {$total}건\n");
    $upd = $pdo->prepare("UPDATE {$table} SET {$dstCol} = ? WHERE {$idCol} = ?");

    $done = 0; $skip = 0;
    foreach ($rows as $i => $row) {
        $n  = $i + 1;
        $ko = vg_translate_ko((string) $row['src']);
        if ($ko !== null) {
            $upd->execute([$ko, $row['id']]);
            $done++;
        } else {
            $skip++;   // 실패 — 컬럼은 NULL 로 남아 다음 실행에서 다시 대상이 된다
        }
        if ($n % 20 === 0 || $n === $total) {
            fwrite(STDOUT, "  [{$table}] 진행 {$n}/{$total} · 번역 {$done} · 실패(재시도예정) {$skip}\n");
        }
        if ($sleepUs > 0 && $n < $total) { usleep($sleepUs); }
    }
    return ['done' => $done, 'skip' => $skip];
}

$cve = vg_translate_ko_batch($pdo, 'tb_cves', 'cve_id', 'summary', 'summary_ko', $limit, $sleepUs);
$kev = vg_translate_ko_batch($pdo, 'tb_kev_catalog', 'cve_id', 'note', 'note_ko', $limit, $sleepUs);

fwrite(STDOUT, sprintf(
    "완료. tb_cves 번역 %d · tb_kev_catalog 번역 %d (실패/재시도예정 %d)\n",
    $cve['done'], $kev['done'], $cve['skip'] + $kev['skip']
));
exit(0);
