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
 *   청크 단위로 vg_translate_ko_batch() 를 불러 동시 번역한다(순차 1건씩이 아니다 — 실측
 *   기준 concurrency=16 이 순차 대비 약 1.5~2배, translate.php 헤더 주석 참고). 청크 사이
 *   고정 sleep 은 두지 않는다 — LibreTranslate 가 못 감당하면 타임아웃/실패로 드러나고,
 *   그 행은 컬럼이 NULL 로 남아 다음 실행에서 재시도된다.
 *
 *   사용:
 *     php bin/translate_ko.php                    # 남은 전부
 *     php bin/translate_ko.php --limit=500         # 앞 500건만(시험용)
 *     php bin/translate_ko.php --chunk=200         # 청크 크기(기본 200)
 *     php bin/translate_ko.php --concurrency=16    # 청크 내 동시요청 수(기본 16)
 */

require __DIR__ . '/../src/db.php';
require __DIR__ . '/../src/translate.php';

$opts        = getopt('', ['limit::', 'chunk::', 'concurrency::']);
$limit       = isset($opts['limit']) ? max(1, (int) $opts['limit']) : 0;   // 0 = 전부
$chunk       = isset($opts['chunk']) ? max(1, (int) $opts['chunk']) : 200;
$concurrency = isset($opts['concurrency']) ? max(1, (int) $opts['concurrency']) : 16;

$pdo = vg_pdo();

/** @return array{done:int,skip:int} */
function vg_translate_ko_run(PDO $pdo, string $table, string $idCol, string $srcCol, string $dstCol, int $limit, int $chunk, int $concurrency): array {
    $sql = "SELECT {$idCol} AS id, {$srcCol} AS src FROM {$table} WHERE {$srcCol} IS NOT NULL AND {$dstCol} IS NULL";
    if ($limit > 0) { $sql .= ' LIMIT ' . $limit; }
    $rows  = $pdo->query($sql)->fetchAll(PDO::FETCH_ASSOC);
    $total = count($rows);
    if ($total === 0) {
        fwrite(STDOUT, "[{$table}] 번역할 행이 없습니다.\n");
        return ['done' => 0, 'skip' => 0];
    }

    fwrite(STDOUT, "[{$table}] 대상 {$total}건 (chunk={$chunk}, concurrency={$concurrency})\n");
    $upd = $pdo->prepare("UPDATE {$table} SET {$dstCol} = ? WHERE {$idCol} = ?");

    $done = 0; $skip = 0; $n = 0;
    $t0 = microtime(true);
    foreach (array_chunk($rows, $chunk) as $batch) {
        $texts = [];
        foreach ($batch as $row) { $texts[$row['id']] = (string) $row['src']; }

        $translated = vg_translate_ko_batch($texts, $concurrency);

        foreach ($translated as $id => $ko) {
            $n++;
            if ($ko !== null) {
                $upd->execute([$ko, $id]);
                $done++;
            } else {
                $skip++;   // 실패 — 컬럼은 NULL 로 남아 다음 실행에서 다시 대상이 된다
            }
        }

        $elapsed = microtime(true) - $t0;
        $rate    = $elapsed > 0 ? $n / $elapsed : 0.0;
        fwrite(STDOUT, sprintf(
            "  [%s] 진행 %d/%d · 번역 %d · 실패(재시도예정) %d · %.2f건/초\n",
            $table, $n, $total, $done, $skip, $rate
        ));
    }
    return ['done' => $done, 'skip' => $skip];
}

$cve = vg_translate_ko_run($pdo, 'tb_cves', 'cve_id', 'summary', 'summary_ko', $limit, $chunk, $concurrency);
$kev = vg_translate_ko_run($pdo, 'tb_kev_catalog', 'cve_id', 'note', 'note_ko', $limit, $chunk, $concurrency);

fwrite(STDOUT, sprintf(
    "완료. tb_cves 번역 %d · tb_kev_catalog 번역 %d (실패/재시도예정 %d)\n",
    $cve['done'], $kev['done'], $cve['skip'] + $kev['skip']
));
exit(0);
