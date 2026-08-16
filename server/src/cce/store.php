<?php
declare(strict_types=1);

/**
 * cce/store.php — 점검 결과를 tb_cce_finding 에 적재한다. 판정은 하지 않는다(SRP).
 *
 *   ※ cce.php 가 로드한다(그 파일의 중복 로드 가드 안에서).
 */

require_once __DIR__ . '/../db.php';    // vg_with_tx
require_once __DIR__ . '/checks.php';   // vg_cce_checks
require_once __DIR__ . '/catalog.php';  // vg_cce_ssg_map

/**
 * 한 스캔에 대해 CCE 점검 수행 → tb_cce_finding 재계산. 반환: 결과별 카운트.
 *   matcher 와 동일하게 스캔별 DELETE 후 재삽입, 자체 트랜잭션으로 원자성 보장.
 */
function vg_evaluate_cce(PDO $pdo, int $scanId, array $data): array {
    $rows = vg_cce_checks($data);

    return vg_with_tx($pdo, function () use ($pdo, $scanId, $rows) {
        $pdo->prepare('DELETE FROM tb_cce_finding WHERE scan_id = ?')->execute([$scanId]);
        $ins = $pdo->prepare(
            'INSERT INTO tb_cce_finding (scan_id, code, ssg_rule_id, title, result, severity, evidence, rationale)
             VALUES (?,?,?,?,?,?,?,?)'
        );
        $counts = ['PASS' => 0, 'FAIL' => 0, 'NA' => 0];
        foreach ($rows as $r) {
            [$code, $title, $result, $sev, $ev, $why] = $r;
            // 검증된 룰셋에 묶는다 — 없으면 null(자체 기준 항목).
            $ssg = vg_cce_ssg_map()[$code] ?? null;
            $ins->execute([$scanId, $code, $ssg, $title, $result, $sev, $ev, $why]);
            $counts[$result] = ($counts[$result] ?? 0) + 1;
        }
        return $counts;
    });
}
