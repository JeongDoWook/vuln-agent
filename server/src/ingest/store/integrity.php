<?php
declare(strict_types=1);

/**
 * ingest/store/integrity.php — 패키지 무결성(rpm -Va / dpkg --verify) 결과 저장.
 *
 *   ⚠ 이 스트림만 **두 분기 밖**에서 돈다(스냅샷 재사용이든 새 스냅샷이든 항상).
 *   무결성은 스냅샷 내용(content_hash)에 안 들어가므로 패키지 목록이 그대로여도 바뀔 수 있고
 *   (파일만 변조), 반대로 이번 실행이 검사를 안 했다면 지난 결과를 남겨 두는 쪽이 더 위험하다 —
 *   오래된 "정상"을 최신 수집시각과 함께 보여주게 된다. 그래서 미수행이면 0 으로 되돌린다.
 */

function vg_ingest_store_integrity(
    PDO $pdo,
    int $scanId,
    bool $integChecked,
    bool $integPartial,
    int $integTotal,
    array $integRows
): void {
    $pdo->prepare('DELETE FROM tb_package_integrity WHERE scan_id = ?')->execute([$scanId]);
    if ($integChecked && $integRows) {
        $ins = $pdo->prepare(
            'INSERT INTO tb_package_integrity (scan_id, package_name, flags, file_path) VALUES (?, ?, ?, ?)'
        );
        foreach ($integRows as $r) {
            $ins->execute([$scanId, ($r[0] !== '' ? $r[0] : null), $r[1], $r[2]]);
        }
    }
    $pdo->prepare(
        'UPDATE tb_scan SET integrity_checked = ?, integrity_partial = ?, integrity_total = ? WHERE scan_id = ?'
    )->execute([$integChecked ? 1 : 0, $integPartial ? 1 : 0, $integChecked ? $integTotal : 0, $scanId]);
}
