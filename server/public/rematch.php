<?php
declare(strict_types=1);

/**
 * rematch.php — 매처를 다시 돌린다 (CVE/KEV 피드 갱신 후 재계산용).
 *   인증: INGEST_TOKEN (헤더 X-Agent-Token 또는 Authorization: Bearer, ingest.php 와 동일)
 *   대상: ?scan_id=N 하나, 없으면 전체 스캔.
 */

header('Content-Type: application/json; charset=utf-8');

$cfg = require __DIR__ . '/../src/config.php';
require __DIR__ . '/../src/db.php';
require __DIR__ . '/../src/matcher.php';

$expected = (string) ($cfg['ingest_token'] ?? '');
$provided = vg_auth_token('X-Agent-Token');
if ($expected === '' || !hash_equals($expected, (string) $provided)) {
    http_response_code(401);
    echo json_encode(['ok' => false, 'error' => 'unauthorized', 'code' => 'unauthorized', 'ts' => date('c')], JSON_UNESCAPED_UNICODE);
    exit;
}

try {
    $pdo = vg_pdo();
    if (isset($_GET['scan_id'])) {
        $ids = [(int) $_GET['scan_id']];
    } else {
        $ids = array_map('intval', $pdo->query('SELECT id FROM tb_scans ORDER BY id')->fetchAll(PDO::FETCH_COLUMN));
    }
    $result = [];
    foreach ($ids as $id) {
        $result[$id] = vg_match_scan($pdo, $id);
    }
    echo json_encode(['ok' => true, 'matched_scans' => count($ids), 'counts' => $result], JSON_UNESCAPED_UNICODE);
} catch (Throwable $e) {
    http_response_code(500);
    echo json_encode(['ok' => false, 'error' => $e->getMessage(), 'code' => 'internal_error', 'ts' => date('c')], JSON_UNESCAPED_UNICODE);
}
