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

// 전량 재매칭(scan_id 없음)은 스캔 하나당 매처를 한 번 도는 배치라 런타임이 스캔 수에 비례한다
// — max_execution_time=30 이라는 웹 요청의 가정이 애초에 이 엔드포인트엔 맞지 않는다.
// 실측(2026-07-17, dev 스캔 398건): 스캔 1건 0.54초 · 전량 158초, kernelcve.php 안에서 죽었다.
// 리눅스는 CPU 시간만 세기에 DB 대기가 빠져 한동안 우연히 통과했을 뿐이고, 스캔이 쌓이면
// 운영에서도 똑같이 터진다. 죽는 줄은 그때그때 다르다(시계가 끝난 지점일 뿐 범인이 아니다).
// 인증을 통과한 배치 호출에만 푼다 — 전역 php.ini 를 올리면 모든 페이지의 안전장치가 풀린다.
set_time_limit(0);

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
    error_log('[rematch] ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['ok' => false, 'error' => 'internal error', 'code' => 'internal_error', 'ts' => date('c')], JSON_UNESCAPED_UNICODE);
}
