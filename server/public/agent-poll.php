<?php
declare(strict_types=1);

/**
 * agent-poll.php — 상시 데몬(agent-daemon-poll-loop)이 아웃바운드로 물어보는 폴링 엔드포인트.
 *   인증 : 호스트 바인딩 개별 토큰 (헤더 X-Agent-Token 또는 Authorization: Bearer) — ingest.php 와 동일.
 *   상태를 바꾸지 않는 순수 조회라 nonce 재전송방지는 강제하지 않는다(초 단위 반복 호출이 정상).
 */

header('Content-Type: application/json; charset=utf-8');

require __DIR__ . '/../src/config.php';
require __DIR__ . '/../src/db.php';
require_once __DIR__ . '/../src/agenttoken.php';  // vg_agent_token_verify (호스트 바인딩)

function respond_fail(int $httpCode, string $msg, string $code): void {
    http_response_code($httpCode);
    echo json_encode(['ok' => false, 'error' => $msg, 'code' => $code, 'ts' => date('c')], JSON_UNESCAPED_UNICODE);
    exit;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'GET') {
    respond_fail(405, 'GET only', 'method_not_allowed');
}

$provided = vg_auth_token('X-Agent-Token');
$pdo = vg_pdo();

$agentTok = vg_agent_token_verify($pdo, (string) $provided);
if ($agentTok === null) {
    respond_fail(401, 'unauthorized', 'unauthorized');
}
$fqdn = $agentTok['fqdn'];

// 호스트가 아직 한 번도 ingest 되지 않았으면 tb_host 행이 없을 수 있다 — 에러가 아니라 기본값.
$st = $pdo->prepare('SELECT host_id, poll_schedule_seconds FROM tb_host WHERE fqdn = ? AND is_deleted = 0 LIMIT 1');
$st->execute([$fqdn]);
$host = $st->fetch();

if (!$host) {
    echo json_encode(['poll_schedule_seconds' => 3600, 'due_command_id' => null], JSON_UNESCAPED_UNICODE);
    exit;
}

$hostId = (int) $host['host_id'];
$pollScheduleSeconds = (int) $host['poll_schedule_seconds'];

$cmdSt = $pdo->prepare(
    "SELECT agent_command_id FROM tb_agent_command
      WHERE host_id = ? AND status = 'pending' AND is_deleted = 0
        AND (run_at IS NULL OR run_at <= NOW())
      ORDER BY COALESCE(run_at, created_at) ASC LIMIT 1"
);
$cmdSt->execute([$hostId]);
$dueCommandId = $cmdSt->fetchColumn();

echo json_encode([
    'poll_schedule_seconds' => $pollScheduleSeconds,
    'due_command_id'        => $dueCommandId !== false ? (int) $dueCommandId : null,
], JSON_UNESCAPED_UNICODE);
