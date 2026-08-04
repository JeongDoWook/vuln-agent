<?php
declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
require __DIR__ . '/../src/config.php';
require __DIR__ . '/../src/db.php';
require_once __DIR__ . '/../src/agenttoken.php';

function progress_fail(int $code, string $message): void {
    http_response_code($code);
    echo json_encode(['ok' => false, 'error' => $message], JSON_UNESCAPED_UNICODE);
    exit;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') { progress_fail(405, 'POST only'); }
$token = vg_agent_token_verify(vg_pdo(), (string) vg_auth_token('X-Agent-Token'));
if ($token === null) { progress_fail(401, 'unauthorized'); }

$commandId = filter_input(INPUT_POST, 'command_id', FILTER_VALIDATE_INT);
$percent = filter_input(INPUT_POST, 'percent', FILTER_VALIDATE_INT);
$stage = trim((string) ($_POST['stage'] ?? ''));
$message = trim((string) ($_POST['message'] ?? ''));
$state = (string) ($_POST['state'] ?? 'running');
if (!$commandId || $percent === false || $percent < 0 || $percent > 100 || !preg_match('/^[a-z_]{2,40}$/', $stage)) {
    progress_fail(422, 'invalid progress payload');
}
if (!in_array($state, ['running', 'failed', 'cancelled'], true)) { progress_fail(422, 'invalid state'); }

$pdo = vg_pdo();
$st = $pdo->prepare('SELECT host_id FROM tb_host WHERE fqdn=? AND is_deleted=0 LIMIT 1');
$st->execute([(string) $token['fqdn']]);
$hostId = (int) $st->fetchColumn();
if ($hostId <= 0) { progress_fail(404, 'host not found'); }

$check = $pdo->prepare('SELECT status,cancel_requested_at FROM tb_agent_command WHERE agent_command_id=? AND host_id=? AND is_deleted=0');
$check->execute([$commandId, $hostId]);
$command = $check->fetch();
if (!$command || !in_array($command['status'], ['pending', 'running'], true)) { progress_fail(409, 'command is not active'); }
$cancelRequested = $command['cancel_requested_at'] !== null;

$sql = "UPDATE tb_agent_command
           SET status=?, progress_percent=?, progress_stage=?, progress_message=?,
               started_at=COALESCE(started_at,NOW()), heartbeat_at=NOW(),
               executed_at=IF(? IN ('failed','cancelled'),NOW(),executed_at),
               cancelled_at=IF(?='cancelled',NOW(),cancelled_at)
         WHERE agent_command_id=? AND host_id=? AND status IN ('pending','running') AND is_deleted=0";
$update = $pdo->prepare($sql);
$update->execute([$state, $percent, $stage, mb_substr($message, 0, 255), $state, $state, $commandId, $hostId]);
if ($update->rowCount() === 0) {
    progress_fail(409, 'command is not active');
}
echo json_encode(['ok' => true, 'cancel_requested' => $cancelRequested], JSON_UNESCAPED_UNICODE);
