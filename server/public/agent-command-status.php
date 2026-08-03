<?php
declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
require __DIR__ . '/../src/auth.php';
require_once __DIR__ . '/../src/agentcommand.php';
vg_require_menu('findings');
if (!vg_can('assets')) { http_response_code(403); echo json_encode(['ok'=>false]); exit; }

$hostId = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
if (!$hostId) { http_response_code(422); echo json_encode(['ok'=>false]); exit; }
$pdo = vg_pdo();
$st = $pdo->prepare(
    "SELECT agent_command_id,status,progress_percent,progress_stage,progress_message,
            run_at,created_at,started_at,heartbeat_at,executed_at,
            TIMESTAMPDIFF(SECOND,COALESCE(started_at,created_at),NOW()) elapsed_seconds,
            TIMESTAMPDIFF(SECOND,heartbeat_at,NOW()) heartbeat_age
       FROM tb_agent_command WHERE host_id=? AND is_deleted=0
      ORDER BY FIELD(status,'running','pending','failed','done'), created_at DESC LIMIT 1"
);
$st->execute([$hostId]);
$row = $st->fetch() ?: null;
$host = $pdo->prepare('SELECT poll_schedule_seconds FROM tb_host WHERE host_id=? AND is_deleted=0');
$host->execute([$hostId]);
$interval = $host->fetchColumn();
echo json_encode(['ok'=>true, 'command'=>$row, 'poll_schedule_seconds'=>$interval !== false ? (int)$interval : null], JSON_UNESCAPED_UNICODE);
