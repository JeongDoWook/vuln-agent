<?php
declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
require __DIR__ . '/../src/auth.php';
vg_require_menu('findings');
if (!vg_can('assets')) {
    http_response_code(403);
    echo json_encode(['ok' => false]);
    exit;
}

$pdo = vg_pdo();
$sql = <<<'SQL'
SELECT c.agent_command_id,c.host_id,c.status,c.progress_percent,c.progress_stage,c.progress_message,
       c.run_at,c.created_at,c.started_at,c.heartbeat_at,c.executed_at,
       h.fqdn,h.hostname,h.poll_schedule_seconds,
       TIMESTAMPDIFF(SECOND,COALESCE(c.started_at,c.created_at),COALESCE(c.executed_at,NOW())) elapsed_seconds,
       TIMESTAMPDIFF(SECOND,c.heartbeat_at,NOW()) heartbeat_age
  FROM tb_agent_command c
  JOIN tb_host h ON h.host_id=c.host_id AND h.is_deleted=0
 WHERE c.is_deleted=0
   AND (c.status IN ('pending','running')
        OR (c.status IN ('done','failed') AND COALESCE(c.executed_at,c.created_at) >= NOW() - INTERVAL 1 HOUR))
   AND NOT EXISTS (
       SELECT 1 FROM tb_agent_command newer
        WHERE newer.host_id=c.host_id AND newer.is_deleted=0
          AND (newer.status IN ('pending','running')
               OR (newer.status IN ('done','failed') AND COALESCE(newer.executed_at,newer.created_at) >= NOW() - INTERVAL 1 HOUR))
          AND newer.agent_command_id > c.agent_command_id
   )
 ORDER BY FIELD(c.status,'running','pending','failed','done'), c.created_at DESC
SQL;
$commands = $pdo->query($sql)->fetchAll();

$running = 0;
$pending = 0;
$progressTotal = 0;
foreach ($commands as &$command) {
    $command['agent_command_id'] = (int) $command['agent_command_id'];
    $command['host_id'] = (int) $command['host_id'];
    $command['poll_schedule_seconds'] = (int) $command['poll_schedule_seconds'];
    $command['progress_percent'] = $command['progress_percent'] !== null ? (int) $command['progress_percent'] : 0;
    $command['elapsed_seconds'] = $command['elapsed_seconds'] !== null ? (int) $command['elapsed_seconds'] : null;
    $command['heartbeat_age'] = $command['heartbeat_age'] !== null ? (int) $command['heartbeat_age'] : null;
    if ($command['status'] === 'running') {
        ++$running;
        $progressTotal += $command['progress_percent'];
    } elseif ($command['status'] === 'pending') {
        ++$pending;
    }
}
unset($command);
$active = $running + $pending;

echo json_encode([
    'ok' => true,
    'summary' => [
        'active' => $active,
        'running' => $running,
        'pending' => $pending,
        'progress_percent' => $active > 0 ? (int) round($progressTotal / $active) : 0,
    ],
    'commands' => $commands,
], JSON_UNESCAPED_UNICODE);
