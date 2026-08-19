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
require_once __DIR__ . '/../src/agentspeedtier.php';  // VG_AGENT_SPEED_TIER_MAP (공용 정의 — host.php 와 공유)
require_once __DIR__ . '/../src/agentupdate.php';  // vg_agent_release_info (파일 기반 최신 버전)
require_once __DIR__ . '/../src/audit.php';        // vg_log_activity (업데이트 결과 보고)

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

// 에이전트 자동 업데이트 — Nexpose 방식: 폴링마다 자기 버전을 같이 보내고(agent_version),
//   배포된 스크립트 파일(agent-src/vuln-inventory-agent.sh)의 버전보다 낮으면 응답에
//   다운로드 경로 + sha256 을 실어 보낸다. 다운로드 경로는 이 서버의 정본 배포
//   엔드포인트(agent-dl.php) 고정 — 에이전트가 임의 URL 을 받지 않는다.
$reportedVersion = trim((string) ($_GET['agent_version'] ?? ''));
$release = vg_agent_release_info();
$updateFields = ['update_available' => false, 'update_version' => null, 'update_sha256' => null, 'update_download_path' => null];
if ($release !== null && $reportedVersion !== '' && version_compare($reportedVersion, $release['version'], '<')) {
    $updateFields = [
        'update_available'      => true,
        'update_version'        => $release['version'],
        'update_sha256'         => $release['sha256'],
        'update_download_path'  => 'agent-dl.php?f=vuln-inventory-agent.sh',
    ];
}

// 호스트가 아직 한 번도 ingest 되지 않았으면 tb_host 행이 없을 수 있다 — 에러가 아니라 기본값.
$st = $pdo->prepare('SELECT host_id, poll_schedule_seconds, agent_speed_tier FROM tb_host WHERE fqdn = ? AND is_deleted = 0 LIMIT 1');
$st->execute([$fqdn]);
$host = $st->fetch();

// 직전 폴링에서 받은 업데이트를 에이전트가 적용해 본 결과 보고(선택) — 새 요청·새 인바운드
//   경로를 만들지 않고 기존 폴링 GET 에 실어 보내는 방식을 재사용한다.
// 감사로그에 실기 전에 화이트리스트·길이 제한을 건다 — 이 값들은 원격 노드(에이전트)가 채운
//   자유 문자열이라, 제한 없이 그대로 저장하면 감사로그 폭주로 디스크를 채울 수 있다
//   (이 저장소는 실제 binlog 디스크풀 장애 이력이 있다).
$updateResult = vg_audit_redact_text(trim((string) ($_GET['update_result'] ?? '')), 32) ?? '';
if ($updateResult !== '') {
    $fromV = vg_audit_redact_text(trim((string) ($_GET['update_from'] ?? '')), 32) ?? '';
    $toV   = vg_audit_redact_text(trim((string) ($_GET['update_to'] ?? ''))  , 32) ?? '';
    $ok    = $updateResult === 'ok';
    vg_log_activity(
        $pdo, 'HOST', $host ? (int) $host['host_id'] : null, 'agent_auto_update',
        ($ok ? '에이전트 자동 업데이트 성공' : "에이전트 자동 업데이트 실패({$updateResult})") . ": {$fromV} → {$toV}",
        ['from' => $fromV, 'to' => $toV, 'result' => $updateResult], null, 'SYSTEM',
        subject: $fqdn, action: 'UPDATE'
    );
}

if (!$host) {
    $defaultTier = VG_AGENT_SPEED_TIER_MAP['normal'];
    echo json_encode([
        'poll_schedule_seconds'      => 3600,
        'due_command_id'             => null,
        'cpu_quota_percent'          => $defaultTier['cpu_quota_percent'],
        'packaging_timeout_seconds'  => $defaultTier['packaging_timeout_seconds'],
        'mem_max_mb'                 => $defaultTier['mem_max_mb'],
    ] + $updateFields, JSON_UNESCAPED_UNICODE);
    exit;
}

$hostId = (int) $host['host_id'];
$pollScheduleSeconds = (int) $host['poll_schedule_seconds'];
$speedTier = VG_AGENT_SPEED_TIER_MAP[$host['agent_speed_tier']] ?? VG_AGENT_SPEED_TIER_MAP['normal'];

$cmdSt = $pdo->prepare(
    "SELECT agent_command_id FROM tb_agent_command
      WHERE host_id = ? AND status = 'pending' AND is_deleted = 0
        AND (run_at IS NULL OR run_at <= NOW())
      ORDER BY COALESCE(run_at, created_at) ASC LIMIT 1"
);
$cmdSt->execute([$hostId]);
$dueCommandId = $cmdSt->fetchColumn();

echo json_encode([
    'poll_schedule_seconds'      => $pollScheduleSeconds,
    'due_command_id'             => $dueCommandId !== false ? (int) $dueCommandId : null,
    'cpu_quota_percent'          => $speedTier['cpu_quota_percent'],
    'packaging_timeout_seconds'  => $speedTier['packaging_timeout_seconds'],
    'mem_max_mb'                 => $speedTier['mem_max_mb'],
] + $updateFields, JSON_UNESCAPED_UNICODE);
