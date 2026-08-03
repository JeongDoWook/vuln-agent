<?php
declare(strict_types=1);

/**
 * agentcommand.php — 에이전트 명령 큐 헬퍼 2종.
 *   즉시/예약 실행 명령을 tb_agent_command 에 넣고(vg_agent_command_create),
 *   호스트별 poll 주기를 tb_host.poll_schedule_seconds 로 바꾼다(vg_agent_command_set_schedule).
 *   실제 실행·poll 은 데몬화된 에이전트/큐 API 쪽(다른 워커) 책임 — 여기는 큐에 넣기만 한다.
 */

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/audit.php';   // vg_log_activity

/**
 * 명령 등록. $runAt=null 이면 즉시 실행(에이전트가 다음 poll 에서 바로 집어간다).
 *   과거 시각을 예약하면 의미가 없으므로(등록 즉시 지난 시각) 거부한다.
 *   반환값은 새로 생성된 tb_agent_command 행의 id.
 */
function vg_agent_command_create(PDO $pdo, int $hostId, ?string $runAt, ?int $userId): int {
    if ($runAt !== null) {
        $ts = strtotime($runAt);
        if ($ts === false) {
            throw new RuntimeException('예약 시각 형식이 올바르지 않습니다.');
        }
        if ($ts < time()) {
            throw new RuntimeException('예약 시각은 현재보다 이후여야 합니다.');
        }
    }

    $st = $pdo->prepare(
        'INSERT INTO tb_agent_command (host_id, run_at, status, created_by)
         VALUES (?, ?, ?, ?)'
    );
    $st->execute([$hostId, $runAt, 'pending', $userId]);
    $id = (int) $pdo->lastInsertId();

    vg_log_activity(
        $pdo, 'AGENT_COMMAND', $id,
        $runAt === null ? 'agent_command_run_now' : 'agent_command_schedule',
        $runAt === null ? '즉시 실행 명령 등록' : "예약 실행 명령 등록: {$runAt}",
        ['host_id' => $hostId, 'run_at' => $runAt],
        $userId
    );

    return $id;
}

/**
 * 호스트별 poll 주기(초) 변경. 30초 미만은 에이전트에 과도한 부하를 주므로 거부한다.
 */
function vg_agent_command_set_schedule(PDO $pdo, int $hostId, int $seconds): void {
    if ($seconds < 30) {
        throw new RuntimeException('수집 주기는 최소 30초 이상이어야 합니다.');
    }

    $st = $pdo->prepare('UPDATE tb_host SET poll_schedule_seconds = ? WHERE host_id = ? AND is_deleted = 0');
    $st->execute([$seconds, $hostId]);

    vg_log_activity(
        $pdo, 'AGENT_COMMAND', $hostId, 'agent_command_set_schedule',
        "수집 주기 변경: {$seconds}초",
        ['host_id' => $hostId, 'poll_schedule_seconds' => $seconds]
    );
}
