<?php
declare(strict_types=1);

/**
 * agentcommand.php — 에이전트 명령 큐 생성/조회, 폴링 주기 변경 헬퍼.
 *   인가(vg_require_menu)·CSRF·폼 렌더링은 호출부(화면 코드) 책임이다 — 여기선 순수 로직만.
 *   agent-poll.php(조회) 와 ingest.php(완료 처리) 가 이 테이블을 함께 쓴다.
 */

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/audit.php';

const VG_AGENT_COMMAND_MIN_SCHEDULE_SECONDS = 30;

/**
 * 즉시/예약 명령을 큐에 넣는다. $runAt 이 null 이면 즉시(다음 폴링 때 바로 수행 대상).
 *   과거 시각을 예약하면 거부한다 — 그런 명령은 "즉시"와 구별할 이유가 없고, 의도치 않은
 *   과거 입력을 조용히 즉시실행으로 흘리면 사용자가 예약이 걸렸다고 착각하게 된다.
 * @return int 생성된 agent_command_id
 */
function vg_agent_command_create(PDO $pdo, int $hostId, ?string $runAt, ?int $userId): int {
    $runAtNormalized = null;
    if ($runAt !== null && trim($runAt) !== '') {
        $ts = strtotime($runAt);
        if ($ts === false) {
            throw new RuntimeException('예약 시각 형식이 올바르지 않습니다.');
        }
        if ($ts < time()) {
            throw new RuntimeException('예약 시각은 현재보다 미래여야 합니다.');
        }
        $runAtNormalized = date('Y-m-d H:i:s', $ts);
    }

    $pdo->prepare(
        'INSERT INTO tb_agent_command (host_id, run_at, created_by) VALUES (?, ?, ?)'
    )->execute([$hostId, $runAtNormalized, $userId]);
    $commandId = (int) $pdo->lastInsertId();

    vg_log_activity(
        $pdo, 'HOST', $hostId,
        $runAtNormalized === null ? 'agent_command_immediate' : 'agent_command_scheduled',
        $runAtNormalized === null ? '즉시 실행 명령 등록' : "예약 실행 명령 등록 ({$runAtNormalized})",
        ['agent_command_id' => $commandId, 'run_at' => $runAtNormalized],
        $userId
    );

    return $commandId;
}

/**
 * 호스트의 폴링 주기를 바꾼다. 최소값 미만은 거부 — 너무 짧으면 상시 데몬이 중앙에
 *   폭주 요청을 보낸다(레이트리밋과 별개로 애초에 그런 설정을 못 걸게 막는다).
 */
function vg_agent_command_set_schedule(PDO $pdo, int $hostId, int $seconds): void {
    if ($seconds < VG_AGENT_COMMAND_MIN_SCHEDULE_SECONDS) {
        throw new RuntimeException('폴링 주기는 최소 ' . VG_AGENT_COMMAND_MIN_SCHEDULE_SECONDS . '초 이상이어야 합니다.');
    }

    $pdo->prepare('UPDATE tb_host SET poll_schedule_seconds = ? WHERE host_id = ?')
        ->execute([$seconds, $hostId]);

    vg_log_activity(
        $pdo, 'HOST', $hostId, 'agent_schedule_change',
        "폴링 주기 변경 → {$seconds}초",
        ['poll_schedule_seconds' => $seconds],
        null
    );
}
