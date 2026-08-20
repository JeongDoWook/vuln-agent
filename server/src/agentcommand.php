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
require_once __DIR__ . '/agentspeedtier.php';

const VG_AGENT_COMMAND_MIN_SCHEDULE_SECONDS = 30;

/**
 * 즉시/예약 명령을 큐에 넣는다. $runAt 이 null 이면 즉시(다음 폴링 때 바로 수행 대상).
 *   과거 시각을 예약하면 거부한다 — 그런 명령은 "즉시"와 구별할 이유가 없고, 의도치 않은
 *   과거 입력을 조용히 즉시실행으로 흘리면 사용자가 예약이 걸렸다고 착각하게 된다.
 *   $verifyFiles 는 이 실행 한 번에만 패키지 무결성 검사(rpm -Va / dpkg --verify)를 붙인다.
 *   기본 false 다 — 설치된 모든 파일을 해시해 대상 서버에 수 분간 부하가 걸리므로, 켜는 것은
 *   언제나 사람의 명시적 선택이어야 한다(에이전트의 대전제: 대상 서버에 무리를 주지 않는다).
 * @return int 생성된 agent_command_id
 */
function vg_agent_command_create(PDO $pdo, int $hostId, ?string $runAt, ?int $userId, bool $verifyFiles = false): int {
    $st = $pdo->prepare('SELECT 1 FROM tb_host WHERE host_id = ? AND is_deleted = 0');
    $st->execute([$hostId]);
    if ($st->fetchColumn() === false) {
        throw new RuntimeException('호스트를 찾을 수 없습니다.');
    }

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
        'INSERT INTO tb_agent_command (host_id, run_at, verify_files, created_by) VALUES (?, ?, ?, ?)'
    )->execute([$hostId, $runAtNormalized, $verifyFiles ? 1 : 0, $userId]);
    $commandId = (int) $pdo->lastInsertId();

    // 무결성 포함 여부를 감사로그 메시지에 남긴다 — 대상 서버에 수 분간 부하를 거는 동작이라
    //   누가 언제 걸었는지가 사후에 반드시 필요하다(data 에만 두면 목록에서 안 보인다).
    $verifyNote = $verifyFiles ? ' · 무결성 검사 포함' : '';
    vg_log_activity(
        $pdo, 'HOST', $hostId,
        $runAtNormalized === null ? 'agent_command_immediate' : 'agent_command_scheduled',
        ($runAtNormalized === null ? '즉시 실행 명령 등록' : "예약 실행 명령 등록 ({$runAtNormalized})") . $verifyNote,
        ['agent_command_id' => $commandId, 'run_at' => $runAtNormalized, 'verify_files' => $verifyFiles ? 1 : 0],
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

    $pdo->prepare('UPDATE tb_host SET poll_schedule_seconds = ? WHERE host_id = ? AND is_deleted = 0')
        ->execute([$seconds, $hostId]);

    vg_log_activity(
        $pdo, 'HOST', $hostId, 'agent_schedule_change',
        "폴링 주기 변경 → {$seconds}초",
        ['poll_schedule_seconds' => $seconds],
        null
    );
}

/**
 * 호스트별 에이전트 CPU 상한·조립 타임아웃 티어를 바꾼다. 실제 값 매핑은 agentspeedtier.php 가
 *   가지고 있고, 변경은 다음 poll/다음 수집 시작부터 반영된다(즉시 적용 아님 — 호출부가 안내).
 * UPDATE 전에 host 존재/미삭제를 확인한다 — 없으면 예외를 던져 무조건 감사로그를 남기지 않는다
 *   (존재하지 않거나 이미 삭제된 host_id 로 반복 호출해 허위 로그를 무한 주입하는 것을 막는다).
 *   rowCount() 로는 이 확인이 안 된다 — PDO_MYSQL 은 기본으로 "matched" 가 아니라 "changed"
 *   행수를 돌려주므로, 이미 같은 티어라 값이 안 바뀌면 정상 호출도 0으로 나와 오탐이 난다.
 */
function vg_agent_command_set_speed_tier(PDO $pdo, int $hostId, string $tier): void {
    if (!in_array($tier, VG_AGENT_SPEED_TIERS, true)) {
        throw new RuntimeException('알 수 없는 속도 티어입니다.');
    }

    $st = $pdo->prepare('SELECT 1 FROM tb_host WHERE host_id = ? AND is_deleted = 0');
    $st->execute([$hostId]);
    if ($st->fetchColumn() === false) {
        throw new RuntimeException('호스트를 찾을 수 없습니다.');
    }

    $pdo->prepare('UPDATE tb_host SET agent_speed_tier = ? WHERE host_id = ? AND is_deleted = 0')
        ->execute([$tier, $hostId]);

    vg_log_activity(
        $pdo, 'HOST', $hostId, 'agent_speed_tier_change',
        "속도 티어 변경 → {$tier}",
        ['agent_speed_tier' => $tier],
        null
    );
}

function vg_agent_command_cancel(PDO $pdo, int $hostId, int $commandId, ?int $userId): void {
    $st = $pdo->prepare("SELECT status FROM tb_agent_command WHERE agent_command_id=? AND host_id=? AND status IN ('pending','running') AND is_deleted=0");
    $st->execute([$commandId, $hostId]);
    $status = $st->fetchColumn();
    if ($status === false) { throw new RuntimeException('중단할 수집 작업을 찾을 수 없습니다.'); }
    if ($status === 'pending') {
        $pdo->prepare("UPDATE tb_agent_command SET status='cancelled', cancel_requested_at=NOW(), cancelled_at=NOW(), executed_at=NOW(), progress_message='실행 전에 취소했습니다.' WHERE agent_command_id=?")->execute([$commandId]);
    } else {
        $pdo->prepare("UPDATE tb_agent_command SET cancel_requested_at=NOW(), progress_message='중단 요청을 에이전트에 전달하고 있습니다.' WHERE agent_command_id=?")->execute([$commandId]);
    }
    vg_log_activity($pdo, 'HOST', $hostId, 'agent_command_cancel', '수집 작업 중단 요청', ['agent_command_id' => $commandId], $userId);
}
