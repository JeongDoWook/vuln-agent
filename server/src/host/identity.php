<?php
declare(strict_types=1);

/**
 * host/identity.php — 자산 상세의 **식별부** 조회. "이 자산이 무엇인가"에 답하는 값들만 있다.
 *   호스트 행 · 등급 확정자 · 에이전트 연결(poll) · 대기 중인 수집 명령 · 최신 스캔 ·
 *   함대 최신 에이전트 버전. 탭과 무관하게 항상 읽는 값이라 탭별 조회층(queries.php)과 나눈다.
 *
 *   각 함수는 SQL 하나만 갖는다 — 호출 순서·권한 판단(vg_can)·감사로그는 host.php 가 갖는다
 *   (조회층이 인가를 대신 판단하면 화면마다 규칙이 갈린다).
 */

/** 호스트 한 행. 삭제된 자산은 없는 것으로 본다(상세 화면도 열리지 않는다). */
function vg_host_find(PDO $pdo, int $hostId): ?array {
    $st = $pdo->prepare('SELECT * FROM tb_host WHERE host_id = ? AND is_deleted = 0');
    $st->execute([$hostId]);
    return $st->fetch() ?: null;
}

/** 등급 확정자 이름(승인 이력) — 사용자가 지워졌으면 FK 가 NULL 이라 여기 안 들어온다. */
function vg_host_load_approver(PDO $pdo, array $host): ?string {
    if (empty($host['approved_by'])) { return null; }
    $st = $pdo->prepare('SELECT username FROM tb_user WHERE user_id = ?');
    $st->execute([(int) $host['approved_by']]);
    $u = $st->fetchColumn();
    return $u === false ? null : (string) $u;
}

/** 에이전트 연결 상태는 수집 실행 시각이 아니라 10초 poll의 마지막 통신으로 판단한다. */
function vg_host_load_poll_age(PDO $pdo, string $fqdn): ?int {
    $st = $pdo->prepare(
        'SELECT TIMESTAMPDIFF(MINUTE, MAX(last_seen_at), NOW())
           FROM tb_agent_token
          WHERE host_fqdn = ? AND is_revoked = 0 AND is_deleted = 0'
    );
    $st->execute([$fqdn]);
    $lastPollAge = $st->fetchColumn();
    return $lastPollAge !== null && $lastPollAge !== false ? (int) $lastPollAge : null;
}

/** 아직 끝나지 않은 수집 명령(예약·실행 중) — 자산 설정 탭의 진행 표시가 이 목록을 읽는다. */
function vg_host_load_pending_commands(PDO $pdo, int $hostId): array {
    $st = $pdo->prepare(
        "SELECT agent_command_id, status, progress_percent, progress_stage, progress_message,
                run_at, created_at, started_at, heartbeat_at, cancel_requested_at
           FROM tb_agent_command
          WHERE host_id = ? AND status IN ('pending','running') AND is_deleted = 0
          ORDER BY status = 'running' DESC, run_at IS NULL DESC, run_at, created_at"
    );
    $st->execute([$hostId]);
    return $st->fetchAll();
}

/**
 * 이 호스트의 최신 스캔 한 행.
 *
 *   컬럼을 못 박는 이유: tb_scan.raw_json 은 호스트당 MB 단위(실측 3.14MB)라
 *   SELECT * 로 끌면 ORDER BY 의 정렬 버퍼(운영 sort_buffer_size=2M)를 한 행만으로도 넘겨 1038 이 난다.
 *   agent_version 은 자산 목록에서 이 화면으로 옮겨 온 값이다(목록은 열어볼지 말지를
 *     정하는 열만 둔다) — 식별부에서 '이 자산이 무엇인가'의 일부로 보여준다.
 */
function vg_host_load_latest_scan(PDO $pdo, int $hostId): ?array {
    $st = $pdo->prepare('SELECT scan_id, collected_at, package_count, agent_version,
                                integrity_checked, integrity_partial, integrity_total,
                                TIMESTAMPDIFF(MINUTE, collected_at, NOW()) AS age_min
                           FROM tb_scan WHERE host_id = ? ORDER BY scan_id DESC LIMIT 1');
    $st->execute([$hostId]);
    return $st->fetch() ?: null;
}

/**
 * 함대에서 관측된 가장 높은 에이전트 버전 — 이보다 낮으면 이 호스트만 옛 에이전트가
 *   돈다는 뜻이다. 중앙은 노드에 내려보내지 않으므로(노드가 밀어 올리기만 한다) 에이전트를
 *   고쳐도 각 노드에 다시 깔 때까지 옛 코드가 계속 돈다 — 실제로 몇 주를 못 알아챈 적이 있어
 *   숫자만이 아니라 '구버전' 신호가 필요하다. 기준을 코드에 박지 않고 관측된 최댓값으로
 *   잡는다(웹 컨테이너는 agent/ 를 마운트하지 않아 저장소 버전을 읽을 수 없다).
 *   버전은 '2.10' > '2.9' 라 문자열 비교로는 틀린다 → version_compare.
 */
function vg_host_load_latest_agent_version(PDO $pdo): string {
    return (string) array_reduce(
        $pdo->query("SELECT DISTINCT agent_version FROM tb_scan
                      WHERE agent_version IS NOT NULL AND agent_version <> '' AND is_deleted = 0"
        )->fetchAll(PDO::FETCH_COLUMN),
        static fn(?string $max, string $v) => ($max === null || version_compare($v, $max, '>')) ? $v : $max
    );
}
