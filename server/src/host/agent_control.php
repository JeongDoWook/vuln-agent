<?php
declare(strict_types=1);

/**
 * host/agent_control.php — 수집 제어(즉시/예약 실행·주기·속도 티어)와 그 POST 처리.
 *
 *   ⚠ 이 파일은 **include 되는 순간 POST 를 처리한다**(아래 최상위 코드).
 *     host.php 가 GET 렌더보다 먼저, 헤더 출력 전에 require 하는 자리를 그대로 지켜야 한다 —
 *     헤더가 나간 뒤로 밀리면 header('Location: …') 리다이렉트가 깨진다.
 *     처리는 vg_redirect_flash()/exit 로 끝나므로 이 블록은 GET 렌더로 흘러 들어가지 않는다.
 */

// --- 수집 제어 POST 처리 (즉시실행/예약실행/주기변경) — GET 렌더보다 먼저, 헤더 출력 전 ---
//   자산관리(assets)와 같은 인가 범위를 쓴다 — 새 메뉴 코드를 만들지 않는다(YAGNI).
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $agentMsg = null; $agentErr = null;
    $postHostId = (int) ($_GET['id'] ?? $_POST['id'] ?? 0);
    $action = (string) ($_POST['action'] ?? '');
    // 수집 제어·자산 등급·삭제는 자산관리(assets) 권한이고, 탐지 결과의 조치 상태는 이 화면과
    //   같은 findings 권한이다 — 축이 다른 작업을 한 메뉴 권한에 묶지 않는다.
    $postMenu = $action === 'finding_set_status' ? 'findings' : 'assets';
    if (!vg_csrf_check($_POST['csrf'] ?? null)) {
        $agentErr = '세션이 만료되었습니다.';
    } elseif (!vg_can($postMenu)) {
        http_response_code(403);
        echo 'forbidden';
        exit;
    } else {
        $pdo = vg_pdo();
        $me = vg_current_user();
        try {
            if ($action === 'agent_run_now') {
                vg_agent_command_create($pdo, $postHostId, null, $me['id'] ?? null);
                $agentMsg = '즉시 실행 명령을 등록했습니다. 에이전트가 다음 poll 에서 실행합니다.';
            } elseif ($action === 'agent_cancel') {
                vg_agent_command_cancel($pdo, $postHostId, (int) ($_POST['command_id'] ?? 0), $me['id'] ?? null);
                $agentMsg = '수집 중단을 요청했습니다.';
            } elseif ($action === 'agent_schedule') {
                $runAtRaw = trim((string) ($_POST['run_at'] ?? ''));
                if ($runAtRaw === '') {
                    throw new RuntimeException('예약 시각을 입력하세요.');
                }
                // <input type="datetime-local"> 은 'YYYY-MM-DDTHH:MM' 을 준다 — DB 포맷으로 변환.
                $runAt = str_replace('T', ' ', $runAtRaw) . ':00';
                vg_agent_command_create($pdo, $postHostId, $runAt, $me['id'] ?? null);
                $agentMsg = '예약 실행 명령을 등록했습니다.';
            } elseif ($action === 'agent_set_schedule') {
                // 화면은 분 단위로 받고 저장은 초로 환산한다(사람이 시간을 셀 때는 분이 더 익숙하다).
                $minutes = (int) ($_POST['schedule_minutes'] ?? 0);
                vg_agent_command_set_schedule($pdo, $postHostId, $minutes * 60);
                $agentMsg = "수집 주기를 {$minutes}분으로 변경했습니다.";
            } elseif ($action === 'agent_set_speed_tier') {
                if (!vg_has_role('admin', 'operator')) {
                    throw new RuntimeException('속도 티어를 변경할 권한이 없습니다.');
                }
                $tier = (string) ($_POST['agent_speed_tier'] ?? '');
                vg_agent_command_set_speed_tier($pdo, $postHostId, $tier);
                $agentMsg = '속도 티어를 변경했습니다. 다음 poll/다음 수집 시작부터 반영됩니다.';
            } elseif ($action === 'host_set_grade') {
                /* 자산 등급 **확정** — 사람의 판정이다. 시스템 제안(grade_suggested)은 여기서
                 * 건드리지 않고, 확정값만 별도 컬럼에 쓴다. 확정은 관리자만 할 수 있다
                 * (인가는 클라이언트 숨김이 아니라 여기 서버측에서 정해진다). */
                if (!vg_has_role('admin')) {
                    throw new RuntimeException('자산 등급을 확정할 권한이 없습니다.');
                }
                // 등급 검증·기록은 assetgrade.php 의 공통 함수를 재사용하고, 전용 모듈이 구조화
                // 검토 정보까지 같은 트랜잭션으로 묶는다. 일괄 확정은 호스트별 검토 정보에 손대지 않는다.
                //   이 폼은 중요도를 늘 함께 보내므로 빈 값이면 "미지정으로 지움"이 맞다(null 이 아니다).
                $newGrade = (string) ($_POST['grade'] ?? '');
                vg_asset_grade_review_confirm(
                    $pdo,
                    $postHostId,
                    $newGrade,
                    (string) ($_POST['criticality'] ?? ''),
                    (string) ($_POST['grade_reason'] ?? ''),
                    $_POST,
                    $me['id'] ?? null
                );
                $agentMsg = $newGrade === ''
                    ? '자산 등급 확정을 해제했습니다.'
                    : "자산 등급을 {$newGrade} 로 확정했습니다.";
            } elseif ($action === 'finding_set_status') {
                /* 탐지 결과 한 건의 조치 상태. 상태 4개와 메모 한 줄이 전부다 —
                 * 담당자·결재선·재점검 확인은 만들지 않는다(마이그레이션 머리주석 참조).
                 * 쓰기 작업이므로 역할을 서버측에서 확정한다(모달에서 폼을 숨긴 것은 통제가 아니다). */
                if (!vg_has_role('admin', 'operator')) {
                    throw new RuntimeException('조치 상태를 변경할 권한이 없습니다.');
                }
                $fsCve = trim((string) ($_POST['cve_id'] ?? ''));
                $fsPkg = trim((string) ($_POST['package_name'] ?? ''));
                if ($fsCve === '' || $fsPkg === '') {
                    throw new RuntimeException('대상 취약점을 확인할 수 없습니다.');
                }
                $fsRef    = (string) ($_POST['container_ref'] ?? '');
                $fsStatus = (string) ($_POST['status'] ?? '');
                $fsNote   = (string) ($_POST['note'] ?? '');
                vg_finding_status_save($pdo, $postHostId, $fsRef, $fsCve, $fsPkg, $fsStatus, $fsNote, $me['id'] ?? null);
                // 누가 무엇을 어떤 상태로 바꿨는지 남긴다. 메모 원문은 메시지에 싣지 않는다 —
                //   사람이 쓴 문장이라 길이를 예측할 수 없다(남긴 사실은 data 로 충분하다).
                vg_log_activity($pdo, 'HOST', $postHostId, 'finding_set_status',
                    "조치 상태 변경: $fsCve · $fsPkg → " . vg_finding_status_label($fsStatus),
                    ['cve_id' => $fsCve, 'package_name' => $fsPkg, 'container_ref' => $fsRef,
                     'status' => $fsStatus, 'note_len' => mb_strlen(trim($fsNote))],
                    $me['id'] ?? null, subject: $fsCve, action: 'UPDATE');
                $agentMsg = $fsCve . ' 의 조치 상태를 ' . vg_finding_status_label($fsStatus) . ' 로 저장했습니다.';
            } elseif ($action === 'host_delete') {
                if (!vg_has_role('admin', 'operator')) {
                    throw new RuntimeException('자산을 삭제할 권한이 없습니다.');
                }
                $st = $pdo->prepare('SELECT fqdn FROM tb_host WHERE host_id = ? AND is_deleted = 0');
                $st->execute([$postHostId]);
                $fqdn = $st->fetchColumn();
                if ($fqdn === false) {
                    throw new RuntimeException('호스트를 찾을 수 없습니다.');
                }
                vg_soft_delete($pdo, 'tb_host', $postHostId);
                vg_log_activity($pdo, 'HOST', $postHostId, 'host_delete', "자산 삭제: $fqdn",
                    subject: (string) $fqdn, action: 'DELETE');
                $_SESSION['vg_flash'] = [
                    'assetMsg' => "자산 '$fqdn' 을(를) 삭제했습니다. 해당 호스트가 다시 수집을 보내면 재등록됩니다.",
                ];
                header('Location: /assets.php', true, 303);
                exit;
            }
        } catch (Throwable $e) {
            error_log('[host-agent-command] ' . $e->getMessage());
            $agentErr = $e instanceof RuntimeException ? $e->getMessage() : '처리 중 오류가 발생했습니다.';
        }
    }
    vg_redirect_flash(['agentMsg' => $agentMsg, 'agentErr' => $agentErr]);
}

/**
 * 수집 제어 카드 — 즉시실행/예약실행/주기변경 폼 + 예약된 명령 미니 목록.
 *   agent-command-queue-api 워커가 만드는 명령 큐(tb_agent_command)에 등록만 한다.
 *   실제 poll·실행은 데몬화된 에이전트 쪽 책임.
 */
function vg_host_render_agent_control(
    int $hostId, array $host, string $csrf, array $agentCommands, ?string $msg, ?string $err
): void {
    $curMinutes = (int) round(((int) ($host['poll_schedule_seconds'] ?? 3600)) / 60);
    $curSpeedTier = (string) ($host['agent_speed_tier'] ?? 'normal');
    $speedTierLabels = [];
    foreach (VG_AGENT_SPEED_TIERS as $t) { $speedTierLabels[$t] = vg_agent_speed_tier_label($t); }
    ?>
    <section class="card agent-control" aria-labelledby="agent-control-title">
      <div class="agent-control__heading">
        <div>
          <strong id="agent-control-title">수집 제어</strong>
        </div>
        <span class="agent-control__status"><span aria-hidden="true"></span>다음 poll 반영</span>
      </div>
      <div class="card__body">
        <?php /* 이 명령의 처리 결과(등록/중단/오류)는 이 카드가 아니라 host.php 가 페이지
                 레벨에서 한 번만 알린다 — 이 카드를 볼 권한(assets)이 없는 계정도 자기 조작
                 결과(예: 조치 상태 저장)는 봐야 하므로, 카드 안에 가둘 수 없다. */ ?>
        <div class="agent-control__facts">
          <span><b>통신 경로</b> <?= vg_h((string)($_SERVER['HTTP_HOST'] ?? '중앙 서버')) ?> · poll 10초</span>
          <span><b>정기 수집</b> <?= number_format($curMinutes) ?>분마다 · 에이전트 로컬 스케줄 기준</span>
        </div>
        <?php $activeCommand = $agentCommands[0] ?? null; ?>
        <?php if ($activeCommand): ?>
          <?php
            $isRunning = $activeCommand['status'] === 'running';
            $pct = $isRunning ? (int) ($activeCommand['progress_percent'] ?? 0) : 0;
            $stageMessage = $isRunning
                ? ((string) ($activeCommand['progress_message'] ?: '수집을 진행하고 있습니다.'))
                : ($activeCommand['run_at'] ? '예약 시각이 되면 다음 poll에서 시작합니다.' : '에이전트의 다음 poll을 기다리고 있습니다.');
          ?>
          <div class="agent-progress" data-agent-progress data-host-id="<?= $hostId ?>" data-command-id="<?= (int)$activeCommand['agent_command_id'] ?>" data-state="<?= vg_h((string)$activeCommand['status']) ?>">
            <div class="agent-progress__top">
              <strong data-progress-title><?= $isRunning ? '수집 진행 중' : '명령 대기 중' ?></strong>
              <span data-progress-percent><?= $pct ?>%</span>
            </div>
            <progress class="agent-progress__track" data-progress-bar max="100" value="<?= $pct ?>"><?= $pct ?>%</progress>
            <div class="agent-progress__meta">
              <span data-progress-message><?= vg_h($stageMessage) ?></span>
              <span data-progress-time><?= $isRunning && $activeCommand['heartbeat_at'] ? '마지막 통신 ' . vg_h((string)$activeCommand['heartbeat_at']) : 'poll 주기 10초 이내' ?></span>
            </div>
            <form method="post" data-confirm="이 수집 작업을 중단할까요?">
              <input type="hidden" name="csrf" value="<?= vg_h($csrf) ?>">
              <input type="hidden" name="action" value="agent_cancel">
              <input type="hidden" name="id" value="<?= (int)$hostId ?>">
              <input type="hidden" name="command_id" value="<?= (int)$activeCommand['agent_command_id'] ?>">
              <button class="btn btn--sm btn--ghost" type="submit"><?= $isRunning ? '수집 중단' : '명령 취소' ?></button>
            </form>
          </div>
        <?php endif; ?>
        <div class="actions actions--stack">
          <form class="agent-control__row" method="post" data-confirm="지금 이 호스트의 스캔을 실행할까요?">
            <input type="hidden" name="csrf" value="<?= vg_h($csrf) ?>">
            <input type="hidden" name="action" value="agent_run_now">
            <input type="hidden" name="id" value="<?= (int) $hostId ?>">
            <?php /* 각 조작의 반영 시점은 카드 머리의 '다음 poll 반영' 배지가 한 번에 말한다 —
                     줄마다 되풀이하면 정작 다른 제약(최소 1분 등)이 묻힌다. */ ?>
            <label><strong>즉시 실행</strong></label>
            <button class="btn btn--sm btn--primary">지금 실행</button>
          </form>

          <form class="agent-control__row" method="post">
            <input type="hidden" name="csrf" value="<?= vg_h($csrf) ?>">
            <input type="hidden" name="action" value="agent_schedule">
            <input type="hidden" name="id" value="<?= (int) $hostId ?>">
            <label for="agent-run-at"><strong>예약 실행</strong></label>
            <input id="agent-run-at" type="datetime-local" name="run_at" min="<?= date('Y-m-d\TH:i') ?>" required>
            <button class="btn btn--sm btn--ghost">등록</button>
          </form>

          <form class="agent-control__row" method="post">
            <input type="hidden" name="csrf" value="<?= vg_h($csrf) ?>">
            <input type="hidden" name="action" value="agent_set_schedule">
            <input type="hidden" name="id" value="<?= (int) $hostId ?>">
            <label for="agent-schedule-minutes"><strong>수집 주기</strong><span>최소 1분</span></label>
            <div class="agent-control__number"><input id="agent-schedule-minutes" type="number" name="schedule_minutes" min="1" value="<?= $curMinutes ?>" required><span>분</span></div>
            <button class="btn btn--sm btn--ghost">저장</button>
          </form>

          <form class="agent-control__row" method="post">
            <input type="hidden" name="csrf" value="<?= vg_h($csrf) ?>">
            <input type="hidden" name="action" value="agent_set_speed_tier">
            <input type="hidden" name="id" value="<?= (int) $hostId ?>">
            <label for="agent-speed-tier"><strong>속도 티어</strong></label>
            <select id="agent-speed-tier" name="agent_speed_tier">
              <?php foreach ($speedTierLabels as $v => $label): ?>
                <option value="<?= vg_h($v) ?>"<?= $curSpeedTier === $v ? ' selected' : '' ?>><?= vg_h($label) ?></option>
              <?php endforeach; ?>
            </select>
            <button class="btn btn--sm btn--ghost">저장</button>
          </form>
        </div>

        <?php if ($agentCommands): ?>
          <div class="mt-lg">
            <strong class="why">예약된 명령</strong>
            <ul class="hint-list">
              <?php foreach ($agentCommands as $c): ?>
                <li>
                  <?= $c['status'] === 'running' ? '수집 실행 중' : ($c['run_at'] === null ? '즉시 실행 대기중' : vg_h((string) $c['run_at']) . ' 예약') ?>
                  <span class="why">(등록 <?= vg_h((string) $c['created_at']) ?>)</span>
                </li>
              <?php endforeach; ?>
            </ul>
          </div>
        <?php endif; ?>
      </div>
    </section>
    <?php
}
