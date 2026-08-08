<?php
declare(strict_types=1);

/**
 * host.php — 호스트 상세(자산 상세). 로그인 필요.
 *   ?id=<host_id> 의 최신 스캔을 하나의 자산 화면으로 보여준다.
 *   상단: 자산 식별 + 최고 위험도 히어로 + KPI.
 *   그 아래 섹션 탭(취약점 / 런타임 / 보안설정 / 억제 / 스캔이력) — 각 탭이 자기 데이터를
 *   서버 페이지네이션한다. ?tab= 이 활성 탭, ?page= 는 그 활성 탭에만 적용된다.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require __DIR__ . '/../src/distro.php';   // vg_distro_unsupported — 피드 미지원 배포판 경고
require_once __DIR__ . '/../src/audit.php';   // vg_log_activity
require_once __DIR__ . '/../src/matcher.php';
require_once __DIR__ . '/../src/agentcommand.php';   // 수집 제어(즉시/예약 실행·주기 변경)
require_once __DIR__ . '/../src/agentspeedtier.php';   // 속도 티어 라벨(agent-poll.php 와 공유 정의)
vg_require_menu('findings');

// --- 수집 제어 POST 처리 (즉시실행/예약실행/주기변경) — GET 렌더보다 먼저, 헤더 출력 전 ---
//   자산관리(assets)와 같은 인가 범위를 쓴다 — 새 메뉴 코드를 만들지 않는다(YAGNI).
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $agentMsg = null; $agentErr = null;
    $postHostId = (int) ($_GET['id'] ?? $_POST['id'] ?? 0);
    if (!vg_csrf_check($_POST['csrf'] ?? null)) {
        $agentErr = '세션이 만료되었습니다.';
    } elseif (!vg_can('assets')) {
        http_response_code(403);
        echo 'forbidden';
        exit;
    } else {
        $pdo = vg_pdo();
        $me = vg_current_user();
        $action = (string) ($_POST['action'] ?? '');
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
$agentFlash = vg_flash_take();
$agentMsg = $agentFlash['agentMsg'] ?? null;
$agentErr = $agentFlash['agentErr'] ?? null;
$agentCsrf = vg_csrf_token();

$err = null; $host = null; $scan = null; $scanAge = null; $pollAge = null;
$unsupContainers = [];   // 피드 미지원 배포판 컨테이너
$missingStages = [];     // 최신 스캔에서 수집 자체가 실패한 단계(한글 라벨)

// 재시작·재부팅 표에 보여줄 최대 건수. 나머지는 취약점 현황(fx=restart)으로 넘긴다.


// 리소스 추이 차트에 그릴 최대 스캔 건수(최근 것부터).


// --- 탭별 데이터 조회 (?tab= 에 따라 갈리는 SQL). 각자 {total, rows, ...} 형태의 배열을 반환한다. ---

function vg_host_load_vuln_tab(PDO $pdo, int $sid, int $critHighTotal, int $perPage, int $offset, ?string $q = null): array {
    /* 성격이 다른 두 부류를 한 목록에 섞고 페이지를 나누면, 어느 한쪽은 반드시 뒤로 밀린다.
     *   - 등급순으로 정렬했더니: 커널 재부팅 건(등급이 낮다)이 2페이지로 밀려 사라졌다.
     *   - 그래서 needs_restart 를 맨 위로 올렸더니: 이번엔 **CRITICAL 이 안 보였다**
     *     (실측: web01 은 재시작 필요 건이 앞을 다 채워 CRITICAL 2건이 44페이지 뒤로 갔다).
     * 정렬로는 못 푼다 — 표를 둘로 나눈다. 각자 자기 기준으로 정렬하고, 둘 다 첫 화면에 있다.
     *   표1(주 목록·페이지네이션): CRITICAL·HIGH — 등급 → EPSS 순
     *   표2(상위 N건 + 전체보기):  재시작·재부팅 필요 — 등급이 낮아도 놓치면 안 되는 부류
     *                              (이미 패치됐는데 옛 코드가 상주해 "패치됨"으로 사라진다)
     * 검색(q)은 표1(주 목록)에만 적용한다 — 표2는 "상위 N건은 놓치지 않는다"가 목적이라
     *   필터링하면 그 의도와 충돌한다.
     */
    $sel = "SELECT f.severity, f.runtime_status, f.cve_id, f.package_name, f.installed_version, f.rationale,
                   f.needs_restart, f.container_id, c.epss, c.epss_percentile, c.ref_urls_json,
               " . VG_FIXED_VERSION_SUBQ . "
              FROM tb_finding f LEFT JOIN tb_cve c ON c.cve_id = f.cve_id";

    $where = "f.scan_id = ? AND f.severity IN ('CRITICAL','HIGH')";
    $params = [$sid];
    if ($q !== null && $q !== '') {
        $where .= ' AND (f.cve_id LIKE ? OR f.package_name LIKE ?)';
        $params[] = '%' . $q . '%';
        $params[] = '%' . $q . '%';
    }

    if ($q !== null && $q !== '') {
        $cnt = $pdo->prepare("SELECT COUNT(*) FROM tb_finding f WHERE $where");
        $cnt->execute($params);
        $total = (int) $cnt->fetchColumn();
    } else {
        $total = $critHighTotal;
    }

    $st = $pdo->prepare(
        "$sel WHERE $where
         ORDER BY FIELD(f.severity,'CRITICAL','HIGH'), c.epss DESC, f.cve_id
         LIMIT $perPage OFFSET $offset"
    );
    $st->execute($params);
    $rows = $st->fetchAll();

    $st = $pdo->prepare(
        "$sel WHERE f.scan_id = ? AND f.needs_restart = 1
         ORDER BY FIELD(f.severity,'CRITICAL','HIGH','MEDIUM','LOW'), c.epss DESC, f.cve_id
         LIMIT " . vg_ui_detail_preview_limit()
    );
    $st->execute([$sid]);
    $restartRows = $st->fetchAll();

    return ['total' => $total, 'rows' => $rows, 'restartRows' => $restartRows];
}

function vg_host_load_runtime_tab(PDO $pdo, int $sid, int $perPage, int $offset, int $ePage, ?string $q = null): array {
    // 노출·프로세스 모두 건수가 늘 수 있어 각자 페이지네이션한다(노출은 ?epage=, 프로세스는 ?page=).
    // 컨테이너 안의 프로세스·포트도 여기 함께 있다(container_id > 0).
    //   출처를 표시하지 않으면 컨테이너의 nginx 가 호스트의 nginx 처럼 보인다 → "위치" 열.
    $q = ($q !== null && $q !== '') ? $q : null;

    $eWhere = 'e.scan_id = ?';
    $eParams = [$sid];
    if ($q !== null) {
        $eWhere .= ' AND (e.proc LIKE ? OR e.exe_pkg LIKE ?)';
        $eParams[] = '%' . $q . '%';
        $eParams[] = '%' . $q . '%';
    }
    $cnt = $pdo->prepare("SELECT COUNT(*) FROM tb_exposure e WHERE $eWhere");
    $cnt->execute($eParams);
    $exposureTotal = (int) $cnt->fetchColumn();

    // vg_toolbar() 의 기본 "초기화" 링크는 page 만 지우고 epage 는 모른다(공용 컴포넌트, 이번
    //   범위에서 손 안 댐) — 검색 초기화 후에도 epage 가 URL 에 남을 수 있다. 그 값을 신뢰해
    //   그대로 OFFSET 에 쓰면 총건수를 넘겨 빈 표가 뜬다. 여기서 유효 범위로 접어 방어한다.
    $eMaxPage = max(1, (int) ceil($exposureTotal / $perPage));
    if ($ePage > $eMaxPage) { $ePage = $eMaxPage; }
    $eOffset = ($ePage - 1) * $perPage;

    $st = $pdo->prepare("SELECT e.proc, e.proto, e.bind_addr, e.port, e.scope, e.exe_pkg, e.loaded_pkgs,
                                IFNULL(c.cid, '') AS ctr
                           FROM tb_exposure e LEFT JOIN tb_container c ON c.container_id = e.container_id
                          WHERE $eWhere
                          ORDER BY FIELD(e.scope,'EXTERNAL','LAN','BOUND','FILTERED','LOCAL','-'), e.port
                          LIMIT $perPage OFFSET $eOffset");
    $st->execute($eParams);
    $exposures = $st->fetchAll();

    $pWhere = 'p.scan_id = ?';
    $pParams = [$sid];
    if ($q !== null) {
        $pWhere .= ' AND (p.comm LIKE ? OR p.username LIKE ? OR p.exe_pkg LIKE ?)';
        $pParams[] = '%' . $q . '%';
        $pParams[] = '%' . $q . '%';
        $pParams[] = '%' . $q . '%';
    }
    $cnt = $pdo->prepare("SELECT COUNT(*) FROM tb_process p WHERE $pWhere");
    $cnt->execute($pParams);
    $total = (int) $cnt->fetchColumn();

    $st = $pdo->prepare("SELECT p.pid, p.comm, p.username, p.exe_pkg, p.loaded_pkgs,
                                IFNULL(c.cid, '') AS ctr
                           FROM tb_process p LEFT JOIN tb_container c ON c.container_id = p.container_id
                          WHERE $pWhere ORDER BY p.comm LIMIT $perPage OFFSET $offset");
    $st->execute($pParams);
    $rows = $st->fetchAll();

    return ['total' => $total, 'exposures' => $exposures, 'exposureTotal' => $exposureTotal, 'rows' => $rows, 'ePage' => $ePage];
}

function vg_host_load_cce_tab(PDO $pdo, int $sid, int $perPage, int $offset, ?string $q = null): array {
    $where = 'f.scan_id = ?';
    $params = [$sid];
    if ($q !== null && $q !== '') {
        $where .= ' AND (f.code LIKE ? OR f.title LIKE ? OR f.ssg_rule_id LIKE ?)';
        $params[] = '%' . $q . '%';
        $params[] = '%' . $q . '%';
        $params[] = '%' . $q . '%';
    }
    $st = $pdo->prepare("SELECT COUNT(*) FROM tb_cce_finding f WHERE $where");
    $st->execute($params); $total = (int) $st->fetchColumn();
    // 점검 항목을 **검증된 룰셋(SSG)** 에 묶어 두었으므로, 그 룰의 기준 참조(CIS/NIST/STIG)를
    //   함께 읽어 화면이 근거를 인용할 수 있게 한다. 묶이지 않은 항목은 refs 가 비어 있다.
    $st = $pdo->prepare(
        "SELECT f.code, f.ssg_rule_id, f.title, f.result, f.severity, f.evidence, f.rationale,
                r.refs_json, r.title AS ssg_title
           FROM tb_cce_finding f
           LEFT JOIN tb_compliance_rule r ON r.rule_id = f.ssg_rule_id AND r.is_deleted = 0
          WHERE $where
          ORDER BY FIELD(f.result,'FAIL','NA','PASS'), FIELD(f.severity,'HIGH','MEDIUM','LOW'), f.code
          LIMIT $perPage OFFSET $offset"
    );
    $st->execute($params);
    $rows = $st->fetchAll();

    return ['total' => $total, 'rows' => $rows];
}

function vg_host_load_suppressed_tab(PDO $pdo, int $sid, int $suppressedCount, int $perPage, int $offset, ?string $q = null): array {
    $where = 'sf.scan_id = ?';
    $params = [$sid];
    if ($q !== null && $q !== '') {
        $where .= ' AND (sf.cve_id LIKE ? OR sf.package_name LIKE ?)';
        $params[] = '%' . $q . '%';
        $params[] = '%' . $q . '%';
    }

    if ($q !== null && $q !== '') {
        $cnt = $pdo->prepare("SELECT COUNT(*) FROM tb_suppressed_finding sf WHERE $where");
        $cnt->execute($params);
        $total = (int) $cnt->fetchColumn();
    } else {
        $total = $suppressedCount;
    }

    $st = $pdo->prepare(
        "SELECT cve_id, package_name, installed_version, base_severity, in_kev, suppress_reason,
                CASE WHEN sf.container_id = 0 THEN 'HOST'
                     ELSE COALESCE((SELECT c.name FROM tb_container c WHERE c.container_id = sf.container_id), CONCAT('container #', sf.container_id)) END AS target
           FROM tb_suppressed_finding sf WHERE $where
          ORDER BY FIELD(base_severity,'CRITICAL','HIGH','MEDIUM','LOW'), cve_id
          LIMIT $perPage OFFSET $offset"
    );
    $st->execute($params);
    $rows = $st->fetchAll();

    return ['total' => $total, 'rows' => $rows];
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
          <p class="why">에이전트의 실행 시점과 반복 수집 주기를 관리합니다.</p>
        </div>
        <span class="agent-control__status"><span aria-hidden="true"></span>다음 poll 반영</span>
      </div>
      <div class="card__body">
        <?php vg_alert($msg, 'ok'); vg_alert($err); ?>
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
            <label><strong>즉시 실행</strong><span>다음 poll에서 바로 시작합니다.</span></label>
            <button class="btn btn--sm btn--primary">지금 실행</button>
          </form>

          <form class="agent-control__row" method="post">
            <input type="hidden" name="csrf" value="<?= vg_h($csrf) ?>">
            <input type="hidden" name="action" value="agent_schedule">
            <input type="hidden" name="id" value="<?= (int) $hostId ?>">
            <label for="agent-run-at"><strong>예약 실행</strong><span>원하는 날짜와 시간을 선택하세요.</span></label>
            <input id="agent-run-at" type="datetime-local" name="run_at" min="<?= date('Y-m-d\TH:i') ?>" placeholder="날짜와 시간 선택" required>
            <button class="btn btn--sm btn--ghost">등록</button>
          </form>

          <form class="agent-control__row" method="post">
            <input type="hidden" name="csrf" value="<?= vg_h($csrf) ?>">
            <input type="hidden" name="action" value="agent_set_schedule">
            <input type="hidden" name="id" value="<?= (int) $hostId ?>">
            <label for="agent-schedule-minutes"><strong>수집 주기</strong><span>최소 1분 단위로 설정합니다.</span></label>
            <div class="agent-control__number"><input id="agent-schedule-minutes" type="number" name="schedule_minutes" min="1" value="<?= $curMinutes ?>" required><span>분</span></div>
            <button class="btn btn--sm btn--ghost">저장</button>
          </form>

          <form class="agent-control__row" method="post">
            <input type="hidden" name="csrf" value="<?= vg_h($csrf) ?>">
            <input type="hidden" name="action" value="agent_set_speed_tier">
            <input type="hidden" name="id" value="<?= (int) $hostId ?>">
            <label for="agent-speed-tier"><strong>속도 티어</strong><span>변경은 다음 poll/다음 수집 시작부터 반영됩니다.</span></label>
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

function vg_host_load_resources_tab(PDO $pdo, int $hostId): array {
    // 새 수집·새 컬럼 없이 스캔 이력 탭과 같은 데이터를 시간순으로만 가져온다.
    //   최신 N건을 DESC 로 뽑은 뒤 뒤집는다 — 표는 최신이 위, 차트는 최신이 오른쪽이라 방향이 반대다.
    $st = $pdo->prepare(
        'SELECT collected_at, peak_rss_mb, cpu_seconds, mem_total_mb, cpu_cores, elapsed_seconds
           FROM tb_scan_run WHERE host_id = ? ORDER BY scan_run_id DESC LIMIT ' . vg_ui_trend_limit()
    );
    $st->execute([$hostId]);
    $resourceScans = array_reverse($st->fetchAll());

    // 스캔(행) 단위로 먼저 %를 계산한다 — 절대치를 먼저 모아 나중에 나누면 스캔마다
    //   다른 스펙(mem_total_mb/cpu_cores)이 섞여 값이 왜곡된다. 필요값이 하나라도 없거나
    //   분모가 0이면 그 스캔은 이 지표에서 제외(NULL) — 0/100 대체 금지.
    foreach ($resourceScans as &$s) {
        $s['mem_pct'] = vg_agent_mem_pct($s['peak_rss_mb'], $s['mem_total_mb']);
        $s['cpu_pct'] = vg_agent_cpu_pct($s['cpu_seconds'], $s['elapsed_seconds'], $s['cpu_cores']);
    }
    unset($s);

    return ['resourceScans' => $resourceScans];
}

function vg_host_load_packages_tab(PDO $pdo, int $scanId, int $perPage, int $offset, string $q): array {
    $where = "scan_id = ? AND container_id = 0 AND manager IN ('dpkg','rpm','apk')";
    $params = [$scanId];
    if ($q !== '') {
        $where .= ' AND (name LIKE ? OR source_pkg LIKE ? OR origin LIKE ? OR vendor LIKE ?)';
        $like = '%' . $q . '%';
        array_push($params, $like, $like, $like, $like);
    }
    $st = $pdo->prepare("SELECT COUNT(*) FROM tb_package WHERE $where");
    $st->execute($params);
    $total = (int) $st->fetchColumn();

    $st = $pdo->prepare(
        "SELECT manager,name,version,arch,source_pkg,source_version,origin,vendor
           FROM tb_package WHERE $where
          ORDER BY name,arch,version LIMIT $perPage OFFSET $offset"
    );
    $st->execute($params);
    return ['total' => $total, 'rows' => $st->fetchAll()];
}

function vg_host_load_scans_tab(PDO $pdo, int $hostId, int $scanTotal, int $perPage, int $offset): array {
    $total = $scanTotal;
    $st = $pdo->prepare(
        "SELECT scan_run_id, scan_id, collected_at, received_at, content_changed,
                package_count, exposure_count, agent_version, elapsed_seconds, peak_rss_mb, cpu_seconds
           FROM tb_scan_run WHERE host_id = ? ORDER BY scan_run_id DESC LIMIT $perPage OFFSET $offset"
    );
    $st->execute([$hostId]);
    $rows = $st->fetchAll();

    $ids = [];
    foreach ($rows as $s) { $ids[] = (int) $s['scan_id']; }
    $sevByScan = vg_sev_by_scan_ids($pdo, $ids);

    return ['total' => $total, 'rows' => $rows, 'sevByScan' => $sevByScan];
}

$counts =['CRITICAL'=>0,'HIGH'=>0,'MEDIUM'=>0,'LOW'=>0];
$exposureCount = 0; $processCount = 0; $runtimeTotal = 0; $cceFail = 0; $suppressedCount = 0; $vulnTotal = 0; $scanTotal = 0;
$critHighTotal = 0; $restartTotal = 0; $restartRows = []; $packageTotal = 0;
$tab = 'vuln'; $page = 1; $ePage = 1; $perPage = vg_perpage(); $total = 0; $exposureTotal = 0;
$rows = []; $exposures = []; $sevByScan = []; $resourceScans = [];
$q = trim((string) ($_GET['q'] ?? ''));
$hasFilter = $q !== '';

try {
    $pdo = vg_pdo();
    $hostId = (int) ($_GET['id'] ?? 0);
    $st = $pdo->prepare('SELECT * FROM tb_host WHERE host_id = ? AND is_deleted = 0');
    $st->execute([$hostId]);
    $host = $st->fetch() ?: null;
    $pendingCommands = [];

    if ($host) {
        // 호스트 상세(설치 패키지·노출 포트·실행 프로세스 등 인프라 민감정보) 열람 감사로그.
        vg_log_activity($pdo, 'HOST', $hostId, 'view_host', (string) ($host['fqdn'] ?? null),
            subject: (string) ($host['fqdn'] ?? ''), action: 'READ');

        // 에이전트 연결 상태는 수집 실행 시각이 아니라 10초 poll의 마지막 통신으로 판단한다.
        $st = $pdo->prepare(
            'SELECT TIMESTAMPDIFF(MINUTE, MAX(last_seen_at), NOW())
               FROM tb_agent_token
              WHERE host_fqdn = ? AND is_revoked = 0 AND is_deleted = 0'
        );
        $st->execute([(string) $host['fqdn']]);
        $lastPollAge = $st->fetchColumn();
        $pollAge = $lastPollAge !== null && $lastPollAge !== false ? (int) $lastPollAge : null;

        if (vg_can('assets')) {
            $st = $pdo->prepare(
                "SELECT agent_command_id, status, progress_percent, progress_stage, progress_message,
                        run_at, created_at, started_at, heartbeat_at, cancel_requested_at
                   FROM tb_agent_command
                  WHERE host_id = ? AND status IN ('pending','running') AND is_deleted = 0
                  ORDER BY status = 'running' DESC, run_at IS NULL DESC, run_at, created_at"
            );
            $st->execute([$hostId]);
            $pendingCommands = $st->fetchAll();
        }

        // 컬럼을 못 박는 이유: tb_scan.raw_json 은 호스트당 MB 단위(실측 3.14MB)라
        // SELECT * 로 끌면 ORDER BY 의 정렬 버퍼(운영 sort_buffer_size=2M)를 한 행만으로도 넘겨 1038 이 난다.
        $st = $pdo->prepare('SELECT scan_id, collected_at, package_count,
                                    TIMESTAMPDIFF(MINUTE, collected_at, NOW()) AS age_min
                               FROM tb_scan WHERE host_id = ? ORDER BY scan_id DESC LIMIT 1');
        $st->execute([$hostId]);
        $scan = $st->fetch() ?: null;
    }

    if ($scan) {
        $sid = (int) $scan['scan_id'];
        $scanAge = $scan['age_min'];

        // 취약점 0건이 "판정 불가"인 컨테이너 — 피드 미지원 배포판 + **패키지 DB 없는 이미지**.
        //   후자는 rhel 처럼 피드가 지원하는 배포판이라 미지원 경고에 안 걸린다 → 따로 잡아야 한다.
        $st = $pdo->prepare(
            'SELECT c.cid, c.os_id, c.os_version, c.manager,
                    CASE WHEN EXISTS (
                        SELECT 1 FROM tb_package p
                         WHERE p.scan_id = c.scan_id AND p.container_id = c.container_id
                    ) THEN 1 ELSE c.pkg_count END AS pkg_count
               FROM tb_container c WHERE c.scan_id = ?'
        );
        $st->execute([$sid]);
        foreach ($st->fetchAll() as $c) {
            $reason = vg_container_unjudgeable(
                $c['os_id'] ?? null, $c['os_version'] ?? null,
                $c['manager'] ?? null, (int) ($c['pkg_count'] ?? 0)
            );
            if ($reason !== null) {
                $unsupContainers[] = ['cid' => (string) $c['cid'], 'reason' => $reason];
            }
        }

        // 수집 단계 누락 — 배포판도 알고 이미지도 멀쩡한데 **에이전트가 그 항목을 아예 못 걷은** 경우.
        //   MISSING 만 모은다. EMPTY 는 "정상적으로 없음"(컨테이너를 안 쓰는 호스트, 언어 패키지가
        //   없는 호스트)이라 같이 경고하면 정상 호스트마다 경고가 떠서 아무도 안 보게 된다.
        //   item_count 는 안 읽는다 — MISSING 은 정의상 0건이라(ingest.php 생산자) 볼 값이 없다.
        $st = $pdo->prepare("SELECT stage_code FROM tb_collection_stage
                              WHERE scan_id = ? AND status = 'MISSING' ORDER BY stage_code");
        $st->execute([$sid]);
        foreach ($st->fetchAll() as $r) {
            $code = (string) $r['stage_code'];
            $missingStages[] = VG_COLLECTION_STAGE_LABEL[$code] ?? $code;   // 모르는 코드는 원문 그대로
        }

        // --- 히어로/KPI 집계 (탭과 무관한 값싼 COUNT) ---
        $st = $pdo->prepare('SELECT severity, COUNT(*) c FROM tb_finding WHERE scan_id = ? GROUP BY severity');
        $st->execute([$sid]);
        foreach ($st->fetchAll() as $r) { if (isset($counts[$r['severity']])) { $counts[$r['severity']] = (int) $r['c']; } }

        $st = $pdo->prepare('SELECT COUNT(*) FROM tb_exposure WHERE scan_id = ?');
        $st->execute([$sid]); $exposureCount = (int) $st->fetchColumn();

        $st = $pdo->prepare("SELECT COUNT(*) FROM tb_cce_finding WHERE scan_id = ? AND result = 'FAIL'");
        $st->execute([$sid]); $cceFail = (int) $st->fetchColumn();

        $st = $pdo->prepare('SELECT COUNT(*) FROM tb_suppressed_finding WHERE scan_id = ?');
        $st->execute([$sid]); $suppressedCount = (int) $st->fetchColumn();

        // 우선순위 취약점 = CRITICAL·HIGH + 재시작 필요(등급이 낮아도 숨기지 않는다).
        //   탭 배지는 둘의 합, 화면은 두 표로 나눠 보여준다(아래 vuln 탭 주석 참고).
        $st = $pdo->prepare("SELECT COUNT(*) FROM tb_finding
                              WHERE scan_id = ? AND (severity IN ('CRITICAL','HIGH') OR needs_restart = 1)");
        $st->execute([$sid]); $vulnTotal = (int) $st->fetchColumn();

        $st = $pdo->prepare("SELECT COUNT(*) FROM tb_finding
                              WHERE scan_id = ? AND severity IN ('CRITICAL','HIGH')");
        $st->execute([$sid]); $critHighTotal = (int) $st->fetchColumn();

        $st = $pdo->prepare('SELECT COUNT(*) FROM tb_finding WHERE scan_id = ? AND needs_restart = 1');
        $st->execute([$sid]); $restartTotal = (int) $st->fetchColumn();

        $st = $pdo->prepare('SELECT COUNT(*) FROM tb_scan_run WHERE host_id = ?');
        $st->execute([$hostId]); $scanTotal = (int) $st->fetchColumn();

        $st = $pdo->prepare('SELECT COUNT(*) FROM tb_process WHERE scan_id = ?');
        $st->execute([$sid]); $processCount = (int) $st->fetchColumn();
        $runtimeTotal = $exposureCount + $processCount;

        $st = $pdo->prepare("SELECT COUNT(*) FROM tb_package
                              WHERE scan_id = ? AND container_id = 0 AND manager IN ('dpkg','rpm','apk')");
        $st->execute([$sid]); $packageTotal = (int) $st->fetchColumn();

        // --- 활성 탭 결정 (억제 탭은 건이 있을 때만 존재) ---
        $validTabs = ['vuln', 'packages', 'runtime', 'cce'];
        if ($suppressedCount > 0) { $validTabs[] = 'suppressed'; }
        $validTabs[] = 'resources';
        $validTabs[] = 'scans';
        $tab = (string) ($_GET['tab'] ?? 'vuln');
        if (!in_array($tab, $validTabs, true)) { $tab = 'vuln'; }

        $page   = vg_page();
        $offset = ($page - 1) * $perPage;
        $ePage  = vg_page('epage');

        // --- 활성 탭 데이터만 조회(+페이지네이션+검색) ---
        if ($tab === 'vuln') {
            ['total' => $total, 'rows' => $rows, 'restartRows' => $restartRows]
                = vg_host_load_vuln_tab($pdo, $sid, $critHighTotal, $perPage, $offset, $q);
        } elseif ($tab === 'packages') {
            ['total' => $total, 'rows' => $rows]
                = vg_host_load_packages_tab($pdo, $sid, $perPage, $offset, $q);
        } elseif ($tab === 'runtime') {
            ['total' => $total, 'exposures' => $exposures, 'exposureTotal' => $exposureTotal, 'rows' => $rows, 'ePage' => $ePage]
                = vg_host_load_runtime_tab($pdo, $sid, $perPage, $offset, $ePage, $q);
        } elseif ($tab === 'cce') {
            ['total' => $total, 'rows' => $rows]
                = vg_host_load_cce_tab($pdo, $sid, $perPage, $offset, $q);
        } elseif ($tab === 'suppressed') {
            ['total' => $total, 'rows' => $rows]
                = vg_host_load_suppressed_tab($pdo, $sid, $suppressedCount, $perPage, $offset, $q);
        } elseif ($tab === 'resources') {
            ['resourceScans' => $resourceScans] = vg_host_load_resources_tab($pdo, $hostId);
        } else { // scans
            ['total' => $total, 'rows' => $rows, 'sevByScan' => $sevByScan]
                = vg_host_load_scans_tab($pdo, $hostId, $scanTotal, $perPage, $offset);
        }
    }
} catch (Throwable $e) {
    if (isset($pdo) && $pdo instanceof PDO && $pdo->inTransaction()) { $pdo->rollBack(); }
    error_log('[host] ' . $e->getMessage());
    $err = $e instanceof InvalidArgumentException || $e instanceof RuntimeException ? $e->getMessage() : '처리 중 오류가 발생했습니다.';
}

// 노출 범위 → 뱃지 톤(색은 CSS 가 결정).
//   FILTERED = 전체 인터페이스에 떠 있지만 방화벽이 막아 외부에서 못 닿는 포트.
// LAN = 링크로컬 멀티캐스트(mDNS 등) — 인터넷엔 안 닿고 같은 세그먼트만(외부노출보다 아래).
$scopeTone = ['EXTERNAL' => 'crit', 'LAN' => 'med', 'BOUND' => 'med', 'FILTERED' => 'muted', 'LOCAL' => 'muted'];

vg_header($host['fqdn'] ?? '호스트', 'assets');
// 예약 실행 입력용 datepicker(flatpickr, 의존성 0개) — CDN 없이 자체호스팅(vendor/).
//   defer 되는 페이지 전용 JS(assets/js/host.js)보다 먼저 실행돼야 하므로 body 시작 지점에서
//   바로 로드한다(defer 스크립트는 문서 순서대로 실행되므로 이 위치면 순서가 보장된다).
?>
<link rel="stylesheet" href="<?= vg_asset('/assets/vendor/flatpickr/flatpickr.min.css') ?>">
<script src="<?= vg_asset('/assets/vendor/flatpickr/flatpickr.min.js') ?>"></script>
<?php if ($err !== null): ?>
  <?php vg_page_title('호스트 상세', 'ASSET DETAIL', '호스트 정보를 불러오지 못했습니다.'); ?>
  <?php vg_alert('오류 · ' . $err); ?>
<?php elseif (!$host): ?>
  <?php vg_page_title('호스트를 찾을 수 없습니다', 'ASSET DETAIL', '삭제되었거나 존재하지 않는 자산입니다.'); ?>
  <div class="card"><?php vg_empty(['icon' => '🖥️', 'title' => '요청한 호스트 정보가 없습니다.', 'cta' => ['href' => '/', 'label' => '← 대시보드']]); ?></div>
<?php elseif (!$scan): ?>
  <?php
  $noScanMeta = [vg_h(trim($host['os_id'] . ' ' . $host['os_version']))];
  if (!empty($host['last_seen_ip'])) { $noScanMeta[] = 'IP ' . vg_h($host['last_seen_ip']); }
  $noScanMeta[] = '<a href="/">대시보드</a>';
  vg_hero(vg_h($host['fqdn']), $noScanMeta, null, 'ok', '수집 상태', '');
  ?>
  <?php if (vg_can('assets')): ?>
    <?php vg_host_render_agent_control($hostId, $host, $agentCsrf, $pendingCommands, $agentMsg, $agentErr); ?>
  <?php endif; ?>
  <div class="card"><?php vg_empty(['icon' => '📭', 'title' => '아직 수집된 스캔이 없습니다.', 'hint' => '에이전트를 --send 로 실행하면 여기에 나타납니다.']); ?></div>
<?php else:
    // 최고 위험도 → 히어로 톤. 하나도 없으면 '양호'(ok).
    $worst = null;
    foreach (['CRITICAL','HIGH','MEDIUM','LOW'] as $s) { if ($counts[$s] > 0) { $worst = $s; break; } }
    $heroTone = $worst ? vg_sev_tone($worst) : 'ok';

    // 탭 정의(배열 순서 = 표시 순서). n 은 라벨 옆 숫자(null 이면 숨김).
    $tabDefs = [
        'vuln'    => ['label' => '취약점',    'n' => $vulnTotal],
        'packages'=> ['label' => '설치 패키지', 'n' => $packageTotal],
        // 이 탭은 노출 소켓과 실행 프로세스 두 목록을 함께 제공하므로 둘의 합계를 표시한다.
        'runtime' => ['label' => '런타임',    'n' => $runtimeTotal],
        'cce'     => ['label' => '보안 설정', 'n' => $cceFail],
    ];
    if ($suppressedCount > 0) { $tabDefs['suppressed'] = ['label' => '억제', 'n' => $suppressedCount]; }
    $tabDefs['resources'] = ['label' => '리소스', 'n' => null];
    $tabDefs['scans'] = ['label' => '스캔 이력', 'n' => $scanTotal];
?>
  <?php
  $meta = [
      vg_h(trim($host['os_id'] . ' ' . $host['os_version'])) ?: 'OS 미상',
      vg_asset_state(
          $scan !== null,
          $pollAge,
          $scanAge,
          (int) ($host['poll_schedule_seconds'] ?? 3600)
      ),
      '최신 수집 ' . vg_h($scan['collected_at']),
      '<a href="' . vg_h(vg_qs(['tab' => 'packages', 'page' => null, 'q' => null])) . '">패키지 '
          . number_format($packageTotal) . '개</a>',
  ];
  if (!empty($host['last_seen_ip'])) { $meta[] = 'IP ' . vg_h($host['last_seen_ip']); }
  $meta[] = '<a href="/">대시보드</a>';
  if (vg_can('assets')) { $meta[] = '<a href="/assets.php">자산관리</a>'; }
  vg_hero(vg_h($host['fqdn']), $meta, $worst ?? '양호', $heroTone, '최고 위험도', '');
  if (vg_can('assets')) {
      vg_host_render_agent_control($hostId, $host, $agentCsrf, $pendingCommands, $agentMsg, $agentErr);
  }

  // CVE 피드가 지원하지 않는 배포판이면 매칭 후보가 아예 없어 **취약점이 0건으로 뜬다.**
  //   운영자는 "안전하다"고 읽는다 — 침묵하는 미탐이라 반드시 화면에 알린다.
  $unsup = [];
  $u = vg_distro_unsupported($host['os_id'] ?? null, $host['os_version'] ?? null);
  if ($u !== null) { $unsup[] = '이 호스트 — ' . $u; }
  foreach ($unsupContainers as $c) {
      $unsup[] = '컨테이너 ' . $c['cid'] . ' — ' . $c['reason'];
  }
  if ($unsup) {
      vg_alert([
          'type'  => 'warn',
          'title' => '취약점 매칭이 수행되지 않습니다',
          'hints' => array_merge(
              [
                  '아래 대상은 피드가 모르는 배포판이거나, 패키지 DB 가 없어 무엇이 깔렸는지 알 수 없습니다.',
                  '취약점 0건은 "안전함"이 아니라 "판정 불가"입니다.',
              ],
              $unsup
          ),
      ]);
  }

  // 위 경고와 같은 주제("0건 = 안전"이 아닐 수 있다)의 세 번째 축.
  //   배포판·이미지 문제가 아니라 **에이전트가 그 항목을 못 걷은** 경우다 — 지금까진 침묵했다.
  if ($missingStages) {
      $stageHints = [
          '해당 항목의 0건은 "없음"이 아니라 "수집 실패"입니다.',
          '에이전트 실행 권한·환경을 확인한 뒤 다시 수집하세요.',
      ];
      foreach ($missingStages as $s) { $stageHints[] = '수집 실패 — ' . $s; }
      vg_alert([
          'type'  => 'warn',
          'title' => '이 스캔은 일부 항목을 수집하지 못했습니다',
          'hints' => $stageHints,
      ]);
  }
  ?>

  <div class="cards">
    <?php foreach (['CRITICAL','HIGH','MEDIUM','LOW'] as $s): ?>
      <div class="kpi kpi--sm tone-<?= vg_sev_tone($s) ?>"><b><?= (int) $counts[$s] ?></b><span><?= $s ?></span></div>
    <?php endforeach; ?>
    <div class="kpi kpi--sm"><b><?= number_format($exposureCount) ?></b><span>노출 소켓</span></div>
    <a class="kpi kpi--sm tone-<?= $cceFail > 0 ? 'high' : 'ok' ?>" href="<?= vg_h(vg_qs(['tab' => 'cce', 'page' => null])) ?>">
      <b><?= (int) $cceFail ?></b><span>설정 취약</span>
    </a>
  </div>

  <?php vg_subtabs($tabDefs, $tab); ?>

  <?php if ($tab === 'vuln'):
    // 두 표(CRITICAL·HIGH / 재시작·재부팅)는 열 구성이 같다 — 스펙을 한 번만 만들어 나눠 쓴다.
    $vulnHeaders = [
        ['label' => '등급', 'key' => 'severity'],
        ['label' => '상태', 'key' => 'runtime_status'],
        ['label' => 'CVE'],
        ['label' => 'EPSS'],
        ['label' => '패키지'],
        ['label' => '근거'],
        ['label' => '조치'],
        ['label' => '이력'],
    ];
    $vulnCells = [
        'severity'       => fn($f) => vg_sev_badge((string) $f['severity']),
        'runtime_status' => fn($f) => vg_status_badge($f['runtime_status']),
        2 => fn($f) => '<strong><a href="/cve.php?cve=' . urlencode($f['cve_id']) . '">' . vg_h($f['cve_id']) . '</a></strong>',
        3 => fn($f) => vg_epss_cell($f['epss'], $f['epss_percentile']),
        // 커널은 재부팅해야 새 코드가 올라온다 — 프로세스 재시작으로는 안 고쳐진다.
        4 => fn($f) => vg_h($f['package_name']) . ' <span class="why">' . vg_h($f['installed_version']) . '</span>'
                       . (!empty($f['needs_restart'])
                          ? ' ' . vg_badge(vg_is_kernel_code_pkg((string) ($f['package_name'] ?? '')) ? '재부팅 필요' : '재시작 필요', 'high')
                          : ''),
        5 => fn($f) => '<span class="why">' . vg_trunc($f['rationale']) . '</span>',
        // 재시작/재부팅이 필요하면 조치는 "업그레이드"가 아니다(이미 패치돼 있다).
        6 => fn($f) => !empty($f['needs_restart'])
                       ? '<span class="pill">' . (vg_is_kernel_code_pkg((string) ($f['package_name'] ?? '')) ? '재부팅' : '프로세스 재시작') . '</span>'
                       : vg_fix_cell($f['fixed_version'] ?? null, $f['ref_urls_json'] ?? null, $f['installed_version'] ?? null),
        7 => fn($f) => '<a class="pill" href="/finding_history.php?id=' . (int) $hostId
                       . '&amp;cid=' . (int) $f['container_id']
                       . '&amp;cve=' . urlencode((string) $f['cve_id'])
                       . '&amp;pkg=' . urlencode((string) $f['package_name'])
                       . '" title="스캔별 이력 보기">🕘 이력</a>',
    ];
    $findingRowAttrs = function (array $f) use ($hostId): array {
        $epss = ($f['epss'] ?? null) === null ? '–' : number_format((float) $f['epss'] * 100, 1) . '%';
        if (($f['epss_percentile'] ?? null) !== null) {
            $top = max(0.01, (1.0 - (float) $f['epss_percentile']) * 100);
            $epss .= ' · 상위 ' . number_format($top, $top < 1 ? 2 : ($top < 10 ? 1 : 0)) . '%';
        }
        $isKernel = vg_is_kernel_code_pkg((string) ($f['package_name'] ?? ''));
        if (!empty($f['needs_restart'])) {
            $action = $isKernel ? '패치된 커널을 적용하려면 호스트를 재부팅하세요.' : '패치된 라이브러리를 적용하려면 관련 프로세스를 재시작하세요.';
        } elseif (!empty($f['fixed_version'])) {
            $action = (string) ($f['installed_version'] ?? '') . ' → ' . (string) $f['fixed_version'] . ' 이상으로 업데이트';
        } else {
            $action = '공식 패치 또는 벤더 권고를 확인하세요.';
        }
        $historyUrl = '/finding_history.php?id=' . (int) $hostId
            . '&cid=' . (int) $f['container_id']
            . '&cve=' . urlencode((string) $f['cve_id'])
            . '&pkg=' . urlencode((string) $f['package_name']);
        $detail = [
            'severity' => (string) $f['severity'],
            'status' => vg_status_label($f['runtime_status'] ?? null),
            'cve' => (string) $f['cve_id'],
            'epss' => $epss,
            'package' => (string) $f['package_name'],
            'installed' => (string) ($f['installed_version'] ?? '–'),
            'fixed' => (string) ($f['fixed_version'] ?? '–'),
            'rationale' => (string) ($f['rationale'] ?? '근거 정보가 없습니다.'),
            'action' => $action,
            'cve_url' => '/cve.php?cve=' . urlencode((string) $f['cve_id']),
            'history_url' => $historyUrl,
        ];
        return [
            'data-finding-detail' => json_encode($detail, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
            'tabindex' => '0',
            'role' => 'button',
            'aria-label' => (string) $f['cve_id'] . ' 상세 보기',
        ];
    };
    $vulnOpts = [
        'card'      => false,
        'row_class' => fn($f) => vg_sev_row((string) $f['severity']),
        'row_attrs' => $findingRowAttrs,
        'cell'      => $vulnCells,
    ];
  ?>
    <?php vg_toolbar([
        ['type' => 'search', 'name' => 'q', 'placeholder' => 'CVE 또는 패키지명 검색', 'value' => $q],
        ['type' => 'hidden', 'name' => 'tab', 'value' => $tab],
        ['type' => 'hidden', 'name' => 'id', 'value' => (string) $hostId],
    ]); ?>
    <div class="card">
      <strong>우선순위 취약점 (CRITICAL·HIGH)</strong>
      <span class="why">— <a href="/findings.php?scan_id=<?= (int) $scan['scan_id'] ?>">전체 취약점 보기 →</a></span>
      <div class="card__body">
      <?php
      vg_table($vulnHeaders, $rows, $vulnOpts + [
          'empty' => $hasFilter
              ? [
                  'icon'  => '🔍',
                  'title' => '검색 결과가 없습니다.',
                  'hint'  => '검색어를 확인하거나 초기화해 보세요.',
                  'cta'   => ['href' => vg_qs(['q' => null, 'page' => null]), 'label' => '검색 초기화'],
              ]
              : [
                  'icon'  => '✅',
                  'title' => 'CRITICAL·HIGH 가 없습니다.',
                  'hint'  => '아래의 재시작·재부팅 필요 항목은 등급이 낮아도 확인하세요.',
              ],
      ]);
      ?>
      </div>
    </div>
    <?php vg_page_nav($total, $perPage, $page); ?>

    <div class="card mt-lg">
      <strong>재시작·재부팅 필요 <span class="hint">(<?= number_format($restartTotal) ?>건)</span></strong>
      <span class="why">— 패치 완료, 재시작 전까지 옛 코드 실행 중
        <?php if ($restartTotal > count($restartRows)): ?>
          · 상위 <?= count($restartRows) ?>건 ·
          <a href="/findings.php?scan_id=<?= (int) $scan['scan_id'] ?>&amp;fx=restart">전체 보기 →</a>
        <?php endif; ?>
      </span>
      <div class="card__body">
      <?php
      vg_table($vulnHeaders, $restartRows, $vulnOpts + [
          'empty' => [
              'icon'  => '✅',
              'title' => '재시작·재부팅이 필요한 항목이 없습니다.',
              'hint'  => '패치된 라이브러리를 옛 프로세스가 물고 있는 경우가 없습니다.',
          ],
      ]);
      ?>
      </div>
    </div>

    <?php
    vg_modal_open('findingDetailModal', '취약점 상세', 'modal--wide finding-detail-modal');
    ?>
      <div class="finding-detail__summary">
        <span class="badge" data-finding-severity></span>
        <span class="badge tone-muted" data-finding-status></span>
        <strong data-finding-cve></strong>
      </div>
      <dl class="finding-detail__grid">
        <div><dt>패키지</dt><dd data-finding-package></dd></div>
        <div><dt>설치 버전</dt><dd data-finding-installed></dd></div>
        <div><dt>조치 버전</dt><dd data-finding-fixed></dd></div>
        <div><dt>EPSS</dt><dd data-finding-epss></dd></div>
      </dl>
      <section class="finding-detail__section">
        <strong>판정 근거</strong>
        <p data-finding-rationale></p>
      </section>
      <section class="finding-detail__section">
        <strong>권장 조치</strong>
        <p data-finding-action></p>
      </section>
    <?php
    vg_modal_foot(null, [
        'extra' => '<a class="btn btn--ghost" data-finding-history href="#">이력 보기</a>'
                 . '<a class="btn btn--primary" data-finding-cve-link href="#">CVE 상세</a>',
        'cancel' => '닫기',
    ]);
    vg_modal_close();
    ?>

  <?php elseif ($tab === 'packages'): ?>
    <?php vg_toolbar([
        ['type' => 'search', 'name' => 'q', 'placeholder' => '패키지명·소스·출처 검색', 'value' => $q],
        ['type' => 'hidden', 'name' => 'tab', 'value' => $tab],
        ['type' => 'hidden', 'name' => 'id', 'value' => (string) $hostId],
    ]); ?>
    <div class="card">
      <strong>설치 패키지</strong>
      <span class="why"> · 최신 수집 기준 호스트 운영체제 패키지 <?= number_format($packageTotal) ?>개</span>
      <div class="card__body">
      <?php
      vg_table(
          [
              ['label' => '패키지', 'key' => 'name', 'class' => 'col-id'],
              ['label' => '설치 버전', 'key' => 'version'],
              ['label' => '아키텍처', 'key' => 'arch'],
              ['label' => '관리자', 'key' => 'manager'],
              ['label' => '소스 패키지', 'key' => 'source_pkg'],
              ['label' => '출처', 'key' => 'origin'],
          ],
          $rows,
          [
              'card' => false,
              'empty' => $hasFilter
                  ? [
                      'icon' => '⌕',
                      'title' => '검색 조건에 맞는 설치 패키지가 없습니다.',
                      'cta' => ['href' => vg_qs(['q' => null, 'page' => null]), 'label' => '검색 초기화'],
                  ]
                  : [
                      'icon' => '□',
                      'title' => '수집된 운영체제 패키지가 없습니다.',
                  ],
              'cell' => [
                  'name' => fn($p) => '<strong>' . vg_h((string)$p['name']) . '</strong>',
                  'version' => fn($p) => '<code>' . vg_h((string)($p['version'] ?? '')) . '</code>',
                  'arch' => fn($p) => $p['arch'] ? vg_h((string)$p['arch']) : '<span class="why">–</span>',
                  'manager' => fn($p) => '<code>' . vg_h((string)$p['manager']) . '</code>',
                  'source_pkg' => function ($p) {
                      if (empty($p['source_pkg'])) { return '<span class="why">–</span>'; }
                      return vg_h((string)$p['source_pkg'])
                          . (!empty($p['source_version']) ? ' <span class="why">' . vg_h((string)$p['source_version']) . '</span>' : '');
                  },
                  'origin' => fn($p) => $p['origin']
                      ? vg_h((string)$p['origin'])
                      : (!empty($p['vendor']) ? vg_h((string)$p['vendor']) : '<span class="why">–</span>'),
              ],
          ]
      );
      ?>
      </div>
    </div>
    <?php vg_page_nav($total, $perPage, $page); ?>

  <?php elseif ($tab === 'runtime'): ?>
    <?php vg_toolbar([
        ['type' => 'search', 'name' => 'q', 'placeholder' => '프로세스명·사용자·실행패키지 검색', 'value' => $q],
        ['type' => 'hidden', 'name' => 'tab', 'value' => $tab],
        ['type' => 'hidden', 'name' => 'id', 'value' => (string) $hostId],
    ]); ?>
    <div class="card">
      <strong>런타임 노출</strong> <span class="why">— 어떤 프로세스가 무슨 포트를 열고 어떤 라이브러리를 로드했나</span>
      <div class="card__body">
      <?php
      vg_table(
          [
              ['label' => '범위'],
              ['label' => '위치'],
              ['label' => '프로세스', 'key' => 'proc'],
              ['label' => '포트'],
              ['label' => '실행패키지', 'key' => 'exe_pkg'],
              ['label' => '로드한 패키지'],
          ],
          $exposures,
          [
              'card' => false,
              'empty' => $hasFilter
                  ? [
                      'icon'  => '🔍',
                      'title' => '검색 결과가 없습니다.',
                      'hint'  => '검색어를 확인하거나 초기화해 보세요.',
                      'cta'   => ['href' => vg_qs(['q' => null, 'page' => null, 'epage' => null]), 'label' => '검색 초기화'],
                  ]
                  : [
                      'icon'  => '✅',
                      'title' => '리스닝 소켓이 없습니다.',
                      'hint'  => '외부·내부 포함 열린 포트가 없습니다.',
                  ],
              'cell' => [
                  0 => fn($e) => vg_badge(vg_scope_label((string) $e['scope']), $scopeTone[$e['scope']] ?? 'muted'),
                  1 => fn($e) => $e['ctr'] !== ''
                        ? '<span class="why">컨테이너 ' . vg_h($e['ctr']) . '</span>'
                        : '<span class="why">호스트</span>',
                  3 => fn($e) => vg_h($e['proto']) . '/' . (int) $e['port'],
                  5 => fn($e) => '<span class="why">' . vg_trunc($e['loaded_pkgs'], 60) . '</span>',
              ],
          ]
      );
      ?>
      </div>
    </div>
    <?php vg_page_nav($exposureTotal, $perPage, $ePage, 'epage'); ?>

    <div class="card mt-lg">
      <strong>실행 프로세스</strong> <span class="why">— 실행 중인 프로그램과 소속 패키지(=실행중), 로드한 라이브러리(=사용중)</span>
      <div class="card__body">
      <?php
      vg_table(
          [
              ['label' => 'PID'],
              ['label' => '위치'],
              ['label' => '프로세스', 'key' => 'comm'],
              ['label' => '사용자'],
              ['label' => '실행 패키지', 'key' => 'exe_pkg'],
              ['label' => '로드한 패키지'],
          ],
          $rows,
          [
              'card' => false,
              'empty' => $hasFilter
                  ? [
                      'icon'  => '🔍',
                      'title' => '검색 결과가 없습니다.',
                      'hint'  => '검색어를 확인하거나 초기화해 보세요.',
                      'cta'   => ['href' => vg_qs(['q' => null, 'page' => null, 'epage' => null]), 'label' => '검색 초기화'],
                  ]
                  : [
                      'icon'  => '🗂️',
                      'title' => '실행 프로세스 데이터가 없습니다.',
                      'hint'  => '구버전 에이전트로 수집된 스캔입니다.',
                  ],
              'cell' => [
                  0 => fn($pr) => '<span class="why">' . (int) $pr['pid'] . '</span>',
                  1 => fn($pr) => $pr['ctr'] !== ''
                        ? '<span class="why">컨테이너 ' . vg_h($pr['ctr']) . '</span>'
                        : '<span class="why">호스트</span>',
                  3 => fn($pr) => '<span class="why">' . vg_h($pr['username']) . '</span>',
                  5 => fn($pr) => '<span class="why">' . vg_trunc($pr['loaded_pkgs'], 60) . '</span>',
              ],
          ]
      );
      ?>
      </div>
    </div>
    <?php vg_page_nav($total, $perPage, $page); ?>

  <?php elseif ($tab === 'cce'): ?>
    <?php vg_toolbar([
        ['type' => 'search', 'name' => 'q', 'placeholder' => '코드·점검항목·SSG 룰 검색', 'value' => $q],
        ['type' => 'hidden', 'name' => 'tab', 'value' => $tab],
        ['type' => 'hidden', 'name' => 'id', 'value' => (string) $hostId],
    ]); ?>
    <div class="card">
      <strong>보안 설정 점검 (CCE)</strong>
      <span class="why">— 버전이 아닌 설정 점검 · NA=미수집</span>
      <div class="card__body">
      <?php
      // 결과 → 톤: FAIL 은 위험도색, PASS 는 low(초록), NA 는 muted.
      $cceBadge = function (array $r): string {
          $tone = $r['result'] === 'FAIL' ? vg_sev_tone($r['severity'])
                : ($r['result'] === 'PASS' ? 'low' : 'muted');
          return vg_badge($r['result'], $tone);
      };
      // 기준 배지 — 이 점검이 **어느 룰셋의 어느 항목**에 근거하는지 보여준다.
      //   예전엔 우리가 정한 코드(CCE-SSH-ROOT)만 있어서 "왜 이게 기준인가" 를 답할 수 없었다.
      //   이제 SSG 룰에 묶여 있고, 그 룰이 CIS·NIST·STIG 참조를 들고 있다.
      $refBadges = static function (array $r): string {
          if (empty($r['ssg_rule_id'])) {
              return '<span class="why">자체 기준(대응 SSG 룰 없음)</span>';
          }
          $refs = vg_json_col($r['refs_json'] ?? '');
          $html = '';
          foreach ($refs as $k => $v) {
              // 기관 기준만 보여준다 — cis-csc 같은 상위 카테고리는 항목 번호가 아니라 생략.
              if (strncmp((string) $k, 'cis@', 4) === 0) {
                  $html .= ' ' . vg_badge('CIS ' . $v, 'info', 'CIS 벤치마크 ' . $k . ' 항목 ' . $v);
              } elseif ($k === 'nist') {
                  $html .= ' ' . vg_badge('NIST ' . vg_trunc((string) $v, 14), 'muted', 'NIST 800-53: ' . $v);
              } elseif ($k === 'stigid') {
                  $html .= ' ' . vg_badge('STIG', 'muted', 'DISA STIG: ' . $v);
              }
          }
          $ruleId = (string) $r['ssg_rule_id'];
          $rule = '<a href="/compliance_rule.php?rule=' . urlencode($ruleId) . '">'
              . '<code class="why">' . vg_h($ruleId) . '</code></a>';
          return $rule . ($html !== '' ? '<br>' . $html : '');
      };

      vg_table(
          [
              ['label' => '결과', 'key' => 'result'],
              ['label' => '점검 항목', 'key' => 'title'],
              ['label' => '코드', 'key' => 'code'],
              ['label' => '기준(SSG 룰 · CIS/NIST)'],
              ['label' => '근거'],
              ['label' => '사유'],
          ],
          $rows,
          [
              'card' => false,
              'empty' => $hasFilter
                  ? [
                      'icon'  => '🔍',
                      'title' => '검색 결과가 없습니다.',
                      'hint'  => '검색어를 확인하거나 초기화해 보세요.',
                      'cta'   => ['href' => vg_qs(['q' => null, 'page' => null]), 'label' => '검색 초기화'],
                  ]
                  : [
                      'icon'  => '🗂️',
                      'title' => 'CCE 점검 데이터가 없습니다.',
                      'hint'  => '구버전 에이전트 또는 security/users 미수집입니다.',
                  ],
              'cell' => [
                  'result' => $cceBadge,
                  'code'   => fn($r) => '<code>' . vg_h($r['code']) . '</code>',
                  3 => $refBadges,
                  4 => fn($r) => '<span class="why">' . vg_trunc($r['evidence'], 40) . '</span>',
                  5 => fn($r) => '<span class="why">' . vg_trunc($r['rationale']) . '</span>',
              ],
          ]
      );
      ?>
      </div>
    </div>
    <?php vg_page_nav($total, $perPage, $page); ?>

  <?php elseif ($tab === 'suppressed'): ?>
    <?php vg_toolbar([
        ['type' => 'search', 'name' => 'q', 'placeholder' => 'CVE 또는 패키지명 검색', 'value' => $q],
        ['type' => 'hidden', 'name' => 'tab', 'value' => $tab],
        ['type' => 'hidden', 'name' => 'id', 'value' => (string) $hostId],
    ]); ?>
    <div class="card">
      <strong>백포트로 억제된 취약점</strong>
      <span class="why">— 백포트로 이미 수정됨 · 오탐 제외 근거</span>
      <div class="card__body">
      <?php
      vg_table(
          [
              ['label' => '원래등급', 'key' => 'base_severity'],
              ['label' => 'CVE'],
              ['label' => '대상', 'key' => 'target'],
              ['label' => '패키지'],
              ['label' => '억제 근거'],
          ],
          $rows,
          [
              'card' => false,
              'empty' => $hasFilter
                  ? [
                      'icon'  => '🔍',
                      'title' => '검색 결과가 없습니다.',
                      'hint'  => '검색어를 확인하거나 초기화해 보세요.',
                      'cta'   => ['href' => vg_qs(['q' => null, 'page' => null]), 'label' => '검색 초기화'],
                  ]
                  : [
                      'icon'  => '✅',
                      'title' => '억제된 취약점이 없습니다.',
                      'hint'  => '백포트로 억제 처리된 항목이 없습니다.',
                  ],
              'row_class' => fn($r) => vg_sev_row((string) $r['base_severity']),
              'cell' => [
                  'base_severity' => fn($r) => vg_sev_badge((string) $r['base_severity'])
                      . ((int) $r['in_kev'] === 1 ? ' ' . vg_badge('KEV', 'crit') : ''),
                  1 => fn($r) => '<strong><a href="/cve.php?cve=' . urlencode($r['cve_id']) . '">' . vg_h($r['cve_id']) . '</a></strong>',
                  3 => fn($r) => vg_h($r['package_name']) . ' <span class="why">' . vg_h($r['installed_version']) . '</span>',
                  4 => fn($r) => '<span class="why">' . vg_trunc($r['suppress_reason'], 90) . '</span>',
              ],
          ]
      );
      ?>
      </div>
    </div>
    <?php vg_page_nav($total, $perPage, $page); ?>

  <?php elseif ($tab === 'resources'):
    $latestResourceScan = $resourceScans ? end($resourceScans) : null;
  ?>
    <div class="card">
      <strong>에이전트 메모리 사용률</strong>
      <span class="why">— 각 수집 실행의 프로세스 트리 피크 RSS를 호스트 총 메모리 대비 %로 표시합니다.
        <?php if ($latestResourceScan && $latestResourceScan['mem_pct'] !== null): ?>
          · 현재 <?= vg_resource_pct($latestResourceScan['mem_pct']) ?>
        <?php endif; ?>
      </span>
      <div class="card__body">
      <?php vg_resource_trend($resourceScans, 'mem_pct', '%', 1, 'mem'); ?>
      </div>
    </div>

    <div class="card mt-lg">
      <strong>에이전트 CPU 사용률</strong>
      <span class="why">— 각 수집 실행에서 에이전트와 자식 프로세스가 사용한 CPU 시간을 호스트 전체 코어 용량 대비 %로 표시합니다.
        <?php if ($latestResourceScan && $latestResourceScan['cpu_pct'] !== null): ?>
          · 현재 <?= vg_resource_pct($latestResourceScan['cpu_pct']) ?>
        <?php endif; ?>
      </span>
      <div class="card__body">
      <?php vg_resource_trend($resourceScans, 'cpu_pct', '%', 1, 'cpu'); ?>
      </div>
    </div>

  <?php else: /* scans */ ?>
    <div class="card">
      <strong>스캔 이력</strong> <span class="why">— 회차를 눌러 그 시점의 취약점을 본다</span>
      <div class="card__body">
      <?php
      vg_table(
          [
              ['label' => '실행', 'key' => 'scan_id'],
              ['label' => '수집시각', 'key' => 'collected_at'],
              ['label' => '수신시각', 'key' => 'received_at'],
              ['label' => '패키지', 'key' => 'package_count', 'align' => 'right'],
              ['label' => '노출', 'key' => 'exposure_count', 'align' => 'right'],
              ['label' => '메모리', 'key' => 'peak_rss_mb', 'align' => 'right'],
              ['label' => 'CPU', 'key' => 'cpu_seconds', 'align' => 'right'],
              ['label' => '에이전트', 'key' => 'agent_version'],
              ['label' => '심각도', 'key' => 'sev'],
          ],
          $rows,
          [
              'card' => false,
              'empty' => [
                  'icon'  => '🕘',
                  'title' => '스캔 이력이 없습니다.',
              ],
              'cell' => [
                  'scan_id'        => fn($s) => '<a href="/findings.php?scan_id=' . (int) $s['scan_id'] . '">#' . (int) $s['scan_run_id'] . '</a>'
                      . ((int) $s['content_changed'] === 1
                          ? ' <span class="badge">변경</span>'
                          : ' <span class="why">동일</span>'),
                  'collected_at'   => fn($s) => vg_h($s['collected_at']),
                  'received_at'    => fn($s) => '<span class="why">' . vg_h($s['received_at']) . '</span>',
                  'package_count'  => fn($s) => number_format((int) $s['package_count']),
                  'exposure_count' => fn($s) => number_format((int) $s['exposure_count']),
                  'peak_rss_mb'    => fn($s) => vg_resource_mem($s['peak_rss_mb']),
                  'cpu_seconds'    => fn($s) => vg_resource_cpu($s['cpu_seconds']),
                  'agent_version'  => fn($s) => $s['agent_version'] ? '<code>' . vg_h($s['agent_version']) . '</code>' : '<span class="why">–</span>',
                  'sev' => fn($s) => vg_sev_counts($sevByScan[(int) $s['scan_id']] ?? []),
              ],
          ]
      );
      ?>
      </div>
    </div>
    <?php vg_page_nav($total, $perPage, $page); ?>
  <?php endif; ?>

  <?php if (vg_has_role('admin', 'operator')): ?>
    <div class="card mt-lg">
      <strong>자산 관리</strong>
      <span class="why"> · 목록과 집계에서 이 자산을 제외합니다. 수집 이력은 보존되며 에이전트가 다시 전송하면 재등록됩니다.</span>
      <div class="card__body">
        <form method="post" class="actions" data-confirm="<?= vg_h((string)$host['fqdn']) ?> 자산을 삭제할까요? 수집 이력은 남고 목록·집계에서만 제외됩니다.">
          <input type="hidden" name="csrf" value="<?= vg_h($agentCsrf) ?>">
          <input type="hidden" name="action" value="host_delete">
          <input type="hidden" name="id" value="<?= (int)$host['host_id'] ?>">
          <button type="submit" class="btn btn--sm btn--danger">자산 삭제</button>
        </form>
      </div>
    </div>
  <?php endif; ?>
<?php endif; ?>
<?php vg_footer();
