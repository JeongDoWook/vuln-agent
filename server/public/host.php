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
require_once __DIR__ . '/../src/finding_history.php';   // vg_finding_history_url — 이력 링크 조립
require_once __DIR__ . '/../src/finding_status.php';    // 조치 상태(사람이 정하는 값) 조회·저장
require_once __DIR__ . '/../src/agentcommand.php';   // 수집 제어(즉시/예약 실행·주기 변경)
require_once __DIR__ . '/../src/agentspeedtier.php';   // 속도 티어 라벨(agent-poll.php 와 공유 정의)
require_once __DIR__ . '/../src/assetgrade.php';       // 자산 중요도·N2SF 등급 어휘와 초안 제안
require_once __DIR__ . '/../src/assetgrade_history.php'; // 시스템 제안 관찰 이력 조회·표시
require_once __DIR__ . '/../src/asset_grade_review.php'; // 단일 자산의 구조화된 사람 검토 정보
require_once __DIR__ . '/../src/account_inventory.php';   // 계정 인벤토리 판정(vg_account_judgments)
require_once __DIR__ . '/../src/packagedep.php';   // 의존성 그래프 — 취약점의 직접/전이 판정
require_once __DIR__ . '/../src/suppression.php';  // 억제 근거 겹 분류·원근거 조회·재시작 필요 목록
/* 자산 상세의 속을 책임별로 나눠 둔 것 — 조회층 / 묶음·의존성 / 등급 카드 / 탭 렌더 디스패처.
 *   수집 제어(agent_control.php)는 POST 를 처리하므로 아래 제자리에서 따로 읽는다. */
require_once __DIR__ . '/../src/host/queries.php';   // vg_host_load_* — 활성 탭 하나의 조회
require_once __DIR__ . '/../src/host/depgraph.php';  // 묶음 조회 + 전이 의존성 판정 셀
require_once __DIR__ . '/../src/host/grade.php';     // vg_host_render_grade
require_once __DIR__ . '/../src/host/tabs.php';      // vg_host_render_tab — 활성 탭 파일만 require
vg_require_menu_any('assets', 'findings');   // 자산 상세: 자산 목록·탐지 결과에서 함께 열린다

/* '리소스' 탭은 '스캔 이력' 탭으로 흡수됐다 — 둘 다 tb_scan_run 하나를 읽었고(회차별 메모리·CPU),
 *   한쪽은 표, 다른 쪽은 같은 값의 추이 차트였다. 탭을 나눠 두면 "이 자산의 수집이 어땠나"를
 *   두 군데서 이어 붙여 읽어야 한다. 기존 링크·북마크를 살리려고 302 로 넘긴다(나머지 쿼리는 유지). */
if (($_GET['tab'] ?? '') === 'resources') {
    header('Location: /host.php' . vg_qs(['tab' => 'scans', 'page' => null]), true, 302);
    exit;
}

/* 수집 제어 POST 처리(즉시실행/예약실행/주기변경 …) — GET 렌더보다 먼저, 헤더 출력 전.
 *   이 파일은 include 되는 순간 그 처리를 하므로 **위치가 곧 실행 순서**다. 뒤로 밀면
 *   header('Location: …') 리다이렉트가 헤더 출력 뒤로 가서 깨진다. */
require_once __DIR__ . '/../src/host/agent_control.php';
$agentFlash = vg_flash_take();
$agentMsg = $agentFlash['agentMsg'] ?? null;
$agentErr = $agentFlash['agentErr'] ?? null;
$agentCsrf = vg_csrf_token();

$err = null; $host = null; $scan = null; $scanAge = null; $pollAge = null; $approver = null; $gradeReview = [];
$latestAgent = '';   // 함대에서 관측된 최신 에이전트 버전('구버전' 판정 기준)
$unsupContainers = [];   // 피드 미지원 배포판 컨테이너
$missingStages = [];     // 최신 스캔에서 수집 자체가 실패한 단계(한글 라벨)
$missingStageCodes = []; // 같은 것의 원본 코드 — 화면이 "이 항목이 미수집인가"를 물을 때 쓴다
$integrityRows = [];     // 패키지 원본과 다른 파일(상위 일부만 — 전체 건수는 tb_scan 에 있다)
$suppEvidence = ['errata' => [], 'changelog' => [], 'debsecan' => []];   // 억제 근거 원 데이터
$suppLayers = [];        // 억제 근거 겹별 건수(스캔 전체)
$staleLibs = ['total' => 0, 'rows' => []];   // 재시작 필요(옛 라이브러리를 물고 있는 프로세스)
$gradeSignals = [];      // 등급 제안 근거 신호(자산 설정 탭에서만 계산한다)

// 무결성 목록은 "상태를 알리는 미리보기"다. 전체 목록 화면은 만들지 않는다(YAGNI).
const VG_HOST_INTEGRITY_TOP = 20;

$counts =['CRITICAL'=>0,'HIGH'=>0,'MEDIUM'=>0,'LOW'=>0];
$exposureCount = 0; $processCount = 0; $runtimeTotal = 0; $cceFail = 0; $suppressedCount = 0; $vulnTotal = 0; $scanTotal = 0;
$critHighTotal = 0; $restartTotal = 0; $restartRows = []; $packageTotal = 0;
// 위험 요약(히어로 바로 아래) — 심각도 분포와 같은 한 번의 집계에서 함께 나온다.
$kevCount = 0; $externalFindings = 0;
// 같은 패키지에서 나온 취약점 묶음 — "이 하나를 올리면 N건". vuln 탭에서만 채운다.
$pkgRollup = ['rows' => [], 'truncated' => false];
// 상세 화면의 기본 페이지 크기는 목록 화면보다 크다(설정: UI_DETAIL_PER_PAGE_DEFAULT).
//   127건을 10개씩 13페이지로 넘기게 하면 "이 자산이 얼마나 위험한가"를 셀 수가 없다.
$tab = 'vuln'; $page = 1; $ePage = 1; $perPage = vg_perpage(vg_ui_detail_per_page_default()); $total = 0; $exposureTotal = 0;
/* 이 화면이 고른 크기를 요청 컨텍스트에도 반영한다. "N개씩 보기" 셀렉트(vg_perpage_select)와
 *   툴바는 공용 컴포넌트라 **쿼리스트링만 보고** 현재 크기를 판단한다 — 그대로 두면 40개를
 *   보여주면서 셀렉트는 "10개씩 보기" 가 선택된 채로 뜬다(사용자에겐 화면이 거짓말을 한다).
 *   사용자가 고른 값이 있으면 건드리지 않는다. */
if (!isset($_GET['per_page'])) { $_GET['per_page'] = (string) $perPage; }
$rows = []; $exposures = []; $sevByScan = []; $resourceScans = []; $restartRows = [];
$findingStatuses = [];   // 취약점 탭 행들의 조치 상태(자연키 → 행). 없으면 미조치로 읽는다.
$accountTotal = 0; $accountJudgments = []; $accountAllCount = 0; $depEdgeTotal = 0; $containerTotal = 0;
$sevByContainer = [];   // [container_id => [severity => n]] — 컨테이너 카드의 심각도 분포
// 전이 의존성 판정 + 손댈 대상(부모)별 묶음. 엣지가 없는 자산에선 이 기본값 그대로다.
$depOrigins = ['origins' => [], 'parents' => [], 'finding_total' => 0, 'finding_truncated' => false,
               'edge_truncated' => false, 'path_truncated' => false];
$gradeSuggestionHistory = [];
$q = trim((string) ($_GET['q'] ?? ''));
// 계정 탭 필터(?acc=). 화이트리스트 밖 값은 전체로 떨군다 — 값이 그대로 SQL 로 가지 않는다.
$accFilter = (string) ($_GET['acc'] ?? '');
if (!in_array($accFilter, ['sudo', 'locked', 'human', 'stale'], true)) { $accFilter = ''; }
$hasFilter = $q !== '' || $accFilter !== '';

try {
    $pdo = vg_pdo();
    $hostId = (int) ($_GET['id'] ?? 0);
    $st = $pdo->prepare('SELECT * FROM tb_host WHERE host_id = ? AND is_deleted = 0');
    $st->execute([$hostId]);
    $host = $st->fetch() ?: null;
    $pendingCommands = [];

    if ($host) {
        $gradeSuggestionHistory = vg_asset_grade_history_recent($pdo, $hostId);
        $gradeReview = vg_has_role('admin') ? vg_asset_grade_review_load($pdo, $hostId) : [];
        // 호스트 상세(설치 패키지·노출 포트·실행 프로세스 등 인프라 민감정보) 열람 감사로그.
        vg_log_activity($pdo, 'HOST', $hostId, 'view_host', (string) ($host['fqdn'] ?? null),
            subject: (string) ($host['fqdn'] ?? ''), action: 'READ');

        // 등급 확정자 이름(승인 이력) — 사용자가 지워졌으면 FK 가 NULL 이라 여기 안 들어온다.
        if (!empty($host['approved_by'])) {
            $st = $pdo->prepare('SELECT username FROM tb_user WHERE user_id = ?');
            $st->execute([(int) $host['approved_by']]);
            $u = $st->fetchColumn();
            $approver = $u === false ? null : (string) $u;
        }

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
        // agent_version 은 자산 목록에서 이 화면으로 옮겨 온 값이다(목록은 열어볼지 말지를
        //   정하는 열만 둔다) — 식별부에서 '이 자산이 무엇인가'의 일부로 보여준다.
        $st = $pdo->prepare('SELECT scan_id, collected_at, package_count, agent_version,
                                    integrity_checked, integrity_partial, integrity_total,
                                    TIMESTAMPDIFF(MINUTE, collected_at, NOW()) AS age_min
                               FROM tb_scan WHERE host_id = ? ORDER BY scan_id DESC LIMIT 1');
        $st->execute([$hostId]);
        $scan = $st->fetch() ?: null;

        /* 함대에서 관측된 가장 높은 에이전트 버전 — 이보다 낮으면 이 호스트만 옛 에이전트가
         *   돈다는 뜻이다. 중앙은 노드에 내려보내지 않으므로(노드가 밀어 올리기만 한다) 에이전트를
         *   고쳐도 각 노드에 다시 깔 때까지 옛 코드가 계속 돈다 — 실제로 몇 주를 못 알아챈 적이 있어
         *   숫자만이 아니라 '구버전' 신호가 필요하다. 기준을 코드에 박지 않고 관측된 최댓값으로
         *   잡는다(웹 컨테이너는 agent/ 를 마운트하지 않아 저장소 버전을 읽을 수 없다).
         *   버전은 '2.10' > '2.9' 라 문자열 비교로는 틀린다 → version_compare. */
        $latestAgent = (string) array_reduce(
            $pdo->query("SELECT DISTINCT agent_version FROM tb_scan
                          WHERE agent_version IS NOT NULL AND agent_version <> '' AND is_deleted = 0"
            )->fetchAll(PDO::FETCH_COLUMN),
            static fn(?string $max, string $v) => ($max === null || version_compare($v, $max, '>')) ? $v : $max
        );
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
            $missingStageCodes[] = $code;
            $missingStages[] = VG_COLLECTION_STAGE_LABEL[$code] ?? $code;   // 모르는 코드는 원문 그대로
        }

        // --- 히어로/KPI 집계 (탭과 무관한 값싼 COUNT) ---
        //   KEV(알려진 악용)·외부노출 건수는 심각도 분포와 같은 성격의 "위험 요약" 이라
        //   쿼리를 늘리지 않고 같은 GROUP BY 에 집계를 얹어 가져온다.
        $st = $pdo->prepare("SELECT severity, COUNT(*) c,
                                    SUM(in_kev = 1) kev, SUM(runtime_status = 'EXTERNAL') ext
                               FROM tb_finding WHERE scan_id = ? GROUP BY severity");
        $st->execute([$sid]);
        foreach ($st->fetchAll() as $r) {
            if (isset($counts[$r['severity']])) { $counts[$r['severity']] = (int) $r['c']; }
            $kevCount += (int) $r['kev'];
            $externalFindings += (int) $r['ext'];
        }

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

        // 의존성 그래프(depgraph.php) 진입 여부 — 엣지가 있는 자산에만 링크를 건다.
        //   uk_pkg_dep_edge 좌측 접두가 (scan_id, container_id)라 scan_id 만으로도 인덱스 레인지다.
        $st = $pdo->prepare('SELECT COUNT(*) FROM tb_package_dependency WHERE scan_id = ?');
        $st->execute([$sid]); $depEdgeTotal = (int) $st->fetchColumn();

        $st = $pdo->prepare('SELECT COUNT(*) FROM tb_host_account WHERE scan_id = ? AND is_deleted = 0');
        $st->execute([$sid]); $accountTotal = (int) $st->fetchColumn();

        $st = $pdo->prepare('SELECT COUNT(*) FROM tb_container WHERE scan_id = ? AND is_deleted = 0');
        $st->execute([$sid]); $containerTotal = (int) $st->fetchColumn();

        // --- 활성 탭 결정 (억제 탭은 건이 있을 때만 존재) ---
        $validTabs = ['vuln', 'packages', 'containers', 'runtime', 'cce', 'accounts'];
        if ($suppressedCount > 0) { $validTabs[] = 'suppressed'; }
        $validTabs[] = 'scans';
        // 설정 탭(수집 제어·자산 등급·자산 삭제) — 조회할 목록이 없어 아래 데이터 로딩에 분기가 없다.
        $validTabs[] = 'manage';
        $tab = (string) ($_GET['tab'] ?? 'vuln');
        if (!in_array($tab, $validTabs, true)) { $tab = 'vuln'; }

        $page   = vg_page();
        $offset = ($page - 1) * $perPage;
        $ePage  = vg_page('epage');

        // --- 활성 탭 데이터만 조회(+페이지네이션+검색) ---
        if ($tab === 'vuln') {
            ['total' => $total, 'rows' => $rows, 'restartRows' => $restartRows]
                = vg_host_load_vuln_tab($pdo, $sid, $critHighTotal, $perPage, $offset, $q);
            // 전이 의존성은 그 패키지만 갈아끼울 수 없다 — 손댈 대상(부모)을 찾아 조치 문구를 바꾸고,
            //   부모별로 묶어 "이 하나를 올리면 N건" 을 탭 상단에 보여준다.
            //   판정 대상은 **스캔 전체**다(페이지마다 답이 달라지면 우선순위가 아니다).
            //   $depEdgeTotal 은 위에서 이미 센 값이다. 0이면 여기서 끝나 쿼리가 늘지 않는다.
            if ($depEdgeTotal > 0) {
                $depOrigins = vg_pkgdep_scan_rollup($pdo, $sid);
            }
            // 위 묶음은 **의존성 엣지가 있는 자산에만** 나온다(언어 패키지). dpkg/rpm 만 있는
            //   자산에서도 "같은 패키지의 서로 다른 CVE" 는 행마다 같은 근거로 반복된다 —
            //   같은 질문("무엇부터 올리나")에 같은 형태로 답한다.
            $pkgRollup = vg_host_load_pkg_rollup($pdo, $sid, vg_ui_detail_preview_limit());
            // 이 화면에 보이는 행들의 조치 상태를 한 번에 읽는다(N+1 방지). 두 표(주 목록·재시작)를
            //   한 번에 물어본다 — 같은 자산의 같은 축이라 쿼리를 나눌 이유가 없다.
            $statusKeys = [];
            foreach (array_merge($rows, $restartRows) as $f) {
                $statusKeys[] = [$hostId, (string) ($f['container_cid'] ?? ''),
                                 (string) $f['cve_id'], (string) $f['package_name']];
            }
            $findingStatuses = vg_finding_statuses_map($pdo, $statusKeys);

        } elseif ($tab === 'packages') {
            ['total' => $total, 'rows' => $rows]
                = vg_host_load_packages_tab($pdo, $sid, $perPage, $offset, $q);
            // 패키지 무결성 — 상태 한 줄 + 상위 목록만(전체 표는 만들지 않는다). 이 탭에서만 조회한다.
            //   digest 불일치(5)를 먼저 보여준다 — 권한·소유자 차이보다 무거운 관측이다.
            $st = $pdo->prepare('SELECT package_name, flags, file_path FROM tb_package_integrity
                                  WHERE scan_id = ? ORDER BY INSTR(flags, \'5\') = 0, package_integrity_id
                                  LIMIT ' . VG_HOST_INTEGRITY_TOP);
            $st->execute([$sid]);
            $integrityRows = $st->fetchAll();
        } elseif ($tab === 'containers') {
            ['total' => $total, 'rows' => $rows, 'sevByContainer' => $sevByContainer]
                = vg_host_load_containers_tab($pdo, $sid, $perPage, $offset, $q);
        } elseif ($tab === 'runtime') {
            ['total' => $total, 'exposures' => $exposures, 'exposureTotal' => $exposureTotal,
             'rows' => $rows, 'ePage' => $ePage, 'stale' => $staleLibs]
                = vg_host_load_runtime_tab($pdo, $sid, $perPage, $offset, $ePage, $q);
        } elseif ($tab === 'cce') {
            ['total' => $total, 'rows' => $rows]
                = vg_host_load_cce_tab($pdo, $sid, $perPage, $offset, $q);
        } elseif ($tab === 'accounts') {
            ['total' => $total, 'rows' => $rows, 'judgments' => $accountJudgments, 'allCount' => $accountAllCount]
                = vg_host_load_accounts_tab($pdo, $sid, $perPage, $offset, $q, $accFilter);
            // 누가 이 호스트의 계정 목록을 열람했는지는 그 자체로 감사 대상이다(원칙 7).
            vg_log_activity($pdo, 'HOST', $hostId, 'view_host_accounts',
                '계정 인벤토리 열람: ' . (string) ($host['fqdn'] ?? ''), ['accounts' => $total]);
        } elseif ($tab === 'suppressed') {
            ['total' => $total, 'rows' => $rows, 'evidence' => $suppEvidence, 'layers' => $suppLayers]
                = vg_host_load_suppressed_tab($pdo, $sid, $suppressedCount, $perPage, $offset, $q);
        } elseif ($tab === 'scans') { // 회차 표 + 같은 회차들의 리소스 추이
            ['total' => $total, 'rows' => $rows, 'sevByScan' => $sevByScan, 'resourceScans' => $resourceScans]
                = vg_host_load_scans_tab($pdo, $hostId, $scanTotal, $perPage, $offset);
        } elseif ($tab === 'manage') {
            // 등급 제안 근거 칩 — 확정 화면(자산 설정)에서만 계산한다. 다른 탭의 쿼리를 늘리지 않는다.
            //   제안 자체와 **같은 함수**를 쓴다(assetgrade.php) — 화면이 근거를 따로 조립하면
            //   "제안은 S 인데 칩은 다른 얘기" 가 된다.
            $gradeSignals = vg_asset_grade_signals($pdo, $sid);
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
  <div class="card"><?php vg_empty(['icon' => 'host', 'title' => '요청한 호스트 정보가 없습니다.', 'cta' => ['href' => '/', 'label' => '← 대시보드']]); ?></div>
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
  <?php vg_host_render_grade($hostId, $host, $gradeReview, $agentCsrf, $approver, vg_has_role('admin')); ?>
  <?php vg_asset_grade_history_render($gradeSuggestionHistory); ?>
  <div class="card"><?php vg_empty(['icon' => 'feed', 'title' => '아직 수집된 스캔이 없습니다.', 'hint' => '에이전트를 --send 로 실행하면 여기에 나타납니다.']); ?></div>
<?php else:
    // 최고 위험도 → 히어로 톤. 하나도 없으면 '양호'(ok).
    $worst = null;
    foreach (['CRITICAL','HIGH','MEDIUM','LOW'] as $s) { if ($counts[$s] > 0) { $worst = $s; break; } }
    $heroTone = $worst ? vg_sev_tone($worst) : 'ok';

    // 탭 정의(배열 순서 = 표시 순서). n 은 라벨 옆 숫자(null 이면 숨김).
    $tabDefs = [
        'vuln'    => ['label' => '취약점',    'n' => $vulnTotal],
        'packages'=> ['label' => '설치 패키지', 'n' => $packageTotal],
        // 컨테이너 대장 — 호스트와 OS 가 다를 수 있는 별도 자산이라 목록을 따로 준다.
        'containers'=> ['label' => '컨테이너', 'n' => $containerTotal],
        // 이 탭은 노출 소켓과 실행 프로세스 두 목록을 함께 제공하므로 둘의 합계를 표시한다.
        'runtime' => ['label' => '런타임',    'n' => $runtimeTotal],
        'cce'     => ['label' => '보안 설정', 'n' => $cceFail],
        // 계정 대장 — "설정 정책"이 아니라 실제로 존재하는 계정(ISMS-P 2.5.x · N2SF AC).
        'accounts'=> ['label' => '계정',      'n' => $accountTotal],
    ];
    if ($suppressedCount > 0) { $tabDefs['suppressed'] = ['label' => '억제', 'n' => $suppressedCount]; }
    // 스캔 이력 = 회차 표 + 그 회차들의 에이전트 리소스 추이(예전 '리소스' 탭을 흡수).
    $tabDefs['scans'] = ['label' => '스캔 이력', 'n' => $scanTotal];
    /* 자산 설정 = 수집 제어 + 자산 등급 + 자산 삭제. 위험을 읽는 탭들 뒤에 둔다.
     *   등급 카드·삭제 카드는 예전엔 **모든 탭 아래**에 매번 붙어 있었다 — 취약점을 보러 온
     *   사람이 탭을 옮길 때마다 열 칸짜리 등급 확정 폼을 지나쳐야 했다. 한 곳으로 모은다. */
    $tabDefs['manage'] = ['label' => '자산 설정', 'n' => null];
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
  /* 의존성 그래프 링크는 식별부에서 내렸다 — 자산 계열 화면(전체 설치 패키지·의존성 그래프)의
   *   진입점은 '구성 > 설치 패키지' 탭 한 곳으로 모은다. 링크 자체는 그 탭에 그대로 있다
   *   (엣지가 있는 자산에만 — 없는 자산에 걸면 빈 화면으로 보내게 된다). */
  if (!empty($host['last_seen_ip'])) { $meta[] = 'IP ' . vg_h($host['last_seen_ip']); }
  /* 에이전트 버전 — 자산 목록에서 내려온 값이다. 숫자만으론 그게 최신인지 알 수 없어
   *   목록이 달고 있던 '구버전' 뱃지도 같이 가져온다(신호를 옮기는 것이지 없애는 게 아니다). */
  if (!empty($scan['agent_version'])) {
      $av  = (string) $scan['agent_version'];
      $old = $latestAgent !== '' && version_compare($av, $latestAgent, '<');
      $meta[] = '에이전트 <code>' . vg_h($av) . '</code>'
          . ($old ? ' ' . vg_badge('구버전', 'med',
                "함대 최신은 {$latestAgent} — master 에서 deploy/agent_push.sh 로 갱신하세요") : '');
  }
  /* 자산 등급은 설정 탭으로 내려갔지만 "이 자산이 무엇인가"의 일부라 식별부에 남긴다 —
   *   옮기는 것이지 지우는 것이 아니다. 미확정이면 확정하러 갈 자리를 링크로 준다. */
  $meta[] = ($host['grade'] ?? '') !== ''
      ? '등급 ' . vg_asset_grade_badge((string) $host['grade'], false, (string) ($host['grade_reason'] ?? ''))
      : '<a href="' . vg_h(vg_qs(['tab' => 'manage', 'page' => null, 'q' => null])) . '">등급 미확정</a>';
  /* 자산 설정(수집 제어·등급·삭제)은 '이력' 그룹의 두 번째 하위 탭이라 상위 탭 한 번으로는
   *   닿지 않는다 — 첫 화면에서 한 번에 갈 자리를 식별부에 남긴다. 탭 줄에서 내린 것이지
   *   기능을 숨긴 것이 아니다(폼은 그 탭에 그대로 있다). */
  if (vg_can('assets')) {
      $meta[] = '<a href="' . vg_h(vg_qs(['tab' => 'manage', 'page' => null, 'q' => null])) . '">자산 설정</a>';
  }
  $meta[] = '<a href="/">대시보드</a>';
  if (vg_can('assets')) { $meta[] = '<a href="/assets.php">자산관리</a>'; }
  vg_hero(vg_h($host['fqdn']), $meta, $worst ?? '양호', $heroTone, '최고 위험도', '');
  /* 수집 제어(즉시 실행·예약·주기·속도 티어)는 '자산 설정' 탭으로 내려갔다.
   *   자산 상세를 여는 이유는 "이 서버가 얼마나 위험한가"이지 "수집 주기가 몇 분인가"가 아니다 —
   *   첫 화면을 설정 폼이 통째로 차지하면 위험 요약과 취약점 목록이 스크롤 아래로 밀린다.
   *   기능은 그대로 살아 있다(같은 폼·같은 action·같은 엔드포인트). */

  /* SBOM 다운로드. 지금까지 sbom.php 는 만들어 두고 **화면 어디에서도 링크하지 않아**,
   *   URL 을 아는 사람만 쓸 수 있었다(grep 결과 링크 0건). 부품표는 자산의 속성이라
   *   자산 상세 첫 화면이 제자리다. 컨테이너별 SBOM 은 컨테이너 상세에 같은 줄로 있다. */
  vg_sbom_links((string) $host['fqdn']);

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

  <?php
  /* 이 화면이 무엇을 담고 있는지 — 호스트 안에 컨테이너가 있고, 그 안에 패키지가 있고,
   *   그중 일부가 실제로 돌고 있으며(프로세스), 그중 일부만 밖에서 닿는다(노출).
   *   아래 탭들이 그 순서 그대로 서 있다 — 도식은 탭의 지도이지 새 정보가 아니다.
   *   숫자는 이미 센 값을 그대로 쓴다(다시 세지 않는다). */
  vg_explain_flow([
      ['icon' => 'host',      'label' => '호스트', 'state' => 'done'],
      ['icon' => 'container', 'label' => '컨테이너', 'value' => number_format($containerTotal), 'state' => 'done'],
      ['icon' => 'package',   'label' => '패키지', 'value' => number_format($packageTotal), 'state' => 'done'],
      ['icon' => 'process',   'label' => '프로세스', 'value' => number_format($processCount), 'state' => 'done'],
      ['icon' => 'port',      'label' => '노출', 'value' => number_format($exposureCount),
       'state' => $externalFindings > 0 ? 'active' : 'done'],
  ], ['label' => '호스트 안의 계층']);
  ?>

  <div class="cards">
    <?php foreach (['CRITICAL','HIGH','MEDIUM','LOW'] as $s): ?>
      <div class="kpi kpi--sm tone-<?= vg_sev_tone($s) ?>"><b><?= (int) $counts[$s] ?></b><span><?= $s ?></span></div>
    <?php endforeach; ?>
    <?php /* 심각도 분포만으로는 "지금 당장 무엇이 무서운가"를 못 읽는다 — 실제로 악용되고 있고
             (KEV) 밖에서 닿는(EXTERNAL) 건수를 같은 줄에 세운다. 둘 다 위 GROUP BY 한 번에서 나온다. */ ?>
    <div class="kpi kpi--sm tone-<?= $kevCount > 0 ? 'crit' : 'muted' ?>"
         title="KEV — 실제 악용이 확인된 취약점(CISA Known Exploited Vulnerabilities)">
      <b><?= number_format($kevCount) ?></b><span>KEV 악용확인</span>
    </div>
    <a class="kpi kpi--sm tone-<?= $externalFindings > 0 ? 'crit' : 'ok' ?>"
       href="/findings.php?scan_id=<?= (int) $scan['scan_id'] ?>&amp;st=EXTERNAL">
      <b><?= number_format($externalFindings) ?></b><span>외부노출 취약점</span>
    </a>
    <a class="kpi kpi--sm" href="<?= vg_h(vg_qs(['tab' => 'runtime', 'page' => null, 'q' => null])) ?>">
      <b><?= number_format($exposureCount) ?></b><span>노출 소켓</span>
    </a>
    <a class="kpi kpi--sm tone-<?= $cceFail > 0 ? 'high' : 'ok' ?>" href="<?= vg_h(vg_qs(['tab' => 'cce', 'page' => null])) ?>">
      <b><?= (int) $cceFail ?></b><span>설정 취약</span>
    </a>
  </div>

  <?php /* 2단 탭 — 상위 4개(위험·구성·준거·이력) + 그 그룹의 하위 탭. 매핑은 nav.php 소유.
           $tab 키와 각 탭의 조회 분기는 그대로다(URL 하위호환 · 쿼리는 여전히 활성 탭 하나만 돈다). */ ?>
  <?php vg_asset_tabs($tabDefs, $tab); ?>

  <?php
  /* 활성 탭 하나만 그린다(host/tabs/<탭>.php). 조회가 활성 탭 것만 도는 것과 같은 이유로,
   *   읽는 파일도 하나다 — 탭 렌더가 늘어도 다른 탭의 코드는 이 요청에 실리지 않는다.
   *   렌더 파일이 이 페이지의 전역을 암묵적으로 주워 쓰지 않도록, 쓰는 값을 전부 여기 열거한다. */
  vg_host_render_tab($tab, [
      // 자산·스캔 식별
      'host' => $host, 'hostId' => $hostId, 'scan' => $scan, 'tab' => $tab,
      // 목록 공통(검색·페이지네이션)
      'q' => $q, 'accFilter' => $accFilter, 'hasFilter' => $hasFilter,
      'perPage' => $perPage, 'page' => $page, 'ePage' => $ePage,
      'total' => $total, 'exposureTotal' => $exposureTotal, 'rows' => $rows, 'exposures' => $exposures,
      // 히어로/KPI 에서 이미 센 값(탭이 다시 세지 않는다)
      'counts' => $counts, 'worst' => $worst, 'kevCount' => $kevCount,
      'externalFindings' => $externalFindings, 'exposureCount' => $exposureCount,
      'vulnTotal' => $vulnTotal, 'critHighTotal' => $critHighTotal, 'restartTotal' => $restartTotal,
      'packageTotal' => $packageTotal, 'containerTotal' => $containerTotal,
      'accountTotal' => $accountTotal, 'depEdgeTotal' => $depEdgeTotal,
      'missingStageCodes' => $missingStageCodes,
      // 활성 탭에서만 채워지는 값
      'restartRows' => $restartRows, 'depOrigins' => $depOrigins, 'pkgRollup' => $pkgRollup,
      'findingStatuses' => $findingStatuses, 'integrityRows' => $integrityRows,
      'sevByContainer' => $sevByContainer, 'sevByScan' => $sevByScan, 'resourceScans' => $resourceScans,
      'staleLibs' => $staleLibs, 'suppLayers' => $suppLayers, 'suppEvidence' => $suppEvidence,
      'accountJudgments' => $accountJudgments, 'gradeSignals' => $gradeSignals,
      // 자산 설정 탭(수집 제어·등급·삭제)
      'scopeTone' => $scopeTone, 'agentCsrf' => $agentCsrf,
      'agentMsg' => $agentMsg, 'agentErr' => $agentErr, 'pendingCommands' => $pendingCommands,
      'gradeReview' => $gradeReview, 'approver' => $approver,
      'gradeSuggestionHistory' => $gradeSuggestionHistory,
  ]);
  ?>
<?php endif; ?>
<?php vg_footer();
