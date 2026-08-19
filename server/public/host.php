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
/* 자산 상세의 속을 책임별로 나눠 둔 것 — 식별부 조회 / 히어로·KPI 집계 / 탭별 조회 /
 *   묶음·의존성 / 등급 카드 / 탭 렌더 디스패처.
 *   수집 제어(agent_control.php)는 POST 를 처리하므로 아래 제자리에서 따로 읽는다. */
require_once __DIR__ . '/../src/host/identity.php';  // 식별부 조회(호스트·최신 스캔·에이전트)
require_once __DIR__ . '/../src/host/summary.php';   // 히어로/KPI 집계 + 머리 경고의 근거 조회
require_once __DIR__ . '/../src/host/queries.php';   // vg_host_load_*_tab — 활성 탭 하나의 조회
require_once __DIR__ . '/../src/host/depgraph.php';  // 묶음 조회 + 전이 의존성 판정 셀
require_once __DIR__ . '/../src/host/hero.php';      // vg_host_render_hero — 탭 줄 위 머리 렌더
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
$missingStageItemCounts = []; // 코드 => item_count. 0 이면 아예 못 걸음, > 0 이면 중간에 끊김
$integrityRows = [];     // 패키지 원본과 다른 파일(상위 일부만 — 전체 건수는 tb_scan 에 있다)
$suppEvidence = ['errata' => [], 'changelog' => [], 'debsecan' => []];   // 억제 근거 원 데이터
$suppLayers = [];        // 억제 근거 겹별 건수(스캔 전체)
$staleLibs = ['total' => 0, 'rows' => []];   // 재시작 필요(옛 라이브러리를 물고 있는 프로세스)
$gradeSignals = [];      // 등급 제안 근거 신호(자산 설정 탭에서만 계산한다)

$counts =['CRITICAL'=>0,'HIGH'=>0,'MEDIUM'=>0,'LOW'=>0];
$exposureCount = 0; $processCount = 0; $runtimeTotal = 0; $cceFail = 0; $suppressedCount = 0; $vulnTotal = 0; $scanTotal = 0;
$critHighTotal = 0; $restartTotal = 0; $restartRows = []; $packageTotal = 0;
// 위험 요약(히어로 바로 아래) — 심각도 분포와 같은 한 번의 집계에서 함께 나온다.
$kevCount = 0; $externalFindings = 0;
// 같은 패키지에서 나온 취약점 묶음 — "이 하나를 올리면 N건". vuln 탭에서만 채운다.
$pkgRollup = ['rows' => [], 'truncated' => false];
$tab = 'vuln'; $page = 1; $ePage = 1; $perPage = vg_perpage(vg_ui_per_page_default()); $total = 0; $exposureTotal = 0;
/* 이 화면이 고른 크기를 요청 컨텍스트에도 반영한다. "N개씩 보기" 셀렉트(vg_perpage_select)와
 *   툴바는 공용 컴포넌트라 **쿼리스트링만 보고** 현재 크기를 판단한다 — 그대로 두면 실제
 *   보여주는 건수와 셀렉트 선택값이 어긋난 채로 뜬다(사용자에겐 화면이 거짓말을 한다).
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
    $host = vg_host_find($pdo, $hostId);
    $pendingCommands = [];

    if ($host) {
        $gradeSuggestionHistory = vg_asset_grade_history_recent($pdo, $hostId);
        $gradeReview = vg_has_role('admin') ? vg_asset_grade_review_load($pdo, $hostId) : [];
        // 호스트 상세(설치 패키지·노출 포트·실행 프로세스 등 인프라 민감정보) 열람 감사로그.
        vg_log_activity($pdo, 'HOST', $hostId, 'view_host', (string) ($host['fqdn'] ?? null),
            subject: (string) ($host['fqdn'] ?? ''), action: 'READ');

        $approver = vg_host_load_approver($pdo, $host);
        $pollAge  = vg_host_load_poll_age($pdo, (string) $host['fqdn']);
        // 대기 중인 수집 명령은 자산 설정 권한이 있는 사람에게만 보여준다(인가는 화면이 확정한다).
        if (vg_can('assets')) {
            $pendingCommands = vg_host_load_pending_commands($pdo, $hostId);
        }
        $scan        = vg_host_load_latest_scan($pdo, $hostId);
        $latestAgent = vg_host_load_latest_agent_version($pdo);
    }

    if ($scan) {
        $sid = (int) $scan['scan_id'];
        $scanAge = $scan['age_min'];

        // 화면 머리의 두 경고("0건 = 안전"이 아닐 수 있다)가 읽는 근거.
        $unsupContainers = vg_host_load_unsupported_containers($pdo, $sid);
        ['codes' => $missingStageCodes, 'labels' => $missingStages, 'itemCounts' => $missingStageItemCounts]
            = vg_host_load_missing_stages($pdo, $sid);

        // --- 히어로/KPI 집계 (탭과 무관한 값싼 COUNT) ---
        ['counts' => $counts, 'kev' => $kevCount, 'external' => $externalFindings]
            = vg_host_load_severity_summary($pdo, $sid);

        [
            'exposureCount' => $exposureCount, 'cceFail' => $cceFail, 'suppressedCount' => $suppressedCount,
            'vulnTotal' => $vulnTotal, 'critHighTotal' => $critHighTotal, 'restartTotal' => $restartTotal,
            'scanTotal' => $scanTotal, 'processCount' => $processCount, 'packageTotal' => $packageTotal,
            'depEdgeTotal' => $depEdgeTotal, 'accountTotal' => $accountTotal, 'containerTotal' => $containerTotal,
        ] = vg_host_load_kpi_counts($pdo, $sid, $hostId);
        // 런타임 탭은 노출 소켓과 실행 프로세스 두 목록을 함께 담아 배지가 둘의 합이다.
        $runtimeTotal = $exposureCount + $processCount;

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
            $integrityRows = vg_host_load_integrity_rows($pdo, $sid);
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
  <?php vg_page_title('호스트 상세', 'ASSET DETAIL'); ?>
  <?php vg_alert('오류 · ' . $err); ?>
<?php elseif (!$host): ?>
  <?php vg_page_title('호스트를 찾을 수 없습니다', 'ASSET DETAIL'); ?>
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

    // 탭 줄 정의 — 숫자는 위에서 이미 센 값 그대로다(host/tabs.php 가 순서·라벨을 갖는다).
    $tabDefs = vg_host_tab_defs([
        'vulnTotal' => $vulnTotal, 'packageTotal' => $packageTotal,
        'containerTotal' => $containerTotal, 'runtimeTotal' => $runtimeTotal,
        'cceFail' => $cceFail, 'accountTotal' => $accountTotal,
        'suppressedCount' => $suppressedCount, 'scanTotal' => $scanTotal,
    ]);
?>
  <?php vg_host_render_hero([
      'host' => $host, 'scan' => $scan, 'pollAge' => $pollAge, 'scanAge' => $scanAge,
      'latestAgent' => $latestAgent, 'worst' => $worst, 'heroTone' => $heroTone,
      'unsupContainers' => $unsupContainers, 'missingStages' => $missingStages,
      'missingStageCodes' => $missingStageCodes,
      'missingStageItemCounts' => $missingStageItemCounts,
      'counts' => $counts, 'kevCount' => $kevCount, 'externalFindings' => $externalFindings,
      'exposureCount' => $exposureCount, 'cceFail' => $cceFail, 'processCount' => $processCount,
      'packageTotal' => $packageTotal, 'containerTotal' => $containerTotal,
      // 즉시 실행 버튼(식별부) — 폼이므로 CSRF 토큰과 대상 자산이 필요하다.
      //   대기 중인 명령이 있으면 버튼 대신 그 상태를 말한다(같은 명령을 두 번 넣지 않게).
      'hostId' => $hostId, 'agentCsrf' => $agentCsrf, 'pendingCommands' => $pendingCommands,
      // 눌린 결과(플래시)는 활성 탭이 설정 탭이 아닐 때만 머리가 그린다(설정 탭은 자기 카드가 그린다).
      'tab' => $tab, 'agentMsg' => $agentMsg, 'agentErr' => $agentErr,
  ]); ?>

  <?php /* 탭 줄은 한 줄(1단)이다 — 2단(위험·구성·준거·이력 + 하위 탭)은 "탭을 타고 타고" 들어가야
           해서 오히려 멀어졌다. 억제를 취약점 탭의 필터로 내려 탭 수를 늘리지 않고 깊이만 줄인다.
           $tab 키와 각 탭의 조회 분기는 그대로다(URL 하위호환 · 쿼리는 여전히 활성 탭 하나만 돈다). */ ?>
  <?php vg_host_render_tabline($tabDefs, $tab); ?>

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
      // 억제 건수는 취약점 탭의 보기 전환(취약점 ↔ 억제됨)이 읽는다 — 탭 줄이 아니라 필터다.
      'suppressedCount' => $suppressedCount,
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
  ], $validTabs);
  ?>
<?php endif; ?>
<?php vg_footer();
