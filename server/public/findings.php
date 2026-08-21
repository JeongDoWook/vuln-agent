<?php
declare(strict_types=1);

/**
 * findings.php — 탐지 결과 한 화면. 로그인 필요.
 *   세 유형을 탭으로 담는다(?type=): cve(기본) / cce(보안설정 점검) / exposure(런타임 노출).
 *   기본  : 전 호스트의 "각 호스트 최신 수집" 을 통합해서 보여준다(호스트 컬럼 표시).
 *   ?host=N     : 그 호스트의 최신 수집만.
 *   ?scan_id=N  : 특정 스캔 하나만(대시보드·호스트 상세에서 넘어오는 링크). 이때만 부제에 scan# 표시.
 *   검색(q)/등급(sev) + 탭별 필터(cve: st·fx / cce: res / exposure: scope) + 페이지네이션.
 *
 *   세 표(tb_finding·tb_cce_finding·tb_exposure)를 UNION 하지 않는다 — tb_finding 이 큰 표라
 *   합쳐서 정렬·페이징하면 인덱스가 죽는다(대시보드 파생테이블 리라이트로 235ms→42초가 된
 *   운영 실측이 있다). 탭마다 자기 쿼리 하나가 정답이다. 화면 구성은 packages.php 의
 *   ?tab=os/lang 패턴을 그대로 따른다(vg_subtabs + 툴바에 탭 hidden).
 *
 *   이 파일은 요청 처리 · 활성 탭 결정 · 화면 머리(범위 줄·탭 줄) · 탭 디스패치만 갖는다.
 *   탭별 조회는 src/findings/queries.php, 탭 본문은 src/findings/tabs/<탭>.php 다
 *   (활성 탭 것 하나만 읽는다). 건수·분포는 각 탭이 자기 KPI·범례로 말한다.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require __DIR__ . '/../src/distro.php';   // vg_distro_unsupported — 피드 미지원 배포판 경고
require_once __DIR__ . '/../src/remediation_note.php';   // 미조치 사유 + 승인자(최소 필드)
require_once __DIR__ . '/../src/finding_history.php';    // vg_finding_history_url — 행별 상세 진입로
require_once __DIR__ . '/../src/finding_status.php';     // 조치 상태(사람이 정하는 값) — 자연키 조인
require_once __DIR__ . '/../src/finding_sla.php';        // 조치 기한 — 설정의 SLA 를 그대로 읽어 남은 일수
require_once __DIR__ . '/../src/findings/queries.php';   // 탭별 조회(합치지 않는다 — 그 파일 머리주석)
require_once __DIR__ . '/../src/findings/tabs.php';      // vg_findings_render_tab — 활성 탭 파일 하나만 require
vg_require_menu('findings');

/**
 * 탐지 유형 탭. "세 유형" 이라는 사실을 여기 하나로만 둔다 — 화이트리스트 검증·탭 렌더·
 *   툴바 hidden 값이 전부 이 상수를 참조한다. 'clear' 는 다른 탭으로 넘어갈 때 비울
 *   그 탭 전용 파라미터다(호스트·스캔·검색어·등급은 공통 축이라 유지한다).
 *   라벨은 여기 없다 — 세 화면이 함께 그리는 탭 줄이라 nav.php 의
 *   vg_findings_subtab_labels() 가 정본이다.
 */
const VG_FINDING_TYPES = [
    'cve'      => ['clear' => ['st', 'fx', 'ctr', 'fst', 'sort']],
    'cce'      => ['clear' => ['res']],
    'exposure' => ['clear' => ['scope']],
];

/**
 * "판정 불가" 경고에 펴 놓을 사유 줄 수. 나머지는 접힘(details) 안으로 간다.
 *   배포판 종류가 많은 환경(dev 실측: 호스트 199대)에서는 사유만도 열 줄이 넘어, 상한이 없으면
 *   요약으로 바꾼 의미가 없다. 3줄은 배너 전체(제목 1 + 요약 3 + 접힘 1)가 다섯 줄을 넘지
 *   않게 잡은 값이다 — .hint-list 의 max-height 가 같은 기준으로 물리적 상한도 건다.
 *   쓰는 곳은 CVE 탭 하나뿐이지만 상수 선언은 페이지에 남긴다(탭 파일은 함수 스코프에서
 *   require 되므로 const 를 두기에 맞는 자리가 아니다).
 */
const VG_UNSUP_HINT_PREVIEW = 3;

$type = (string) ($_GET['type'] ?? 'cve');
if (!isset(VG_FINDING_TYPES[$type])) { $type = 'cve'; }

$notes = [];   // 이 페이지 행들의 미조치 사유 메모 (자연키 → 메모)
$firstSeen = [];   // 이 페이지 행들의 최초 발견 경과일 (자연키 → ['first_seen','days'])
$policy = null;    // 조치 기한(SLA) 기준일 — 설정값. vg_compliance_policy() 가 정본이다.

// 취약점 0건이 "안전"이 아니라 "판정 불가"인 대상(호스트 + 컨테이너). 사유별로 묶는다 —
//   대상마다 사유를 통째로 반복하면(운영 실측 41줄, 그중 20줄이 같은 100자 문장) 경고가
//   길어서 아무도 안 읽는다. 사유 한 줄 + 그 사유에 걸린 대상 목록이면 정보량은 같다.
$unsupBy = [];      // 사유 => [대상명, …]

// 등급 어휘는 탭마다 다르다 — CCE 판정에는 CRITICAL 이 없다(cce.php 가 HIGH/MEDIUM/LOW 만 준다).
//   탭별 화이트리스트로 검증하므로, 탭을 옮기며 sev 를 들고 가도 그 탭에 없는 값이면 자동으로 풀린다.
$sevOptions = $type === 'cce' ? ['HIGH', 'MEDIUM', 'LOW'] : ['CRITICAL', 'HIGH+', 'HIGH', 'MEDIUM', 'LOW'];
$stOptions  = ['EXTERNAL', 'LAN', 'FILTERED', 'LISTENING', 'RUNNING', 'LOADED', 'INSTALLED'];
// 노출 범위(tb_exposure.scope) — 표시 라벨은 vg_scope_label() 이 갖는다(format.php).
//   '-'(bind 주소를 못 읽은 소켓)까지 포함해야 카드 합계가 목록 건수와 맞는다 — 빼면
//   "카드 어디에도 없는 행" 이 표에만 남아 숫자가 안 맞는 것처럼 보인다.
$scopeOptions = ['EXTERNAL', 'LAN', 'BOUND', 'FILTERED', 'LOCAL', '-'];
// CCE 판정 결과. 기본은 위반(FAIL)만 본다 — 'ALL' 이어야 PASS·NA 까지 함께 나온다.
$resOptions = ['FAIL', 'PASS', 'NA', 'ALL'];

$err = null; $scan = null; $rows = []; $total = 0; $perPage = vg_perpage();
$scanIds = []; $hostOptions = []; $hostFound = false; $hostOptionCount = 0;
$counts = ['CRITICAL'=>0,'HIGH'=>0,'MEDIUM'=>0,'LOW'=>0];
$cceResultCounts = ['FAIL'=>0, 'PASS'=>0, 'NA'=>0];   // cce 탭 카드
$cceFailSevCounts = ['HIGH'=>0, 'MEDIUM'=>0, 'LOW'=>0];   // cce 탭 두 번째 카드(위반의 등급 구성)
$scopeCounts = [];                                    // exposure 탭 카드 (scope => 건수)
$expProcCounts = [];                                  // exposure 탭 두 번째 카드 (프로세스 => [건수, 외부노출])
$expCveCounts = [];                                   // 노출 행 → 그 실행 패키지에 걸린 CVE 건수
// 'total'·'overdue_base' 는 미니 도넛의 **분모**다(조회층이 이미 세는 값을 그대로 받는다).
$actionCounts = ['kev' => 0, 'restart' => 0, 'overdue' => 0, 'total' => 0, 'overdue_base' => 0];
// 노출 상태 도넛(cve 탭). 키·순서의 정본은 VG_RUNTIME_DONUT 이다 — 여기서 다시 나열하지 않는다.
$runtimeCounts = array_fill_keys(array_keys(VG_RUNTIME_DONUT), 0);

$q   = trim((string) ($_GET['q'] ?? ''));
$sev = (string) ($_GET['sev'] ?? '');
$st  = (string) ($_GET['st'] ?? '');
$fx  = (string) ($_GET['fx'] ?? '');
// 조치 상태(사람이 정한 값). 위의 $st(노출 상태)와는 **다른 축**이라 파라미터·라벨을 갈라 둔다.
//   값 목록은 vg_finding_status_labels() 하나가 정본이다 — 여기서 다시 나열하지 않는다.
$fst = (string) ($_GET['fst'] ?? '');
// 정렬. 기본은 지금까지의 위험도 순서고, 'due' 일 때만 조치 기한이 임박한 순으로 세운다.
$sort = (string) ($_GET['sort'] ?? '');
$res = (string) ($_GET['res'] ?? '');
$scope = (string) ($_GET['scope'] ?? '');
if (!in_array($res, $resOptions, true)) { $res = 'FAIL'; }
if (!in_array($scope, $scopeOptions, true)) { $scope = ''; }
if (!in_array($sev, $sevOptions, true)) { $sev = ''; }
if (!in_array($st, $stOptions, true)) { $st = ''; }
// 조치 가능성: '' 전체 / action 조치 가능 / nofix 조치 불가(벤더가 수정본을 안 냈다)
//              / restart 재시작·재부팅만 하면 됨(패치는 이미 됐다 — 자산 상세에서 넘어온다)
if (!in_array($fx, ['action', 'nofix', 'restart', 'kev', 'overdue'], true)) { $fx = ''; }
if ($fst !== '' && !vg_finding_status_valid($fst)) { $fst = ''; }
if ($sort !== 'due') { $sort = ''; }
$page   = vg_page();
$hostId = (int) ($_GET['host'] ?? 0);
$scanId = (int) ($_GET['scan_id'] ?? 0);
// 컨테이너 스코프(?ctr=). **0 은 "호스트 자신"** 이라 "없음" 과 구분해야 한다(tb_finding.container_id
//   규약 — 18-containers.sql). 그래서 값이 아니라 파라미터의 존재 여부로 켠다.
//   제거 권고 목록에서 컨테이너 행을 눌러 왔을 때, 같은 호스트의 다른 컨테이너 판정까지
//   섞여 보이지 않게 한다. 툴바에 넣지 않는 이유는 이게 필터가 아니라 컨텍스트이기 때문
//   (scan_id·host 와 같은 부류 — '필터 초기화' 로도 사라지지 않는다).
$ctrParam = $_GET['ctr'] ?? null;
$ctrId    = ($ctrParam !== null && $ctrParam !== '' && ctype_digit((string) $ctrParam)) ? (int) $ctrParam : null;
$ctrLabel = null;   // 부제에 뭘 보고 있는지 밝힌다(스코프를 숨기면 0건이 '안전' 으로 읽힌다)

try {
    $pdo = vg_pdo();

    // 호스트별 최신 수집 (삭제된 호스트 제외) — 통합 뷰의 대상 스캔 집합.
    $hosts = vg_findings_load_hosts($pdo);
    foreach ($hosts as $h) {
        $hid = (int) $h['host_id'];
        if ($hid === $hostId) { $hostFound = true; }
        if ($hostOptionCount < vg_ui_filter_option_limit() || $hid === $hostId) {
            $hostOptions[$hid] = (string) $h['fqdn'];
            $hostOptionCount++;
        }
        // 피드가 지원하지 않는 배포판은 매칭 후보가 없어 0건으로 뜬다 → 목록에 모아 경고한다.
        $reason = vg_distro_unsupported($h['os_id'] ?? null, $h['os_version'] ?? null);
        if ($reason !== null) { $unsupBy[$reason][] = (string) $h['fqdn']; }
    }

    // 컨테이너도 같은 이유로 0건이 된다 — 특히 **패키지 DB 가 없는 이미지**(Calico 등)는
    //   rhel 로 잡혀 "미지원 배포판" 경고에도 안 걸린 채 조용히 0건으로 지나갔다(운영 실측 9개).
    // CVE 탭 전용이다 — 이 경고는 "취약점 매칭이 안 됐다" 는 뜻이라 CCE·노출 탭에는 해당이 없다.
    //   다른 탭에서는 이 쿼리를 아예 돌리지 않는다(안 쓰는 집계를 매 요청에 붙이지 않는다).
    $ctrs = $type === 'cve' ? vg_findings_load_containers($pdo) : [];
    foreach ($ctrs as $c) {
        $reason = vg_container_unjudgeable(
            $c['os_id'] ?? null, $c['os_version'] ?? null,
            $c['manager'] ?? null, (int) ($c['pkg_count'] ?? 0)
        );
        if ($reason !== null) {
            $unsupBy[$reason][] = $c['fqdn'] . ' · 컨테이너 ' . $c['cid'];
        }
    }

    // 대상 스캔이 딸린 **호스트 집합**. 조치 기한 정렬이 최초 발견 시각을 되짚을 때, 되짚을
    //   범위를 이 호스트들로 못 박는다(전 호스트를 훑지 않게).
    $targetHostIds = [];
    if ($scanId > 0) {
        // 단일 스캔 모드 — 어느 호스트의 어느 시점인지 부제에 명시해야 한다.
        $stmt = $pdo->prepare(
            'SELECT s.scan_id, s.collected_at, s.host_id, h.fqdn FROM tb_scan s JOIN tb_host h ON h.host_id = s.host_id WHERE s.scan_id = ?'
        );
        $stmt->execute([$scanId]);
        $scan = $stmt->fetch() ?: null;
        if ($scan) {
            $scanIds = [(int) $scan['scan_id']];
            $targetHostIds = [(int) $scan['host_id']];
        }
    } else {
        if ($hostId > 0 && !$hostFound) { $hostId = 0; }   // 없는 호스트면 전체로
        foreach ($hosts as $h) {
            if ($hostId === 0 || (int) $h['host_id'] === $hostId) {
                $scanIds[] = (int) $h['scan_id'];
                $targetHostIds[] = (int) $h['host_id'];
            }
        }
    }

    // 대상 스캔 집합은 세 탭이 공유한다(같은 자산·같은 시점을 본다는 뜻).
    //   조회는 **활성 탭 것 하나만** 돈다 — 세 탭을 한 쿼리로 합치지 않는 것과 같은 이유다.
    if ($scanIds && $type === 'cve') {
        $r = vg_findings_load_cve($pdo, $scanIds, $targetHostIds, [
            'q' => $q, 'sev' => $sev, 'st' => $st, 'fx' => $fx, 'fst' => $fst, 'sort' => $sort,
            'ctrId' => $ctrId, 'page' => $page, 'perPage' => $perPage,
        ]);
        $rows = $r['rows']; $total = $r['total'];
        $counts = $r['counts']; $actionCounts = $r['actionCounts'];
        $runtimeCounts = $r['runtimeCounts'];
        $notes = $r['notes']; $firstSeen = $r['firstSeen']; $policy = $r['policy'];
        $ctrLabel = $r['ctrLabel'];
    }

    if ($scanIds && $type === 'cce') {
        $r = vg_findings_load_cce($pdo, $scanIds, [
            'q' => $q, 'sev' => $sev, 'res' => $res, 'page' => $page, 'perPage' => $perPage,
        ]);
        $rows = $r['rows']; $total = $r['total']; $page = $r['page'];
        $cceResultCounts = $r['resultCounts']; $cceFailSevCounts = $r['failSevCounts'];
    }

    if ($scanIds && $type === 'exposure') {
        $r = vg_findings_load_exposure($pdo, $scanIds, [
            'q' => $q, 'scope' => $scope, 'page' => $page, 'perPage' => $perPage,
        ]);
        $rows = $r['rows']; $total = $r['total']; $page = $r['page'];
        $scopeCounts = $r['scopeCounts']; $expCveCounts = $r['cveCounts'];
        $expProcCounts = $r['procCounts'];
    }

} catch (Throwable $e) {
    error_log('[findings] ' . $e->getMessage());
    $err = '처리 중 오류가 발생했습니다.';
}

// 탭을 제목에 싣는다 — vg_header() 안의 vg_log_page_view() 가 이 제목을 감사로그 메시지로
//   남기므로, 이것만으로 "누가 어느 유형의 목록을 봤나"가 접속기록에서 구분된다(쿼리 키도 함께
//   기록된다). CVE 탭은 지금까지와 완전히 같은 제목을 유지한다(기존 로그와의 연속성).
vg_header($type === 'cve' ? '탐지 결과' : '탐지 결과 · ' . vg_findings_subtab_labels()[$type], 'findings');
// 컨텍스트(호스트·스캔)를 벗어나는 링크의 목적지 — 지금 보고 있는 탭은 유지한다.
$typeHome = $type === 'cve' ? '/findings.php' : '/findings.php?type=' . $type;
?>
  <?php
  // 이 줄은 **좁혀 본 범위**만 말한다 — 안 좁혔을 때(전체 호스트·최신 수집)는 아무것도 적지
  //   않는다. "전체 호스트 11대 · 각 호스트의 최신 수집 기준" 은 기본값을 설명하는 줄이라
  //   화면 해설이지 값이 아니었다. 좁혀 본 상태·스캔 없음·컨테이너 기준은 그대로 남긴다
  //   (숨기면 0건이 "안전" 으로 읽힌다).
  $hasScopeLine = $scan || $scanId > 0 || $hostId > 0 || !$hostOptions || $ctrLabel !== null;
  ?>
  <div class="page-title page-title--stack"><div><h1>탐지 결과</h1>
  <?php if ($hasScopeLine): ?>
  <div class="sub">
    <?php if ($scan): ?>
      호스트 <strong><?= vg_h($scan['fqdn']) ?></strong> · scan #<?= (int) $scan['scan_id'] ?> · <?= vg_h($scan['collected_at']) ?>
      · <a href="<?= vg_h($typeHome) ?>">전체 호스트 보기 →</a>
    <?php elseif ($scanId > 0): ?>
      수집 #<?= $scanId ?> 을(를) 찾을 수 없습니다. · <a href="<?= vg_h($typeHome) ?>">전체 호스트 보기 →</a>
    <?php elseif ($hostId > 0): ?>
      호스트 <strong><?= vg_h($hostOptions[$hostId]) ?></strong> · 최신 수집 기준
      · <a href="<?= vg_h($typeHome) ?>">전체 호스트 보기 →</a>
    <?php elseif (!$hostOptions): ?>수집 없음<?php endif; ?>
    <?php if ($ctrLabel !== null): ?>
      <?php // 스코프를 숨기면 0건이 "안전" 으로 읽힌다 — 무엇으로 좁혀 봤는지 밝히고 해제 링크를 준다. ?>
      · <strong><?= vg_h($ctrLabel) ?></strong> 기준
      · <a href="<?= vg_h(vg_qs(['ctr' => null, 'page' => 1])) ?>">이 호스트 전체 보기 →</a>
    <?php endif; ?>
  </div>
  <?php endif; ?>
  </div>

  <?php
  // 탐지 유형 세 개가 앞에 서고, 그 뒤로 기존의 다른 화면(변화·제거 권고)이 이어진다.
  //   세 유형은 같은 대상 스캔을 다른 눈으로 보는 것이라 한 줄에 나란히 둔다.
  //   탭을 옮길 때 그 탭 전용 필터만 비우고(호스트·스캔·검색어·등급은 공통 축이라 유지),
  //   페이지 번호는 항상 지운다(2페이지에서 탭을 바꾸면 없는 페이지가 된다).
  //   탭 줄 자체(라벨·순서·목적지)는 nav.php 의 vg_findings_subtabs() 가 정본이고, 여기서는
  //   이 화면에서만 의미 있는 것 — 필터를 이어받는 href — 만 얹는다. 건수 뱃지는 달지 않는다:
  //   각 탭이 자기 카드와 '총 N건' 페이지네이션으로 이미 말하고, 뱃지 하나 때문에 지금 탭이
  //   아닌 유형까지 매 요청에 COUNT 해야 했다.
  //   변화·제거 권고 탭은 이어받을 필터가 없어 기본 href 그대로 둔다.
  $tabOverrides = [];
  foreach (VG_FINDING_TYPES as $key => $def) {
      $qs = ['page' => null];
      foreach (VG_FINDING_TYPES as $other => $otherDef) {
          if ($other === $key) { continue; }
          foreach ($otherDef['clear'] as $name) { $qs[$name] = null; }
      }
      // 기본 탭은 type 파라미터를 붙이지 않는다 — /findings.php 라는 기존 주소를 정본으로 남긴다.
      $qs['type'] = $key === 'cve' ? null : $key;
      $tabOverrides[$key] = ['href' => vg_qs($qs)];
  }
  vg_findings_subtabs($type, $tabOverrides);
  ?>

<?php if ($err !== null): ?>
  <?php vg_alert('오류 · ' . $err); ?>
<?php else: ?>
  <?php
  // 활성 탭 하나만 그린다. 탭 파일은 전역을 주워 쓰지 않고 아래 열거한 값만 받는다.
  vg_findings_render_tab($type, [
      'rows' => $rows, 'total' => $total, 'page' => $page, 'perPage' => $perPage,
      'scan' => $scan, 'scanId' => $scanId, 'hostId' => $hostId, 'hostOptions' => $hostOptions,
      'q' => $q, 'sev' => $sev, 'st' => $st, 'fx' => $fx, 'fst' => $fst, 'sort' => $sort,
      'res' => $res, 'scope' => $scope, 'type' => $type,
      'sevOptions' => $sevOptions, 'stOptions' => $stOptions, 'scopeOptions' => $scopeOptions,
      'unsupBy' => $unsupBy, 'counts' => $counts, 'actionCounts' => $actionCounts,
      'runtimeCounts' => $runtimeCounts,
      'notes' => $notes, 'firstSeen' => $firstSeen, 'policy' => $policy,
      'cceResultCounts' => $cceResultCounts, 'cceFailSevCounts' => $cceFailSevCounts,
      'scopeCounts' => $scopeCounts, 'expProcCounts' => $expProcCounts,
      'expCveCounts' => $expCveCounts,
  ]);
  ?>
<?php endif; ?>
<?php vg_footer();
