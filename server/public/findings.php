<?php
declare(strict_types=1);

/**
 * findings.php — 탐지 결과 한 화면. 로그인 필요.
 *   세 유형을 탭으로 담는다(?type=): cve(기본) / cce(보안설정 점검) / exposure(런타임 노출).
 *   기본  : 전 호스트의 "각 호스트 최신 스캔" 을 통합해서 보여준다(호스트 컬럼 표시).
 *   ?host=N     : 그 호스트의 최신 스캔만.
 *   ?scan_id=N  : 특정 스캔 하나만(대시보드·호스트 상세에서 넘어오는 링크). 이때만 부제에 scan# 표시.
 *   검색(q)/등급(sev) + 탭별 필터(cve: st·fx / cce: res / exposure: scope) + 페이지네이션.
 *
 *   세 표(tb_finding·tb_cce_finding·tb_exposure)를 UNION 하지 않는다 — tb_finding 이 큰 표라
 *   합쳐서 정렬·페이징하면 인덱스가 죽는다(대시보드 파생테이블 리라이트로 235ms→42초가 된
 *   운영 실측이 있다). 탭마다 자기 쿼리 하나가 정답이다. 화면 구성은 packages.php 의
 *   ?tab=os/lang 패턴을 그대로 따른다(vg_subtabs + 툴바에 탭 hidden).
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require __DIR__ . '/../src/distro.php';   // vg_distro_unsupported — 피드 미지원 배포판 경고
require_once __DIR__ . '/../src/remediation_note.php';   // 미조치 사유 + 승인자(최소 필드)
require_once __DIR__ . '/../src/finding_history.php';    // vg_finding_history_url — 행별 상세 진입로
require_once __DIR__ . '/../src/finding_status.php';     // 조치 상태(사람이 정하는 값) — 자연키 조인
require_once __DIR__ . '/../src/finding_sla.php';        // 조치 기한 — 설정의 SLA 를 그대로 읽어 남은 일수
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
// 탭 머리의 유형별 건수(대상 스캔 기준 — 탭 자체가 필터라는 걸 눈으로 알게 한다).
//   현재 탭 것은 그 탭이 이미 집계한 값을 재사용하고, 나머지 둘만 값싼 COUNT 로 채운다.
$typeCounts = ['cve' => null, 'cce' => null, 'exposure' => null];
$cceResultCounts = ['FAIL'=>0, 'PASS'=>0, 'NA'=>0];   // cce 탭 카드
$scopeCounts = [];                                    // exposure 탭 카드 (scope => 건수)
$expCveCounts = [];                                   // 노출 행 → 그 실행 패키지에 걸린 CVE 건수
$actionCounts = ['high' => 0, 'kev' => 0, 'external' => 0, 'restart' => 0, 'overdue' => 0];
$overdueFindingIds = [];

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

    // 호스트별 최신 스캔 (삭제된 호스트 제외) — 통합 뷰의 대상 스캔 집합.
    $hosts = $pdo->query(
        'SELECT h.host_id, h.fqdn, h.os_id, h.os_version, t.mid AS scan_id
           FROM tb_host h
           JOIN ' . vg_latest_scan_subq() . ' t ON t.host_id = h.host_id
          WHERE h.is_deleted = 0
          ORDER BY h.last_seen DESC, h.fqdn'
    )->fetchAll();
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
    $ctrs = $type === 'cve' ? $pdo->query(
        'SELECT h.fqdn, c.cid, c.os_id, c.os_version, c.manager,
                CASE WHEN EXISTS (
                    SELECT 1 FROM tb_package p
                     WHERE p.scan_id = c.scan_id AND p.container_id = c.container_id
                ) THEN 1 ELSE c.pkg_count END AS pkg_count
           FROM tb_container c
           JOIN tb_scan s ON s.scan_id = c.scan_id
           JOIN tb_host h ON h.host_id = s.host_id
           JOIN ' . vg_latest_scan_subq() . ' t ON t.mid = s.scan_id
          WHERE h.is_deleted = 0
          ORDER BY h.fqdn, c.cid'
    )->fetchAll() : [];
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
    $in = $scanIds ? implode(',', array_fill(0, count($scanIds), '?')) : '';

    if ($scanIds && $type === 'cve') {
        $policy = vg_compliance_policy();
        $statusJoin = "LEFT JOIN tb_finding_status fs
                              ON fs.host_id = s.host_id
                             AND fs.container_ref = COALESCE(ctr.cid, '')
                             AND fs.cve_id = f.cve_id
                             AND fs.package_name = f.package_name";

        // KPI 는 필터 무관 — 대상 스캔 전체 기준
        $typeCounts['cve'] = 0;
        $stmt = $pdo->prepare("SELECT severity, COUNT(*) c FROM tb_finding WHERE scan_id IN ($in) GROUP BY severity");
        $stmt->execute($scanIds);
        foreach ($stmt->fetchAll() as $r) {
            // 탭 뱃지의 CVE 건수는 이 집계를 그대로 합쳐 쓴다(같은 값을 두 번 세지 않는다).
            //   등급 카드는 알려진 4종만 세지만, 뱃지는 그 밖의 등급이 와도 빠지지 않게 전부 더한다.
            $typeCounts['cve'] = (int) ($typeCounts['cve'] ?? 0) + (int) $r['c'];
            if (isset($counts[$r['severity']])) { $counts[$r['severity']] = (int) $r['c']; }
        }
        $actionCounts['high'] = $counts['CRITICAL'] + $counts['HIGH'];

        // 행동 큐의 신호는 모두 같은 대상 스캔 집합에서 센다. 기한 초과는 대시보드와 같은
        // High 이상 KEV 모집단이며 DONE·EXCEPTED는 제외한다.
        $stmt = $pdo->prepare(
            "SELECT SUM(f.in_kev = 1) kev, SUM(f.runtime_status = 'EXTERNAL') external_cnt,
                    SUM(f.needs_restart = 1) restart_cnt
               FROM tb_finding f WHERE f.scan_id IN ($in) AND f.is_deleted = 0"
        );
        $stmt->execute($scanIds);
        $queueAgg = $stmt->fetch() ?: [];
        $actionCounts['kev'] = (int) ($queueAgg['kev'] ?? 0);
        $actionCounts['external'] = (int) ($queueAgg['external_cnt'] ?? 0);
        $actionCounts['restart'] = (int) ($queueAgg['restart_cnt'] ?? 0);

        $stmt = $pdo->prepare(
            "SELECT f.finding_id, s.host_id, COALESCE(ctr.cid, '') cid, f.cve_id, f.package_name,
                    fs.status
               FROM tb_finding f
               JOIN tb_scan s ON s.scan_id = f.scan_id
               LEFT JOIN tb_container ctr ON ctr.container_id = f.container_id
               $statusJoin
              WHERE f.scan_id IN ($in) AND f.is_deleted = 0 AND f.in_kev = 1
                AND f.severity IN ('CRITICAL','HIGH')"
        );
        $stmt->execute($scanIds);
        $overdueCandidates = $stmt->fetchAll();
        $overdueKeys = [];
        foreach ($overdueCandidates as $candidate) {
            if (in_array((string) ($candidate['status'] ?? ''), ['DONE', 'EXCEPTED'], true)) { continue; }
            $overdueKeys[] = [(int) $candidate['host_id'], (string) $candidate['cid'],
                              (string) $candidate['cve_id'], (string) $candidate['package_name']];
        }
        $overdueSeen = vg_finding_first_seen_map($pdo, $overdueKeys, vg_finding_sla_lookback_days($policy));
        $kevDays = vg_finding_sla_days(true, 'CRITICAL', $policy);
        foreach ($overdueCandidates as $candidate) {
            if (in_array((string) ($candidate['status'] ?? ''), ['DONE', 'EXCEPTED'], true)) { continue; }
            $key = vg_finding_status_key((int) $candidate['host_id'], (string) $candidate['cid'],
                                         (string) $candidate['cve_id'], (string) $candidate['package_name']);
            $days = $overdueSeen[$key]['days'] ?? null;
            if ($days !== null && $kevDays !== null && (int) $days > $kevDays) {
                $overdueFindingIds[] = (int) $candidate['finding_id'];
            }
        }
        $actionCounts['overdue'] = count($overdueFindingIds);

        // 필터 WHERE 조립 (COUNT 와 목록 쿼리에 동일하게 사용)
        $where  = "f.scan_id IN ($in)";
        $params = $scanIds;
        if ($ctrId !== null) {
            // uq_find 가 (scan_id, container_id, …) 라 scan_id 범위 뒤 두 번째 컬럼 등치다 —
            //   IN 리스트 패턴을 그대로 두고 인덱스도 더 좁게 탄다.
            $where .= ' AND f.container_id = ?';
            $params[] = $ctrId;
            if ($ctrId === 0) {
                $ctrLabel = '호스트 자신(컨테이너 제외)';
            } else {
                $s = $pdo->prepare('SELECT cid FROM tb_container WHERE container_id = ?');
                $s->execute([$ctrId]);
                $cid = $s->fetchColumn();
                $ctrLabel = $cid !== false ? '컨테이너 ' . (string) $cid : '컨테이너 #' . $ctrId;
            }
        }
        if ($q !== '') {
            $where .= ' AND (f.cve_id LIKE ? OR f.package_name LIKE ?)';
            $params[] = '%' . $q . '%';
            $params[] = '%' . $q . '%';
        }
        if ($sev !== '') {
            if ($sev === 'HIGH+') {
                $where .= " AND f.severity IN ('CRITICAL','HIGH')";
            } else {
                $where .= ' AND f.severity = ?';
                $params[] = $sev;
            }
        }
        if ($st !== '') {
            $where .= ' AND f.runtime_status = ?';
            $params[] = $st;
        }
        // 조치 가능성 필터 — 벤더가 수정본을 안 낸 CVE(no_fix)는 "지금 할 수 있는 일이 없는" 것이다.
        //   기본은 전부 보여주되 **조치 가능한 것을 위로 올린다**(아래 ORDER BY).
        //   섞어서 등급순으로만 세우면 조치 불가 수백 건이 고칠 수 있는 몇 건을 덮어버린다.
        if ($fx === 'action')  { $where .= ' AND f.no_fix = 0'; }
        if ($fx === 'nofix')   { $where .= ' AND f.no_fix = 1'; }
        // 재시작·재부팅만 하면 되는 것 — 자산 상세의 "전체 보기" 가 여기로 온다.
        if ($fx === 'restart') { $where .= ' AND f.needs_restart = 1'; }
        if ($fx === 'kev')     { $where .= ' AND f.in_kev = 1'; }
        if ($fx === 'overdue') {
            $where .= $overdueFindingIds
                ? ' AND f.finding_id IN (' . implode(',', array_map('intval', $overdueFindingIds)) . ')'
                : ' AND 1 = 0';
        }

        // 조치 상태는 스캔이 바뀌어도 유지되는 **자연키**로 붙는다(host_id·컨테이너 이름·CVE·패키지) —
        //   tb_finding.finding_id 는 스캔마다 새로 발급되는 surrogate PK 라 붙일 수 없다.
        //   조인은 한 번뿐이고, 목록은 이미 페이지네이션돼 있으므로 현재 페이지 범위만 걸린다.
        //   uq_finding_status 가 host_id 선두라 이 조인은 그 유니크 인덱스를 탄다.
        // 기록이 없는 조합은 행 자체가 없다 = 미조치(OPEN). 그래서 OPEN 필터만 NULL 을 함께 받는다
        //   (3.8만 건에 OPEN 행을 미리 깔지 않는다는 설계의 대가를 여기서 한 줄로 치른다).
        $countFrom = 'tb_finding f';
        if ($fst !== '') {
            // COUNT 는 평소 조인이 없다 — 상태 필터가 걸렸을 때만 같은 조인을 붙여 목록과 수를 맞춘다.
            $countFrom = "tb_finding f
                          JOIN tb_scan s ON s.scan_id = f.scan_id
                          LEFT JOIN tb_container ctr ON ctr.container_id = f.container_id
                          $statusJoin";
            $where .= $fst === 'OPEN' ? " AND (fs.status IS NULL OR fs.status = 'OPEN')" : ' AND fs.status = ?';
            if ($fst !== 'OPEN') { $params[] = $fst; }
        }

        $stmt = $pdo->prepare("SELECT COUNT(*) FROM $countFrom WHERE $where");
        $stmt->execute($params);
        $total = (int) $stmt->fetchColumn();

        $offset = ($page - 1) * $perPage;

        // 조치 기한 기준일은 설정값을 그대로 읽는다(compliance 화면과 같은 숫자여야 한다).
        /* 기한 임박순 정렬 — 남은 일수는 "최초 발견 시각 + 등급별 기한" 이라 컬럼 하나로는 못 센다.
         *   그래서 이 정렬을 고른 경우에만, 대상 호스트의 역산 구간 안 스캔을 묶어 최초 시각을
         *   집계한 파생표를 조인한다(기본 정렬에서는 아예 붙지 않는다 — 목록의 기본 응답을
         *   무겁게 만들지 않는다). 화면에 찍는 값은 아래 페이지 단위 집계가 따로 준다. */
        $dueJoin = ''; $dueParams = []; $selectParams = [];
        $orderBy = "f.no_fix ASC, FIELD(f.severity,'CRITICAL','HIGH','MEDIUM','LOW'), c.epss DESC, f.cvss DESC, h.fqdn";
        $slaCase = "CASE WHEN f.in_kev = 1 THEN ? WHEN f.severity = 'CRITICAL' THEN ?
                         WHEN f.severity = 'HIGH' THEN ? ELSE NULL END";
        if ($sort === 'due') {
            $dueHostIds = $targetHostIds ?: [0];
            $hostIn = implode(',', array_fill(0, count($dueHostIds), '?'));
            $dueJoin = "LEFT JOIN (
                            SELECT s2.host_id AS h_id, COALESCE(c2.cid, '') AS c_ref,
                                   f2.cve_id AS c_cve, f2.package_name AS c_pkg,
                                   MIN(COALESCE(s2.received_at, s2.collected_at)) AS first_seen
                              FROM tb_finding f2
                              JOIN tb_scan s2 ON s2.scan_id = f2.scan_id AND s2.is_deleted = 0
                              LEFT JOIN tb_container c2 ON c2.container_id = f2.container_id
                             WHERE f2.is_deleted = 0 AND s2.host_id IN ($hostIn)
                               AND COALESCE(s2.received_at, s2.collected_at) >= DATE_SUB(NOW(), INTERVAL ? DAY)
                             GROUP BY s2.host_id, c_ref, f2.cve_id, f2.package_name
                        ) fsn ON fsn.h_id = s.host_id AND fsn.c_ref = COALESCE(ctr.cid, '')
                             AND fsn.c_cve = f.cve_id AND fsn.c_pkg = f.package_name";
            $dueParams = array_merge($dueHostIds, [vg_finding_sla_lookback_days($policy)]);
            // 기한 없는 등급(MEDIUM·LOW)과 최초 시각 미상은 맨 뒤로 — 알 수 없는 것을 급한 척하지 않는다.
            $selectParams = [$policy['kev'], $policy['crit'], $policy['high']];
            $orderBy = 'due_at IS NULL, due_at ASC, ' . $orderBy;
        }
        $dueSelect = $sort === 'due'
            ? ", DATE_ADD(fsn.first_seen, INTERVAL $slaCase DAY) AS due_at"
            : '';

        $stmt = $pdo->prepare(
            // 목록이 안 쓰는 값은 실어 오지 않는다: 요약(summary)·EPSS 백분위·참조 URL(JSON)·
            //   판정 출처(match_source)는 전부 상세(finding_history.php)가 보여준다.
            //   특히 ref_urls_json 은 CVE 한 건당 수 KB 짜리 JSON 이라 페이지 크기에 그대로 실렸다.
            "SELECT f.*, h.host_id, h.fqdn, c.epss,
                    ctr.cid AS container_cid, ctr.image AS container_image,
                    CASE WHEN f.container_id = 0 THEN s.os_id ELSE ctr.os_id END AS package_os_id,
                    CASE WHEN f.container_id = 0 THEN s.os_version ELSE ctr.os_version END AS package_os_version,
                    fe.fixed_version AS evidence_fixed_version,
                    fs.status AS finding_status, fs.note AS finding_status_note
                    $dueSelect,
                " . VG_FIXED_VERSION_SUBQ . "
             FROM tb_finding f
             JOIN tb_scan s ON s.scan_id = f.scan_id
             JOIN tb_host h ON h.host_id = s.host_id
             LEFT JOIN tb_container ctr ON ctr.container_id = f.container_id
             LEFT JOIN tb_cve c ON c.cve_id = f.cve_id
             LEFT JOIN tb_finding_evidence fe ON fe.finding_id = f.finding_id
             $statusJoin
             $dueJoin
             WHERE $where
             ORDER BY $orderBy
             LIMIT $perPage OFFSET $offset"
        );
        $stmt->execute(array_merge($selectParams, $dueParams, $params));
        $rows = $stmt->fetchAll();

        // 사람이 남긴 미조치 사유는 이 페이지에 보이는 행들만 한 번에 읽는다(N+1 방지).
        $noteKeys = [];
        foreach ($rows as $r) {
            $noteKeys[] = [(int) $r['host_id'], (string) ($r['container_cid'] ?? ''),
                           (string) $r['cve_id'], (string) $r['package_name']];
        }
        $notes = vg_remediation_notes_map($pdo, $noteKeys);

        // 조치 기한의 기준일(최초 발견 시각)도 이 페이지에 보이는 행들만 한 번에 읽는다(N+1 방지).
        //   기한이 있는 등급(KEV·CRITICAL·HIGH)만 물어본다 — MEDIUM·LOW 는 기한 자체가 없어
        //   되짚을 이유가 없다(그만큼 조회 대상이 준다).
        $slaKeys = [];
        foreach ($rows as $r) {
            if (vg_finding_sla_days((bool) $r['in_kev'], (string) $r['severity'], $policy) === null) { continue; }
            $slaKeys[] = [(int) $r['host_id'], (string) ($r['container_cid'] ?? ''),
                          (string) $r['cve_id'], (string) $r['package_name']];
        }
        $firstSeen = vg_finding_first_seen_map($pdo, $slaKeys, vg_finding_sla_lookback_days($policy));
    }

    if ($scanIds && $type === 'cce') {
        // 결과 분포는 필터 무관 — 대상 스캔 전체 기준(CVE 탭의 등급 KPI 와 같은 자리·같은 성격).
        //   NA 를 PASS 와 섞지 않는다: 위반 0건이 "준수" 로 읽히는 걸 이 제품은 반복해서 경계해 왔다.
        //   uq_cce(scan_id, code) 가 scan_id 선두라 IN 범위를 그대로 탄다.
        $stmt = $pdo->prepare("SELECT result, COUNT(*) c FROM tb_cce_finding WHERE scan_id IN ($in) GROUP BY result");
        $stmt->execute($scanIds);
        foreach ($stmt->fetchAll() as $r) {
            if (isset($cceResultCounts[$r['result']])) { $cceResultCounts[$r['result']] = (int) $r['c']; }
        }
        // 탭 뱃지는 이 탭의 기본값(위반)을 센다 — 탭을 눌렀을 때 보게 될 숫자와 같아야 한다.
        $typeCounts['cce'] = $cceResultCounts['FAIL'];

        $where  = "f.scan_id IN ($in)";
        $params = $scanIds;
        if ($res !== 'ALL') {
            $where .= ' AND f.result = ?';
            $params[] = $res;
        }
        if ($sev !== '') {
            $where .= ' AND f.severity = ?';
            $params[] = $sev;
        }
        if ($q !== '') {
            $where .= ' AND (f.code LIKE ? OR f.title LIKE ? OR f.ssg_rule_id LIKE ?)';
            $like = '%' . addcslashes($q, '%_\\') . '%';
            $params[] = $like; $params[] = $like; $params[] = $like;
        }

        $stmt = $pdo->prepare("SELECT COUNT(*) FROM tb_cce_finding f WHERE $where");
        $stmt->execute($params);
        $total = (int) $stmt->fetchColumn();
        if ($total > 0) { $page = min($page, (int) ceil($total / $perPage)); }
        $offset = ($page - 1) * $perPage;

        // 룰 상세는 compliance_rule.php 가 이미 갖고 있다 — 여기서는 기준 참조(CIS/NIST/STIG)만
        //   함께 읽어 근거를 인용하고 링크로 보낸다(host.php 의 CCE 탭과 같은 조인).
        $stmt = $pdo->prepare(
            "SELECT f.code, f.ssg_rule_id, f.title, f.result, f.severity, f.evidence, f.rationale,
                    h.host_id, h.fqdn, r.refs_json
               FROM tb_cce_finding f
               JOIN tb_scan s ON s.scan_id = f.scan_id
               JOIN tb_host h ON h.host_id = s.host_id
               LEFT JOIN tb_compliance_rule r ON r.rule_id = f.ssg_rule_id AND r.is_deleted = 0
              WHERE $where
              ORDER BY FIELD(f.result,'FAIL','NA','PASS'), FIELD(f.severity,'HIGH','MEDIUM','LOW'), h.fqdn, f.code
              LIMIT $perPage OFFSET $offset"
        );
        $stmt->execute($params);
        $rows = $stmt->fetchAll();
    }

    if ($scanIds && $type === 'exposure') {
        // 범위 분포 — EXTERNAL 이 몇 건인지가 이 탭의 첫 질문이다. idx_exp_scan(scan_id) 범위 집계.
        //   scope 는 NULL 을 허용하는 컬럼이라 '-'(범위 미상)로 접어 센다 — 접지 않으면 카드
        //   어디에도 없는 행이 표에만 남아 합계가 안 맞는 것처럼 보인다. 아래 필터도 같은 식이다.
        $stmt = $pdo->prepare("SELECT COALESCE(scope, '-') sc, COUNT(*) c FROM tb_exposure WHERE scan_id IN ($in) GROUP BY sc");
        $stmt->execute($scanIds);
        $typeCounts['exposure'] = 0;
        foreach ($stmt->fetchAll() as $r) {
            $scopeCounts[(string) $r['sc']] = (int) $r['c'];
            $typeCounts['exposure'] += (int) $r['c'];
        }

        $where  = "e.scan_id IN ($in)";
        $params = $scanIds;
        if ($scope !== '') {
            $where .= " AND COALESCE(e.scope, '-') = ?";
            $params[] = $scope;
        }
        if ($q !== '') {
            $where .= ' AND (e.proc LIKE ? OR e.exe_pkg LIKE ?)';
            $like = '%' . addcslashes($q, '%_\\') . '%';
            $params[] = $like; $params[] = $like;
        }

        $stmt = $pdo->prepare("SELECT COUNT(*) FROM tb_exposure e WHERE $where");
        $stmt->execute($params);
        $total = (int) $stmt->fetchColumn();
        if ($total > 0) { $page = min($page, (int) ceil($total / $perPage)); }
        $offset = ($page - 1) * $perPage;

        // 정렬은 host.php 의 노출 표와 같은 FIELD 순서 — EXTERNAL 이 맨 위다.
        $stmt = $pdo->prepare(
            "SELECT e.scan_id, e.container_id, e.proc, e.proto, e.bind_addr, e.port, e.scope,
                    e.exe_pkg, e.loaded_pkgs, h.host_id, h.fqdn, IFNULL(c.cid, '') AS ctr
               FROM tb_exposure e
               JOIN tb_scan s ON s.scan_id = e.scan_id
               JOIN tb_host h ON h.host_id = s.host_id
               LEFT JOIN tb_container c ON c.container_id = e.container_id
              WHERE $where
              ORDER BY FIELD(e.scope,'EXTERNAL','LAN','BOUND','FILTERED','LOCAL','-'), h.fqdn, e.port
              LIMIT $perPage OFFSET $offset"
        );
        $stmt->execute($params);
        $rows = $stmt->fetchAll();

        // "이 리스너에 걸린 CVE 건수" — 노출과 취약점을 잇는 게 이 제품의 축이다.
        //   행마다 세면 N+1 이라, **이 페이지에 보이는 행들**의 (스캔·컨테이너·실행패키지)만
        //   한 번의 GROUP BY 로 읽는다. 인덱스는 uq_find(scan_id, container_id, …) 의 앞 두 컬럼까지
        //   타고 package_name 은 그 범위 안에서 걸러진다 — 대상 스캔이 이미 CVE 탭 COUNT 와
        //   같은 범위라 비용이 그 이상으로 커지지 않는다.
        $expScans = []; $expCtrs = []; $expPkgs = [];
        foreach ($rows as $r) {
            if (($r['exe_pkg'] ?? '') === '') { continue; }
            $expScans[] = (int) $r['scan_id'];
            $expCtrs[]  = (int) $r['container_id'];
            // 값 목록으로 모은다(키로 모으면 숫자로만 된 패키지명이 int 키가 되어 int 로 바인딩된다).
            $expPkgs[]  = (string) $r['exe_pkg'];
        }
        $expScans = array_values(array_unique($expScans));
        $expCtrs  = array_values(array_unique($expCtrs));
        $expPkgs  = array_values(array_unique($expPkgs));
        if ($expPkgs) {
            $ph = static fn(array $a): string => implode(',', array_fill(0, count($a), '?'));
            $stmt = $pdo->prepare(
                'SELECT scan_id, container_id, package_name, COUNT(*) c
                   FROM tb_finding
                  WHERE scan_id IN (' . $ph($expScans) . ')
                    AND container_id IN (' . $ph($expCtrs) . ')
                    AND package_name IN (' . $ph($expPkgs) . ')
                  GROUP BY scan_id, container_id, package_name'
            );
            $stmt->execute(array_merge($expScans, $expCtrs, $expPkgs));
            foreach ($stmt->fetchAll() as $r) {
                $expCveCounts[$r['scan_id'] . '|' . $r['container_id'] . '|' . $r['package_name']] = (int) $r['c'];
            }
        }
    }

    // 지금 탭이 아닌 유형의 건수 — 탭 머리에 붙는 요약이다. 각각 인덱스 선두(scan_id) 범위
    //   COUNT 하나뿐이라 값싸다(현재 탭 것은 위에서 이미 집계했으므로 다시 세지 않는다).
    if ($scanIds) {
        if ($typeCounts['cve'] === null) {
            $stmt = $pdo->prepare("SELECT COUNT(*) FROM tb_finding WHERE scan_id IN ($in)");
            $stmt->execute($scanIds);
            $typeCounts['cve'] = (int) $stmt->fetchColumn();
        }
        if ($typeCounts['cce'] === null) {
            $stmt = $pdo->prepare("SELECT COUNT(*) FROM tb_cce_finding WHERE scan_id IN ($in) AND result = 'FAIL'");
            $stmt->execute($scanIds);
            $typeCounts['cce'] = (int) $stmt->fetchColumn();
        }
        if ($typeCounts['exposure'] === null) {
            $stmt = $pdo->prepare("SELECT COUNT(*) FROM tb_exposure WHERE scan_id IN ($in)");
            $stmt->execute($scanIds);
            $typeCounts['exposure'] = (int) $stmt->fetchColumn();
        }
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
  <div class="page-title page-title--stack"><div><h1>탐지 결과</h1>
  <div class="sub">
    <?php if ($scan): ?>
      호스트 <strong><?= vg_h($scan['fqdn']) ?></strong> · scan #<?= (int) $scan['scan_id'] ?> · <?= vg_h($scan['collected_at']) ?>
      · <a href="<?= vg_h($typeHome) ?>">전체 호스트 보기 →</a>
    <?php elseif ($scanId > 0): ?>
      스캔 #<?= $scanId ?> 을(를) 찾을 수 없습니다. · <a href="<?= vg_h($typeHome) ?>">전체 호스트 보기 →</a>
    <?php elseif ($hostId > 0): ?>
      호스트 <strong><?= vg_h($hostOptions[$hostId]) ?></strong> · 최신 스캔 기준
      · <a href="<?= vg_h($typeHome) ?>">전체 호스트 보기 →</a>
    <?php elseif ($hostOptions): ?>
      전체 호스트 <?= count($hostOptions) ?>대 · 각 호스트의 최신 스캔 기준
    <?php else: ?>스캔 없음<?php endif; ?>
    <?php if ($ctrLabel !== null): ?>
      <?php // 스코프를 숨기면 0건이 "안전" 으로 읽힌다 — 무엇으로 좁혀 봤는지 밝히고 해제 링크를 준다. ?>
      · <strong><?= vg_h($ctrLabel) ?></strong> 기준
      · <a href="<?= vg_h(vg_qs(['ctr' => null, 'page' => 1])) ?>">이 호스트 전체 보기 →</a>
    <?php endif; ?>
  </div></div>

  <?php
  // 탐지 유형 세 개가 앞에 서고, 그 뒤로 기존의 다른 화면(변화·제거 권고)이 이어진다.
  //   세 유형은 같은 대상 스캔을 다른 눈으로 보는 것이라 한 줄에 나란히 둔다. 뱃지 숫자는
  //   대상 스캔 기준 건수(CCE 는 그 탭의 기본인 위반 건수) — 탭이 곧 필터라는 걸 눈으로 알린다.
  //   탭을 옮길 때 그 탭 전용 필터만 비우고(호스트·스캔·검색어·등급은 공통 축이라 유지),
  //   페이지 번호는 항상 지운다(2페이지에서 탭을 바꾸면 없는 페이지가 된다).
  //   탭 줄 자체(라벨·순서·목적지)는 nav.php 의 vg_findings_subtabs() 가 정본이고, 여기서는
  //   이 화면에서만 의미 있는 것 — 뱃지 숫자와 필터를 이어받는 href — 만 얹는다.
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
      $tabOverrides[$key] = ['href' => vg_qs($qs), 'n' => $typeCounts[$key]];
  }
  vg_findings_subtabs($type, $tabOverrides);

  /* 이 화면이 무엇을 판단하는 자리인지를 도식 한 장으로 답한다 — 순서는 vg_signal_slots() 의
   *   네 축(노출→악용→등급→조치)과 같다. 같은 판단 순서를 화면마다 다른 순서로 그리지 않는다.
   *   숫자는 위 탭별 집계에서 이미 나온 값만 쓴다(새 쿼리 없음). CCE·노출 탭은 축이 다르므로
   *   각자의 순서를 그린다 — 없는 축을 빈 칸으로 세워 두지 않는다. */
  if ($err === null) {
      if ($type === 'cve') {
          /* 이 탭은 바로 아래 [먼저 볼 작업] 스트립이 같은 네 축의 **건수**를 이미 링크와 함께
           *   보여준다 — 도식에까지 같은 숫자를 넣으면 한 화면에서 같은 값을 두 번 세게 된다.
           *   그래서 여기서는 숫자를 빼고 **순서**만 말한다(표의 '신호' 칸도 이 순서를 따른다). */
          vg_explain_flow([
              ['icon' => 'port',   'label' => '노출',
               'state' => $actionCounts['external'] > 0 ? 'active' : 'done'],
              ['icon' => 'feed',   'label' => '악용', 'state' => 'done'],
              ['icon' => 'warn',   'label' => '등급', 'state' => 'done'],
              ['icon' => 'check',  'label' => '조치',
               'state' => $actionCounts['overdue'] > 0 ? 'active' : 'done'],
          ], ['label' => '취약점 판단 순서']);
      } elseif ($type === 'cce') {
          vg_explain_flow([
              ['icon' => 'shield', 'label' => '점검', 'value' => number_format((int) $cceResultCounts['PASS'] + (int) $cceResultCounts['FAIL']), 'state' => 'done'],
              ['icon' => 'warn',   'label' => '위반', 'value' => number_format((int) $cceResultCounts['FAIL']),
               'state' => $cceResultCounts['FAIL'] > 0 ? 'active' : 'done'],
              ['icon' => 'block',  'label' => '판정불가', 'value' => number_format((int) $cceResultCounts['NA']), 'state' => 'done'],
              ['icon' => 'check',  'label' => '양호', 'value' => number_format((int) $cceResultCounts['PASS']), 'state' => 'done'],
          ], ['label' => '보안설정 점검 순서']);
      } else {
          vg_explain_flow([
              ['icon' => 'process', 'label' => '프로세스', 'state' => 'done'],
              ['icon' => 'port',    'label' => '리스너', 'value' => number_format(array_sum(array_map('intval', $scopeCounts))), 'state' => 'done'],
              ['icon' => 'feed',    'label' => vg_scope_label('EXTERNAL'), 'value' => number_format((int) ($scopeCounts['EXTERNAL'] ?? 0)),
               'state' => ((int) ($scopeCounts['EXTERNAL'] ?? 0)) > 0 ? 'active' : 'done'],
          ], ['label' => '노출 판단 순서']);
      }
  }

  // 결론 배너 — 카드와 표는 값을 보여줄 뿐이라, "지금 이 탭에서 무엇이 몇 건인가"는
  //   사용자가 직접 세어야 했다. 그 한 줄을 탭 바로 아래 한 번만 세운다(role="status").
  //   수치는 각 탭이 위에서 이미 집계한 값만 쓴다 — 새 쿼리를 추가하지 않는다.
  //   기준이 둘이라는 걸 숨기지 않는다: 분포(등급·결과·범위)는 **대상 스캔 전체** 기준이고
  //   '현재 목록'만 필터가 반영된 수다. 그래서 note 에 기준을 적어 둔다.
  if ($err === null) {
      $listStat = ['label' => '현재 목록 · 건', 'value' => number_format($total)];
      $note = '대상 자산 ' . number_format(count($scanIds)) . '대 · 분포는 대상 스캔 전체 기준 · 현재 목록만 필터 반영';
      if ($type === 'cve') {
          $crit = (int) $counts['CRITICAL'];
          $high = (int) $counts['HIGH'];
          $unsup = 0;
          foreach ($unsupBy as $names) { $unsup += count($names); }
          $stats = [$listStat,
              ['label' => 'CRITICAL · 건', 'value' => number_format($crit), 'tone' => $crit > 0 ? 'crit' : 'ok'],
              ['label' => 'HIGH · 건',     'value' => number_format($high), 'tone' => $high > 0 ? 'warn' : 'ok']];
          if ($unsup > 0) {
              $stats[] = ['label' => '판정 불가 대상 · 개', 'value' => number_format($unsup), 'tone' => 'muted'];
          }
          if ($crit > 0) {
              $vTone = 'crit';
              $vHead = '현재 목록 ' . number_format($total) . '건 — CRITICAL ' . number_format($crit) . '건이 가장 먼저 조치할 대상입니다.';
          } elseif ($high > 0) {
              $vTone = 'warn';
              $vHead = '현재 목록 ' . number_format($total) . '건 — CRITICAL 은 없고 HIGH ' . number_format($high) . '건이 우선 대상입니다.';
          } elseif ($total > 0) {
              $vTone = 'warn';
              $vHead = '현재 목록 ' . number_format($total) . '건 — CRITICAL·HIGH 는 없습니다.';
          } else {
              // 0건을 "안전" 으로 읽히게 두지 않는다 — 판정 불가 대상이 있으면 톤부터 낮춘다.
              $vTone = $unsup > 0 ? 'muted' : 'ok';
              $vHead = $unsup > 0
                  ? '현재 조건에 해당하는 취약점이 없습니다 — 다만 판정 불가 대상 ' . number_format($unsup) . '개가 있어 "안전"으로 읽을 수 없습니다.'
                  : '현재 조건에 해당하는 취약점이 없습니다.';
          }
      } elseif ($type === 'cce') {
          $fail = (int) $cceResultCounts['FAIL'];
          $na   = (int) $cceResultCounts['NA'];
          $pass = (int) $cceResultCounts['PASS'];
          $stats = [$listStat,
              ['label' => '위반(FAIL) · 건',     'value' => number_format($fail), 'tone' => $fail > 0 ? 'crit' : 'ok'],
              ['label' => '판정 불가(NA) · 건',  'value' => number_format($na),   'tone' => $na > 0 ? 'muted' : 'ok'],
              ['label' => '양호(PASS) · 건',     'value' => number_format($pass), 'tone' => 'ok']];
          if ($fail > 0) {
              $vTone = 'crit';
              $vHead = '보안설정 위반 ' . number_format($fail) . '건이 확인됐습니다.';
          } elseif ($na > 0) {
              $vTone = 'warn';
              $vHead = '위반은 0건이지만 판정 불가(NA) ' . number_format($na) . '건이 남아 "준수"로 읽을 수 없습니다.';
          } elseif ($pass > 0) {
              $vTone = 'ok';
              $vHead = '점검한 ' . number_format($pass) . '건이 모두 양호합니다.';
          } else {
              $vTone = 'muted';
              $vHead = '아직 보안설정 점검 결과가 없습니다.';
          }
      } else {
          $ext = (int) ($scopeCounts['EXTERNAL'] ?? 0);
          $lan = (int) ($scopeCounts['LAN'] ?? 0);
          $expAll = array_sum(array_map('intval', $scopeCounts));
          // 범위 어휘는 vg_scope_label() 이 정본이다 — 여기서 다시 이름 짓지 않는다.
          $stats = [$listStat,
              ['label' => vg_scope_label('EXTERNAL') . ' · 건', 'value' => number_format($ext), 'tone' => $ext > 0 ? 'crit' : 'ok'],
              ['label' => vg_scope_label('LAN') . ' · 건',      'value' => number_format($lan), 'tone' => $lan > 0 ? 'warn' : 'ok']];
          if ($ext > 0) {
              $vTone = 'crit';
              $vHead = '외부에 노출된 리스너 ' . number_format($ext) . '건이 있습니다 — 가장 먼저 확인할 접점입니다.';
          } elseif ($lan > 0) {
              $vTone = 'warn';
              $vHead = '외부 노출은 없고 ' . vg_scope_label('LAN') . ' ' . number_format($lan) . '건이 있습니다.';
          } elseif ($expAll > 0) {
              $vTone = 'ok';
              $vHead = '외부·로컬 세그먼트에 노출된 리스너가 없습니다.';
          } else {
              $vTone = 'muted';
              $vHead = '아직 수집된 리스너가 없습니다.';
          }
      }
      vg_verdict($vTone, $vHead, $stats, $note);
  }
  ?>

<?php if ($err !== null): ?>
  <?php vg_alert('오류 · ' . $err); ?>
<?php elseif ($type === 'cve'): ?>
  <?php if ($unsupBy):
      // 기본은 **사유별 대수 요약**만 펴 둔다. 예전엔 사유 한 줄에 그 사유가 걸린 대상 이름을
      //   전부 이어 붙여서, 미지원 호스트가 199개인 환경에선 배너 혼자 화면 6줄을 먹고 KPI·필터·
      //   표를 아래로 밀어냈다(실측). 대상 이름은 지우지 않고 접힘 안으로 내린다 — 닫혀 있어도
      //   HTML 에는 그대로 있어 Ctrl+F 검색과 tests/smoke.sh 의 '컨테이너 nodb' 단언이 같이 산다.
      // 경고 제목은 한 글자도 바꾸지 않았다: "0건 = 안전 아님" 은 이 제품이 허위 안심을 막는
      //   핵심 문구이고 smoke 가 '판정 불가' 를 단언한다(tests/smoke.sh 의 [미지원 배포판 경고]).
      $unsupTotal = 0;
      foreach ($unsupBy as $names) { $unsupTotal += count($names); }
      // 많은 사유부터 세운다 — 두세 대짜리 사유가 맨 위에 오면 요약이 대표성을 잃는다.
      uasort($unsupBy, static fn(array $a, array $b): int => count($b) <=> count($a));
      $hints = []; $unsupItems = [];
      foreach ($unsupBy as $reason => $names) {
          $line = $reason . ' · ' . number_format(count($names)) . '개 대상';
          if (count($hints) < VG_UNSUP_HINT_PREVIEW) {
              // 요약 줄은 **한 줄**이어야 뜻이 있다 — 사유 중에는 괄호 안 설명까지 붙어 100자를
              //   넘는 것이 있어(패키지 DB 없는 이미지) 좁은 폭에서 혼자 두 줄이 된다. 미리보기
              //   에서만 줄이고, 온전한 문장은 바로 아래 접힘 안에 그대로 둔다.
              //   vg_trunc 를 안 쓰는 이유: vg_alert 의 hints 는 순수 문자열이라 여기서 HTML 을
              //   넘기면 vg_h() 로 다시 이스케이프돼 태그가 글자로 보인다.
              $hints[] = mb_strimwidth($reason, 0, 60, '…') . ' · ' . number_format(count($names)) . '개 대상';
          }
          $unsupItems[] = $line . ' — ' . implode(', ', $names);
      }
      $more = count($unsupItems) - count($hints);
      if ($more > 0) { $hints[] = '외 ' . number_format($more) . '종 (아래 접힘에 전체가 있습니다)'; }
      vg_alert([
          'type'  => 'warn',
          'title' => '일부 대상은 취약점 매칭이 수행되지 않습니다 — 0건은 "안전"이 아니라 "판정 불가"입니다',
          'hints' => $hints,
          'details' => [
              'summary' => '판정 불가 대상 ' . number_format($unsupTotal) . '개 · 사유 '
                         . number_format(count($unsupItems)) . '종 — 목록 보기',
              'items'   => $unsupItems,
          ],
      ]);
  endif; ?>

  <section class="action-queue" data-action-queue aria-labelledby="findingActionQueueTitle">
    <div class="action-queue__head">
      <strong id="findingActionQueueTitle">먼저 볼 작업</strong>
      <span class="why">— 최신 자산 스캔 기준 · 누르면 같은 모집단으로 필터됩니다</span>
    </div>
    <?php vg_kpi_strip([
        ['label' => 'High 이상', 'value' => number_format($actionCounts['high']), 'tone' => 'high',
         'href' => vg_qs(['sev' => 'HIGH+', 'fx' => null, 'st' => null, 'page' => 1]), 'selected' => $sev === 'HIGH+'],
        ['label' => '기한 초과', 'value' => number_format($actionCounts['overdue']), 'tone' => 'crit',
         'href' => vg_qs(['sev' => 'HIGH+', 'fx' => 'overdue', 'sort' => 'due', 'st' => null, 'page' => 1]), 'selected' => $fx === 'overdue'],
        ['label' => 'KEV 등재', 'value' => number_format($actionCounts['kev']), 'tone' => 'crit',
         'href' => vg_qs(['sev' => null, 'fx' => 'kev', 'st' => null, 'page' => 1]), 'selected' => $fx === 'kev'],
        ['label' => '외부 노출', 'value' => number_format($actionCounts['external']), 'tone' => 'high',
         'href' => vg_qs(['sev' => null, 'fx' => null, 'st' => 'EXTERNAL', 'page' => 1]), 'selected' => $st === 'EXTERNAL'],
        ['label' => '재시작 필요', 'value' => number_format($actionCounts['restart']), 'tone' => 'med',
         'href' => vg_qs(['sev' => null, 'fx' => 'restart', 'st' => null, 'page' => 1]), 'selected' => $fx === 'restart'],
    ], ['compact' => true]); ?>
  </section>

  <div class="cards">
    <?php foreach (['CRITICAL','HIGH','MEDIUM','LOW'] as $s):
      // 카드 크기·글자 크기는 CSS 가 전 등급에 똑같이 준다 — 그래서 자릿수가 많은 등급이 무조건
      //   커 보인다(실측: 'LOW 34184' 가 'CRITICAL 1' 보다 크게 읽혔다). 마크업에서 할 수 있는
      //   보정은 둘이다: (1) 천단위 구분으로 자릿수를 눈에 띄게 끊고(대시보드가 이미 '34,184' 로
      //   쓴다 — 같은 값이 화면마다 다르게 표기되지 않게 통일), (2) 0건인 등급은 등급색을 걷어
      //   중립(muted)으로 낮춘다. 0건은 "지금 볼 것이 없다" 는 뜻이라 색을 가져갈 이유가 없다.
      //   새 클래스(.kpi--zero 등)를 만들지 않는 이유: 색은 app.css 가 소유하고 지금 다른 작업이
      //   그 파일을 고치고 있다 — 이미 있는 tone-muted 로 같은 결과를 낸다.
      $zero = ((int) $counts[$s]) === 0;
    ?>
      <a href="<?= vg_h(vg_qs(['sev' => $sev === $s ? '' : $s, 'page' => 1])) ?>"
         class="kpi kpi--sm tone-<?= $zero ? 'muted' : vg_sev_tone($s) ?><?= $sev === $s ? ' is-selected' : '' ?>"
         title="<?= vg_h($s . ' ' . number_format((int) $counts[$s]) . '건' . ($sev === $s ? ' · 선택 해제' : ' 만 보기')) ?>">
        <b><?= number_format((int) $counts[$s]) ?></b><span><?= $s ?></span>
      </a>
    <?php endforeach; ?>
  </div>

  <?php
  // 단일 스캔 모드에선 scan_id 를 유지하고, 통합 모드에선 호스트 선택 드롭다운을 준다.
  $toolbar = $scan
      ? [['type' => 'hidden', 'name' => 'scan_id', 'value' => (string) $scan['scan_id']]]
      : [['type' => 'select', 'name' => 'host', 'empty_label' => '전체 호스트',
          'selected' => $hostId > 0 ? (string) $hostId : '', 'options' => $hostOptions]];
  // KPI 카드로 고른 등급(sev)은 검색 폼 필드가 아니라, 폼 제출 시 사라지지 않도록 hidden 으로 함께 싣는다.
  if ($sev !== '') {
      $toolbar[] = ['type' => 'hidden', 'name' => 'sev', 'value' => $sev, 'reset' => true];
  }
  vg_toolbar(array_merge($toolbar, [
      ['type' => 'search', 'name' => 'q', 'placeholder' => 'CVE 또는 패키지명 검색', 'value' => $q],
      // '전체 상태' 였던 것을 '노출 상태' 로 못박는다 — 바로 옆에 사람이 정하는 '조치 상태'가
      //   서기 때문에, 라벨이 둘 다 '상태' 면 어느 축인지 화면만 보고는 알 수 없다.
      ['type' => 'select', 'name' => 'st', 'empty_label' => '전체 노출 상태', 'selected' => $st,
          'options' => array_combine($stOptions, array_map('vg_status_label', $stOptions))],
      // 조치 상태 — 값 목록·라벨은 vg_finding_status_labels() 하나가 정본이다.
      ['type' => 'select', 'name' => 'fst', 'empty_label' => '전체 조치 상태', 'selected' => $fst,
          'options' => vg_finding_status_labels()],
      // 조치 가능성 — 벤더가 수정본을 안 낸 CVE 를 걸러 보거나, 그것만 모아 볼 수 있다.
      ['type' => 'select', 'name' => 'fx', 'empty_label' => '전체 조치 가능성', 'selected' => $fx,
          'options' => ['action' => '조치 가능', 'nofix' => '조치 불가(벤더 미수정)',
                        'restart' => '재시작·재부팅만 하면 됨', 'kev' => 'KEV 등재',
                        'overdue' => '기한 초과']],
      // 정렬은 표 머리글이 아니라 여기에 둔다 — vg_table 은 정렬 링크를 갖지 않는다(공용 표를
      //   이 화면 하나 때문에 바꾸지 않는다). 기한순은 최초 발견 시각을 되짚는 집계가 필요해
      //   기본값으로 두지 않는다.
      ['type' => 'select', 'name' => 'sort', 'empty_label' => '위험도순(기본)', 'selected' => $sort,
          'options' => ['due' => '조치 기한 임박순']],
  ]));

  // 컬럼 11개는 가로 스크롤을 만들어서, 정작 제일 중요한 "조치" 가 화면 밖으로 밀려났었다.
  // 값을 버리는 게 아니라 관련된 것끼리 한 칸에 쌓는다(패키지+버전, CVSS+EPSS+KEV).
  // 호스트 컬럼은 통합 모드에서만 — 단일 스캔 모드는 부제가 이미 호스트를 밝힌다.
  // 폭 배분: 목록 표는 table-layout:fixed 라(app.css 의 '목록 화면' 구역) 여기 적은 width 가
  //   그대로 지켜진다. 짧은 값(등급·상태·CVSS)은 내용 크기로 좁히고, 이름이 긴 주 식별자
  //   (호스트·CVE·패키지)에 폭을 몰아준다. 폭을 안 준 '근거' 가 남는 폭을 전부 갖는다.
  // 단위: **내용 크기가 고정된 열은 rem, 이름이 늘어나는 열은 %** 다.
  //   뱃지·점수는 화면이 좁아져도 안 줄어드는 고정 크기 덩어리라, % 로 주면 좁은 폭에서 칸보다
  //   커져 옆 열을 덮는다(cves.php 의 '심각도' 열이 같은 이유로 6.5rem 이다). 실제로 '위험도'
  //   8% 는 1440px 에서 'CVSS 9.8' 을 담지 못해 **점수가 화면에서 사라졌다.**
  //   반대로 rem 만 쓰면 넓은 화면에서 남는 폭이 전부 '근거' 로 몰리므로 이름 열은 % 로 둔다.
  //   합이 표 폭을 넘지 않게 유지한다 — 넘으면 폭 없는 '근거' 가 0 이 되고 표가 카드를 뚫는다
  //   (% 합 56.5% + 고정 19.5rem = 312px. 1060px 실측에서 근거 149px·행 높이 두 줄로 안정,
  //    가로 스크롤 없음).
  // 폭을 호스트(14.5→17%)와 조치(11.5→14%)로 옮겼다: 둘 다 **식별자** 열인데 잘리고 있었고
  //   (실측 'rollupchk.dep-rollup.example….', '1:1.22.1-3….'), 남는 폭을 전부 갖던 '근거' 는
  //   원래 두 줄 말줄임(clamp-2 + title)이라 좁아져도 잃는 정보가 없다. 식별자는 잘리면
  //   대조 자체가 불가능해진다 — 같은 폭이면 식별자에 준다.
  // 조치 상태·기한 두 칸이 늘면서 폭 예산을 다시 나눴다. 늘린 만큼은 **말줄임으로 잃는 정보가
  //   가장 적은 열**에서 가져온다: 근거(18→12.5%)는 원래 두 줄 말줄임 + title 이라 좁아져도
  //   전체 문장이 남고, 호스트·CVE·패키지 같은 식별자 열은 잘리면 대조 자체가 불가능해지므로
  //   1~2%p 만 줄였다(기존 주석의 원칙 그대로다).
  // 열 다이어트(2026-08): '근거' 열을 상세로 보냈다 — 판정 사유 문장과 판정 출처(match_source)는
  //   목록에서 "이게 뭔지·급한지·눌러 들어갈지" 를 정하는 데 쓰이지 않고, 이 표에서 유일하게
  //   여러 줄이 되는 칸이라 행 높이를 혼자 결정했다. 두 값 모두 finding_history.php 의
  //   '현재 상태' 카드(판정 근거 · 판정 출처)와 '스캔별 상태 타임라인'(회차별 근거)에 이미 있고,
  //   모든 행의 CVE 칸에 그리로 가는 '이 자산 판정 →' 링크가 있다.
  //   비운 폭(12.5%)은 전부 **식별자 열**로 돌린다 — 잘리면 대조 자체가 불가능해지는 값이라
  //   이 표에서 폭이 가장 아쉬운 곳이다(호스트 16→19 · CVE 15→17 · 패키지 10→14 · 조치 12→15.5).
  //   % 합(65.5%)과 고정폭(22rem) 총합은 이전과 같으므로 기존 실측 폭 예산이 그대로 유지된다.
  $headers = $scan ? [] : [['label' => '호스트', 'key' => 'fqdn', 'width' => '19%', 'class' => 'col-id']];
  $headers = array_merge($headers, [
      // 뱃지 폭(CRITICAL 69px) + 칸 여백 32px = 101px → 6.5rem.
      ['label' => '등급',  'key' => 'severity',       'width' => '6.5rem', 'nowrap' => true],
      /* '노출 상태'·'조치 상태'·'기한' 세 열을 한 칸으로 합쳤다 — 셋 다 뱃지 하나짜리인데
       *   열을 따로 세우니 표가 10열이 되어 정작 '조치·올릴 버전' 이 눌렸다. 칸 안의 순서는
       *   vg_signal_slots() 의 축 순서(노출 → 조치)를 그대로 따르고 기한은 조치에 붙는다.
       *   합친 건 **표시뿐이고 쿼리는 그대로다** — 세 값 모두 원래 쿼리가 이미 들고 있던
       *   컬럼이라 SELECT·정렬·필터(st·fst·sort=due)는 한 글자도 바뀌지 않았다.
       *   vg_signal_slots() 네 칸을 행 안에 넣지 않은 이유: .signal-slots 는 min-width 18rem 이라
       *   폭이 고정된(table-layout:fixed) 이 표의 한 칸에 들어가면 표가 가로로 넘친다. */
      ['label' => '신호', 'key' => 'signals', 'width' => '9.5rem',
          'title' => '노출 상태(수집 결과) · 조치 상태와 남은 기한(사람이 정한 값)'],
      // CVE 는 nowrap 이 아니다 — 링크 뒤에 KEV·조치불가 표식이 붙어 한 줄에 안 들어간다.
      //   폭이 고정된 표에서 nowrap 이면 칸을 뚫고 나가 표가 가로로 넘친다. 대신 **식별자 자체가**
      //   쪼개지지 않게 셀에서 <code> 로 감싼다(app.css: td code 는 nowrap) — 예전엔 폭이 모자라
      //   'CVE-2023-' / '4911' 로 두 줄이 났다.
      // 폭 16% 는 실측값이다: 둘째 줄(KEV 뱃지 39px + '이 자산 판정 →' 92px = 135px)이 접히지
      //   않는 최소 폭(칸 여백 29px 포함 164px ≈ 15.5%)에 여유를 얹었다. 접히면 한 행이 세 줄이 된다.
      ['label' => 'CVE',   'key' => 'cve_id',         'width' => '17%'],
      ['label' => '패키지', 'key' => 'package_name',  'width' => '14%', 'class' => 'col-id'],
      // 점수 칸 — cves.php 의 같은 칸과 같은 모양·같은 정렬로 맞춘다(같은 뜻은 화면마다 같은 모양).
      //   6rem 은 둘째 줄 'EPSS 100.0%'(66px) + 칸 여백(29px) 기준이다.
      ['label' => 'CVSS',  'key' => 'risk',           'width' => '6rem', 'nowrap' => true,
          'align' => 'right', 'title' => 'CVSS 기본점수 · 아랫줄은 EPSS(30일 내 악용 확률)'],
      // 라벨에 '이 버전 이상' 을 못 담아 값 뒤에 '이상' 을 붙이던 것을 머리글로 올린다 —
      //   좁은 칸에서는 그 두 글자가 정작 버전 문자열을 밀어냈다.
      // col-fix: 이 칸에서만 버전 문자열의 줄바꿈을 허용한다(app.css '목록 화면' 구역).
      //   공용 .badge 는 nowrap 이라 rhel 모듈 버전이 12자에서 잘려 나갔는데, "무엇으로
      //   올려야 하는가" 가 이 열의 존재 이유라 잘리면 열 자체가 무의미해진다.
      ['label' => '조치 · 올릴 버전', 'key' => 'fix', 'width' => '15.5%', 'class' => 'col-fix',
          'title' => '이 버전 이상으로 올리면 해결됩니다'],
  ]);

  // 필터 초기화 CTA — vg_qs() 는 지금 $_GET 을 기준으로 넘겨받은 키만 비우므로, 단일 호스트
  //   모드(?host=N)·단일 스캔 모드(?scan_id=N)에서 눌러도 그 컨텍스트는 유지되고 필터만 지워진다
  //   (하드코딩된 '/findings.php' 였다면 호스트·스캔 컨텍스트까지 함께 날아갔다).
  // href 는 이중으로 안전하다: vg_qs() 자체가 모든 키·값을 urlencode() 하고(server/src/view/
  //   components.php 의 vg_qs 정의), 그 결과를 vg_empty() 가 다시 vg_h() 로 이스케이프해서
  //   출력한다(vg_empty 의 cta.href 렌더 라인 — title 과 동일한 규약). 그래서 호출부(여기)에서
  //   vg_h() 를 또 감싸면 '&' 가 '&amp;amp;' 로 이중 이스케이프된다 — 하면 안 된다.
  //   (같은 vg_qs() 를 KPI 카드처럼 직접 <a href=...> 를 만드는 코드에 쓸 땐, 그건 vg_empty() 를
  //   거치지 않으므로 그 호출부가 스스로 vg_h() 해야 한다 — 여기와는 다른 경로다.)
  //   tests/smoke.sh 가 임의 쿼리값 주입으로 이 전제를 회귀 검증한다.
  /* 표의 등급·노출 뱃지는 색으로 서열을 말하는데 그 색의 뜻이 화면에 없었다.
   *   어휘·톤은 각각 vg_sev_tone()·$scopeTone(이 파일의 노출 탭)이 소유한다 — 새 색을 만들지 않는다. */
  vg_legend(array_map(
      fn(string $s): array => ['label' => $s, 'tone' => vg_sev_tone($s), 'n' => (int) $counts[$s]],
      ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
  ), ['inline' => true, 'caption' => '심각도']);

  $filterCta  = ['href' => vg_qs(['q' => '', 'sev' => '', 'st' => '', 'fx' => '', 'fst' => '', 'sort' => '', 'page' => 1]), 'label' => '필터 초기화'];
  $hasAnyFilter = $q !== '' || $sev !== '' || $st !== '' || $fx !== '' || $fst !== '' || $sort !== '';
  if ($scanId > 0 && !$scan) {
      // 단일 스캔 모드인데 그 스캔이 없는 경우(삭제됐거나 잘못된 id) — 필터 문제가 아니다.
      //   초기화 CTA 를 줘도 scan_id 는 그대로 유지돼(컨텍스트 보존이 이번 변경의 의도) 계속
      //   0건이므로, 전체 호스트 뷰로 보내는 별도 CTA 를 둔다.
      $emptySpec = [
          'icon'  => '📭',
          'title' => '스캔 #' . $scanId . ' 을(를) 찾을 수 없습니다.',
          'hint'  => '삭제됐거나 존재하지 않는 스캔입니다.',
          'cta'   => ['href' => '/findings.php', 'label' => '전체 호스트 보기'],
      ];
  } elseif (!$hostOptions) {
      // 필터 문제가 아니라 수집된 스캔 자체가 없는 경우 — "필터를 넓혀라" 는 오해를 준다.
      $emptySpec = [
          'icon'  => '📭',
          'title' => '아직 수집된 스캔이 없습니다.',
          'hint'  => '에이전트가 자산을 최소 한 번은 수집해야 이 화면에 판정이 뜹니다.',
      ];
  } elseif ($q !== '') {
      // $q 검색인데 0건이면 "필터를 넓혀라" 가 아니라 왜 안 나오는지를 알려준다 —
      //   vendor.php/packages.php 가 보여주는 패키지는 실제 설치 여부와 무관한 전역 데이터라,
      //   이 화면(호스트별 최신 스캔에서 매처가 실제로 잡은 판정)엔 없을 수 있다.
      $emptySpec = [
          'icon'  => '🔍',
          // title 은 vg_empty() 가 렌더링 시 vg_h() 로 이스케이프한다(cta.href 주석 참고 — 같은 함수).
          //   vg_trunc() 는 자체적으로 HTML/vg_h 를 반환하므로 여기서 같이 쓰면 이중 이스케이프로
          //   깨진다 — 그래서 순수 문자열 자르기(mb_strimwidth)만 쓴다. tests/smoke.sh 의
          //   "findings.php 검색어 XSS 이스케이프" 항목이 이 전제를 회귀 검증한다.
          'title' => "'" . mb_strimwidth($q, 0, 60, '…') . "' 는 이 화면(실제 스캔·매칭된 현재 판정)에는 없습니다.",
          'hint'  => '벤더 판정·영향 패키지 목록은 실제 설치 여부와 무관한 전역 데이터라 다를 수 있습니다. '
                   . '등급·상태·조치 가능성 필터도 확인해 보세요.',
          'cta'   => $filterCta,
      ];
  } elseif ($hasAnyFilter) {
      // 검색어 없이 등급·상태·조치 가능성만으로 0건 — KPI 카드 클릭으로 sev 가 걸린 경우
      //   특히 눈치채기 어려우므로 초기화 CTA 를 준다.
      $emptySpec = [
          'icon'  => '🔍',
          'title' => '조건에 맞는 판정 결과가 없습니다.',
          'hint'  => '등급·상태·조치 가능성 필터를 넓혀 보세요.',
          'cta'   => $filterCta,
      ];
  } else {
      $emptySpec = [
          'icon'  => '🔍',
          'title' => '조건에 맞는 판정 결과가 없습니다.',
          'hint'  => '검색어·등급·상태 필터를 넓혀 보세요.',
      ];
  }

  vg_table(
      $headers,
      $rows,
      [
          'empty' => $emptySpec,
          'row_class' => fn($r) => vg_sev_row((string) $r['severity']),
          'cell' => [
              // 호스트는 이 표의 **주 식별자**다 — 어느 서버 얘긴지 모르면 나머지 값이 다 무의미하다.
              //   그런데 한 줄로 쓰면 칸 폭에 먹혀 'rollupchk.dep-rollup.example….' 로 끊겼다(실측).
              //   호스트 이름(첫 라벨)과 도메인을 두 줄로 나누면 같은 폭에서 보이는 글자 수가 두 배가
              //   되고, 이 표의 행은 이미 CVE·근거 칸 때문에 두 줄이라 행 높이도 안 는다.
              //   그래도 도메인이 길면 말줄임이 남으므로 전체 값은 title 로 남긴다(잘리는 열의 공통 규칙).
              'fqdn' => function ($r) {
                  $fqdn = (string) $r['fqdn'];
                  $dot  = strpos($fqdn, '.');
                  $head = $dot === false ? $fqdn : substr($fqdn, 0, $dot);
                  $rest = $dot === false ? '' : substr($fqdn, $dot);
                  return '<a href="/host.php?id=' . (int) $r['host_id'] . '" title="' . vg_h($fqdn) . '">'
                       . vg_h($head)
                       . ($rest === '' ? '' : '<div class="why">' . vg_h($rest) . '</div>')
                       . '</a>';
              },
              'severity'       => fn($r) => vg_sev_badge((string) $r['severity']),
              /* 신호 한 칸 — 노출(수집이 말하는 것) 윗줄, 조치와 기한(사람이 정하는 것) 아랫줄.
               *   값·톤·계산은 셋 다 원래 쓰던 헬퍼 그대로다(새로 세지 않는다).
               *   상태 라벨은 '로컬 세그먼트 노출' 처럼 길어 좁은 칸에선 말줄임에 먹히므로
               *   전체 문구를 title 로 남긴다(잘라야만 하는 값의 공통 규칙).
               *   조치 메모도 title 로만 준다 — 좁은 칸에 문장을 풀면 행 높이가 튄다. */
              'signals' => function ($r) use ($firstSeen, $policy) {
                  $exposure = '<span title="' . vg_h(vg_status_label($r['runtime_status'])) . '">'
                      . vg_status_badge($r['runtime_status']) . '</span>';

                  // 조치 상태 — 행이 없으면 미조치다(vg_finding_status_badge 가 null 을 OPEN 으로 눕힌다).
                  $note  = trim((string) ($r['finding_status_note'] ?? ''));
                  $fix   = vg_finding_status_badge($r['finding_status'] ?? null);
                  if ($note !== '') {
                      $fix = '<span title="' . vg_h(mb_strimwidth($note, 0, 120, '…')) . '">' . $fix . '</span>';
                  }

                  // 남은 일수 — 계산·표기는 vg_finding_due_cell() 하나가 갖는다(화면마다 다시 세지 않게).
                  $sla  = vg_finding_sla_days((bool) $r['in_kev'], (string) $r['severity'], $policy);
                  $seen = $firstSeen[vg_finding_status_key(
                      (int) $r['host_id'], (string) ($r['container_cid'] ?? ''),
                      (string) $r['cve_id'], (string) $r['package_name']
                  )] ?? null;
                  $due = vg_finding_due_cell(
                      $seen === null ? null : (int) $seen['days'], $sla,
                      $r['finding_status'] ?? null
                  );

                  return '<div>' . $exposure . '</div><div>' . $fix . ' ' . $due . '</div>';
              },
              // CVE — 링크 + KEV 뱃지(별도 컬럼이던 '✔' 를 여기로).
              // CVE 요약(summary)은 뺐다. 근거와 나란히 두면 긴 텍스트 컬럼이 둘이라
              // 표가 화면을 넘겨서 정작 제일 중요한 '조치' 가 밖으로 밀려난다.
              // 요약은 일반적인 CVE 설명이라 상세 페이지에 있고, 근거는 이 제품만의 판정 이유다.
              // 이 칸에 링크가 둘이다 — 둘의 대상이 다르므로 라벨로 구분한다.
              //   CVE-XXXX(=취약점 자체의 일반 설명, cve.php) / '이 자산 판정'(=이 호스트·패키지에서
              //   왜 그렇게 판정됐고 스캔마다 어땠는지, finding_history.php).
              //   진입로를 이 칸의 둘째 줄에 두는 이유: 행 높이는 '근거' 칸(clamp-2 = 두 줄)이
              //   결정하는데(아래 rationale 주석), CVE 칸은 보통 한 줄이라 여기 한 줄을 더해도
              //   행이 안 높아진다. '조치' 칸에 넣으면 조치 알약(clamp-2)이 이미 두 줄일 때 세 줄이 된다.
              'cve_id' => function ($r) {
                  // 식별자는 줄바꿈하면 안 된다 — 'CVE-2023-' / '4911' 로 쪼개지면 검색도 대조도
                  //   못 한다. <code> 는 app.css 에서 표 안 nowrap 이라(td code) 칸이 좁아도
                  //   하이픈에서 접히지 않는다. 칸 자체를 nowrap 으로 만들지 않는 건 뒤에 붙는
                  //   KEV·조치불가 표식이 잘려 사라지기 때문이다(cves.php 에 같은 기록이 있다).
                  // 두 줄 구조를 **마크업으로 고정**한다: 첫 줄은 식별자만, 둘째 줄에 표식과
                  //   진입로를 모은다. 예전처럼 식별자 옆에 뱃지를 흘려 두면 폭이 모자랄 때마다
                  //   뱃지가 다음 줄로 밀려 한 행이 세 줄이 됐다(KEV 행이 목록 맨 위를 채우므로
                  //   사실상 상단 전체가 세 줄이었다). 줄 수가 행마다 달라지지 않는 게 훑기에 낫다.
                  $html = '<div><a href="/cve.php?cve=' . urlencode($r['cve_id']) . '">'
                        . '<code>' . vg_h($r['cve_id']) . '</code></a></div>';
                  $marks = '';
                  if ($r['in_kev']) { $marks .= vg_badge('KEV', 'crit', 'CISA KEV 등재') . ' '; }
                  // 벤더가 수정본을 내지 않은 CVE — 패치로는 못 고친다(완화·격리·제거가 답).
                  // 뱃지 두 개가 겹쳐 시끄러워지는 걸 피하려고, 우선순위가 더 높은 KEV 만
                  // 뱃지로 두드러지게 하고 이건 평범한 텍스트(.why 톤)로 낮춘다 — 정보는 그대로.
                  if (!empty($r['no_fix'])) {
                      $marks .= '<span class="why">조치 불가</span> ';
                  }
                  $href = vg_finding_history_url(
                      (int) $r['host_id'], $r['container_id'] === null ? 0 : (int) $r['container_id'],
                      (string) $r['cve_id'], (string) $r['package_name']
                  );
                  $html .= '<div class="why">' . $marks . '<a href="' . vg_h($href) . '">이 자산 판정 →</a></div>';
                  return $html;
              },
              // 패키지 — 이름 + 설치 버전(아래줄).
              //   컨테이너 안의 취약점은 호스트 것과 조치 방법이 다르다(이미지 재빌드) → 구분해 보여준다.
              //   이미지는 버전 옆에 붙인다(칸을 새로 만들면 표가 다시 가로로 넘친다).
              'package_name' => function ($r) {
                  $name = vg_h((string) $r['package_name']);
                  $eco = vg_osv_ecosystem($r['package_os_id'] ?? null, $r['package_os_version'] ?? null);
                  if ($eco !== null) {
                      $name = '<a href="/package.php?name=' . urlencode((string) $r['package_name'])
                          . '&amp;eco=' . urlencode($eco) . '">' . $name . '</a>';
                  }
                  // col-id 열이라 넘치는 값은 말줄임으로 잘린다 — 이름·버전·이미지를 한 문장으로
                  //   모아 title 에 남긴다(호스트 칸과 같은 규칙).
                  $full = (string) $r['package_name'] . ' ' . (string) $r['installed_version']
                        . (!empty($r['container_cid']) ? ' · 컨테이너 ' . (string) $r['container_cid'] : '')
                        . (!empty($r['container_image']) ? ' · ' . (string) $r['container_image'] : '');
                  return '<span title="' . vg_h($full) . '">' . $name
                      . (!empty($r['container_cid']) ? ' ' . vg_badge('컨테이너 ' . $r['container_cid'], 'med') : '')
                      . '</span>'
                      . '<div class="why"><code>' . vg_h($r['installed_version']) . '</code>'
                      . (!empty($r['container_image']) ? ' · ' . vg_h((string) $r['container_image']) : '')
                      . '</div>';
              },
              // 위험도 — CVSS(얼마나 심한가) + EPSS(실제로 악용될 확률). 다른 걸 재므로 같이 본다.
              //   백분위("상위 N%")는 여기선 뺀다 — 좁은 칸에서 4줄로 접힌다. 상세 페이지에 있다.
              // 값 앞의 'CVSS' 다섯 글자를 뺀 이유: 이 칸에서 유일하게 안 잘려야 하는 건 **점수**인데,
              //   접두어가 폭을 먼저 먹어 정작 숫자가 잘려 나갔다(실측 'CVSS …' — 점수가 화면에서
              //   사라졌다). 무슨 숫자인지는 열 머리글('CVSS')이 말한다. EPSS 는 값이 둘째 줄이라
              //   무엇인지 알 수 없으므로 라벨을 남긴다.
              'risk' => function ($r) {
                  $cvss = $r['cvss'] !== null
                      ? '<strong>' . vg_h((string) $r['cvss']) . '</strong>'
                      : '<span class="why">–</span>';
                  $epss = $r['epss'] !== null && $r['epss'] !== ''
                      ? 'EPSS ' . vg_h(number_format((float) $r['epss'] * 100, 1)) . '%'
                      : 'EPSS –';
                  return $cvss . '<div class="why">' . $epss . '</div>';
              },
              // 설치 버전을 조치 칸에 다시 싣지 않는다(같은 행 '패키지' 칸에 이미 있다) — 한 칸에
              //   "설치 → 고침" 을 다 넣으니 알약이 세 줄이 되어 행 높이를 결정해 버렸다.
              // 조치 + 사람이 남긴 "미조치 사유" 표식. 사유 전문·승인자·승인일시는 이력 화면에 있다
              //   (좁은 칸에 사유 문장을 그대로 풀면 행 높이가 다시 근거 칸처럼 튄다 — title 로만 준다).
              //   예전엔 이 표식이 상세로 가는 링크였는데, 이제 CVE 칸의 '이 자산 판정 →' 가 모든 행에서
              //   같은 곳으로 간다 — 한 행에 같은 대상 링크가 둘이면 어느 쪽을 눌러야 하는지 헷갈린다.
              //   그래서 여기는 링크를 떼고 표식(뱃지)으로만 남긴다.
              // 값은 vg_fix_cell() 과 같지만 **모양은 이 표의 규칙**을 따른다. vg_fix_cell 의 알약
              //   (.pill)은 파란 배경 + 강조색 글자라, 링크가 아닌 '2.38-1ubuntu6 이상' 이 목록에서
              //   링크로 보였다(실측). 여기서는 중립 뱃지(tone-muted)로 낮추고, 이 칸에서 **진짜
              //   링크인 참조 URL 만** 링크색을 갖게 한다. 공용 헬퍼를 고치지 않는 이유: 같은 함수를
              //   폭이 다른 화면(host.php)이 함께 쓰고, 여기 필요한 건 이 표의 폭 규칙이라서다.
              'fix'       => function ($r) use ($notes) {
                  $fixed = (string) ($r['evidence_fixed_version'] ?? ($r['fixed_version'] ?? ''));
                  if ($fixed !== '') {
                      // 예전엔 12자에서 잘라 넣었다(vg_trunc) — rhel 모듈 버전
                      //   '1:1.22.1-3.module+el9.2.0+…' 이 '1:1.22.1-3….' 이 되어, 화면만 보고는
                      //   어느 버전으로 올려야 하는지 알 수 없었다. 자르는 대신 이 칸에서만
                      //   줄바꿈을 허용해(col-fix) 전체를 보인다. title 은 그대로 남긴다 —
                      //   줄바꿈된 값을 복사·대조할 때 원문 한 줄이 필요하다.
                      $html = '<span class="badge tone-muted" title="' . vg_h($fixed) . '">'
                            . vg_h($fixed) . '</span>';
                  } else {
                      // 참조 URL(벤더 어드바이저리·패치 링크)은 상세로 보냈다 — 목록의 이 칸이
                      //   답해야 하는 건 "어느 버전으로 올리나" 하나이고, 외부 링크는 그 답이
                      //   없을 때만 뜨는 곁가지였다. 같은 링크를 finding_history.php 의
                      //   '수정 버전'(vg_fix_cell 이 ref_urls_json 을 그대로 편다)과 cve.php 의
                      //   참조 목록이 이미 갖고 있고, 그 덕에 목록 쿼리에서 수 KB 짜리
                      //   ref_urls_json 을 안 실어 온다.
                      $html = '<span class="why">상세에서 확인</span>';
                  }
                  $note = $notes[vg_remediation_note_key(
                      (int) $r['host_id'], (string) ($r['container_cid'] ?? ''),
                      (string) $r['cve_id'], (string) $r['package_name']
                  )] ?? null;
                  if ($note !== null) {
                      $html .= ' ' . vg_badge('미조치 사유', 'info');
                  }
                  return $html;
              },
          ],
      ]
  );
  if ($rows) { vg_page_nav($total, $perPage, $page); }
  ?>

<?php elseif ($type === 'cce'): ?>
  <?php
  // 위반 0건이 "준수" 로 읽히는 걸 막는다 — 판정 불가(NA)가 있으면 그 사실을 먼저 알린다.
  //   CVE 탭의 "0건은 안전이 아니라 판정 불가" 경고와 같은 자리·같은 역할이다.
  if ($cceResultCounts['NA'] > 0) {
      vg_alert([
          'type'  => 'warn',
          'title' => '판정 불가(NA) ' . number_format($cceResultCounts['NA']) . '건 — 위반 0건이 "준수"를 뜻하지 않습니다',
          'hints' => ['NA 는 점검에 필요한 설정값을 수집하지 못한 항목입니다.'],
      ]);
  }
  ?>

  <div class="cards">
    <?php
    // 결과 카드가 res 필터를 토글한다(다시 누르면 전체). CVE 탭의 등급 카드와 같은 조작이다.
    //   NA 는 PASS 와 절대 같은 색을 쓰지 않는다 — 회색(판정 불가)과 초록(양호)은 다른 사실이다.
    $cceCardTone = ['FAIL' => 'high', 'NA' => 'muted', 'PASS' => 'low'];
    $cceCardLabel = ['FAIL' => '위반', 'NA' => '판정 불가', 'PASS' => '양호'];
    foreach (['FAIL', 'NA', 'PASS'] as $rk): ?>
      <a href="<?= vg_h(vg_qs(['res' => $res === $rk ? 'ALL' : $rk, 'page' => 1])) ?>"
         class="kpi kpi--sm tone-<?= $cceCardTone[$rk] ?><?= $res === $rk ? ' is-selected' : '' ?>">
        <b><?= number_format($cceResultCounts[$rk]) ?></b><span><?= $cceCardLabel[$rk] ?>(<?= $rk ?>)</span>
      </a>
    <?php endforeach; ?>
  </div>

  <?php
  // 툴바 구성은 세 탭이 같다: 자산 → 등급 → (카드로 고른 필터를 hidden 으로) → 검색.
  $toolbar = $scan
      ? [['type' => 'hidden', 'name' => 'scan_id', 'value' => (string) $scan['scan_id']]]
      : [['type' => 'select', 'name' => 'host', 'empty_label' => '전체 호스트',
          'selected' => $hostId > 0 ? (string) $hostId : '', 'options' => $hostOptions]];
  vg_toolbar(array_merge($toolbar, [
      ['type' => 'select', 'name' => 'sev', 'empty_label' => '전체 등급', 'selected' => $sev,
          'options' => array_combine($sevOptions, $sevOptions)],
      // 결과는 바로 위 카드가 토글한다 — 검색을 제출해도 선택이 풀리지 않게 hidden 으로 싣는다.
      ['type' => 'hidden', 'name' => 'res', 'value' => $res === 'FAIL' ? '' : $res, 'reset' => true],
      ['type' => 'search', 'name' => 'q', 'placeholder' => '코드·점검항목·SSG 룰 검색', 'value' => $q],
      ['type' => 'hidden', 'name' => 'type', 'value' => $type],
  ]));

  $hasAnyFilter = $q !== '' || $sev !== '' || $res !== 'FAIL';
  $filterCta = ['href' => vg_qs(['q' => '', 'sev' => '', 'res' => '', 'page' => 1]), 'label' => '필터 초기화'];
  if (!$hostOptions) {
      $emptySpec = [
          'icon'  => '📭',
          'title' => '아직 수집된 스캔이 없습니다.',
          'hint'  => '에이전트가 자산을 최소 한 번은 수집해야 이 화면에 판정이 뜹니다.',
      ];
  } elseif ($cceResultCounts['FAIL'] + $cceResultCounts['PASS'] + $cceResultCounts['NA'] === 0) {
      // 점검 자체가 없는 것과 "위반이 없는 것" 은 다르다 — 여기서 "안전" 이라고 말하지 않는다.
      $emptySpec = [
          'icon'  => '📭',
          'title' => '아직 보안설정 점검 결과가 없습니다.',
          'hint'  => '에이전트가 설정값을 수집하고 서버가 판정해야 이 목록이 채워집니다.',
      ];
  } elseif ($res === 'FAIL' && !$hasAnyFilter) {
      $emptySpec = [
          'icon'  => '🔍',
          'title' => '위반(FAIL) 0건입니다 — 점검된 항목 기준입니다.',
          'hint'  => '판정 불가(NA) ' . number_format($cceResultCounts['NA']) . '건은 수집이 안 된 항목입니다.',
          'cta'   => ['href' => vg_qs(['res' => 'ALL', 'page' => 1]), 'label' => '전체 결과 보기'],
      ];
  } else {
      $emptySpec = [
          'icon'  => '🔍',
          'title' => '조건에 맞는 점검 결과가 없습니다.',
          'hint'  => '등급·결과 필터나 검색어를 넓혀 보세요.',
          'cta'   => $filterCta,
      ];
  }

  /* 결과 세 갈래(PASS/FAIL/NA)의 색 뜻. FAIL 은 등급색을 그대로 쓰므로 대표로 crit 을 세운다 —
   *   실제 톤 매핑은 아래 'result' 셀이 갖는다(여기서 분류표를 새로 만들지 않는다). */
  vg_legend([
      ['label' => 'FAIL · 위반', 'tone' => 'crit', 'n' => (int) $cceResultCounts['FAIL']],
      ['label' => 'PASS · 양호', 'tone' => 'low',  'n' => (int) $cceResultCounts['PASS']],
      ['label' => 'NA · 판정 불가', 'tone' => 'muted', 'n' => (int) $cceResultCounts['NA']],
  ], ['inline' => true, 'caption' => '점검 결과']);

  // 컬럼 순서는 CVE 탭과 같은 뼈대다 — 자산이 첫 칸, 그 다음이 판정(결과·등급), 마지막이 근거.
  //   노출 축(runtime_status)은 여기 없다: 설정 점검에는 리스닝·외부노출 개념이 없어서
  //   억지로 만들면 없는 걸 있는 척하는 게 된다. 빈 칸을 만들지 않고 컬럼 자체를 두지 않는다.
  $headers = $scan ? [] : [['label' => '호스트', 'key' => 'fqdn', 'width' => '17%', 'class' => 'col-id']];
  $headers = array_merge($headers, [
      ['label' => '결과',  'key' => 'result',   'width' => '8%',  'nowrap' => true],
      ['label' => '등급',  'key' => 'severity', 'width' => '9%',  'nowrap' => true],
      ['label' => '점검 항목', 'key' => 'title', 'width' => '24%'],
      ['label' => '기준(코드 · SSG 룰)', 'key' => 'code', 'width' => '17%', 'class' => 'col-id'],
      ['label' => '근거 (무엇을 보고 그렇게 판정했나)', 'key' => 'evidence'],
  ]);

  vg_table(
      $headers,
      $rows,
      [
          'empty' => $emptySpec,
          'row_class' => fn($r) => $r['result'] === 'FAIL' ? vg_sev_row((string) $r['severity']) : '',
          'cell' => [
              'fqdn' => fn($r) => '<a href="/host.php?id=' . (int) $r['host_id'] . '" title="' . vg_h($r['fqdn']) . '">' . vg_h($r['fqdn']) . '</a>',
              // 결과 → 톤: FAIL 은 위험도색, PASS 는 low(초록), NA 는 muted(회색). host.php 와 같은 규칙.
              'result' => fn($r) => vg_badge(
                  (string) $r['result'],
                  $r['result'] === 'FAIL' ? vg_sev_tone((string) $r['severity'])
                      : ($r['result'] === 'PASS' ? 'low' : 'muted')
              ),
              // 등급은 위반일 때만 뜻이 있다 — PASS·NA 에 등급 뱃지를 붙이면 없는 위험을 있는 것처럼 만든다.
              'severity' => fn($r) => $r['result'] === 'FAIL'
                  ? vg_sev_badge((string) $r['severity'])
                  : '<span class="why">–</span>',
              'title' => fn($r) => '<div class="clamp-2">' . vg_h((string) $r['title']) . '</div>',
              // 룰 상세 화면은 이미 compliance_rule.php 가 갖고 있다 — 새로 만들지 않고 링크한다.
              'code' => function ($r) {
                  $code = (string) $r['code'];
                  $html = '<a href="/cce-rule.php?code=' . urlencode($code) . '"><code>'
                        . vg_h($code) . '</code></a>';
                  if (empty($r['ssg_rule_id'])) {
                      return $html . '<div class="why">자체 기준(대응 SSG 룰 없음)</div>';
                  }
                  $ruleId = (string) $r['ssg_rule_id'];
                  $html .= '<div class="why"><a href="/compliance_rule.php?rule=' . urlencode($ruleId) . '">'
                        . vg_h(vg_trunc($ruleId, 28)) . ' →</a></div>';
                  return $html;
              },
              'evidence' => function ($r) {
                  $why = trim((string) ($r['rationale'] ?? ''));
                  $ev  = trim((string) ($r['evidence'] ?? ''));
                  $html = '<div class="why clamp-2">' . ($why !== '' ? vg_h($why) : '<span class="why">판정 사유 없음</span>') . '</div>';
                  if ($ev !== '') {
                      $html .= '<div class="why clamp-2"><code>' . vg_h($ev) . '</code></div>';
                  }
                  return $html;
              },
          ],
      ]
  );
  if ($rows) { vg_page_nav($total, $perPage, $page); }
  ?>

<?php else: ?>
  <div class="cards">
    <?php
    // 범위 카드가 scope 필터를 토글한다. 톤은 host.php 의 $scopeTone 과 같은 매핑이다.
    $scopeTone = ['EXTERNAL' => 'crit', 'LAN' => 'med', 'BOUND' => 'med', 'FILTERED' => 'muted', 'LOCAL' => 'muted', '-' => 'muted'];
    foreach ($scopeOptions as $sc): ?>
      <a href="<?= vg_h(vg_qs(['scope' => $scope === $sc ? '' : $sc, 'page' => 1])) ?>"
         class="kpi kpi--sm tone-<?= $scopeTone[$sc] ?><?= $scope === $sc ? ' is-selected' : '' ?>">
        <b><?= number_format((int) ($scopeCounts[$sc] ?? 0)) ?></b><span><?= vg_h(vg_scope_label($sc)) ?></span>
      </a>
    <?php endforeach; ?>
  </div>

  <?php
  $toolbar = $scan
      ? [['type' => 'hidden', 'name' => 'scan_id', 'value' => (string) $scan['scan_id']]]
      : [['type' => 'select', 'name' => 'host', 'empty_label' => '전체 호스트',
          'selected' => $hostId > 0 ? (string) $hostId : '', 'options' => $hostOptions]];
  vg_toolbar(array_merge($toolbar, [
      // 범위는 위 카드가 토글한다(같은 필터에 컨트롤을 둘 두지 않는다) — 검색 제출 시 유지되게 hidden.
      ['type' => 'hidden', 'name' => 'scope', 'value' => $scope, 'reset' => true],
      ['type' => 'search', 'name' => 'q', 'placeholder' => '프로세스 또는 실행 패키지 검색', 'value' => $q],
      ['type' => 'hidden', 'name' => 'type', 'value' => $type],
  ]));

  $hasAnyFilter = $q !== '' || $scope !== '';
  if (!$hostOptions) {
      $emptySpec = [
          'icon'  => '📭',
          'title' => '아직 수집된 스캔이 없습니다.',
          'hint'  => '에이전트가 자산을 최소 한 번은 수집해야 이 화면에 노출이 뜹니다.',
      ];
  } elseif ($hasAnyFilter) {
      $emptySpec = [
          'icon'  => '🔍',
          'title' => '조건에 맞는 리스닝 소켓이 없습니다.',
          'hint'  => '범위 필터나 검색어를 넓혀 보세요.',
          'cta'   => ['href' => vg_qs(['q' => '', 'scope' => '', 'page' => 1]), 'label' => '필터 초기화'],
      ];
  } else {
      // 0건을 "안전" 으로 말하지 않는다 — 구버전 에이전트·수집 실패면 열린 포트가 있어도 0건이다.
      $emptySpec = [
          'icon'  => '📭',
          'title' => '수집된 네트워크 노출이 없습니다.',
          'hint'  => '에이전트가 리스닝 소켓을 수집해야 이 목록이 채워집니다 — 0건이 "열린 포트 없음"을 보장하지 않습니다.',
      ];
  }

  /* 범위 뱃지의 색이 무슨 뜻인지 — 어휘는 vg_scope_label(), 톤은 위 카드와 같은 $scopeTone 이다.
   *   이 화면에서 색으로 위험을 가르는 유일한 축이라 표 바로 위에 한 줄로 둔다. */
  vg_legend(array_map(
      fn(string $sc): array => ['label' => vg_scope_label($sc), 'tone' => $scopeTone[$sc] ?? 'muted',
                                'n' => (int) ($scopeCounts[$sc] ?? 0)],
      $scopeOptions
  ), ['inline' => true, 'caption' => '노출 범위']);

  $headers = $scan ? [] : [['label' => '호스트', 'key' => 'fqdn', 'width' => '17%', 'class' => 'col-id']];
  $headers = array_merge($headers, [
      // 노출 근거(범위)가 이 탭의 판정 축이다 — CVE 탭의 '상태' 칸과 같은 자리다.
      ['label' => '범위',   'key' => 'scope',   'width' => '11%', 'nowrap' => true],
      ['label' => '프로세스', 'key' => 'proc',  'width' => '16%', 'class' => 'col-id'],
      ['label' => '포트',   'key' => 'port',    'width' => '11%', 'nowrap' => true],
      ['label' => '실행 패키지', 'key' => 'exe_pkg', 'width' => '18%', 'class' => 'col-id'],
      ['label' => '로드한 패키지', 'key' => 'loaded_pkgs'],
  ]);

  vg_table(
      $headers,
      $rows,
      [
          'empty' => $emptySpec,
          // 외부노출 행은 CVE 표의 CRITICAL 행과 같은 강조를 준다(같은 화면에서 같은 뜻의 색).
          'row_class' => fn($r) => $r['scope'] === 'EXTERNAL' ? vg_sev_row('CRITICAL') : '',
          // 범위는 NULL 도 '-'(범위 미상)로 접어 카드·필터와 같은 값으로 다룬다.
          'cell' => [
              'fqdn' => fn($r) => '<a href="/host.php?id=' . (int) $r['host_id'] . '" title="' . vg_h($r['fqdn']) . '">' . vg_h($r['fqdn']) . '</a>',
              // 톤 매핑은 위 카드와 같은 $scopeTone 하나를 쓴다(같은 값이 카드와 표에서 다른 색이면 안 된다).
              'scope' => function ($r) use ($scopeTone) {
                  $sc = ((string) ($r['scope'] ?? '')) !== '' ? (string) $r['scope'] : '-';
                  return vg_badge(vg_scope_label($sc), $scopeTone[$sc] ?? 'muted');
              },
              // 컨테이너의 nginx 를 호스트의 nginx 로 착각하지 않게 위치를 함께 적는다(host.php 와 같은 판단).
              'proc' => fn($r) => vg_h((string) ($r['proc'] ?? ''))
                  . '<div class="why">' . ($r['ctr'] !== '' ? '컨테이너 ' . vg_h((string) $r['ctr']) : '호스트') . '</div>',
              'port' => fn($r) => vg_h((string) ($r['proto'] ?? '')) . '/' . (int) $r['port']
                  . '<div class="why">' . vg_h((string) ($r['bind_addr'] ?? '')) . '</div>',
              // 이 리스너에 걸린 CVE 건수 — 누르면 CVE 탭에서 같은 자산·같은 패키지로 좁혀 본다.
              //   노출과 취약점을 잇는 자리라 이 제품의 축이 한 줄에서 완성된다.
              'exe_pkg' => function ($r) use ($expCveCounts) {
                  $pkg = (string) ($r['exe_pkg'] ?? '');
                  if ($pkg === '') { return '<span class="why">–</span>'; }
                  $html = vg_h($pkg);
                  $n = $expCveCounts[$r['scan_id'] . '|' . $r['container_id'] . '|' . $pkg] ?? 0;
                  if ($n > 0) {
                      $href = '/findings.php?host=' . (int) $r['host_id'] . '&amp;q=' . urlencode($pkg);
                      $html .= '<div class="why"><a href="' . $href . '">CVE ' . number_format($n) . '건 →</a></div>';
                  }
                  return $html;
              },
              'loaded_pkgs' => fn($r) => '<span class="why">' . vg_trunc($r['loaded_pkgs'], 80) . '</span>',
          ],
      ]
  );
  if ($rows) { vg_page_nav($total, $perPage, $page); }
  ?>
<?php endif; ?>
<?php vg_footer();
