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
vg_require_menu('findings');

/**
 * 탐지 유형 탭. "세 유형" 이라는 사실을 여기 하나로만 둔다 — 화이트리스트 검증·탭 렌더·
 *   툴바 hidden 값이 전부 이 상수를 참조한다. 'clear' 는 다른 탭으로 넘어갈 때 비울
 *   그 탭 전용 파라미터다(호스트·스캔·검색어·등급은 공통 축이라 유지한다).
 *   라벨은 여기 없다 — 세 화면이 함께 그리는 탭 줄이라 nav.php 의
 *   vg_findings_subtab_labels() 가 정본이다.
 */
const VG_FINDING_TYPES = [
    'cve'      => ['clear' => ['st', 'fx', 'ctr']],
    'cce'      => ['clear' => ['res']],
    'exposure' => ['clear' => ['scope']],
];

$type = (string) ($_GET['type'] ?? 'cve');
if (!isset(VG_FINDING_TYPES[$type])) { $type = 'cve'; }

$notes = [];   // 이 페이지 행들의 미조치 사유 메모 (자연키 → 메모)

// 취약점 0건이 "안전"이 아니라 "판정 불가"인 대상(호스트 + 컨테이너). 사유별로 묶는다 —
//   대상마다 사유를 통째로 반복하면(운영 실측 41줄, 그중 20줄이 같은 100자 문장) 경고가
//   길어서 아무도 안 읽는다. 사유 한 줄 + 그 사유에 걸린 대상 목록이면 정보량은 같다.
$unsupBy = [];      // 사유 => [대상명, …]

// 등급 어휘는 탭마다 다르다 — CCE 판정에는 CRITICAL 이 없다(cce.php 가 HIGH/MEDIUM/LOW 만 준다).
//   탭별 화이트리스트로 검증하므로, 탭을 옮기며 sev 를 들고 가도 그 탭에 없는 값이면 자동으로 풀린다.
$sevOptions = $type === 'cce' ? ['HIGH', 'MEDIUM', 'LOW'] : ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
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

$q   = trim((string) ($_GET['q'] ?? ''));
$sev = (string) ($_GET['sev'] ?? '');
$st  = (string) ($_GET['st'] ?? '');
$fx  = (string) ($_GET['fx'] ?? '');
$res = (string) ($_GET['res'] ?? '');
$scope = (string) ($_GET['scope'] ?? '');
if (!in_array($res, $resOptions, true)) { $res = 'FAIL'; }
if (!in_array($scope, $scopeOptions, true)) { $scope = ''; }
if (!in_array($sev, $sevOptions, true)) { $sev = ''; }
if (!in_array($st, $stOptions, true)) { $st = ''; }
// 조치 가능성: '' 전체 / action 조치 가능 / nofix 조치 불가(벤더가 수정본을 안 냈다)
//              / restart 재시작·재부팅만 하면 됨(패치는 이미 됐다 — 자산 상세에서 넘어온다)
if (!in_array($fx, ['action', 'nofix', 'restart'], true)) { $fx = ''; }
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

    if ($scanId > 0) {
        // 단일 스캔 모드 — 어느 호스트의 어느 시점인지 부제에 명시해야 한다.
        $stmt = $pdo->prepare(
            'SELECT s.scan_id, s.collected_at, h.fqdn FROM tb_scan s JOIN tb_host h ON h.host_id = s.host_id WHERE s.scan_id = ?'
        );
        $stmt->execute([$scanId]);
        $scan = $stmt->fetch() ?: null;
        if ($scan) { $scanIds = [(int) $scan['scan_id']]; }
    } else {
        if ($hostId > 0 && !$hostFound) { $hostId = 0; }   // 없는 호스트면 전체로
        foreach ($hosts as $h) {
            if ($hostId === 0 || (int) $h['host_id'] === $hostId) { $scanIds[] = (int) $h['scan_id']; }
        }
    }

    // 대상 스캔 집합은 세 탭이 공유한다(같은 자산·같은 시점을 본다는 뜻).
    $in = $scanIds ? implode(',', array_fill(0, count($scanIds), '?')) : '';

    if ($scanIds && $type === 'cve') {
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
            $where .= ' AND f.severity = ?';
            $params[] = $sev;
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

        $stmt = $pdo->prepare("SELECT COUNT(*) FROM tb_finding f WHERE $where");
        $stmt->execute($params);
        $total = (int) $stmt->fetchColumn();

        $offset = ($page - 1) * $perPage;

        $stmt = $pdo->prepare(
            "SELECT f.*, h.host_id, h.fqdn, c.summary, c.epss, c.epss_percentile, c.ref_urls_json,
                    ctr.cid AS container_cid, ctr.image AS container_image,
                    CASE WHEN f.container_id = 0 THEN s.os_id ELSE ctr.os_id END AS package_os_id,
                    CASE WHEN f.container_id = 0 THEN s.os_version ELSE ctr.os_version END AS package_os_version,
                    fe.match_source, fe.fixed_version AS evidence_fixed_version,
                " . VG_FIXED_VERSION_SUBQ . "
             FROM tb_finding f
             JOIN tb_scan s ON s.scan_id = f.scan_id
             JOIN tb_host h ON h.host_id = s.host_id
             LEFT JOIN tb_container ctr ON ctr.container_id = f.container_id
             LEFT JOIN tb_cve c ON c.cve_id = f.cve_id
             LEFT JOIN tb_finding_evidence fe ON fe.finding_id = f.finding_id
             WHERE $where
             ORDER BY f.no_fix ASC, FIELD(f.severity,'CRITICAL','HIGH','MEDIUM','LOW'), c.epss DESC, f.cvss DESC, h.fqdn
             LIMIT $perPage OFFSET $offset"
        );
        $stmt->execute($params);
        $rows = $stmt->fetchAll();

        // 사람이 남긴 미조치 사유는 이 페이지에 보이는 행들만 한 번에 읽는다(N+1 방지).
        $noteKeys = [];
        foreach ($rows as $r) {
            $noteKeys[] = [(int) $r['host_id'], (string) ($r['container_cid'] ?? ''),
                           (string) $r['cve_id'], (string) $r['package_name']];
        }
        $notes = vg_remediation_notes_map($pdo, $noteKeys);
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
  ?>

<?php if ($err !== null): ?>
  <?php vg_alert('오류 · ' . $err); ?>
<?php elseif ($type === 'cve'): ?>
  <?php if ($unsupBy):
      // 사유 한 줄에 그 사유가 걸린 대상을 모아 붙인다. 사유 자체가 이미 "왜 판정할 수 없는가"를
      //   말하므로, 예전에 앞에 두던 총론 한 줄("피드가 모르는 배포판이거나…")은 뺐다.
      $hints = [];
      foreach ($unsupBy as $reason => $names) {
          $hints[] = $reason . ' (' . count($names) . ') — ' . implode(', ', $names);
      }
      vg_alert([
          'type'  => 'warn',
          'title' => '일부 대상은 취약점 매칭이 수행되지 않습니다 — 0건은 "안전"이 아니라 "판정 불가"입니다',
          'hints' => $hints,
      ]);
  endif; ?>

  <div class="cards">
    <?php foreach (['CRITICAL','HIGH','MEDIUM','LOW'] as $s): ?>
      <a href="<?= vg_h(vg_qs(['sev' => $sev === $s ? '' : $s, 'page' => 1])) ?>"
         class="kpi kpi--sm tone-<?= vg_sev_tone($s) ?><?= $sev === $s ? ' is-selected' : '' ?>">
        <b><?= (int) $counts[$s] ?></b><span><?= $s ?></span>
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
      ['type' => 'select', 'name' => 'st', 'empty_label' => '전체 상태', 'selected' => $st,
          'options' => array_combine($stOptions, array_map('vg_status_label', $stOptions))],
      // 조치 가능성 — 벤더가 수정본을 안 낸 CVE 를 걸러 보거나, 그것만 모아 볼 수 있다.
      ['type' => 'select', 'name' => 'fx', 'empty_label' => '전체(조치 가능성)', 'selected' => $fx,
          'options' => ['action' => '조치 가능', 'nofix' => '조치 불가(벤더 미수정)',
                        'restart' => '재시작·재부팅만 하면 됨']],
      ['type' => 'search', 'name' => 'q', 'placeholder' => 'CVE 또는 패키지명 검색', 'value' => $q],
  ]));

  // 컬럼 11개는 가로 스크롤을 만들어서, 정작 제일 중요한 "조치" 가 화면 밖으로 밀려났었다.
  // 값을 버리는 게 아니라 관련된 것끼리 한 칸에 쌓는다(패키지+버전, CVSS+EPSS+KEV).
  // 호스트 컬럼은 통합 모드에서만 — 단일 스캔 모드는 부제가 이미 호스트를 밝힌다.
  // 폭 배분: 목록 표는 table-layout:fixed 라(app.css 의 '목록 화면' 구역) 여기 적은 width 가
  //   그대로 지켜진다. 짧은 값(등급·상태·위험도)은 내용 크기로 좁히고, 이름이 긴 주 식별자
  //   (호스트·CVE·패키지)에 폭을 몰아준다. 폭을 안 준 '근거' 가 남는 폭을 전부 갖는다.
  //   단위가 rem 이 아니라 % 인 이유: fixed 에서 지정폭 합이 표 폭을 넘으면 폭 없는 열이 0 이 되고
  //   표가 카드를 뚫어 가로 스크롤이 생긴다. % 는 어느 화면 폭에서도 합이 그대로라 그 일이 없다.
  // 폭을 준 열들의 합을 79.5% 로 낮춘 이유: 남는 폭을 갖는 '근거' 칸 맨 앞에는 판정 출처 뱃지가
  //   있는데(고정 크기 100px), 83.5% 였을 때 870px 에서 근거 칸이 83px 로 줄어 뱃지가 17.5px 넘쳤다.
  $headers = $scan ? [] : [['label' => '호스트', 'key' => 'fqdn', 'width' => '17%', 'class' => 'col-id']];
  $headers = array_merge($headers, [
      ['label' => '등급',  'key' => 'severity',       'width' => '9%',   'nowrap' => true],
      ['label' => '상태',  'key' => 'runtime_status', 'width' => '8.5%', 'nowrap' => true],
      // CVE 는 nowrap 이 아니다 — 링크 뒤에 KEV·조치불가 표식이 붙어 한 줄에 안 들어간다.
      //   폭이 고정된 표에서 nowrap 이면 칸을 뚫고 나가 표가 가로로 넘친다.
      ['label' => 'CVE',   'key' => 'cve_id',         'width' => '13%'],
      ['label' => '패키지', 'key' => 'package_name',  'width' => '10.5%', 'class' => 'col-id'],
      // CVSS+EPSS 숫자 칸 — cves.php 의 같은 '위험도' 칸과 같은 정렬로 맞춘다.
      ['label' => '위험도', 'key' => 'risk',          'width' => '8%', 'nowrap' => true, 'align' => 'right'],
      ['label' => '근거 (왜 위험한가)', 'key' => 'rationale'],
      ['label' => '조치',  'key' => 'fix',            'width' => '13.5%'],
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
  $filterCta  = ['href' => vg_qs(['q' => '', 'sev' => '', 'st' => '', 'fx' => '', 'page' => 1]), 'label' => '필터 초기화'];
  $hasAnyFilter = $q !== '' || $sev !== '' || $st !== '' || $fx !== '';
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
              // 칸을 넘치는 긴 FQDN 은 col-id 가 말줄임으로 접는다 — 전체 이름은 title 로 남긴다.
              'fqdn' => fn($r) => '<a href="/host.php?id=' . (int) $r['host_id'] . '" title="' . vg_h($r['fqdn']) . '">' . vg_h($r['fqdn']) . '</a>',
              'severity'       => fn($r) => vg_sev_badge((string) $r['severity']),
              'runtime_status' => fn($r) => vg_status_badge($r['runtime_status']),
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
                  $html = '<strong><a href="/cve.php?cve=' . urlencode($r['cve_id']) . '">'
                        . vg_h($r['cve_id']) . '</a></strong>';
                  if ($r['in_kev']) { $html .= ' ' . vg_badge('KEV', 'crit', 'CISA KEV 등재'); }
                  // 벤더가 수정본을 내지 않은 CVE — 패치로는 못 고친다(완화·격리·제거가 답).
                  // 뱃지 두 개가 겹쳐 시끄러워지는 걸 피하려고, 우선순위가 더 높은 KEV 만
                  // 뱃지로 두드러지게 하고 이건 평범한 텍스트(.why 톤)로 낮춘다 — 정보는 그대로.
                  if (!empty($r['no_fix'])) {
                      $html .= ' <span class="why">조치 불가</span>';
                  }
                  $href = vg_finding_history_url(
                      (int) $r['host_id'], $r['container_id'] === null ? 0 : (int) $r['container_id'],
                      (string) $r['cve_id'], (string) $r['package_name']
                  );
                  $html .= '<div class="why"><a href="' . vg_h($href) . '">이 자산 판정 →</a></div>';
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
                  return $name
                      . (!empty($r['container_cid']) ? ' ' . vg_badge('컨테이너 ' . $r['container_cid'], 'med') : '')
                      . '<div class="why"><code>' . vg_h($r['installed_version']) . '</code>'
                      . (!empty($r['container_image']) ? ' · ' . vg_h((string) $r['container_image']) : '')
                      . '</div>';
              },
              // 위험도 — CVSS(얼마나 심한가) + EPSS(실제로 악용될 확률). 다른 걸 재므로 같이 본다.
              //   백분위("상위 N%")는 여기선 뺀다 — 좁은 칸에서 4줄로 접힌다. 상세 페이지에 있다.
              'risk' => function ($r) {
                  $cvss = $r['cvss'] !== null
                      ? 'CVSS <strong>' . vg_h((string) $r['cvss']) . '</strong>'
                      : '<span class="why">CVSS –</span>';
                  $epss = $r['epss'] !== null && $r['epss'] !== ''
                      ? 'EPSS ' . vg_h(number_format((float) $r['epss'] * 100, 1)) . '%'
                      : 'EPSS –';
                  return $cvss . '<div class="why">' . $epss . '</div>';
              },
              // 근거는 이 표에서 유일하게 여러 줄이 되는 칸이라 행 높이를 혼자 끌어올렸다(실측 5줄·102px).
              //   기본은 두 줄까지만 보이고(clamp-2), 잘린 뒷부분은 title 에 통째로 남는다.
              //   글자수로 미리 자르지(vg_trunc) 않는 건, 칸 폭이 화면마다 달라 몇 자가 들어가는지
              //   서버가 알 수 없기 때문이다 — 자르는 일은 폭을 아는 CSS 에 맡긴다.
              'rationale' => function ($r) {
                  $why = (string) ($r['rationale'] ?? '');
                  // 판정 출처 뱃지는 근거 문장 앞에 같이 흐른다 — 따로 한 줄을 차지하면
                  //   근거 칸이 이 표에서 가장 높은 칸이 되어 행 전체를 끌어올린다.
                  return '<div class="why clamp-2">'
                       . '<span class="badge tone-muted">' . vg_h((string) ($r['match_source'] ?? 'catalog')) . '</span> '
                       . vg_h($why) . '</div>';
              },
              // 설치 버전을 조치 칸에 다시 싣지 않는다(같은 행 '패키지' 칸에 이미 있다) — 한 칸에
              //   "설치 → 고침" 을 다 넣으니 알약이 세 줄이 되어 행 높이를 결정해 버렸다.
              // 조치 + 사람이 남긴 "미조치 사유" 표식. 사유 전문·승인자·승인일시는 이력 화면에 있다
              //   (좁은 칸에 사유 문장을 그대로 풀면 행 높이가 다시 근거 칸처럼 튄다 — title 로만 준다).
              //   예전엔 이 표식이 상세로 가는 링크였는데, 이제 CVE 칸의 '이 자산 판정 →' 가 모든 행에서
              //   같은 곳으로 간다 — 한 행에 같은 대상 링크가 둘이면 어느 쪽을 눌러야 하는지 헷갈린다.
              //   그래서 여기는 링크를 떼고 표식(뱃지)으로만 남긴다.
              'fix'       => function ($r) use ($notes) {
                  $html = vg_fix_cell($r['evidence_fixed_version'] ?? ($r['fixed_version'] ?? null), $r['ref_urls_json'] ?? null);
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
                  $html = '<code>' . vg_h((string) $r['code']) . '</code>';
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
