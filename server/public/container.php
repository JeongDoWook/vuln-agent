<?php
declare(strict_types=1);

/**
 * container.php — 컨테이너 상세. 로그인 필요.
 *   ?id=<host_id>&cid=<컨테이너 cid> 의 **최신 스캔** 기준으로 그 컨테이너 하나를 보여준다.
 *
 * ── 이 화면이 답하는 것 ──────────────────────────────────────────────────
 *   에이전트는 컨테이너 안의 OS·패키지 관리자·설치 패키지·프로세스·열린 포트·취약점을
 *   전부 수집해 저장하고 있었지만, 화면은 자산 상세의 컨테이너 탭에 **표 6열**뿐이었다.
 *   "이 컨테이너 안에 무엇이 깔려 있나 / 무엇이 취약한가" 를 볼 방법이 아예 없었다.
 *   컨테이너는 호스트와 OS 가 다른 별개 자산이므로(alpine 컨테이너 위 ubuntu 호스트)
 *   호스트 화면에 섞지 않고 자기 상세를 준다.
 *
 * ── 왜 cid(문자열)로 찾나 ────────────────────────────────────────────────
 *   tb_container 의 자연키는 (scan_id, cid) 다. 숫자 container_id 는 스캔마다 새로 발급돼
 *   북마크·링크가 다음 수집에서 통째로 깨진다. 조치 상태가 컨테이너 **이름**으로 붙는 것과
 *   같은 이유다(finding_history.php 머리주석).
 *   예외는 depgraph.php 링크 하나 — 그 화면의 ?cid= 는 숫자 container_id 다(같은 이름,
 *   다른 값). 여기서 조회한 숫자 id 를 넘겨준다.
 *
 * 새 수집은 하지 않는다 — 이미 DB 에 있는 것만 보여준다(이미지 레이어 분석·레지스트리 조회 없음).
 *
 * 이 파일은 **무엇을 어떤 순서로 그리나**만 갖는다. 탭별 SQL 은 src/container/queries.php,
 *   머리(히어로·식별·KPI)는 src/container/overview.php, 탭별 HTML 은 src/container/tabs/*.php 다.
 *   페이저 파라미터 이름(page/epage)은 여기서만 정해 아래로 값만 넘긴다.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require __DIR__ . '/../src/distro.php';        // vg_container_unjudgeable — 판정 불가 경고
require_once __DIR__ . '/../src/audit.php';    // vg_log_activity
require_once __DIR__ . '/../src/container/queries.php';   // vg_container_load_* — 활성 탭 하나의 조회
require_once __DIR__ . '/../src/container/overview.php';  // vg_container_render_overview — 히어로·식별·KPI
require_once __DIR__ . '/../src/container/tabs.php';      // vg_container_render_tab — 활성 탭 파일만 require
// 자산 상세(host.php)에서만 들어오는 화면이라 인가 범위도 그쪽과 같다 —
//   여기만 좁히면 탐지 결과에서 들어온 사용자에게 눌리는데 403 인 링크가 생긴다.
vg_require_menu_any('assets', 'findings');

$err = null; $host = null; $scan = null; $container = null;
$counts = ['CRITICAL' => 0, 'HIGH' => 0, 'MEDIUM' => 0, 'LOW' => 0];
$kevCount = 0; $externalFindings = 0;
$vulnTotal = 0; $packageTotal = 0; $exposureCount = 0; $processCount = 0; $runtimeTotal = 0;
$depEdgeTotal = 0; $unjudgeable = null;
$rows = []; $exposures = []; $total = 0; $exposureTotal = 0;
$tab = 'vuln'; $page = 1; $ePage = 1; $perPage = vg_perpage(vg_ui_detail_per_page_default());
// 이 화면이 고른 페이지 크기를 요청 컨텍스트에도 반영한다 — 공용 툴바·"N개씩 보기" 셀렉트는
//   쿼리스트링만 보고 현재 크기를 판단해서, 안 맞추면 40개를 보여주며 "10개씩"으로 표시된다.
if (!isset($_GET['per_page'])) { $_GET['per_page'] = (string) $perPage; }

$hostId = (int) ($_GET['id'] ?? 0);
$cid    = trim((string) ($_GET['cid'] ?? ''));
$q      = trim((string) ($_GET['q'] ?? ''));

try {
    $pdo = vg_pdo();

    $st = $pdo->prepare('SELECT host_id, fqdn, os_id, os_version FROM tb_host WHERE host_id = ? AND is_deleted = 0');
    $st->execute([$hostId]);
    $host = $st->fetch() ?: null;

    if ($host) {
        // raw_json 은 호스트당 MB 단위라 SELECT * 로 끌지 않는다(host.php 와 같은 이유).
        $st = $pdo->prepare('SELECT scan_id, collected_at FROM tb_scan
                              WHERE host_id = ? AND is_deleted = 0 ORDER BY scan_id DESC LIMIT 1');
        $st->execute([$hostId]);
        $scan = $st->fetch() ?: null;
    }

    if ($scan && $cid !== '') {
        $st = $pdo->prepare(
            'SELECT container_id, cid, name, image, image_digest, k8s_namespace, k8s_pod, k8s_container,
                    workload_ref, runtime_state, sbom_format, sbom_hash, os_id, os_version, manager, pkg_count
               FROM tb_container WHERE scan_id = ? AND cid = ? AND is_deleted = 0 LIMIT 1'
        );
        $st->execute([(int) $scan['scan_id'], $cid]);
        $container = $st->fetch() ?: null;
    }

    if ($container) {
        $sid   = (int) $scan['scan_id'];
        $ctrId = (int) $container['container_id'];

        // 이 컨테이너 안 열람도 감사 대상이다 — 설치 패키지·열린 포트·프로세스가 다 들어 있다.
        vg_log_activity($pdo, 'HOST', $hostId, 'view_container',
            '컨테이너 상세 열람: ' . (string) $host['fqdn'] . ' / ' . (string) $container['cid'],
            ['container' => (string) $container['cid'], 'image' => (string) ($container['image'] ?? '')],
            subject: (string) $host['fqdn'] . '/' . (string) $container['cid'], action: 'READ');

        // 히어로 위험도 + KPI. 심각도 분포·KEV·외부노출을 한 번의 GROUP BY 로 가져온다.
        $st = $pdo->prepare("SELECT severity, COUNT(*) c,
                                    SUM(in_kev = 1) kev, SUM(runtime_status = 'EXTERNAL') ext
                               FROM tb_finding WHERE scan_id = ? AND container_id = ? GROUP BY severity");
        $st->execute([$sid, $ctrId]);
        foreach ($st->fetchAll() as $r) {
            if (isset($counts[$r['severity']])) { $counts[$r['severity']] = (int) $r['c']; }
            $vulnTotal        += (int) $r['c'];
            $kevCount         += (int) $r['kev'];
            $externalFindings += (int) $r['ext'];
        }

        $st = $pdo->prepare('SELECT COUNT(*) FROM tb_package WHERE scan_id = ? AND container_id = ? AND is_deleted = 0');
        $st->execute([$sid, $ctrId]); $packageTotal = (int) $st->fetchColumn();

        $st = $pdo->prepare('SELECT COUNT(*) FROM tb_exposure WHERE scan_id = ? AND container_id = ?');
        $st->execute([$sid, $ctrId]); $exposureCount = (int) $st->fetchColumn();

        $st = $pdo->prepare('SELECT COUNT(*) FROM tb_process WHERE scan_id = ? AND container_id = ?');
        $st->execute([$sid, $ctrId]); $processCount = (int) $st->fetchColumn();
        $runtimeTotal = $exposureCount + $processCount;

        // 의존성 그래프 진입은 엣지가 있을 때만 건다 — 없으면 빈 화면으로 보내는 링크가 된다.
        //   uk_pkg_dep_edge 좌측 접두가 (scan_id, container_id) 라 이 둘이면 인덱스 레인지다.
        $st = $pdo->prepare('SELECT COUNT(*) FROM tb_package_dependency WHERE scan_id = ? AND container_id = ?');
        $st->execute([$sid, $ctrId]); $depEdgeTotal = (int) $st->fetchColumn();

        // 취약점 0건이 "안전"이 아니라 "판정 불가"인 경우(피드 미지원 배포판·패키지 DB 없는 이미지).
        //   pkg_count 대신 실제 저장된 패키지 수를 쓴다 — 대장 값이 0이어도 패키지가 있으면 판정된다.
        $unjudgeable = vg_container_unjudgeable(
            $container['os_id'] ?? null, $container['os_version'] ?? null,
            $container['manager'] ?? null, $packageTotal
        );

        $validTabs = ['vuln', 'packages', 'runtime'];
        $tab = (string) ($_GET['tab'] ?? 'vuln');
        if (!in_array($tab, $validTabs, true)) { $tab = 'vuln'; }

        $page   = vg_page();
        $offset = ($page - 1) * $perPage;
        $ePage  = vg_page('epage');

        if ($tab === 'vuln') {
            ['total' => $total, 'rows' => $rows]
                = vg_container_load_vuln_tab($pdo, $sid, $ctrId, $perPage, $offset, $q);
        } elseif ($tab === 'packages') {
            ['total' => $total, 'rows' => $rows]
                = vg_container_load_pkg_tab($pdo, $sid, $ctrId, $perPage, $offset, $q);
        } else {
            ['total' => $total, 'rows' => $rows, 'exposures' => $exposures,
             'exposureTotal' => $exposureTotal, 'ePage' => $ePage]
                = vg_container_load_runtime_tab($pdo, $sid, $ctrId, $perPage, $offset, $ePage, $q);
        }
    }
} catch (Throwable $e) {
    error_log('[container] ' . $e->getMessage());
    $err = '컨테이너 정보를 불러오는 중 오류가 발생했습니다.';
}

// 노출 범위 → 뱃지 톤(색은 CSS 가 결정). host.php 와 같은 표를 쓴다 — 같은 값을 두 화면이
//   다른 색으로 부르지 않게 한다.
$scopeTone = ['EXTERNAL' => 'crit', 'LAN' => 'med', 'BOUND' => 'med', 'FILTERED' => 'muted', 'LOCAL' => 'muted'];
$hasFilter = $q !== '';

vg_header(($container['cid'] ?? '컨테이너') . ' · ' . ($host['fqdn'] ?? ''), 'assets');

if ($err !== null) {
    vg_page_title('컨테이너 상세', 'CONTAINER');
    vg_alert('오류 · ' . $err);
    vg_footer();
    return;
}
if (!$container) {
    vg_page_title('컨테이너를 찾을 수 없습니다', 'CONTAINER');
    echo '<div class="card">';
    vg_empty([
        'icon'  => '📦',
        'title' => '요청한 컨테이너가 최신 수집에 없습니다.',
        'hint'  => '컨테이너는 스캔 시점에 떠 있던 것만 기록됩니다. 자산 상세의 컨테이너 탭에서 현재 목록을 확인하세요.',
        'cta'   => $host
            ? ['href' => '/host.php?id=' . (int) $hostId . '&tab=containers', 'label' => '자산의 컨테이너 목록']
            : ['href' => '/assets.php', 'label' => '자산 목록'],
    ]);
    echo '</div>';
    vg_footer();
    return;
}

// 컨테이너 OS 는 머리(히어로)와 설치 패키지 탭이 함께 쓴다 — 한 곳에서 만들어 둘 다에 넘긴다.
$ctrOs = trim((string) ($container['os_id'] ?? '') . ' ' . (string) ($container['os_version'] ?? ''));

vg_container_render_overview([
    'container' => $container, 'host' => $host, 'hostId' => $hostId, 'scan' => $scan,
    'counts' => $counts, 'ctrOs' => $ctrOs, 'packageTotal' => $packageTotal,
    'vulnTotal' => $vulnTotal, 'exposureCount' => $exposureCount,
    'externalFindings' => $externalFindings, 'kevCount' => $kevCount,
    'unjudgeable' => $unjudgeable,
]);

vg_subtabs([
    'vuln'     => ['label' => '취약점',   'n' => $vulnTotal,
                   'href' => vg_qs(['tab' => 'vuln', 'page' => null, 'epage' => null, 'q' => null])],
    'packages' => ['label' => '설치 패키지', 'n' => $packageTotal,
                   'href' => vg_qs(['tab' => 'packages', 'page' => null, 'epage' => null, 'q' => null])],
    'runtime'  => ['label' => '런타임',   'n' => $runtimeTotal,
                   'href' => vg_qs(['tab' => 'runtime', 'page' => null, 'epage' => null, 'q' => null])],
], $tab);

// 검색 폼은 탭마다 대상이 달라도 형태가 같다 — 필드만 바꿔 한 번만 조립한다(DRY).
$searchPlaceholder = [
    'vuln'     => 'CVE·패키지 검색',
    'packages' => '패키지·소스·출처 검색',
    'runtime'  => '프로세스명·사용자·실행패키지 검색',
];
vg_toolbar([
    ['type' => 'search', 'name' => 'q', 'placeholder' => $searchPlaceholder[$tab], 'value' => $q],
    ['type' => 'hidden', 'name' => 'tab', 'value' => $tab],
    ['type' => 'hidden', 'name' => 'id',  'value' => (string) $hostId],
    ['type' => 'hidden', 'name' => 'cid', 'value' => (string) $container['cid']],
]);

/* 활성 탭 하나만 그린다. 페이저는 이 파일이 정한 값만 받는다 — 취약점·설치 패키지는
 *   page/per_page, 런타임은 표가 둘이라 노출이 epage 를 따로 쓴다. */
vg_container_render_tab($tab, [
    'container' => $container, 'hostId' => $hostId, 'ctrOs' => $ctrOs,
    'rows' => $rows, 'exposures' => $exposures, 'hasFilter' => $hasFilter,
    'total' => $total, 'exposureTotal' => $exposureTotal,
    'page' => $page, 'ePage' => $ePage, 'perPage' => $perPage,
    'vulnTotal' => $vulnTotal, 'packageTotal' => $packageTotal,
    'depEdgeTotal' => $depEdgeTotal, 'scopeTone' => $scopeTone,
]);

vg_footer();
