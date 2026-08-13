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
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require __DIR__ . '/../src/distro.php';        // vg_container_unjudgeable — 판정 불가 경고
require_once __DIR__ . '/../src/audit.php';    // vg_log_activity
// 자산 상세(host.php)에서만 들어오는 화면이라 인가 범위도 그쪽과 같다 —
//   여기만 좁히면 탐지 결과에서 들어온 사용자에게 눌리는데 403 인 링크가 생긴다.
vg_require_menu_any('assets', 'findings');

// --- 탭별 데이터 조회. 각자 {total, rows, ...} 를 돌려준다(host.php 와 같은 규약). ---

/**
 * 취약점 탭 — 이 컨테이너의 tb_finding.
 *   uq_find 좌측 접두가 (scan_id, container_id) 라 이 둘로 좁히면 인덱스를 그대로 탄다.
 *   호스트 화면과 달리 등급을 CRITICAL·HIGH 로 자르지 않는다 — 컨테이너 하나의 건수는
 *   자산 전체보다 작아 한 표에 담기고, 잘라 두면 "이미지에 무엇이 남아 있나" 를 못 센다.
 */
function vg_container_load_vuln_tab(PDO $pdo, int $sid, int $ctrId, int $perPage, int $offset, string $q): array {
    $where  = 'f.scan_id = ? AND f.container_id = ?';
    $params = [$sid, $ctrId];
    if ($q !== '') {
        $where .= ' AND (f.cve_id LIKE ? OR f.package_name LIKE ?)';
        $like = '%' . $q . '%';
        array_push($params, $like, $like);
    }

    $st = $pdo->prepare("SELECT COUNT(*) FROM tb_finding f WHERE $where");
    $st->execute($params);
    $total = (int) $st->fetchColumn();

    $st = $pdo->prepare(
        "SELECT f.severity, f.runtime_status, f.cve_id, f.package_name, f.installed_version,
                f.rationale, f.needs_restart, f.in_kev, c.epss, c.epss_percentile, c.ref_urls_json,
                " . VG_FIXED_VERSION_SUBQ . "
           FROM tb_finding f
           LEFT JOIN tb_cve c ON c.cve_id = f.cve_id
          WHERE $where
          ORDER BY FIELD(f.severity,'CRITICAL','HIGH','MEDIUM','LOW'), c.epss DESC, f.cve_id
          LIMIT $perPage OFFSET $offset"
    );
    $st->execute($params);
    return ['total' => $total, 'rows' => $st->fetchAll()];
}

/** 패키지 탭 — 이 컨테이너 안에 설치된 것. 호스트 것(container_id = 0)과 섞지 않는다. */
function vg_container_load_pkg_tab(PDO $pdo, int $sid, int $ctrId, int $perPage, int $offset, string $q): array {
    $where  = 'scan_id = ? AND container_id = ? AND is_deleted = 0';
    $params = [$sid, $ctrId];
    if ($q !== '') {
        $where .= ' AND (name LIKE ? OR source_pkg LIKE ? OR origin LIKE ? OR vendor LIKE ?)';
        $like = '%' . $q . '%';
        array_push($params, $like, $like, $like, $like);
    }

    $st = $pdo->prepare("SELECT COUNT(*) FROM tb_package WHERE $where");
    $st->execute($params);
    $total = (int) $st->fetchColumn();

    $st = $pdo->prepare(
        "SELECT manager, name, version, arch, source_pkg, source_version, origin, vendor, license
           FROM tb_package WHERE $where
          ORDER BY name, arch, version LIMIT $perPage OFFSET $offset"
    );
    $st->execute($params);
    return ['total' => $total, 'rows' => $st->fetchAll()];
}

/**
 * 런타임 탭 — 이 컨테이너 안에서 실제로 돌고 있는 것.
 *   노출(?epage=)과 프로세스(?page=)를 각자 페이지네이션한다(host.php 런타임 탭과 같은 규약).
 */
function vg_container_load_runtime_tab(PDO $pdo, int $sid, int $ctrId, int $perPage, int $offset, int $ePage, string $q): array {
    $eWhere  = 'scan_id = ? AND container_id = ?';
    $eParams = [$sid, $ctrId];
    if ($q !== '') {
        $eWhere .= ' AND (proc LIKE ? OR exe_pkg LIKE ?)';
        $like = '%' . $q . '%';
        array_push($eParams, $like, $like);
    }
    $st = $pdo->prepare("SELECT COUNT(*) FROM tb_exposure WHERE $eWhere");
    $st->execute($eParams);
    $exposureTotal = (int) $st->fetchColumn();

    // 검색을 초기화해도 ?epage= 는 URL 에 남을 수 있다(vg_toolbar 의 초기화는 page 만 지운다).
    //   그 값을 그대로 OFFSET 에 쓰면 총건수를 넘겨 빈 표가 뜬다 — 유효 범위로 접는다.
    $eMaxPage = max(1, (int) ceil($exposureTotal / $perPage));
    if ($ePage > $eMaxPage) { $ePage = $eMaxPage; }
    $eOffset = ($ePage - 1) * $perPage;

    $st = $pdo->prepare(
        "SELECT proc, proto, bind_addr, port, scope, exe_pkg, loaded_pkgs
           FROM tb_exposure WHERE $eWhere
          ORDER BY FIELD(scope,'EXTERNAL','LAN','BOUND','FILTERED','LOCAL','-'), port
          LIMIT $perPage OFFSET $eOffset"
    );
    $st->execute($eParams);
    $exposures = $st->fetchAll();

    $pWhere  = 'scan_id = ? AND container_id = ?';
    $pParams = [$sid, $ctrId];
    if ($q !== '') {
        $pWhere .= ' AND (comm LIKE ? OR username LIKE ? OR exe_pkg LIKE ?)';
        $like = '%' . $q . '%';
        array_push($pParams, $like, $like, $like);
    }
    $st = $pdo->prepare("SELECT COUNT(*) FROM tb_process WHERE $pWhere");
    $st->execute($pParams);
    $total = (int) $st->fetchColumn();

    $st = $pdo->prepare(
        "SELECT pid, comm, username, exe_pkg, loaded_pkgs
           FROM tb_process WHERE $pWhere ORDER BY comm LIMIT $perPage OFFSET $offset"
    );
    $st->execute($pParams);

    return ['total' => $total, 'rows' => $st->fetchAll(), 'exposures' => $exposures,
            'exposureTotal' => $exposureTotal, 'ePage' => $ePage];
}

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
    vg_page_title('컨테이너 상세', 'CONTAINER', '');
    vg_alert('오류 · ' . $err);
    vg_footer();
    return;
}
if (!$container) {
    vg_page_title('컨테이너를 찾을 수 없습니다', 'CONTAINER',
        '최신 스캔에 이 컨테이너가 없습니다 — 이미 내려갔거나, 자산이 삭제되었을 수 있습니다.');
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

// 최고 위험도 → 히어로 톤. 하나도 없으면 '양호'(ok) — host.php 와 같은 규칙.
$worst = null;
foreach (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as $s) { if ($counts[$s] > 0) { $worst = $s; break; } }
$heroTone = $worst ? vg_sev_tone($worst) : 'ok';

$ctrOs   = trim((string) ($container['os_id'] ?? '') . ' ' . (string) ($container['os_version'] ?? ''));
$image   = (string) ($container['image'] ?? '');
$state   = (string) ($container['runtime_state'] ?? '');
// 런타임 상태 톤 — dead 만 위험으로 올린다(멈춘 컨테이너는 위험이 아니라 사실).
$stateTone = ['running' => 'ok', 'restarting' => 'med', 'dead' => 'high'];

$meta = ['<a href="/host.php?id=' . (int) $hostId . '&amp;tab=containers">← ' . vg_h((string) $host['fqdn']) . '</a>'];
if ($image !== '')   { $meta[] = '<code>' . vg_h($image) . '</code>'; }
if ($state !== '')   { $meta[] = vg_badge($state, $stateTone[$state] ?? 'muted'); }
$meta[] = $ctrOs !== '' ? vg_h($ctrOs) : 'OS 미상';
$meta[] = !empty($container['manager'])
    ? '<code>' . vg_h((string) $container['manager']) . '</code>'
    : '<span class="why">패키지 관리자 미상</span>';
$meta[] = '패키지 ' . number_format($packageTotal) . '개';
$k8s = array_filter(
    [$container['k8s_namespace'] ?? null, $container['k8s_pod'] ?? null, $container['k8s_container'] ?? null],
    static fn($v) => (string) $v !== ''
);
if ($k8s) { $meta[] = 'k8s ' . vg_h(implode(' / ', $k8s)); }
if (!empty($container['workload_ref'])) { $meta[] = '워크로드 ' . vg_h((string) $container['workload_ref']); }
$meta[] = '최신 수집 ' . vg_h((string) $scan['collected_at']);

vg_hero(vg_h((string) $container['cid']), $meta, $worst ?? '양호', $heroTone, '최고 위험도', 'CONTAINER');
?>

<?php /* 이미지 다이제스트·SBOM 해시는 길어서 히어로 한 줄에 못 넣는다 — "이 이미지가 정확히
         무엇인가" 를 증명하는 값이라 접지 않고 자기 자리에서 통째로 보여준다(선택·복사 대상). */ ?>
<?php if (!empty($container['image_digest']) || !empty($container['sbom_hash']) || !empty($container['name'])): ?>
  <div class="card">
    <strong>이미지 식별</strong>
    <div class="card__body">
      <dl class="kv">
        <?php if (!empty($container['name']) && (string) $container['name'] !== (string) $container['cid']): ?>
          <dt>컨테이너 이름</dt><dd><?= vg_h((string) $container['name']) ?></dd>
        <?php endif; ?>
        <?php if ($image !== ''): ?>
          <dt>이미지</dt><dd class="selectable"><?= vg_h($image) ?></dd>
        <?php endif; ?>
        <?php if (!empty($container['image_digest'])): ?>
          <dt>다이제스트</dt><dd class="selectable"><?= vg_h((string) $container['image_digest']) ?></dd>
        <?php endif; ?>
        <?php if (!empty($container['sbom_format']) || !empty($container['sbom_hash'])): ?>
          <dt>수집 SBOM</dt>
          <dd class="selectable">
            <?= vg_h(trim((string) ($container['sbom_format'] ?? '') . ' ' . (string) ($container['sbom_hash'] ?? ''))) ?>
          </dd>
        <?php endif; ?>
      </dl>
    </div>
  </div>
<?php endif; ?>

<?php
// 이 컨테이너의 부품표. 호스트 SBOM 과 범위를 섞지 않는다(sbom.php 머리주석).
vg_sbom_links((string) $host['fqdn'], (string) $container['cid']);

// 취약점 0건이 "안전"으로 읽히면 안 되는 컨테이너는 그 이유를 화면에 적는다.
if ($unjudgeable !== null) {
    vg_alert([
        'type'  => 'warn',
        'title' => '이 컨테이너는 취약점 매칭이 수행되지 않습니다',
        'hints' => [
            $unjudgeable,
            '취약점 0건은 "안전함"이 아니라 "판정 불가"입니다.',
        ],
    ]);
}
?>

<div class="cards">
  <?php foreach (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as $s): ?>
    <div class="kpi kpi--sm tone-<?= vg_sev_tone($s) ?>"><b><?= (int) $counts[$s] ?></b><span><?= $s ?></span></div>
  <?php endforeach; ?>
  <div class="kpi kpi--sm tone-<?= $kevCount > 0 ? 'crit' : 'muted' ?>"
       title="KEV — 실제 악용이 확인된 취약점(CISA Known Exploited Vulnerabilities)">
    <b><?= number_format($kevCount) ?></b><span>KEV 악용확인</span>
  </div>
  <div class="kpi kpi--sm tone-<?= $externalFindings > 0 ? 'crit' : 'ok' ?>"
       title="이 컨테이너에서 밖으로 열린 포트를 통해 닿는 취약점">
    <b><?= number_format($externalFindings) ?></b><span>외부노출 취약점</span>
  </div>
  <div class="kpi kpi--sm"><b><?= number_format($packageTotal) ?></b><span>설치 패키지</span></div>
  <div class="kpi kpi--sm"><b><?= number_format($exposureCount) ?></b><span>노출 소켓</span></div>
</div>

<?php
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
?>

<?php if ($tab === 'vuln'): ?>
  <div class="card">
    <strong>취약점</strong>
    <span class="why"> · 이 컨테이너 안에 설치된 패키지 기준 <?= number_format($vulnTotal) ?>건</span>
    <div class="card__body">
    <?php
    vg_table(
        [
            ['label' => '등급·상태', 'key' => 'severity', 'width' => '13%'],
            ['label' => 'CVE', 'nowrap' => true, 'width' => '13%'],
            ['label' => 'EPSS', 'align' => 'right', 'nowrap' => true, 'width' => '10%'],
            ['label' => '패키지', 'width' => '16%'],
            ['label' => '근거', 'width' => '28%'],
            ['label' => '조치', 'width' => '20%'],
        ],
        $rows,
        [
            'card' => false,
            // 행 강조는 등급 문자열을 받는다 — 행 배열을 그대로 넘기면 안 된다(vg_table 은 행을 준다).
            'row_class' => fn($f) => vg_sev_row((string) $f['severity']),
            'empty' => $hasFilter
                ? [
                    'icon'  => '🔍',
                    'title' => '검색 조건에 맞는 취약점이 없습니다.',
                    'cta'   => ['href' => vg_qs(['q' => null, 'page' => null]), 'label' => '검색 초기화'],
                ]
                : [
                    'icon'  => '✅',
                    'title' => '이 컨테이너에서 판정된 취약점이 없습니다.',
                    'hint'  => '설치 패키지 탭에서 실제로 무엇이 깔렸는지 확인할 수 있습니다.',
                ],
            'cell' => [
                'severity' => fn($f) => vg_sev_badge((string) $f['severity'])
                    . ' ' . vg_status_badge($f['runtime_status'])
                    . (!empty($f['in_kev']) ? ' ' . vg_badge('KEV', 'crit', '실제 악용이 확인된 취약점') : ''),
                1 => fn($f) => '<strong><a href="/cve.php?cve=' . urlencode((string) $f['cve_id']) . '">'
                    . vg_h((string) $f['cve_id']) . '</a></strong>',
                2 => fn($f) => vg_epss_cell($f['epss'], $f['epss_percentile']),
                3 => fn($f) => '<strong>' . vg_h((string) $f['package_name']) . '</strong> <code>'
                    . vg_h((string) $f['installed_version']) . '</code>'
                    . (!empty($f['needs_restart']) ? ' ' . vg_badge('재시작 필요', 'high') : ''),
                4 => fn($f) => '<span class="why">' . vg_h((string) ($f['rationale'] ?? '')) . '</span>',
                // 컨테이너의 조치는 대개 "이미지를 다시 빌드" 다 — 그래도 목표 버전은 알려준다.
                5 => fn($f) => vg_fix_cell($f['fixed_version'] ?? null, $f['ref_urls_json'] ?? null,
                                           $f['installed_version'] ?? null),
            ],
        ]
    );
    ?>
    </div>
  </div>
  <?php vg_page_nav($total, $perPage, $page); ?>

<?php elseif ($tab === 'packages'): ?>
  <div class="card">
    <strong>설치 패키지</strong>
    <span class="why"> · 이 컨테이너 안 <?= number_format($packageTotal) ?>개
      <?= $ctrOs !== '' ? '· ' . vg_h($ctrOs) : '' ?></span>
    <?php if ($depEdgeTotal > 0): ?>
      <span class="why"> · <a href="/depgraph.php?id=<?= (int) $hostId ?>&amp;cid=<?= (int) $container['container_id'] ?>">무엇이 이 패키지를 끌어왔나(의존성 그래프)</a></span>
    <?php endif; ?>
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
                    'icon'  => '🔍',
                    'title' => '검색 조건에 맞는 패키지가 없습니다.',
                    'cta'   => ['href' => vg_qs(['q' => null, 'page' => null]), 'label' => '검색 초기화'],
                ]
                : [
                    'icon'  => '□',
                    'title' => '이 컨테이너에서 수집된 패키지가 없습니다.',
                    'hint'  => '패키지 DB 가 없는 이미지(distroless·scratch)이거나 수집이 실패한 경우입니다.',
                ],
            'cell' => [
                'name'    => fn($p) => '<strong>' . vg_h((string) $p['name']) . '</strong>',
                'version' => fn($p) => '<code>' . vg_h((string) ($p['version'] ?? '')) . '</code>',
                'arch'    => fn($p) => $p['arch'] ? vg_h((string) $p['arch']) : '<span class="why">–</span>',
                'manager' => fn($p) => '<code>' . vg_h((string) $p['manager']) . '</code>',
                'source_pkg' => function ($p) {
                    if (empty($p['source_pkg'])) { return '<span class="why">–</span>'; }
                    return vg_h((string) $p['source_pkg'])
                        . (!empty($p['source_version']) ? ' <span class="why">' . vg_h((string) $p['source_version']) . '</span>' : '');
                },
                'origin'  => fn($p) => $p['origin']
                    ? vg_h((string) $p['origin'])
                    : (!empty($p['vendor']) ? vg_h((string) $p['vendor']) : '<span class="why">–</span>'),
            ],
        ]
    );
    ?>
    </div>
  </div>
  <?php vg_page_nav($total, $perPage, $page); ?>

<?php else: ?>
  <div class="card">
    <strong>런타임 노출</strong>
    <span class="why">— 이 컨테이너가 연 포트. 호스트로 포워딩된 포트는 밖에서 그대로 닿는다</span>
    <div class="card__body">
    <?php
    vg_table(
        [
            ['label' => '범위'],
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
                    'cta'   => ['href' => vg_qs(['q' => null, 'page' => null, 'epage' => null]), 'label' => '검색 초기화'],
                ]
                : [
                    'icon'  => '✅',
                    'title' => '이 컨테이너에는 리스닝 소켓이 없습니다.',
                ],
            'cell' => [
                0 => fn($e) => vg_badge(vg_scope_label((string) $e['scope']), $scopeTone[$e['scope']] ?? 'muted'),
                2 => fn($e) => vg_h((string) $e['proto']) . '/' . (int) $e['port'],
                4 => fn($e) => '<span class="why">' . vg_trunc($e['loaded_pkgs'], 60) . '</span>',
            ],
        ]
    );
    ?>
    </div>
  </div>
  <?php vg_page_nav($exposureTotal, $perPage, $ePage, 'epage'); ?>

  <div class="card mt-lg">
    <strong>실행 프로세스</strong>
    <span class="why">— 이 컨테이너 안에서 돌고 있는 프로그램과 그 소속 패키지</span>
    <div class="card__body">
    <?php
    vg_table(
        [
            ['label' => 'PID'],
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
                    'cta'   => ['href' => vg_qs(['q' => null, 'page' => null, 'epage' => null]), 'label' => '검색 초기화'],
                ]
                : [
                    'icon'  => '🗂️',
                    'title' => '이 컨테이너의 프로세스 정보가 없습니다.',
                    'hint'  => '구버전 에이전트로 수집된 스캔이거나 컨테이너가 멈춘 상태입니다.',
                ],
            'cell' => [
                0 => fn($pr) => '<span class="why">' . (int) $pr['pid'] . '</span>',
                2 => fn($pr) => '<span class="why">' . vg_h((string) $pr['username']) . '</span>',
                4 => fn($pr) => '<span class="why">' . vg_trunc($pr['loaded_pkgs'], 60) . '</span>',
            ],
        ]
    );
    ?>
    </div>
  </div>
  <?php vg_page_nav($total, $perPage, $page); ?>
<?php endif; ?>

<?php vg_footer();
