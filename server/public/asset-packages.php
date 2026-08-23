<?php
declare(strict_types=1);

/** 전체 활성 자산의 최신 스캔에 설치된 운영체제 패키지 통합 조회. */
require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require __DIR__ . '/../src/distro.php';
require_once __DIR__ . '/../src/audit.php';   // vg_log_activity — auth.php 가 이미 로드했을 수 있다
require_once __DIR__ . '/../src/view/charts_pareto.php'; // vg_pareto, VG_PARETO_TOP
vg_require_menu('assets');

$err = null;
$rows = [];
$total = 0;
$hostOptions = [];
$paretoItems = []; $paretoTotalValue = 0; $paretoTotalPkgs = 0;
$q = trim((string)($_GET['q'] ?? ''));
$hostId = (int)($_GET['host'] ?? 0);
$manager = trim((string)($_GET['manager'] ?? ''));
$page = vg_page();
$perPage = vg_perpage();
$managerOptions = ['dpkg' => 'dpkg', 'rpm' => 'rpm', 'apk' => 'apk'];
if (!isset($managerOptions[$manager])) { $manager = ''; }

try {
    $pdo = vg_pdo();
    $hostRows = $pdo->query(
        'SELECT host_id,fqdn FROM tb_host WHERE is_deleted=0 ORDER BY fqdn'
    )->fetchAll();
    foreach ($hostRows as $host) {
        $hostOptions[(string)$host['host_id']] = (string)$host['fqdn'];
    }
    if ($hostId > 0 && !isset($hostOptions[(string)$hostId])) { $hostId = 0; }

    $from = 'FROM tb_host h
             JOIN ' . vg_latest_scan_subq() . ' latest ON latest.host_id=h.host_id
             JOIN tb_scan s ON s.scan_id=latest.mid
             JOIN tb_package p ON p.scan_id=s.scan_id';
    $where = "h.is_deleted=0 AND p.is_deleted=0 AND p.container_id=0
              AND p.manager IN ('dpkg','rpm','apk')";
    // 파레토는 목록 필터(host·manager·q) 이전의 이 기준 그대로 쓴다 — "자산 전체" 의
    //   설치 집중도를 보여주는 고정된 그림이라, 목록을 좁혀도 파레토까지 같이 좁아지면
    //   "전체" 라는 말이 거짓이 된다. $where 에 필터를 얹기 전에 값을 떠 둔다.
    $paretoWhere = $where;
    $params = [];
    if ($hostId > 0) {
        $where .= ' AND h.host_id=?';
        $params[] = $hostId;
    }
    if ($manager !== '') {
        $where .= ' AND p.manager=?';
        $params[] = $manager;
    }
    if ($q !== '') {
        $where .= ' AND (p.name LIKE ? OR p.source_pkg LIKE ? OR p.origin LIKE ? OR p.vendor LIKE ?)';
        $like = '%' . $q . '%';
        array_push($params, $like, $like, $like, $like);
    }

    $st = $pdo->prepare("SELECT COUNT(*) $from WHERE $where");
    $st->execute($params);
    $total = (int)$st->fetchColumn();

    $offset = ($page - 1) * $perPage;
    $st = $pdo->prepare(
        "SELECT h.host_id,h.fqdn,p.manager,p.name,p.version,p.arch,
                p.source_pkg,p.source_version,p.origin,p.vendor,s.collected_at,
                s.os_id,s.os_version
           $from WHERE $where
          ORDER BY p.name,h.fqdn,p.arch,p.version
          LIMIT $perPage OFFSET $offset"
    );
    $st->execute($params);
    $rows = $st->fetchAll();

    /* 파레토(상위 집중도) — 상위 N + 전체 합계·전체 종수를 윈도우 함수 한 쿼리로 뽑는다
     *   (packages.php 의 같은 패턴). $from·$paretoWhere 는 목록 쿼리와 같은 조인·기준
     *   (활성 호스트 최신 스캔의 OS 패키지, 컨테이너 제외)이라 새 인덱스가 필요 없다. */
    $paretoRows = $pdo->query(
        "SELECT p.name, COUNT(*) AS cnt,
                SUM(COUNT(*)) OVER () AS total_cnt,
                COUNT(*) OVER () AS total_pkgs
           $from WHERE $paretoWhere
          GROUP BY p.name
          ORDER BY cnt DESC
          LIMIT " . VG_PARETO_TOP
    )->fetchAll();
    foreach ($paretoRows as $r) {
        $paretoItems[] = [
            'label' => (string) $r['name'],
            'value' => (int) $r['cnt'],
            'href'  => '/asset-packages.php?q=' . urlencode((string) $r['name']),
        ];
        $paretoTotalValue = (int) $r['total_cnt'];
        $paretoTotalPkgs  = (int) $r['total_pkgs'];
    }

    /* 열람 감사 — 전 자산의 설치 패키지 목록은 host.php 상세와 같은 등급의 인프라 정보다.
     *   상세는 view_host 로 남는데 이 통합 조회만 빠져 있었다(원칙 7). */
    vg_log_activity($pdo, 'PAGE', null, 'view_asset_packages', '전체 설치 패키지 조회',
        ['host_id' => $hostId, 'manager' => $manager, 'q' => $q, 'matched' => $total]);
} catch (Throwable $e) {
    error_log('[asset-packages] ' . $e->getMessage());
    $err = '설치 패키지를 불러오는 중 오류가 발생했습니다.';
}

vg_header('전체 설치 패키지', 'asset_packages');
?>
  <?php vg_page_title('전체 설치 패키지', '', [
      'count' => $total,
  ]); ?>
  <?php vg_asset_subtabs('packages'); ?>
  <?php vg_alert($err !== null ? '오류 · ' . $err : null); ?>
  <?php if ($err === null): ?>
    <?php if (count($paretoItems) >= 2): ?>
      <div class="card">
        <strong>설치 패키지 — 상위 집중도</strong>
        <div class="card__body"><?php vg_pareto($paretoItems, [
            'total_value' => $paretoTotalValue,
            'total_items' => $paretoTotalPkgs,
            'unit'        => '건',
            'item_unit'   => '종',
            'alt'         => '설치 상위 패키지 파레토',
        ]); ?></div>
      </div>
    <?php endif; ?>

    <?php vg_toolbar([
        ['type' => 'select', 'name' => 'host', 'selected' => $hostId > 0 ? (string)$hostId : '',
         'empty_label' => '전체 호스트', 'options' => $hostOptions],
        ['type' => 'select', 'name' => 'manager', 'selected' => $manager,
         'empty_label' => '전체 관리자', 'options' => $managerOptions],
        ['type' => 'search', 'name' => 'q', 'placeholder' => '패키지명·소스·출처 검색', 'value' => $q],
    ]); ?>

    <?php vg_table(
        [
            ['label' => '패키지', 'key' => 'name', 'class' => 'col-id'],
            ['label' => '호스트', 'key' => 'fqdn'],
            // 8열이라 '수집 시각' 이 늘 잘렸다(아래 주석의 실측). 열 상한(7열)에 맞춰 '아키텍처'를
            //   독립 열에서 뺀다 — 상세는 자산 상세의 설치 패키지 탭이 갖는다(host.php 의 '아키텍처' 열).
            //   다만 값을 화면에서 지우지는 않는다: 같은 패키지가 아키텍처만 다르게 두 행 오는 일이
            //   흔해서, 값이 사라지면 **똑같아 보이는 중복 행**이 된다. 버전 칸 옆에 작게 잇는다.
            ['label' => '설치 버전', 'key' => 'version'],
            ['label' => '관리자', 'key' => 'manager'],
            ['label' => '소스 패키지', 'key' => 'source_pkg'],
            ['label' => '출처', 'key' => 'origin'],
            /* '수집 시각' 열을 걷었다 — 이 화면이 답하는 질문은 "어느 자산에 무엇이 깔려 있나" 이고
               날짜는 그 판단에 안 쓰인다(어제 수집이든 오늘 수집이든 깔린 건 같다). 게다가 값은
               그 호스트의 **최신 수집** 한 시점이라 같은 호스트 행들에선 늘 같은 글자였다.
               지운 게 아니라 호스트 링크의 툴팁으로 내렸고, 회차별 정본은 그 자산 상세의
               '수집 이력' 탭이 갖는다(advisory.php·cve.php 의 같은 열과 같은 처리). */
        ],
        $rows,
        [
            'empty' => ($q !== '' || $hostId > 0 || $manager !== '')
                ? [
                    'icon' => 'search',
                    'title' => '검색 조건에 맞는 설치 패키지가 없습니다.',
                    'cta' => ['href' => '/asset-packages.php', 'label' => '필터 초기화'],
                ]
                : [
                    'icon' => 'package',
                    'title' => '수집된 설치 패키지가 없습니다.',
                ],
            'cell' => [
                'name' => function ($p) {
                    $eco = vg_osv_ecosystem($p['os_id'] ?? null, $p['os_version'] ?? null);
                    $name = vg_h((string)$p['name']);
                    if ($eco !== null) {
                        $name = '<a href="/package.php?name=' . urlencode((string)$p['name'])
                            . '&amp;eco=' . urlencode($eco) . '">' . $name . '</a>';
                    }
                    // '이 자산에서 보기 →' 링크는 걷었다 — 같은 행의 '호스트' 열 링크가 같은
                    //   자산 상세 설치 패키지 탭으로 이미 간다(한 행에 같은 목적지 링크 둘).
                    return '<strong>' . $name . '</strong>';
                },
                // 걷어낸 '수집 시각' 이 여기로 온다 — 이 행이 어느 회차 수집인지는 호스트에 붙은 사실이다.
                'fqdn' => fn($p) => '<a href="/host.php?id=' . (int)$p['host_id'] . '&amp;tab=packages"'
                    . ' title="' . vg_h('수집 ' . (string)($p['collected_at'] ?? '')) . '">'
                    . vg_h((string)$p['fqdn']) . '</a>',
                'version' => fn($p) => '<code>' . vg_h((string)($p['version'] ?? '')) . '</code>'
                    . (!empty($p['arch']) ? ' <span class="why">' . vg_h((string)$p['arch']) . '</span>' : ''),
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
    ); ?>
    <?php vg_page_nav($total, $perPage, $page); ?>
  <?php endif; ?>
<?php vg_footer();
