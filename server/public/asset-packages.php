<?php
declare(strict_types=1);

/** 전체 활성 자산의 최신 스캔에 설치된 운영체제 패키지 통합 조회. */
require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require __DIR__ . '/../src/distro.php';
require_once __DIR__ . '/../src/audit.php';   // vg_log_activity — auth.php 가 이미 로드했을 수 있다
vg_require_menu('assets');

$err = null;
$rows = [];
$total = 0;
$hostOptions = [];
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
  <?php vg_page_title('전체 설치 패키지', '', '모든 자산의 최신 수집에서 확인된 운영체제 패키지입니다.', [
      'count' => $total,
  ]); ?>
  <?php vg_subtabs([
      'assets' => ['label' => '자산 목록', 'href' => '/assets.php'],
      'packages' => ['label' => '전체 설치 패키지', 'href' => '/asset-packages.php'],
  ], 'packages'); ?>
  <?php
  // 화면 오리엔테이션 도식 — 같은 '패키지' 라는 말이 카탈로그(packages.php)와 설치 현황(이 화면)
  //   두 곳에서 쓰여 헷갈린다. 이 화면의 출처가 **자산의 최신 수집** 이라는 것을 먼저 세운다.
  vg_explain_flow([
      ['icon' => 'host',    'label' => '자산',      'value' => number_format(count($hostOptions)) . '대', 'state' => 'done'],
      ['icon' => 'clock',   'label' => '최신 수집', 'state' => 'done'],
      ['icon' => 'package', 'label' => '설치 패키지', 'value' => number_format($total) . '건', 'state' => 'active'],
  ], ['label' => '설치 패키지 수집 흐름']);
  ?>
  <div class="sub"><span class="why">취약 영향 패키지 카탈로그가 아닌 실제 서버 설치 현황입니다.</span></div>

  <?php vg_alert($err !== null ? '오류 · ' . $err : null); ?>
  <?php if ($err === null): ?>
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
            ['label' => '수집 시각', 'key' => 'collected_at', 'nowrap' => true],
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
                    return '<strong>' . $name . '</strong>'
                        . '<div class="why"><a href="/host.php?id=' . (int)$p['host_id']
                        . '&amp;tab=packages&amp;q=' . urlencode((string)$p['name'])
                        . '">이 자산에서 보기 →</a></div>';
                },
                'fqdn' => fn($p) => '<a href="/host.php?id=' . (int)$p['host_id'] . '&amp;tab=packages">'
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
                /* 자산 목록(assets.php)의 '최신 수집' 과 같은 이유로 분까지만 보인다 — 예전 8열 표에서
                 *   이 열에 돌아오는 폭은 19자를 못 담아 말줄임으로 잘렸다. 전체 값은 title 로. */
                'collected_at' => function ($p) {
                    $at = (string) ($p['collected_at'] ?? '');
                    if ($at === '') { return '<span class="why">–</span>'; }
                    return '<span class="why" title="' . vg_h($at) . '">' . vg_h(substr($at, 0, 16)) . '</span>';
                },
            ],
        ]
    ); ?>
    <?php vg_page_nav($total, $perPage, $page); ?>
  <?php endif; ?>
<?php vg_footer();
