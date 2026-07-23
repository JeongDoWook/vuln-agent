<?php
declare(strict_types=1);

/**
 * changes.php — 변화 추적(시계열). 로그인 필요(취약점 메뉴 권한 재사용).
 *   각 호스트의 "최근 2개 스캔"을 비교해 무엇이 달라졌는지 보여준다.
 *     - 신규   : 지난 스캔엔 없다가 이번에 생긴 취약점
 *     - 해결   : 지난 스캔엔 있었는데 이번에 사라진 것
 *     - 등급↑/↓: 양쪽에 있으나 심각도가 바뀐 것
 *   취약점 식별자는 (cve_id, package_name). 새 테이블 없이 tb_findings 만 대조한다.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
vg_require_menu('findings');

const VG_SEV_RANK = ['LOW' => 1, 'MEDIUM' => 2, 'HIGH' => 3, 'CRITICAL' => 4];
// 변화유형: 정렬·필터·배지에 공유
const VG_CHANGE_TYPES = ['new' => '신규', 'up' => '등급 상승', 'down' => '등급 하락', 'resolved' => '해결'];
// 패키지 변경유형(tb_pkg_changes.change_type)
const VG_PKG_CHANGE_TYPES = [
    'installed'   => '설치',
    'removed'     => '제거',
    'upgraded'    => '업그레이드',
    'downgraded'  => '다운그레이드',
];
// 다운그레이드는 되돌아간 것이라 눈에 띄어야 한다(취약 버전으로 회귀했을 수 있다).
function vg_pkgchg_tone(string $t): string {
    return ['upgraded' => 'ok', 'installed' => 'med', 'removed' => 'muted', 'downgraded' => 'high'][$t] ?? 'muted';
}

$err = null;
$changes = [];
$summary = ['new' => 0, 'up' => 0, 'down' => 0, 'resolved' => 0];
$hostOptions = [];
$baselineHosts = [];   // 스캔이 1개뿐이라 비교 불가(첫 수집)

$hostId = (int) ($_GET['host'] ?? 0);
$type   = (string) ($_GET['type'] ?? '');
$page   = vg_page();
$perPage = vg_perpage();
if (!isset(VG_CHANGE_TYPES[$type])) { $type = ''; }

// 취약점 변화 / 패키지 변경 — 두 목록을 세로로 쌓지 않고 탭으로 가른다.
//   ?page= 는 활성 탭에만 적용된다(페이저가 하나만 살아 있게).
$tab = (string) ($_GET['tab'] ?? 'vuln');
if (!in_array($tab, ['vuln', 'pkg'], true)) { $tab = 'vuln'; }

$pkgChanges = []; $pkgTotal = 0;

try {
    $pdo = vg_pdo();

    /* 패키지 변경 이력. 예전엔 LIMIT 200 으로 잘라놓고 "더 있다" 는 표시가 없어서
     * 201번째부터의 변경은 화면에서 볼 방법이 아예 없었다 — 제대로 페이지네이션한다.
     * 호스트 필터는 취약점 변화 목록과 공유한다. */
    $pkgFrom = 'FROM tb_pkg_changes c
                JOIN tb_hosts h ON h.id = c.host_id AND h.is_deleted = 0
                JOIN tb_scans s ON s.id = c.scan_id
               WHERE c.is_deleted = 0' . ($hostId ? ' AND c.host_id = ?' : '');
    $pkgParams = $hostId ? [$hostId] : [];

    $st = $pdo->prepare("SELECT COUNT(*) $pkgFrom");
    $st->execute($pkgParams);
    $pkgTotal = (int) $st->fetchColumn();

    if ($tab === 'pkg') {
        $pkgOffset = ($page - 1) * $perPage;
        $st = $pdo->prepare(
            "SELECT c.host_id, h.fqdn, c.manager, c.package_name, c.change_type,
                    c.old_version, c.new_version, s.collected_at AS `when`
             $pkgFrom
             ORDER BY c.id DESC
             LIMIT $perPage OFFSET $pkgOffset"
        );
        $st->execute($pkgParams);
        $pkgChanges = $st->fetchAll(PDO::FETCH_ASSOC);
    }

    // 호스트별 스캔을 최신순으로. PHP 에서 앞의 2개(최신·직전)만 취한다.
    $rows = $pdo->query(
        "SELECT s.host_id, h.fqdn, s.id AS scan_id, s.collected_at
           FROM tb_scans s
           JOIN tb_hosts h ON h.id = s.host_id AND h.is_deleted = 0
          WHERE s.is_deleted = 0
          ORDER BY s.host_id, s.id DESC"
    )->fetchAll(PDO::FETCH_ASSOC);

    $perHost = [];   // host_id => [{scan_id, fqdn, collected_at}, ...] 최신순
    foreach ($rows as $r) {
        $hid = (int) $r['host_id'];
        $hostOptions[$hid] = (string) $r['fqdn'];
        if (count($perHost[$hid] ?? []) < 2) { $perHost[$hid][] = $r; }
    }

    // 비교에 필요한 모든 스캔 id 수집(최신 + 직전)
    $scanIds = [];
    foreach ($perHost as $hid => $scans) {
        if ($hostId && $hid !== $hostId) { continue; }
        if (count($scans) < 2) { $baselineHosts[$hid] = $scans[0]['fqdn'] ?? (string) $hid; continue; }
        $scanIds[] = (int) $scans[0]['scan_id'];
        $scanIds[] = (int) $scans[1]['scan_id'];
    }

    // findings 를 한 번에 로드 → scan_id => key(cve|pkg) => row
    //   SQL LIMIT/OFFSET 페이지네이션(패키지 변경 탭과 동일한 방식)은 실측으로 기각됐다 —
    //   호스트쌍마다 tb_findings 를 자기조인(신규/해결 판정용 LEFT JOIN anti-join)하는 SQL 로
    //   diff 를 내리면, 이 dev DB(findings 51만행·비교대상 호스트 56개) 기준 인덱스 힌트를
    //   줘도 30초+ 걸렸다(현재 이 방식의 벌크 로드는 1.2초). 자기조인이 호스트당 반복되며
    //   인덱스 탐색 비용이 누적되는 게 원인 — 개선하려면 전용 커버링 인덱스나
    //   tb_pkg_changes 처럼 변경 이력을 미리 적재해두는 테이블이 필요해, 이번 "경미한
    //   정리" 범위를 넘는다. 대신 실제 쓰지 않는 컬럼(cvss, exposure_scope)만 걷어낸다
    //   (vg_change_row() 는 cve_id/package_name/severity/in_kev/exposed/rationale 만 쓴다).
    $bySc = [];
    if ($scanIds) {
        $in = implode(',', array_map('intval', $scanIds));
        $fst = $pdo->query(
            "SELECT scan_id, cve_id, package_name, severity, in_kev, exposed, rationale
               FROM tb_findings WHERE scan_id IN ($in) AND is_deleted = 0"
        );
        foreach ($fst->fetchAll(PDO::FETCH_ASSOC) as $f) {
            $bySc[(int) $f['scan_id']][$f['cve_id'] . '|' . $f['package_name']] = $f;
        }
    }

    // 호스트별 diff
    foreach ($perHost as $hid => $scans) {
        if ($hostId && $hid !== $hostId) { continue; }
        if (count($scans) < 2) { continue; }
        $fqdn = (string) $scans[0]['fqdn'];
        $when = (string) $scans[0]['collected_at'];
        $cur  = $bySc[(int) $scans[0]['scan_id']] ?? [];
        $prev = $bySc[(int) $scans[1]['scan_id']] ?? [];

        foreach ($cur as $k => $f) {
            if (!isset($prev[$k])) {
                $changes[] = vg_change_row('new', $hid, $fqdn, $when, $f);
                $summary['new']++;
            } else {
                $a = VG_SEV_RANK[$prev[$k]['severity']] ?? 0;
                $b = VG_SEV_RANK[$f['severity']] ?? 0;
                if ($b > $a) { $changes[] = vg_change_row('up', $hid, $fqdn, $when, $f, $prev[$k]['severity']); $summary['up']++; }
                elseif ($b < $a) { $changes[] = vg_change_row('down', $hid, $fqdn, $when, $f, $prev[$k]['severity']); $summary['down']++; }
            }
        }
        foreach ($prev as $k => $f) {
            if (!isset($cur[$k])) {
                $changes[] = vg_change_row('resolved', $hid, $fqdn, $when, $f);
                $summary['resolved']++;
            }
        }
    }

    // 정렬: 신규 > 등급상승 > 등급하락 > 해결, 그 안에서 심각도 높은 순
    $order = ['new' => 0, 'up' => 1, 'down' => 2, 'resolved' => 3];
    usort($changes, function ($x, $y) use ($order) {
        return [$order[$x['type']], -(VG_SEV_RANK[$x['severity']] ?? 0)]
           <=> [$order[$y['type']], -(VG_SEV_RANK[$y['severity']] ?? 0)];
    });

    if ($type !== '') {
        $changes = array_values(array_filter($changes, fn($c) => $c['type'] === $type));
    }
} catch (Throwable $e) {
    error_log('[changes] ' . $e->getMessage());
    $err = '처리 중 오류가 발생했습니다.';
}

/** 변화 1건을 표 행으로. */
function vg_change_row(string $type, int $hid, string $fqdn, string $when, array $f, ?string $from = null): array {
    return [
        'type'         => $type,
        'host_id'      => $hid,
        'fqdn'         => $fqdn,
        'when'         => $when,
        'cve_id'       => (string) $f['cve_id'],
        'package_name' => (string) $f['package_name'],
        'severity'     => (string) $f['severity'],
        'from_sev'     => $from,
        'in_kev'       => (int) ($f['in_kev'] ?? 0),
        'exposed'      => (int) ($f['exposed'] ?? 0),
        'rationale'    => (string) ($f['rationale'] ?? ''),
    ];
}

function vg_change_tone(string $type): string {
    return ['new' => 'crit', 'up' => 'high', 'down' => 'muted', 'resolved' => 'ok'][$type] ?? 'muted';
}

vg_header('변화 추적', 'findings');
?>
  <h1>변화 추적 <span class="hint">(각 호스트 최근 2스캔 비교)</span> <?= vg_info_icon('지난 수집 대비 새로 생긴 / 해결된 / 등급이 바뀐 취약점. 무엇이 달라졌는지 한눈에 본다.') ?></h1>

  <nav class="subtabs">
    <a href="/findings.php">현황</a>
    <a class="on" href="/changes.php">변화</a>
  </nav>

<?php if ($err !== null): ?>
  <?php vg_alert('오류 · ' . $err); ?>
<?php else: ?>

  <?php
  /* 요약 KPI. 예전엔 .card 를 인라인 style 로 KPI 처럼 꾸며 썼는데(디자인 규칙 위반),
   * 이제 .kpi 를 그대로 쓴다 — 눌러서 그 변화유형만 거를 수 있게 링크로. */
  $changeTone = ['new' => 'crit', 'up' => 'high', 'down' => 'low', 'resolved' => 'ok'];
  ?>
  <div class="cards">
    <?php foreach (VG_CHANGE_TYPES as $k => $lbl): ?>
      <a class="kpi tone-<?= vg_h($changeTone[$k]) ?><?= $type === $k ? ' is-selected' : '' ?>"
         href="<?= vg_h(vg_qs(['type' => $type === $k ? '' : $k, 'tab' => 'vuln', 'page' => 1])) ?>">
        <b><?= (int) $summary[$k] ?></b><span><?= vg_h($lbl) ?></span>
      </a>
    <?php endforeach; ?>
  </div>

  <?php
  $total = count($changes);
  vg_subtabs([
      'vuln' => ['label' => '취약점 변화',   'n' => $total],
      'pkg'  => ['label' => '패키지 변경',   'n' => $pkgTotal],
  ], $tab);

  // 변화유형 필터는 취약점 변화 탭에만 뜻이 있다 — 패키지 변경엔 그 어휘가 없다.
  $filters = [
      ['type' => 'select', 'name' => 'host', 'selected' => (string) ($hostId ?: ''),
       'empty_label' => '전체 호스트', 'options' => $hostOptions],
  ];
  if ($tab === 'vuln') {
      $filters[] = ['type' => 'select', 'name' => 'type', 'selected' => $type,
                    'empty_label' => '전체 변화', 'options' => VG_CHANGE_TYPES];
  }
  $filters[] = ['type' => 'hidden', 'name' => 'tab', 'value' => $tab];
  vg_toolbar($filters);

  if ($baselineHosts) {
      // 호스트 수가 많으면(운영에서 실측 50+대) 한 줄 텍스트로는 화면을 다 차지한다 —
      // findings.php 의 "판정 불가" 목록과 같은 컴포넌트(.hint-list, 스크롤 캡)를 재사용한다.
      echo '<div class="sub">기준선(첫 수집이라 비교 대상 없음)</div>';
      echo '<ul class="hint-list">';
      foreach ($baselineHosts as $bh) { echo '<li>' . vg_h($bh) . '</li>'; }
      echo '</ul>';
  }
  ?>

  <?php if ($tab === 'vuln'): ?>
    <?php
    $paged = array_slice($changes, ($page - 1) * $perPage, $perPage);
    vg_table(
        [
            ['label' => '변화', 'width' => '7rem', 'nowrap' => true],
            ['label' => '호스트'],
            ['label' => 'CVE', 'width' => '12rem', 'nowrap' => true],
            ['label' => '패키지'],
            ['label' => '등급', 'width' => '13rem'],
            ['label' => '수집 시각', 'width' => '11rem', 'nowrap' => true],
        ],
        $paged,
        [
            'empty' => ($type !== '' || $hostId)
                ? [
                    'icon'  => '🔍',
                    'title' => '조건에 맞는 변화가 없습니다.',
                    'hint'  => '호스트나 변화유형 필터를 바꿔 보세요.',
                    'cta'   => ['href' => '/changes.php', 'label' => '필터 초기화'],
                ]
                : [
                    'icon'  => '📉',
                    'title' => '아직 비교할 변화가 없습니다.',
                    'hint'  => '호스트마다 스캔이 2회 이상 쌓여야 직전과 비교할 수 있습니다.',
                ],
            'row_class' => fn($r) => vg_sev_row((string) $r['severity']),
            'cell' => [
                0 => fn($r) => vg_badge(VG_CHANGE_TYPES[$r['type']], vg_change_tone($r['type'])),
                1 => fn($r) => '<a href="/host.php?id=' . (int) $r['host_id'] . '">' . vg_h($r['fqdn']) . '</a>',
                2 => fn($r) => '<a href="/cve.php?cve=' . urlencode($r['cve_id']) . '">' . vg_h($r['cve_id']) . '</a>'
                              . ($r['in_kev'] ? ' ' . vg_badge('KEV', 'crit') : ''),
                3 => fn($r) => vg_h($r['package_name']),
                4 => function ($r) {
                    $sev = vg_sev_badge((string) $r['severity']);
                    if ($r['from_sev']) {
                        $sev = '<span class="why">' . vg_h($r['from_sev']) . ' →</span> ' . $sev;
                    }
                    if ($r['exposed']) { $sev .= ' ' . vg_badge('외부노출', 'high'); }
                    return $sev;
                },
                5 => fn($r) => '<span class="why">' . vg_h($r['when'] ?: '–') . '</span>',
            ],
        ]
    );
    if ($paged) { vg_page_nav($total, $perPage, $page); }
    ?>

  <?php else: ?>
    <div class="sub">패키지 변경 이력 <?= vg_info_icon('언제 무엇이 설치·제거·업그레이드됐는지. 수집 내용이 직전과 같으면 스냅샷을 새로 찍지 않으므로, 여기 남는 건 실제로 달라진 것뿐입니다.') ?></div>
    <?php
    vg_table(
        [
            ['label' => '변화', 'width' => '8rem', 'nowrap' => true],
            ['label' => '호스트'],
            ['label' => '패키지'],
            ['label' => '버전'],
            ['label' => '시각', 'width' => '11rem', 'nowrap' => true],
        ],
        $pkgChanges,
        [
            'empty' => [
                'icon'  => '📦',
                'title' => '아직 패키지 변경이 없습니다.',
                'hint'  => '첫 수집 이후 실제로 달라진 것이 생기면 여기에 남습니다.',
            ],
            'cell' => [
                0 => fn($r) => vg_badge(VG_PKG_CHANGE_TYPES[$r['change_type']] ?? $r['change_type'],
                                        vg_pkgchg_tone((string) $r['change_type'])),
                1 => fn($r) => '<a href="/host.php?id=' . (int) $r['host_id'] . '">' . vg_h($r['fqdn']) . '</a>',
                2 => fn($r) => vg_h($r['package_name'])
                              . ' <span class="why">' . vg_h((string) $r['manager']) . '</span>',
                3 => fn($r) => $r['old_version'] !== null && $r['new_version'] !== null
                              ? '<span class="why">' . vg_h($r['old_version']) . ' →</span> ' . vg_h($r['new_version'])
                              : vg_h((string) ($r['new_version'] ?? $r['old_version'])),
                4 => fn($r) => '<span class="why">' . vg_h($r['when'] ?: '–') . '</span>',
            ],
        ]
    );
    if ($pkgChanges) { vg_page_nav($pkgTotal, $perPage, $page); }
    ?>
  <?php endif; ?>
<?php endif; ?>
<?php vg_footer();
