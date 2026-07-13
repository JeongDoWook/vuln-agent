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
$page   = max(1, (int) ($_GET['page'] ?? 1));
if (!isset(VG_CHANGE_TYPES[$type])) { $type = ''; }

$pkgChanges = [];

try {
    $pdo = vg_pdo();

    // 패키지 변경 이력 — 최근 것부터. 호스트 필터를 공유한다.
    $sql = "SELECT c.host_id, h.fqdn, c.manager, c.package_name, c.change_type,
                   c.old_version, c.new_version, s.collected_at AS `when`
              FROM tb_pkg_changes c
              JOIN tb_hosts h ON h.id = c.host_id AND h.is_deleted = 0
              JOIN tb_scans s ON s.id = c.scan_id
             WHERE c.is_deleted = 0" . ($hostId ? ' AND c.host_id = ?' : '') . '
             ORDER BY c.id DESC LIMIT 200';
    $st = $pdo->prepare($sql);
    $st->execute($hostId ? [$hostId] : []);
    $pkgChanges = $st->fetchAll(PDO::FETCH_ASSOC);

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
    $bySc = [];
    if ($scanIds) {
        $in = implode(',', array_map('intval', $scanIds));
        $fst = $pdo->query(
            "SELECT scan_id, cve_id, package_name, severity, cvss, in_kev, exposed, exposure_scope, rationale
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
    $err = $e->getMessage();
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

vg_header('변화 추적', 'changes');
?>
  <h1>변화 추적 <span class="hint">(각 호스트 최근 2스캔 비교)</span></h1>
  <div class="sub">지난 수집 대비 <strong>새로 생긴 / 해결된 / 등급이 바뀐</strong> 취약점. 무엇이 달라졌는지 한눈에 본다.</div>

<?php if ($err !== null): ?>
  <div class="err"><strong>오류</strong> · <?= vg_h($err) ?></div>
<?php else: ?>

  <div class="cards" style="display:flex;gap:.7rem;flex-wrap:wrap;margin:1rem 0;">
    <?php foreach (['new' => '신규', 'up' => '등급 상승', 'down' => '등급 하락', 'resolved' => '해결'] as $k => $lbl): ?>
      <div class="card" style="flex:1;min-width:8rem;text-align:center;">
        <div style="font-size:1.6rem;font-weight:700;"><?= (int) $summary[$k] ?></div>
        <div class="why"><?= vg_h($lbl) ?></div>
      </div>
    <?php endforeach; ?>
  </div>

  <?php vg_toolbar([
      ['type' => 'select', 'name' => 'host', 'selected' => (string) ($hostId ?: ''), 'empty_label' => '전체 호스트',
       'options' => $hostOptions],
      ['type' => 'select', 'name' => 'type', 'selected' => $type, 'empty_label' => '전체 변화',
       'options' => VG_CHANGE_TYPES],
  ]); ?>

  <?php
  if ($baselineHosts) {
      echo '<div class="sub" style="margin:.4rem 0 1rem;">기준선(첫 수집이라 비교 대상 없음): '
         . vg_h(implode(', ', $baselineHosts)) . '</div>';
  }

  $perPage = vg_perpage();
  $total   = count($changes);
  $paged   = array_slice($changes, ($page - 1) * $perPage, $perPage);

  vg_table(
      [
          ['label' => '변화', 'width' => '6rem'],
          ['label' => '호스트'],
          ['label' => 'CVE', 'width' => '11rem'],
          ['label' => '패키지'],
          ['label' => '등급', 'width' => '9rem'],
          ['label' => '수집 시각', 'width' => '11rem'],
      ],
      $paged,
      [
          'empty' => $type !== '' || $hostId ? '조건에 맞는 변화가 없습니다.' : '아직 비교할 변화가 없습니다(호스트마다 스캔이 2회 이상 쌓이면 표시).',
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

  <h2 style="margin-top:2rem;">패키지 변경 이력</h2>
  <div class="sub">언제 무엇이 <strong>설치·제거·업그레이드</strong>됐는지. 수집 내용이 직전과 같으면
    스냅샷을 새로 찍지 않으므로, 여기 남는 건 실제로 달라진 것뿐이다.</div>
  <?php
  vg_table(
      [
          ['label' => '변화', 'width' => '7rem'],
          ['label' => '호스트'],
          ['label' => '패키지'],
          ['label' => '버전'],
          ['label' => '시각', 'width' => '11rem'],
      ],
      $pkgChanges,
      [
          'empty' => '아직 패키지 변경이 없습니다(첫 수집 이후 달라진 것이 생기면 표시).',
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
  ?>
<?php endif; ?>
<?php vg_footer();
