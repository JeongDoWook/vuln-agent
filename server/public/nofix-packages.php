<?php
declare(strict_types=1);

/**
 * nofix-packages.php — 벤더 미수정이 몰린 패키지(제거·대체 검토 권고).
 *   findings.php 가 CVE 한 건씩 흩어 보여주는 것을 (호스트×패키지) 단위로 묶어,
 *   "패치 대기" 가 아니라 "제거 또는 대체" 가 조치라는 걸 드러낸다.
 *   판정 기준·문구는 server/src/nofix.php 가 소유한다(임계값도 거기 상수 하나).
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require_once __DIR__ . '/../src/audit.php';   // vg_log_activity — auth.php 가 이미 로드했을 수 있다
require_once __DIR__ . '/../src/nofix.php';
vg_require_menu('findings');

$err = null;
$rows = [];
$pageRows = [];
$total = 0;
$hostOptions = [];
$truncated = false;
$q = trim((string) ($_GET['q'] ?? ''));
$hostId = (int) ($_GET['host'] ?? 0);
$page = vg_page();
$perPage = vg_perpage();

try {
    $pdo = vg_pdo();
    $scans = vg_nofix_latest_scans($pdo);       // [scan_id => ['host_id','fqdn']]
    foreach ($scans as $info) { $hostOptions[(string) $info['host_id']] = $info['fqdn']; }
    if ($hostId > 0 && !isset($hostOptions[(string) $hostId])) { $hostId = 0; }

    $scanIds = [];
    foreach ($scans as $scanId => $info) {
        if ($hostId === 0 || $info['host_id'] === $hostId) { $scanIds[] = $scanId; }
    }

    $rows = vg_nofix_pkg_groups($pdo, $scanIds, $q);
    $truncated = count($rows) >= VG_NOFIX_MAX_GROUPS;
    $cids = vg_nofix_container_cids($pdo, $rows);
    foreach ($rows as $i => $r) {
        $info = $scans[(int) $r['scan_id']] ?? ['host_id' => 0, 'fqdn' => '?'];
        $rows[$i]['host_id'] = $info['host_id'];
        $rows[$i]['fqdn'] = $info['fqdn'];
        $rows[$i]['container_cid'] = $cids[(int) $r['container_id']] ?? null;
    }

    // HAVING 이 이미 권고 대상만 남기므로 남는 행은 소수다 — 페이지 자르기는 PHP 에서 한다
    //   (그룹 개수를 세려고 파생테이블로 한 번 더 감싸지 않는다).
    $total = count($rows);
    $pageRows = array_slice($rows, ($page - 1) * $perPage, $perPage);

    // 열람 감사 — 누가 어떤 자산의 위험을 봤는지가 이 화면의 감사 포인트다.
    vg_log_activity($pdo, 'PAGE', $hostId > 0 ? $hostId : null, 'view_nofix_packages',
        '제거·대체 검토 권고 조회', ['host_id' => $hostId, 'q' => $q, 'matched' => $total]);
} catch (Throwable $e) {
    error_log('[nofix-packages] ' . $e->getMessage());
    $err = '제거 권고 목록을 불러오는 중 오류가 발생했습니다.';
}

vg_header('제거 권고', 'findings');
?>
  <?php vg_page_title('제거·대체 검토 권고', '', '벤더가 수정본을 내지 않은 CVE 가 한 패키지에 몰려 있는 조합입니다.', [
      'count' => $total,
      'count_label' => '개 패키지',
  ]); ?>

  <nav class="subtabs">
    <a href="/findings.php">현황</a>
    <a href="/changes.php">변화</a>
    <a class="on" href="/nofix-packages.php">제거 권고</a>
  </nav>

<?php if ($err !== null): ?>
  <?php vg_alert('오류 · ' . $err); ?>
<?php else: ?>
  <?php vg_alert(vg_nofix_notice()); ?>
  <?php if ($truncated): ?>
    <?php vg_alert('권고 대상이 ' . VG_NOFIX_MAX_GROUPS . '개를 넘어 앞쪽만 보여줍니다 — 호스트·패키지 필터로 좁혀 보세요.', 'warn'); ?>
  <?php endif; ?>

  <?php vg_toolbar([
      ['type' => 'select', 'name' => 'host', 'empty_label' => '전체 호스트',
       'selected' => $hostId > 0 ? (string) $hostId : '', 'options' => $hostOptions],
      ['type' => 'search', 'name' => 'q', 'placeholder' => '패키지명 검색', 'value' => $q],
  ]); ?>

  <?php vg_table(
      [
          ['label' => '호스트', 'key' => 'fqdn', 'width' => '16%', 'class' => 'col-id'],
          ['label' => '패키지', 'key' => 'package_name', 'width' => '18%', 'class' => 'col-id'],
          ['label' => '등급', 'key' => 'severity', 'width' => '9%', 'nowrap' => true],
          ['label' => '상태', 'key' => 'runtime_status', 'width' => '10%', 'nowrap' => true],
          ['label' => '관측 (왜 권고인가)', 'key' => 'reason'],
          ['label' => '조치', 'key' => 'advice', 'width' => '17%'],
      ],
      $pageRows,
      [
          'empty' => ($q !== '' || $hostId > 0)
              ? [
                  'icon' => '🔍',
                  'title' => '조건에 맞는 권고 대상이 없습니다.',
                  'hint' => '기준을 넘긴 패키지만 여기 뜹니다 — 개별 CVE 는 탐지 결과에서 보세요.',
                  'cta' => ['href' => '/nofix-packages.php', 'label' => '필터 초기화'],
              ]
              : [
                  'icon' => '□',
                  'title' => '제거·대체를 권고할 패키지가 없습니다.',
                  'hint' => '벤더 미수정 CVE 가 한 패키지에 몰린 조합이 아직 없습니다.',
                  'cta' => ['href' => '/findings.php?fx=nofix', 'label' => '조치 불가 CVE 보기'],
              ],
          'row_class' => fn($r) => vg_sev_row((string) ($r['severity'] ?? '')),
          'cell' => [
              'fqdn' => fn($r) => '<a href="/host.php?id=' . (int) $r['host_id'] . '" title="' . vg_h((string) $r['fqdn']) . '">'
                  . vg_h((string) $r['fqdn']) . '</a>',
              'package_name' => fn($r) => '<strong>' . vg_h((string) $r['package_name']) . '</strong>'
                  . (!empty($r['container_cid']) ? ' ' . vg_badge('컨테이너 ' . (string) $r['container_cid'], 'med') : ''),
              'severity' => fn($r) => !empty($r['severity'])
                  ? vg_sev_badge((string) $r['severity'])
                  : '<span class="why">–</span>',
              'runtime_status' => fn($r) => vg_status_badge($r['runtime_status'] ?? null),
              'reason' => fn($r) => '<div class="why">' . vg_h(vg_nofix_reason($r)) . '</div>',
              // 조치는 "패치" 가 아니다 — 배지로 그 사실을 먼저 말하고, 개별 CVE 로 내려가는 길을 준다.
              'advice' => fn($r) => vg_nofix_badge()
                  . '<div class="why"><a href="/findings.php?host=' . (int) $r['host_id']
                  . '&amp;q=' . urlencode((string) $r['package_name']) . '&amp;fx=nofix">CVE 목록 →</a></div>',
          ],
      ]
  ); ?>
  <?php vg_page_nav($total, $perPage, $page); ?>
<?php endif; ?>
<?php vg_footer();
