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
    $rows = vg_nofix_attach_containers($pdo, $rows);
    foreach ($rows as $i => $r) {
        $info = $scans[(int) $r['scan_id']] ?? ['host_id' => 0, 'fqdn' => '?'];
        $rows[$i]['host_id'] = $info['host_id'];
        $rows[$i]['fqdn'] = $info['fqdn'];
    }

    // HAVING 이 이미 권고 대상만 남기므로 남는 행은 소수다 — 페이지 자르기는 PHP 에서 한다
    //   (그룹 개수를 세려고 파생테이블로 한 번 더 감싸지 않는다).
    $total = count($rows);
    // 범위를 벗어난 페이지(?page=99, 목록이 줄어든 뒤 남은 북마크)는 마지막 페이지로 당긴다.
    //   안 하면 제목엔 "(18개 패키지)" 인데 본문은 "권고할 패키지가 없습니다" 가 떠 서로 어긋난다.
    //   SQL OFFSET 으로 자르는 화면들은 이걸 못 하지만(전체 건수를 세는 쿼리가 따로다) 여기는
    //   행이 이미 전부 메모리에 있어 클램프가 공짜다. vg_page_nav 도 같은 기준으로 표시한다.
    $page = min($page, max(1, (int) ceil($total / $perPage)));
    $pageRows = array_slice($rows, ($page - 1) * $perPage, $perPage);

    // 열람 감사 — 누가 어떤 자산의 위험을 봤는지가 이 화면의 감사 포인트다.
    //   scope_id 는 비운다 — scope 가 'PAGE' 인데 host_id 를 넣으면 감사로그에 'PAGE #462' 로
    //   찍혀 페이지 id 처럼 읽힌다. 어떤 호스트를 봤는지는 data 에 남는다.
    vg_log_activity($pdo, 'PAGE', null, 'view_nofix_packages',
        '제거·대체 검토 권고 조회', ['host_id' => $hostId, 'q' => $q, 'matched' => $total]);
} catch (Throwable $e) {
    error_log('[nofix-packages] ' . $e->getMessage());
    $err = '제거 권고 목록을 불러오는 중 오류가 발생했습니다.';
}

vg_header('제거 권고', 'nofix_packages');
?>
  <?php vg_page_title('제거·대체 검토 권고', '', '벤더가 수정본을 내지 않은 CVE 가 한 패키지에 몰려 있는 조합입니다.', [
      'count' => $total,
      'count_label' => '개 패키지',
  ]); ?>

  <?php /* 탐지 결과 계열의 갈래 — 정의는 nav.php 의 vg_findings_subtabs() 한 곳에만 있다. */ ?>
  <?php vg_findings_subtabs('nofix'); ?>

<?php if ($err !== null): ?>
  <?php vg_alert('오류 · ' . $err); ?>
<?php else: ?>
  <?php
  // 화면 오리엔테이션 도식 — 이 목록의 행은 CVE 가 아니라 **패키지 조합**이다. 어떻게 여기까지
  //   왔는지(수정본 없음 → 한 패키지에 몰림 → 제거·대체 검토)를 세워 두지 않으면, 왜 조치 칸에
  //   패치 버전이 없는지가 안 읽힌다.
  vg_explain_flow([
      ['icon' => 'block',   'label' => '수정본 없음', 'state' => 'done'],
      ['icon' => 'package', 'label' => '패키지 집중', 'value' => number_format($total) . '개', 'state' => 'active'],
      ['icon' => 'warn',    'label' => '제거·대체',   'state' => 'todo'],
  ], ['label' => '제거 권고 흐름']);
  ?>
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
                  'icon' => 'search',
                  'title' => '조건에 맞는 권고 대상이 없습니다.',
                  'hint' => '기준을 넘긴 패키지만 여기 뜹니다 — 개별 CVE 는 탐지 결과에서 보세요.',
                  'cta' => ['href' => '/nofix-packages.php', 'label' => '필터 초기화'],
              ]
              : [
                  'icon' => 'package',
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
              // 런타임 상태를 모르는 그룹은 빈 뱃지가 되면 안 된다 — 모르는 건 모른다고 쓴다.
              'runtime_status' => fn($r) => !empty($r['runtime_status'])
                  ? vg_status_badge((string) $r['runtime_status'])
                  : '<span class="why">–</span>',
              'reason' => fn($r) => '<div class="why">' . vg_h(vg_nofix_reason($r)) . '</div>',
              // 조치는 "패치" 가 아니다 — 배지로 그 사실을 먼저 말하고, 개별 CVE 로 내려가는 길을 준다.
              //   ctr 로 이 행의 스코프(호스트 자신=0 / 그 컨테이너)까지 넘긴다 — 안 넘기면 같은
              //   호스트의 다른 컨테이너 판정까지 섞여 건수가 안 맞는다.
              'advice' => fn($r) => vg_badge('제거·대체 검토', 'high')
                  . '<div class="why"><a href="/findings.php?host=' . (int) $r['host_id']
                  . '&amp;ctr=' . (int) $r['container_id']
                  . '&amp;q=' . urlencode((string) $r['package_name']) . '&amp;fx=nofix">상세 CVE '
                  . number_format((int) $r['nofix_cnt']) . '건 →</a></div>',
          ],
      ]
  ); ?>
  <?php // 등급 뱃지와 행 배경색이 같은 4단계 어휘를 쓴다 — 그 색이 무슨 뜻인지 한 줄로.
  vg_legend([
      ['label' => 'CRITICAL', 'tone' => vg_sev_tone('CRITICAL')],
      ['label' => 'HIGH',     'tone' => vg_sev_tone('HIGH')],
      ['label' => 'MEDIUM',   'tone' => vg_sev_tone('MEDIUM')],
      ['label' => 'LOW',      'tone' => vg_sev_tone('LOW')],
  ], ['inline' => true, 'caption' => '등급']); ?>
  <?php vg_page_nav($total, $perPage, $page); ?>
<?php endif; ?>
<?php vg_footer();
