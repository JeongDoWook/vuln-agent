<?php
declare(strict_types=1);

/**
 * activity.php — 감사로그(접속기록) 뷰 (admin 전용).
 *   ISMS-P 2.9.4(접속기록 보관·5요소)를 이 제품이 스스로 만족하게 하는 화면이다.
 *   표는 5요소를 독립 컬럼으로 노출한다: 접속일시(created_at) · 식별자(user_name) ·
 *   접속지 IP(ip_address) · 처리 대상(subject) · 수행업무(action).
 *   필터는 기간·사용자·IP·수행업무(+기존 범위·자유검색). 다른 목록 화면과 같은 공용 표 모듈로 렌더한다.
 *
 *   주의: 이 화면 열람도 감사 대상이다 — vg_header() 안의 vg_log_page_view() 가 page_view 를 남긴다.
 *   기록만 하고 그 기록을 다시 읽지 않으므로(로그를 남기는 행위가 또 조회를 부르지 않는다) 재귀는 없다.
 *   감사로그는 삭제·편집 수단을 UI 로 노출하지 않는다(소프트 삭제 컬럼이 있어도 마찬가지).
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require_once __DIR__ . '/../src/audit.php';   // VG_ACTIVITY_ACTIONS / vg_activity_*_labels()
vg_require_menu('activity');

$pdo = vg_pdo();

$err = null; $rows = []; $total = 0; $scopes = []; $accessRows = [];

// ── 필터: 5요소 기준(기간·사용자·접속지 IP·수행업무) + 기존 범위·자유검색 ──
$scope    = trim((string) ($_GET['scope'] ?? ''));
$q        = trim((string) ($_GET['q'] ?? ''));
$fromDate = trim((string) ($_GET['from'] ?? ''));
$toDate   = trim((string) ($_GET['to'] ?? ''));
$userName = trim((string) ($_GET['user'] ?? ''));
$ipFilter = trim((string) ($_GET['ip'] ?? ''));
$action   = trim((string) ($_GET['action'] ?? ''));
// 형식이 어긋난 날짜는 조용히 버린다(잘못된 값으로 빈 목록이 뜨면 사용자가 이유를 못 찾는다).
if (preg_match('/^\d{4}-\d{2}-\d{2}$/', $fromDate) !== 1) { $fromDate = ''; }
if (preg_match('/^\d{4}-\d{2}-\d{2}$/', $toDate) !== 1)   { $toDate = ''; }
if (!in_array($action, VG_ACTIVITY_ACTIONS, true)) { $action = ''; }

$page = vg_page();
$perPage = vg_perpage();

// 액션(activity_type) 코드 → 한글 라벨(SSOT: vg_activity_type_labels(), user.php 와 공유).
$activityLabels = vg_activity_type_labels();
// 수행업무(action) 코드 → 한글 라벨(SSOT: vg_activity_action_labels()).
$actionLabels = vg_activity_action_labels();

try {
    // 사용자별 접속 현황 — tb_user 의 로그인 보안 컬럼(login_security 마이그레이션)을 그대로 노출.
    // session_token 은 만료 로직이 없어 "현재 접속중"으로 오인될 수 있어 화면에 안 보여준다(last_login 시각만).
    // vg_can('activity') 는 tb_role_permission 으로 operator/user 에게도 위임될 수 있어(vg_require_menu 는
    // "activity 메뉴 접근"만 보장) failed_login_count/locked_until(브루트포스 잠금 정보)은 그 게이트만으론
    // admin 전용이 아니다 — 여기서 vg_has_role('admin') 을 추가로 확인해 진짜 admin 에게만 조회/렌더한다.
    if (vg_has_role('admin')) {
        // user_id 를 같이 뽑는다 — 잠긴 계정을 발견해도 여기서 상세(잠금 해제)로 갈 길이 없었다.
        $accessRows = $pdo->query(
            "SELECT user_id, username, role, last_login, failed_login_count, locked_until
               FROM tb_user
              WHERE is_deleted = 0
              ORDER BY last_login IS NULL, last_login DESC"
        )->fetchAll();
    }

    $scopes = $pdo->query(
        "SELECT DISTINCT scope FROM tb_activity_log WHERE is_deleted = 0 ORDER BY scope"
    )->fetchAll(PDO::FETCH_COLUMN);
    if (!in_array($scope, $scopes, true)) { $scope = ''; }

    $where = 'is_deleted = 0';
    $params = [];
    if ($scope !== '') {
        $where .= ' AND scope = ?';
        $params[] = $scope;
    }
    if ($action !== '') {
        $where .= ' AND action = ?';          // idx_activity_action
        $params[] = $action;
    }
    if ($fromDate !== '') {
        $where .= ' AND created_at >= ?';     // idx_activity_created
        $params[] = $fromDate . ' 00:00:00';
    }
    if ($toDate !== '') {
        $where .= ' AND created_at <= ?';
        $params[] = $toDate . ' 23:59:59';
    }
    if ($userName !== '') {
        $where .= ' AND user_name LIKE ?';
        $params[] = '%' . $userName . '%';
    }
    if ($ipFilter !== '') {
        $where .= ' AND ip_address LIKE ?';
        $params[] = $ipFilter . '%';          // 접속지는 대역 앞자리로 좁히는 경우가 많다 → 접두 일치
    }
    if ($q !== '') {
        $where .= ' AND (message LIKE ? OR user_name LIKE ? OR activity_type LIKE ? OR subject LIKE ?)';
        $params[] = '%' . $q . '%';
        $params[] = '%' . $q . '%';
        $params[] = '%' . $q . '%';
        $params[] = '%' . $q . '%';
    }

    $stmt = $pdo->prepare("SELECT COUNT(*) FROM tb_activity_log WHERE $where");
    $stmt->execute($params);
    $total = (int) $stmt->fetchColumn();

    $offset = ($page - 1) * $perPage;

    $stmt = $pdo->prepare(
        "SELECT created_at, scope, scope_id, activity_type, actor_type, user_name, message,
                subject, action, data, ip_address
         FROM tb_activity_log
         WHERE $where
         ORDER BY activity_log_id DESC
         LIMIT $perPage OFFSET $offset"
    );
    $stmt->execute($params);
    $rows = $stmt->fetchAll();
} catch (Throwable $e) {
    error_log('[activity] ' . $e->getMessage());
    $err = '처리 중 오류가 발생했습니다.';
}

vg_header('감사 로그', 'activity');
?>
  <?php vg_page_title('감사 로그', 'AUDIT'); ?>

<?php if ($err !== null): ?>
  <?php vg_alert('오류 · ' . $err); ?>
<?php else: ?>
  <?php if (vg_has_role('admin')): ?>
  <h2>사용자별 접속 현황</h2>
  <?php
  vg_table([
      ['label' => '아이디'],
      ['label' => '역할',        'width' => '8%'],
      ['label' => '최근 로그인', 'nowrap' => true],
      // 값(횟수·상태)보다 머리글 글자가 길어서 폭을 머리글에 맞춘다 — th 는 nowrap 이라
      //   좁으면 옆 열을 덮고, 맨 끝 열이 넘치면 표가 카드 밖으로 밀린다.
      ['label' => '로그인 실패', 'width' => '16%', 'align' => 'right'],
      ['label' => '잠금 상태',   'width' => '14%', 'nowrap' => true],
  ], $accessRows, [
      'empty' => [
          'icon'  => '👤',
          'title' => '등록된 사용자가 없습니다.',
      ],
      'cell' => [
          0 => static fn (array $u): string => '<strong><a href="/user.php?id=' . (int) $u['user_id'] . '">'
              . vg_h((string) $u['username']) . '</a></strong>',
          1 => static fn (array $u): string => '<span class="pill">' . vg_h(vg_role_label((string) $u['role'])) . '</span>',
          2 => static fn (array $u): string => !empty($u['last_login'])
              ? vg_h((string) $u['last_login'])
              : '<span class="why">—</span>',
          3 => static fn (array $u): string => vg_h((string) $u['failed_login_count']),
          4 => static function (array $u): string {
              $isLocked = $u['locked_until'] !== null && strtotime((string) $u['locked_until']) > time();
              return $isLocked
                  ? '<span class="badge tone-crit">🔒 잠김 — ' . vg_h((string) $u['locked_until']) . '까지</span>'
                  : '<span class="badge tone-ok">정상</span>';
          },
      ],
  ]);
  ?>
  <h2>접속기록</h2>
  <?php endif; ?>

  <?php vg_toolbar([
      ['type' => 'date',   'name' => 'from', 'value' => $fromDate, 'placeholder' => '시작일'],
      ['type' => 'date',   'name' => 'to',   'value' => $toDate,   'placeholder' => '종료일'],
      ['type' => 'select', 'name' => 'action', 'empty_label' => '전체 수행업무', 'selected' => $action,
          'options' => $actionLabels],
      ['type' => 'select', 'name' => 'scope', 'empty_label' => '전체 범위', 'selected' => $scope,
          'options' => array_combine($scopes, $scopes)],
      ['type' => 'search', 'name' => 'user', 'placeholder' => '사용자(식별자)', 'value' => $userName],
      ['type' => 'search', 'name' => 'ip',   'placeholder' => '접속지 IP(앞자리)', 'value' => $ipFilter],
      ['type' => 'search', 'name' => 'q', 'placeholder' => '메시지/대상/액션 검색', 'value' => $q],
  ]); ?>

  <?php
  // 구분(scope) 뱃지 톤 — 종류별로 색을 살짝 달리해 표에서 훑기 쉽게. 모르는 scope 는 muted.
  $scopeTone = static function (string $s): string {
      switch (strtoupper($s)) {
          case 'USER':        return 'info';
          case 'HOST':        return 'purple';
          case 'AGENT_TOKEN': return 'med';
          case 'API_TOKEN':   return 'ok';
          case 'CONNECTOR':   return 'high';
          case 'PERMISSION':  return 'info';
          default:            return 'muted';
      }
  };

  $hasFilter = $scope !== '' || $q !== '' || $action !== '' || $fromDate !== '' || $toDate !== ''
      || $userName !== '' || $ipFilter !== '';

  // 컬럼 순서는 접속기록 5요소를 그대로 따른다: 접속일시 · 식별자 · 접속지 IP · 처리 대상 · 수행업무.
  // 그 뒤에 기존의 구분/내용(세부 activity_type + data)을 보조로 붙인다.
  vg_table([
      ['label' => '접속일시',   'width' => '12%', 'nowrap' => true],
      ['label' => '식별자',     'width' => '10%', 'nowrap' => true],
      ['label' => '접속지 IP', 'width' => '11%', 'nowrap' => true],
      ['label' => '처리 대상',  'width' => '15%'],
      ['label' => '수행업무',   'width' => '9%', 'nowrap' => true],
      ['label' => '구분',       'width' => '9%', 'nowrap' => true],
      ['label' => '내용'],
  ], $rows, [
      'empty' => [
          'icon'  => '📋',
          'title' => '기록된 활동이 없습니다.',
          'hint'  => $hasFilter ? '이 조건에는 기록이 없습니다. 필터를 바꿔 보세요.' : '사용자·시스템 행위가 생기면 여기에 쌓입니다.',
      ],
      'cell' => [
          // 접속일시 — 날짜+시각(초까지). 다른 표처럼 매 행에 그대로 둔다.
          0 => static fn (array $r): string => vg_h(str_replace('T', ' ', substr((string) $r['created_at'], 0, 19))),
          // 식별자 — 이름이 있으면 이름, 없으면 actor_type 을 한글로(SYSTEM=시스템, 그 외=사용자).
          1 => static function (array $r): string {
              $who = !empty($r['user_name'])
                  ? (string) $r['user_name']
                  : (((string) ($r['actor_type'] ?? '')) === 'SYSTEM' ? '시스템' : '사용자');
              return vg_h($who);
          },
          // 접속지 IP — 시스템 내부 이벤트 등 NULL 인 경우 플레이스홀더.
          2 => static function (array $r): string {
              $ip = trim((string) ($r['ip_address'] ?? ''));
              return $ip !== '' ? vg_h($ip) : '<span class="why">—</span>';
          },
          // 처리 대상 — 이 제품은 개인정보를 처리하지 않아 "정보주체" 자리에 대상 자원을 담는다
          //   (호스트 FQDN·CVE·패키지·계정 등). 옛 기록에는 값이 없어 플레이스홀더가 나온다.
          3 => static function (array $r): string {
              $subject = trim((string) ($r['subject'] ?? ''));
              return $subject !== '' ? vg_h($subject) : '<span class="why">—</span>';
          },
          // 수행업무 — 정규화 동사(READ/UPDATE/…)를 한글 라벨로.
          4 => static function (array $r) use ($actionLabels): string {
              $code = (string) ($r['action'] ?? '');
              if ($code === '') { return '<span class="why">—</span>'; }
              return '<span class="pill">' . vg_h($actionLabels[$code] ?? $code) . '</span>';
          },
          // 구분 — scope(+대상 id) 를 톤 뱃지로.
          5 => static function (array $r) use ($scopeTone): string {
              $label = (string) $r['scope'] . ($r['scope_id'] !== null ? ' #' . (int) $r['scope_id'] : '');
              return '<span class="badge tone-' . $scopeTone((string) $r['scope']) . '">' . vg_h($label) . '</span>';
          },
          // 내용 — 세부 액션(activity_type) + 메시지 + (있으면) data(JSON) 를 셀 안 <details> 로 접어 둔다.
          6 => static function (array $r) use ($activityLabels): string {
              $code  = (string) $r['activity_type'];
              $label = $activityLabels[$code] ?? $code;
              $msg   = trim((string) ($r['message'] ?? ''));
              // 원본 코드(activity_type)는 라벨 밑에 한 줄로 또 적지 않는다 — 라벨이 그 코드의
              //   번역이라 행마다 같은 사실이 두 번 서 있었고, 라벨이 없는 코드는 아예 같은
              //   문자열이 두 줄이 됐다. 근거는 지우지 않고 title 로 내린다.
              $out   = '<strong title="' . vg_h($code) . '">' . vg_h($label) . '</strong>';
              if ($msg !== '') { $out .= ' ' . vg_h($msg); }
              if (!empty($r['data'])) {
                  $decoded = json_decode((string) $r['data'], true);
                  $pretty  = $decoded !== null
                      ? json_encode($decoded, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)
                      : (string) $r['data'];
                  $out .= '<details><summary>상세 데이터</summary><pre class="out">' . vg_h((string) $pretty) . '</pre></details>';
              }
              return $out;
          },
      ],
  ]);
  ?>
  <?php vg_page_nav($total, $perPage, $page); ?>
<?php endif; ?>
<?php vg_footer();
