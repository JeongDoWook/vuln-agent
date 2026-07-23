<?php
declare(strict_types=1);

/**
 * activity.php — 감사로그 뷰 (admin 전용).
 *   tb_activity_log 를 최신순으로 목록. scope 필터 + 페이지네이션.
 *   다른 목록 페이지와 같은 공용 표 모듈(vg_table)로 렌더한다(형식 통일).
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
vg_require_menu('activity');

$err = null; $rows = []; $total = 0; $scopes = []; $accessRows = [];
$scope = trim((string) ($_GET['scope'] ?? ''));
$q = trim((string) ($_GET['q'] ?? ''));
$page = vg_page();
$perPage = vg_perpage();

// 액션(activity_type) 코드 → 한글 라벨(SSOT: vg_activity_type_labels(), user.php 와 공유).
$activityLabels = vg_activity_type_labels();

try {
    $pdo = vg_pdo();

    // 사용자별 접속 현황 — tb_users 의 로그인 보안 컬럼(login_security 마이그레이션)을 그대로 노출.
    // session_token 은 만료 로직이 없어 "현재 접속중"으로 오인될 수 있어 화면에 안 보여준다(last_login 시각만).
    // vg_can('activity') 는 tb_role_permissions 로 operator/user 에게도 위임될 수 있어(vg_require_menu 는
    // "activity 메뉴 접근"만 보장) failed_login_count/locked_until(브루트포스 잠금 정보)은 그 게이트만으론
    // admin 전용이 아니다 — 여기서 vg_has_role('admin') 을 추가로 확인해 진짜 admin 에게만 조회/렌더한다.
    if (vg_has_role('admin')) {
        $accessRows = $pdo->query(
            "SELECT username, role, last_login, failed_login_count, locked_until
               FROM tb_users
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
    if ($q !== '') {
        $where .= ' AND (message LIKE ? OR user_name LIKE ? OR activity_type LIKE ?)';
        $params[] = '%' . $q . '%';
        $params[] = '%' . $q . '%';
        $params[] = '%' . $q . '%';
    }

    $stmt = $pdo->prepare("SELECT COUNT(*) FROM tb_activity_log WHERE $where");
    $stmt->execute($params);
    $total = (int) $stmt->fetchColumn();

    $offset = ($page - 1) * $perPage;

    $stmt = $pdo->prepare(
        "SELECT created_at, scope, scope_id, activity_type, actor_type, user_name, message, data, ip_address
         FROM tb_activity_log
         WHERE $where
         ORDER BY id DESC
         LIMIT $perPage OFFSET $offset"
    );
    $stmt->execute($params);
    $rows = $stmt->fetchAll();
} catch (Throwable $e) {
    error_log('[activity] ' . $e->getMessage());
    $err = '처리 중 오류가 발생했습니다.';
}

vg_header('감사로그', 'activity');
?>
  <?php vg_page_title('감사로그', 'AUDIT', '사용자와 시스템의 주요 행위를 최신순으로 추적합니다.'); ?>

<?php if ($err !== null): ?>
  <?php vg_alert('오류 · ' . $err); ?>
<?php else: ?>
  <?php if (vg_has_role('admin')): ?>
  <h2>사용자별 접속 현황</h2>
  <?php
  vg_table([
      ['label' => '아이디'],
      ['label' => '역할',        'width' => '90px'],
      ['label' => '최근 로그인', 'nowrap' => true],
      ['label' => '로그인 실패', 'width' => '90px', 'align' => 'right'],
      ['label' => '잠금 상태',   'width' => '140px', 'nowrap' => true],
  ], $accessRows, [
      'empty' => [
          'icon'  => '👤',
          'title' => '등록된 사용자가 없습니다.',
      ],
      'cell' => [
          0 => static fn (array $u): string => '<strong>' . vg_h((string) $u['username']) . '</strong>',
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
  <?php endif; ?>

  <?php vg_toolbar([
      ['type' => 'search', 'name' => 'q', 'placeholder' => '메시지/사용자/액션 검색', 'value' => $q],
      ['type' => 'select', 'name' => 'scope', 'empty_label' => '전체 범위', 'selected' => $scope,
          'options' => array_combine($scopes, $scopes)],
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

  vg_table([
      ['label' => '시각',     'width' => '140px', 'nowrap' => true],
      ['label' => '구분',     'width' => '120px', 'nowrap' => true],
      ['label' => '액션',     'width' => '150px', 'nowrap' => true],
      ['label' => '내용'],
      ['label' => '사용자',   'width' => '110px', 'nowrap' => true],
      ['label' => '출처 IP', 'width' => '110px', 'nowrap' => true],
  ], $rows, [
      'empty' => [
          'icon'  => '📋',
          'title' => '기록된 활동이 없습니다.',
          'hint'  => ($scope !== '' || $q !== '') ? '이 조건에는 기록이 없습니다. 필터를 바꿔 보세요.' : '사용자·시스템 행위가 생기면 여기에 쌓입니다.',
      ],
      'cell' => [
          // 시각 — 날짜+시각(초까지). 다른 표처럼 매 행에 그대로 둔다.
          0 => static fn (array $r): string => vg_h(str_replace('T', ' ', substr((string) $r['created_at'], 0, 19))),
          // 구분 — scope(+대상 id) 를 톤 뱃지로.
          1 => static function (array $r) use ($scopeTone): string {
              $label = (string) $r['scope'] . ($r['scope_id'] !== null ? ' #' . (int) $r['scope_id'] : '');
              return '<span class="badge tone-' . $scopeTone((string) $r['scope']) . '">' . vg_h($label) . '</span>';
          },
          // 액션 — 한글 라벨 표시, 원본 코드는 툴팁(title)과 작은 회색 글씨로 보조.
          2 => static function (array $r) use ($activityLabels): string {
              $code = (string) $r['activity_type'];
              $label = $activityLabels[$code] ?? $code;
              return vg_h($label) . '<div class="why" title="' . vg_h($code) . '">' . vg_h($code) . '</div>';
          },
          // 내용 — 메시지 + (있으면) data(JSON) 를 셀 안 <details> 로 접어 둔다.
          3 => static function (array $r): string {
              $msg = trim((string) ($r['message'] ?? ''));
              $out = $msg !== '' ? vg_h($msg) : '<span class="why">—</span>';
              if (!empty($r['data'])) {
                  $decoded = json_decode((string) $r['data'], true);
                  $pretty  = $decoded !== null
                      ? json_encode($decoded, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)
                      : (string) $r['data'];
                  $out .= '<details><summary>상세 데이터</summary><pre class="out">' . vg_h((string) $pretty) . '</pre></details>';
              }
              return $out;
          },
          // 사용자 — 이름이 있으면 이름, 없으면 actor_type 을 한글로(SYSTEM=시스템, 그 외=사용자).
          4 => static function (array $r): string {
              $who = !empty($r['user_name'])
                  ? (string) $r['user_name']
                  : (((string) ($r['actor_type'] ?? '')) === 'SYSTEM' ? '시스템' : '사용자');
              return vg_h($who);
          },
          // 출처 IP — 시스템 내부 이벤트 등 NULL 인 경우 플레이스홀더.
          5 => static function (array $r): string {
              $ip = trim((string) ($r['ip_address'] ?? ''));
              return $ip !== '' ? vg_h($ip) : '<span class="why">—</span>';
          },
      ],
  ]);
  ?>
  <?php vg_page_nav($total, $perPage, $page); ?>
<?php endif; ?>
<?php vg_footer();
