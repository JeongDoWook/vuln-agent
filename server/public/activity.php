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

$err = null; $rows = []; $total = 0; $scopes = [];
$scope = trim((string) ($_GET['scope'] ?? ''));
$q = trim((string) ($_GET['q'] ?? ''));
$page = max(1, (int) ($_GET['page'] ?? 1));
$perPage = vg_perpage();

// 액션(activity_type) 코드 → 한글 라벨. 실제 존재하는 값만(vg_log_activity 호출부 기준) — 새 값은
// 코드에 없으면 원본 그대로 fallback 하니 여기 없다고 화면이 깨지진 않는다.
$activityLabels = [
    'login'                => '로그인',
    'password_change'      => '비밀번호 변경',
    'agent_token_issue'    => '에이전트 토큰 발급',
    'agent_token_revoke'   => '에이전트 토큰 폐기',
    'agent_token_delete'   => '에이전트 토큰 삭제',
    'token_issue'          => 'API 토큰 발급',
    'token_revoke'         => 'API 토큰 폐기',
    'host_delete'          => '호스트 삭제',
    'connector_save'       => '커넥터 저장',
    'connector_toggle'     => '커넥터 사용여부 전환',
    'connector_delete'     => '커넥터 삭제',
    'ingest'               => '수집 반영',
    'ingest_spoof_blocked' => '수집 위조 차단',
    'ingest_shared_token'  => '공유 토큰 수집',
    'permission_update'    => '권한 변경',
    'user_add'             => '사용자 추가',
    'user_role'            => '사용자 권한 변경',
    'user_pw_reset'        => '사용자 비밀번호 재설정',
    'user_delete'          => '사용자 삭제',
    'feed_run'             => '피드 실행',
];

try {
    $pdo = vg_pdo();

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
    $err = $e->getMessage();
}

vg_header('감사로그', 'activity');
?>
  <h1>감사로그</h1>
  <div class="sub">admin 전용 · 사용자/시스템 행위 기록(최신순)</div>

<?php if ($err !== null): ?>
  <?php vg_alert('오류 · ' . $err); ?>
<?php else: ?>
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
