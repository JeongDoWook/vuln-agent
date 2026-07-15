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
$page = max(1, (int) ($_GET['page'] ?? 1));
$perPage = vg_perpage();

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

    $stmt = $pdo->prepare("SELECT COUNT(*) FROM tb_activity_log WHERE $where");
    $stmt->execute($params);
    $total = (int) $stmt->fetchColumn();

    $offset = ($page - 1) * $perPage;

    $stmt = $pdo->prepare(
        "SELECT created_at, scope, scope_id, activity_type, actor_type, user_name, message, data
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
          default:            return 'muted';
      }
  };

  vg_table([
      ['label' => '시각',   'width' => '170px', 'nowrap' => true],
      ['label' => '구분',   'width' => '150px', 'nowrap' => true],
      ['label' => '액션',   'width' => '180px', 'nowrap' => true],
      ['label' => '내용'],
      ['label' => '사용자', 'width' => '130px', 'nowrap' => true],
  ], $rows, [
      'empty' => [
          'icon'  => '📋',
          'title' => '기록된 활동이 없습니다.',
          'hint'  => $scope !== '' ? '이 범위에는 기록이 없습니다. 필터를 바꿔 보세요.' : '사용자·시스템 행위가 생기면 여기에 쌓입니다.',
      ],
      'cell' => [
          // 시각 — 날짜+시각(초까지). 다른 표처럼 매 행에 그대로 둔다.
          0 => static fn (array $r): string => vg_h(str_replace('T', ' ', substr((string) $r['created_at'], 0, 19))),
          // 구분 — scope(+대상 id) 를 톤 뱃지로.
          1 => static function (array $r) use ($scopeTone): string {
              $label = (string) $r['scope'] . ($r['scope_id'] !== null ? ' #' . (int) $r['scope_id'] : '');
              return '<span class="badge tone-' . $scopeTone((string) $r['scope']) . '">' . vg_h($label) . '</span>';
          },
          // 액션 — activity_type 코드.
          2 => static fn (array $r): string => '<code>' . vg_h((string) $r['activity_type']) . '</code>',
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
      ],
  ]);
  ?>
  <?php vg_page_nav($total, $perPage, $page); ?>
<?php endif; ?>
<?php vg_footer();
