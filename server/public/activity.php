<?php
declare(strict_types=1);

/**
 * activity.php — 감사로그 뷰 (admin 전용).
 *   tb_activity_log 를 최신순으로 목록. scope 필터 + 페이지네이션(50개씩).
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
vg_require_login();
vg_require_admin();

const VG_PER_PAGE = 50;

$err = null; $rows = []; $total = 0; $scopes = [];
$scope = trim((string) ($_GET['scope'] ?? ''));
$page = max(1, (int) ($_GET['page'] ?? 1));

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

    $perPage = VG_PER_PAGE;
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
  <div class="err"><strong>오류</strong> · <?= vg_h($err) ?></div>
<?php else: ?>
  <?php vg_toolbar([
      ['type' => 'select', 'name' => 'scope', 'empty_label' => '전체 범위', 'selected' => $scope,
          'options' => array_combine($scopes, $scopes)],
  ]); ?>

  <?php
  vg_table(
      [
          ['label' => '시각'],
          ['label' => '범위'],
          ['label' => '행위'],
          ['label' => '주체'],
          ['label' => '사용자'],
          ['label' => '메시지'],
      ],
      $rows,
      [
          'empty' => '기록된 활동이 없습니다.',
          'cell' => [
              0 => fn($r) => '<span class="why">' . vg_h($r['created_at']) . '</span>',
              1 => fn($r) => '<span class="pill">' . vg_h($r['scope']) . '</span>' . ($r['scope_id'] !== null ? ' <span class="why">#' . (int) $r['scope_id'] . '</span>' : ''),
              2 => fn($r) => vg_h($r['activity_type']),
              3 => fn($r) => '<span class="why">' . vg_h($r['actor_type']) . '</span>',
              4 => fn($r) => vg_h($r['user_name'] ?? '–'),
              5 => function ($r) {
                  $html = $r['message'] ? vg_trunc((string) $r['message']) : '<span class="why">–</span>';
                  if (!empty($r['data'])) {
                      $html .= ' <span class="why trunc" style="max-width:280px;" title="' . vg_h((string) $r['data']) . '">[data]</span>';
                  }
                  return $html;
              },
          ],
      ]
  );
  if ($rows) { vg_page_nav($total, VG_PER_PAGE, $page); }
  ?>
<?php endif; ?>
<?php vg_footer();
