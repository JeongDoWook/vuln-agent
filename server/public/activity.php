<?php
declare(strict_types=1);

/**
 * activity.php — 감사로그 뷰 (admin 전용).
 *   tb_activity_log 를 최신순으로 목록. scope 필터 + 페이지네이션(50개씩).
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

  <?php if (!$rows): ?>
    <div class="card">
      <?php vg_empty([
          'icon'  => '📋',
          'title' => '기록된 활동이 없습니다.',
          'hint'  => $scope !== '' ? '이 범위에는 기록이 없습니다. 필터를 바꿔 보세요.' : '사용자·시스템 행위가 생기면 여기에 쌓입니다.',
      ]); ?>
    </div>
  <?php else: ?>
    <div class="card">
      <ul class="tl">
        <?php
        // 날짜가 바뀔 때만 헤더를 끼운다 — 표의 '시각' 컬럼에서 날짜가 매 행 반복되던 걸 없앤다.
        $curDay = null;
        foreach ($rows as $r):
            $ts  = (string) $r['created_at'];
            $day = substr($ts, 0, 10);
            if ($day !== $curDay) {
                $curDay = $day;
                echo '<li class="tl__day">' . vg_h($day) . '</li>';
            }

            // data 는 JSON 문자열. 예쁘게 펴서 보여준다(못 펴면 원문 그대로).
            $pretty = null;
            if (!empty($r['data'])) {
                $decoded = json_decode((string) $r['data'], true);
                $pretty  = $decoded !== null
                    ? json_encode($decoded, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)
                    : (string) $r['data'];
            }
        ?>
          <li class="tl__item">
            <div class="tl__time"><?= vg_h(substr($ts, 11, 5)) ?></div>
            <div class="tl__body">
              <div class="tl__head">
                <span class="pill"><?= vg_h((string) $r['scope']) ?><?php
                    if ($r['scope_id'] !== null) { echo ' #' . (int) $r['scope_id']; }
                ?></span>
                <strong><?= vg_h((string) $r['activity_type']) ?></strong>
                <?php
                /* 주체 표시. 이름이 있으면 이름만 — actor_type 을 괄호로 덧붙이면 중복이다.
                 * 이름이 없으면 actor_type 을 한글로 푼다. 이름 없다고 무턱대고 "시스템" 이라
                 * 쓰면 actor_type=USER 인 행이 "시스템 (USER)" 로 나와 모순된다
                 * (사용자가 눌렀는데 이름이 기록 안 된 경우다). */
                $who = !empty($r['user_name'])
                    ? (string) $r['user_name']
                    : (((string) ($r['actor_type'] ?? '')) === 'SYSTEM' ? '시스템' : '사용자');
                ?>
                <span class="tl__who"><?= vg_h($who) ?></span>
              </div>

              <?php if (!empty($r['message'])): ?>
                <div class="tl__msg"><?= vg_h((string) $r['message']) ?></div>
              <?php endif; ?>

              <?php if ($pretty !== null): ?>
                <details>
                  <summary>상세 데이터</summary>
                  <pre class="out"><?= vg_h($pretty) ?></pre>
                </details>
              <?php endif; ?>
            </div>
          </li>
        <?php endforeach; ?>
      </ul>
    </div>
    <?php vg_page_nav($total, $perPage, $page); ?>
  <?php endif; ?>
<?php endif; ?>
<?php vg_footer();
