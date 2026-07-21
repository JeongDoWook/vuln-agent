<?php
declare(strict_types=1);

/**
 * stats.php — 사용 통계 (admin 전용).
 *   activity.php(원장 나열)와 달리 tb_activity_log 를 집계해 보여준다: 오늘/최근 KPI,
 *   일자별 로그인 건수, 기능별 사용 건수. 사전집계 테이블 없이 온디맨드 GROUP BY로 처리
 *   (현재 규모에서 충분 — CLAUDE.md YAGNI).
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
vg_require_menu('stats');

// 기간 선택 화이트리스트 — 임의의 days 값으로 무거운 쿼리를 유발하지 못하게 막는다.
const VG_STATS_DAYS_OPTIONS = [7, 30, 90];
const VG_STATS_DAYS_DEFAULT = 30;
// 기능별 사용 건수 상위 몇 개까지 보여줄지 — 화면은 순위 목록이라 나머지는 의미가 옅다(총건수 표시 불요).
const VG_STATS_TYPE_TOP = 20;

$err = null;
$todayLogins = 0; $activeUsers24h = 0; $totalUsers = 0;
$loginTrend = []; $typeUsage = [];

$days = (int) ($_GET['days'] ?? VG_STATS_DAYS_DEFAULT);
if (!in_array($days, VG_STATS_DAYS_OPTIONS, true)) { $days = VG_STATS_DAYS_DEFAULT; }

try {
    $pdo = vg_pdo();

    $todayLogins = (int) $pdo->query(
        "SELECT COUNT(*) FROM tb_activity_log
          WHERE activity_type = 'login' AND is_deleted = 0 AND created_at >= CURDATE()"
    )->fetchColumn();

    $activeUsers24h = (int) $pdo->query(
        "SELECT COUNT(DISTINCT user_id) FROM tb_activity_log
          WHERE is_deleted = 0 AND user_id IS NOT NULL AND created_at >= NOW() - INTERVAL 24 HOUR"
    )->fetchColumn();

    $totalUsers = (int) $pdo->query('SELECT COUNT(*) FROM tb_users WHERE is_deleted = 0')->fetchColumn();

    $stmt = $pdo->prepare(
        "SELECT DATE(created_at) d, COUNT(*) c FROM tb_activity_log
          WHERE activity_type = 'login' AND is_deleted = 0
            AND created_at >= NOW() - INTERVAL ? DAY
          GROUP BY DATE(created_at) ORDER BY d DESC"
    );
    $stmt->execute([$days]);
    $loginTrend = $stmt->fetchAll();

    $stmt = $pdo->prepare(
        "SELECT activity_type, COUNT(*) c FROM tb_activity_log
          WHERE is_deleted = 0 AND created_at >= NOW() - INTERVAL ? DAY
          GROUP BY activity_type ORDER BY c DESC LIMIT " . VG_STATS_TYPE_TOP
    );
    $stmt->execute([$days]);
    $typeUsage = $stmt->fetchAll();
} catch (Throwable $e) {
    $err = $e->getMessage();
}

$activityLabels = vg_activity_type_labels();

vg_header('사용 통계', 'stats');
?>
  <h1>사용 통계</h1>
  <div class="sub">admin 전용 · 접속·기능 사용 현황 집계</div>

<?php if ($err !== null): ?>
  <?php vg_alert('오류 · ' . $err); ?>
<?php else: ?>
  <div class="cards">
    <div class="kpi kpi--static">
      <b><?= number_format($todayLogins) ?></b><span>오늘 로그인</span>
    </div>
    <div class="kpi kpi--static">
      <b><?= number_format($activeUsers24h) ?></b><span>최근 24시간 활성 사용자</span>
    </div>
    <div class="kpi kpi--static">
      <b><?= number_format($totalUsers) ?></b><span>전체 사용자</span>
    </div>
  </div>

  <?php vg_toolbar([
      ['type' => 'select', 'name' => 'days', 'empty_label' => '기간 선택', 'selected' => (string) $days,
          'options' => array_combine(
              array_map('strval', VG_STATS_DAYS_OPTIONS),
              array_map(fn($d) => $d . '일', VG_STATS_DAYS_OPTIONS)
          )],
  ]); ?>

  <div class="split split--even">
    <div class="card">
      <strong>일자별 로그인 건수</strong>
      <span class="why">— 최근 <?= $days ?>일 · 로그인이 있었던 날짜만 표시(0건인 날짜는 생략)</span>
      <div class="card__body">
        <?php vg_hbar_list(
            array_map(fn($r) => ['label' => (string) $r['d'], 'n' => (int) $r['c']], $loginTrend),
            'label', 'n',
            ['icon' => '📈', 'title' => '이 기간에 로그인 기록이 없습니다.']
        ); ?>
      </div>
    </div>

    <div class="card">
      <strong>기능별 사용 건수</strong>
      <span class="why">— 최근 <?= $days ?>일 · 상위 <?= VG_STATS_TYPE_TOP ?>개</span>
      <div class="card__body">
        <?php vg_hbar_list(
            array_map(fn($r) => [
                'label' => $activityLabels[$r['activity_type']] ?? (string) $r['activity_type'],
                'n' => (int) $r['c'],
            ], $typeUsage),
            'label', 'n',
            ['icon' => '📊', 'title' => '이 기간에 기록된 활동이 없습니다.']
        ); ?>
      </div>
    </div>
  </div>
<?php endif; ?>
<?php vg_footer();
