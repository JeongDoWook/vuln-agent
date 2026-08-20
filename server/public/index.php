<?php
declare(strict_types=1);

/**
 * index.php — 대시보드 (로그인 필요).
 *   호스트별 최신 스캔 + 심각도 요약. 각 행에서 취약점 상세로.
 *
 *   이 파일은 요청 처리(페이지네이션)·조회 호출 순서·섹션 배치만 갖는다.
 *   조회는 src/dashboard/queries.php, 섹션 렌더는 src/dashboard/sections/<섹션>.php 다.
 *   ⚠ 대시보드 SQL 은 이 저장소에서 성능 회귀가 난 자리라(파생테이블 리라이트 235ms→42초 등)
 *     쿼리를 옮기기만 했고 형태는 그대로다 — 조회층 머리주석이 그 이력을 갖고 있다.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require_once __DIR__ . '/../src/finding_sla.php';   // 조치 기한 — 목록 화면과 같은 계산을 그대로 쓴다
require_once __DIR__ . '/../src/dashboard/queries.php';    // vg_dash_* 조회 + VG_TREND_DAYS
require_once __DIR__ . '/../src/dashboard/sections.php';   // vg_dash_render_* 섹션 렌더
vg_require_menu('dashboard');

$err = null; $rows = []; $totals = ['CRITICAL'=>0,'HIGH'=>0,'MEDIUM'=>0,'LOW'=>0];
$hostCount = 0; $total = 0; $sevByScan = [];
$kevCount = 0; $kevOverdue = 0; $runtime = [];
$kevSlaDays = 0;   // KEV 조치 기한(일) — 퍼널 4번 칸 라벨이 이 숫자를 그대로 말한다
$trend = [];
$page = vg_page();
$perPage = vg_perpage();
try {
    $pdo = vg_pdo();
    $hostCount = vg_dash_host_count($pdo);

    ['totals' => $totals, 'kev' => $kevCount, 'runtime' => $runtime] = vg_dash_severity_totals($pdo);
    ['overdue' => $kevOverdue, 'slaDays' => $kevSlaDays] = vg_dash_kev_overdue($pdo);

    $trend = vg_dash_trend($pdo, VG_TREND_DAYS);

    $total  = vg_dash_host_total($pdo);
    $offset = ($page - 1) * $perPage;
    ['rows' => $rows, 'sevByScan' => $sevByScan] = vg_dash_host_rows($pdo, $perPage, $offset);
} catch (Throwable $e) {
    error_log('[index] ' . $e->getMessage());
    $err = '처리 중 오류가 발생했습니다.';
}

vg_header('대시보드', 'dashboard');
?>
  <?php vg_page_title('대시보드', 'OVERVIEW'); ?>

<?php if ($err !== null): ?>
  <?php vg_alert('DB 오류 · ' . $err); ?>
<?php else: ?>
  <?php /* 순서가 곧 위계다 — "지금 무엇부터 손대야 하나" 에 답하는 것(퍼널 · 주요 신호)이 위,
           배경(추세)과 전수 목록(호스트)이 아래다. */ ?>
  <?php vg_dash_render_funnel($totals, $hostCount, $kevCount, $kevOverdue, $kevSlaDays); ?>

  <?php vg_dash_render_signals($totals, $runtime, $kevCount, $kevOverdue, $kevSlaDays); ?>

  <?php vg_dash_render_trend($trend, VG_TREND_DAYS); ?>

  <?php vg_dash_render_hosts($rows, $sevByScan, $total, $perPage, $page); ?>
<?php endif; ?>
<?php vg_footer();
