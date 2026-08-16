<?php
declare(strict_types=1);

/**
 * connectors.php — CVE 피드 커넥터 관리 (admin 전용).
 *   목록/추가/편집/삭제, 즉시 실행(수동), 최근 수집 이력.
 *   활성 여부는 편집 폼의 '활성' 체크박스 하나로만 바꾼다.
 *
 *   속은 책임별로 src/connectors/ 에 나눠 두었다 — 이 파일은 **화면 뼈대와 실행 순서**만 갖는다.
 *   특히 POST 처리는 여기 그대로 둔다: action='run' 은 vg_connector_handle_post() 안에서
 *   session_write_close() 를 호출해 세션 락을 놓는다(#144). 그 호출 시점이 밀리면 커넥터를
 *   한 번 실행하는 동안 같은 사용자의 다른 탭이 통째로 막힌다 — 순서가 곧 동작이다.
 */

require_once __DIR__ . '/../src/auth.php';
require_once __DIR__ . '/../src/view.php';
require_once __DIR__ . '/../src/feeds.php';
require_once __DIR__ . '/../src/matcher.php';
require_once __DIR__ . '/../src/audit.php';   // vg_soft_delete / vg_log_activity
require_once __DIR__ . '/../src/connector_actions.php';   // POST 액션(save/run/delete) 처리
require_once __DIR__ . '/../src/connectors/vocab.php';      // 상태·계기·역할 어휘와 상태 뱃지
require_once __DIR__ . '/../src/connectors/queries.php';    // 목록·이력·편집 대상 조회
require_once __DIR__ . '/../src/connectors/list_view.php';  // 역할 그룹 카드 + 소스 표
require_once __DIR__ . '/../src/connectors/form.php';       // 추가·편집 모달
require_once __DIR__ . '/../src/connectors/history.php';    // ?conn=N 수집 이력 상세
vg_require_menu('connectors');   // 피드 커넥터: 설정형 권한

$pdo = vg_pdo();
$msg = null; $err = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!vg_csrf_check($_POST['csrf'] ?? null)) {
        $err = '세션이 만료되었습니다.';
    } else {
        // 주의: action='run' 이면 이 호출 안에서 session_write_close() 가 일어난다 →
        //   이 아래에서 세션에 '쓰는' 코드를 추가하면 조용히 유실된다.
        $r = vg_connector_handle_post($pdo, $_POST);
        $msg = $r['msg'];
        $err = $r['err'];
    }
}

$connectors = vg_connectors_all($pdo);

/* 수집 이력. 목록의 [상세]에서 ?conn=N 으로 들어오면 해당 커넥터 정보와 전체 이력을
 * 한곳에 보여준다. 최근 이력 모달과 전체 이력 화면이 같은 내용을 중복하던 경로는 합쳤다. */
$perPage  = vg_perpage();
$page     = vg_page();
$connFilter = (int) ($_GET['conn'] ?? 0);

$logCountByConn = vg_connectors_log_counts($pdo);

$logData = [];
vg_connectors_load_logs($pdo, $connectors, $connFilter, $logCountByConn, $page, $perPage, $logData);
['logs' => $logs, 'logTotal' => $logTotal, 'connName' => $connName, 'connDetail' => $connDetail] = $logData;

$csrf = vg_csrf_token();

// 쿼리스트링은 라우트가 읽는다 — 이 URL 이 무엇을 받는지는 이 파일에 남아 있어야 한다.
$edit = vg_connectors_edit_target($connectors, isset($_GET['edit']) ? (int) $_GET['edit'] : null, $_POST, $err);
$econn = $edit ? vg_json_col($edit['connection_json']) : [];
$esched = $edit ? vg_json_col($edit['schedule_json']) : [];

vg_header('데이터 수집', 'connectors');
?>
  <?php // 소스 종수는 도식이 갖고 있던 값이다 — 제목의 건수 슬롯으로 옮긴다. ?>
  <?php vg_page_title('데이터 수집', 'DATA SOURCES', '외부 취약점 데이터와 수집 상태를 관리합니다.', [
      'count' => count($connectors), 'count_label' => '종',
      'actions' => vg_capture(static fn() => vg_modal_btn('connModal', '+ 데이터 소스 추가')),
  ]); ?>

  <?php vg_alert($msg, 'ok'); vg_alert($err); ?>

  <?php
  // 스케줄 라벨·다음 실행을 얹는다 — 상세 카드($connDetail)도 같은 행을 그대로 쓴다.
  $connectors = vg_connectors_decorate($connectors, $connFilter, $connDetail);
  vg_connectors_render_list($connectors, $csrf, $logCountByConn);
  ?>

  <?php vg_connectors_render_form($edit, $econn, $esched, $csrf); ?>

  <?php
  // API 미리보기 동작(vgPreview)은 assets/app.js 가 소유한다(전역 노출). PHP 안에 인라인 JS 를 두지 않는다.
  ?>

  <?php vg_connectors_render_history($connFilter, $connName, $connDetail, $logs, $logTotal, $perPage, $page); ?>

<?php vg_footer();
