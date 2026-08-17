<?php
declare(strict_types=1);

/**
 * assets.php — 자산(호스트) 관리. 로그인 + assets 메뉴 권한 필요.
 *   목록: 에이전트가 등록한 호스트 + 최신 수집 상태(정상/지연/오프라인/수집없음).
 *   삭제: admin·operator 만. 소프트삭제(is_deleted=1) 라 대시보드·취약점 집계에서 빠진다.
 *   스캔 이력은 호스트 상세(host.php)의 "스캔 이력" 카드에서 본다.
 *
 *   속은 책임별로 src/assets/ 에 나눠 두었다 — 이 파일은 **화면 뼈대**(필터 파싱·실행 순서·
 *   KPI·툴바·모달 배치)만 갖는다. SQL 은 queries.php, 표는 table.php, 모달 본문은 modal_*.php.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require_once __DIR__ . '/../src/assetgrade.php';   // 등급 어휘·뱃지·최고등급 승계
require_once __DIR__ . '/../src/assets/confirm_post.php';   // 등급 일괄 확정 POST 처리
require_once __DIR__ . '/../src/assets/queries.php';        // 목록·KPI·부서옵션 조회
require_once __DIR__ . '/../src/assets/table.php';          // 목록 표(머리글·범례·셀)
require_once __DIR__ . '/../src/assets/modal_grade.php';    // 일괄 확정 입력창
require_once __DIR__ . '/../src/assets/modal_install.php';  // 에이전트 설치 안내
vg_require_menu('assets');

// 연결 상태 판정 기준과 vg_asset_state() 는 format.php 에 있다(호스트 상세와 공유).

$err = null; $msg = null;
$q     = trim((string) ($_GET['q'] ?? ''));
$state = trim((string) ($_GET['state'] ?? ''));
// 등급 필터. 허용값은 VG_ASSET_GRADES(단일 출처) + 'none'(아직 확정 안 된 자산 찾기).
$grade = trim((string) ($_GET['grade'] ?? ''));
if ($grade !== 'none' && !isset(VG_ASSET_GRADES[$grade])) { $grade = ''; }
/* 담당 부서 필터. 어휘를 코드에 박지 않는다 — 부서명은 기관마다 다르고 등급 검토 폼이
 *   자유 입력으로 받는 값이라, 옵션은 **DB 에 실제로 들어 있는 값**에서만 뽑는다. */
$dept = trim((string) ($_GET['dept'] ?? ''));
$page  = vg_page();
$perPage = vg_perpage();

// 연결 상태 어휘. 최신 수집 시각은 별도 열에서 보여준다.
const VG_ASSET_STATES = ['ok' => '정상', 'stale' => '지연', 'offline' => '오프라인', 'none' => '수집없음'];
if (!isset(VG_ASSET_STATES[$state])) { $state = ''; }

$pdo = vg_pdo();

/* 등급 일괄 확정 POST — **GET 렌더보다 먼저·헤더 출력 전**이어야 한다. 성공·실패 모두
 *   vg_redirect_flash() 로 끝나므로(PRG), 이 호출이 뒤로 밀리면 헤더가 이미 나간 뒤가 된다. */
vg_assets_handle_post($pdo);

$assetFlash = vg_flash_take();
$msg = $assetFlash['assetMsg'] ?? null;
$err = $assetFlash['assetErr'] ?? null;

$assetData = [];
try {
    vg_assets_load($pdo, $q, $state, $grade, $dept, $page, $perPage, $assetData);
} catch (Throwable $e) {
    error_log('[assets] ' . $e->getMessage());
    $err = '처리 중 오류가 발생했습니다.';
}
// 조회가 중간에 실패해도 그때까지 읽은 값이 그대로 온다(queries.php 머리주석).
['deptOptions' => $deptOptions, 'stateCounts' => $stateCounts, 'rows' => $rows, 'total' => $total,
 'sevByScan' => $sevByScan, 'systemGrade' => $systemGrade, 'unconfirmed' => $unconfirmed] = $assetData;

// 에이전트가 POST 할 수집 엔드포인트(현재 접속 주소 기준).
$https  = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
       || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
$ingest = ($https ? 'https' : 'http') . '://' . ($_SERVER['HTTP_HOST'] ?? 'localhost') . '/ingest.php';

vg_header('자산', 'assets');
?>
  <?php
  /* 상태 판정 기준. 예전엔 제목 옆 '?' 로 띄웠는데, 정작 궁금해지는 자리는 '상태' 열이다.
   *   같은 문구를 두 곳에 두지 않고 그 열의 머리글 범례로만 단다(등급 열과 같은 방식). */
  $stateHelp = '10초 poll 통신 기준: 1분 초과 지연 · 5분 초과 오프라인. 자산 스캔 주기와는 별개입니다.';
  ?>
  <?php /* 제목 옆 '?' 는 이 화면 전체에 걸리는 규칙만 담는다 — 열별 기준은 각 열 머리글이 갖는다.
           등급 확정 경계는 관리자용 일괄 확정 카드 밖에는 적혀 있지 않아 여기로 올린다. */ ?>
  <?php vg_page_title('자산', 'ASSETS', [
      'suffix_html' => vg_help('시스템 제안은 초안이며, 자산 등급은 사람이 확정합니다.'),
      'actions' => vg_capture(static function (): void {
          vg_modal_btn('agentInstall', '에이전트 설치 안내', 'btn btn--sm btn--ghost');
      }),
  ]); ?>
  <?php vg_subtabs([
      'assets' => ['label' => '자산 목록', 'href' => '/assets.php'],
      'packages' => ['label' => '전체 설치 패키지', 'href' => '/asset-packages.php'],
  ], 'assets'); ?>

  <?php vg_alert($msg, 'ok'); vg_alert($err !== null ? '오류 · ' . $err : null); ?>

  <?php
  /* 수집 상태 KPI. 눌러서 그 상태만 거른다 — 예전엔 오프라인 자산을 찾으려면
   * 목록을 눈으로 훑는 수밖에 없었다. 이미 선택된 걸 다시 누르면 필터가 풀린다. */
  /* 톤(색 어휘)은 이 화면이 소유한다 — KPI 카드·표 범례·등급 뱃지가 같은 값을 두 색으로
   *   부르지 않도록, 표를 그리는 table.php 와 확정 모달에도 이 값을 그대로 넘긴다. */
  $stateTone = ['ok' => 'ok', 'stale' => 'high', 'offline' => 'crit', 'none' => 'muted'];
  $gradeTone = ['C' => 'crit', 'S' => 'high', 'O' => 'low'];
  $totalHosts = array_sum($stateCounts);
  ?>
  <div class="cards">
    <div class="kpi kpi--sm"><b><?= number_format($totalHosts) ?></b><span>전체 자산</span></div>
    <?php /* 정보시스템 등급 — 확정 등급의 최고값 승계. 확정이 하나도 없으면 값은 대시 하나다.
             "왜 비었는가" 는 타일 안에 문장으로 두지 않고 title 로 내린다(타일은 값 자리다). */ ?>
    <div class="kpi kpi--sm" title="<?= $systemGrade !== null ? '확정 자산 중 최고 등급' : '확정된 자산 등급이 없어 승계할 값이 없다' ?>">
      <b><?= vg_h($systemGrade['grade'] ?? '–') ?></b><span>정보시스템 등급</span>
    </div>
    <?php /* 미확정 — 눌러서 그 자산만 거른다(등급 필터의 '미지정'과 같은 조건). 0 이면 톤을 뺀다. */ ?>
    <a class="kpi kpi--sm<?= $unconfirmed > 0 ? ' tone-med' : '' ?><?= $grade === 'none' ? ' is-selected' : '' ?>"
       title="시스템 제안만 있는 자산 포함"
       href="<?= vg_h(vg_qs(['grade' => $grade === 'none' ? '' : 'none', 'page' => null])) ?>">
      <b><?= number_format($unconfirmed) ?></b><span>등급 미확정</span>
    </a>
    <?php /* 0건이면 톤을 뺀다 — '지연 0 · 오프라인 0 · 수집없음 0' 은 **좋은 소식**인데
             강조 테두리가 붙으면 경고로 읽힌다(등급 미확정 카드가 이미 쓰던 판단과 같다).
             새 클래스(.kpi--zero)를 붙이지 않은 건 app.css 가 다른 워커 소유라 정의를 넣을 수
             없고, ui_lint 가 정의 없는 클래스를 죽은 클래스로 잡아 게이트에서 막기 때문이다. */ ?>
    <?php foreach (VG_ASSET_STATES as $key => $label): ?>
      <a class="kpi kpi--sm<?= $stateCounts[$key] > 0 ? ' tone-' . vg_h($stateTone[$key]) : '' ?><?= $state === $key ? ' is-selected' : '' ?>"
         href="<?= vg_h(vg_qs(['state' => $state === $key ? '' : $key, 'page' => null])) ?>">
        <b><?= number_format($stateCounts[$key]) ?></b><span><?= vg_h($label) ?></span>
      </a>
    <?php endforeach; ?>
  </div>

  <?php
  vg_toolbar([
      ['type' => 'select', 'name' => 'state', 'empty_label' => '전체 상태',
       'selected' => $state, 'options' => VG_ASSET_STATES],
      // 등급 어휘는 VG_ASSET_GRADES 가 소유한다 + '미지정'(아직 확정 안 된 자산 찾기).
      ['type' => 'select', 'name' => 'grade', 'empty_label' => '전체 등급',
       'selected' => $grade, 'options' => VG_ASSET_GRADES + ['none' => '미지정']],
      // 옵션은 DB 에서 뽑은 실제 값이다(위 $deptOptions) — 값이 하나도 없으면 선택지가 비어
      //   고를 것이 없으므로 아예 내지 않는다.
      ...($deptOptions ? [['type' => 'select', 'name' => 'dept', 'empty_label' => '전체 부서',
       'selected' => $dept, 'options' => $deptOptions]] : []),
      ['type' => 'search', 'name' => 'q', 'placeholder' => '호스트명·IP·설치 패키지 검색', 'value' => $q],
  ]);

  /* 등급 확정은 관리자만 한다 — 체크박스 열도 관리자에게만 보인다.
   *   (인가 자체는 POST 처리부가 정한다. 여기서 숨기는 건 안 되는 조작을 보여주지 않기 위해서다.) */
  $canConfirm = vg_has_role('admin');
  // 빈 목록 안내는 "필터 때문에 빈 것" 과 "자산이 없는 것" 을 갈라 말한다.
  $filtered = ($q !== '' || $state !== '' || $grade !== '' || $dept !== '');

  /* 표 전체를 일괄 확정 폼으로 감싼다 — 행의 체크박스와 확정 입력창이 한 폼이어야 같이 전송된다.
   *   선택은 **지금 보고 있는 페이지** 안에서만 유효하다(페이지를 넘기면 체크가 풀린다).
   *   "필터에 걸린 전체"를 대상으로 삼지 않는 건 의도다 — 눈에 안 보이는 자산까지 확정되면 안 된다.
   *
   *   확정 조작은 **표 위**에 둔다 — 체크는 표에서 하는데 버튼이 페이지네이션 아래에 있으면
   *   고른 것과 누르는 것 사이를 페이저가 끊는다. 여기 있는 건 모달을 여는 버튼뿐이고,
   *   실제 입력(등급·중요도·근거)과 제출 버튼은 폼 안의 모달(vg_modal_open)에 있다.
   *   data-confirm 은 걷어냈다 — 모달 자체가 대상 목록을 보여주는 확인 단계다(확인창 위에
   *   확인창을 또 띄우지 않는다). 감사로그는 그대로 vg_asset_grade_confirm() 이 남긴다. */
  if ($canConfirm) {
      echo '<form method="post">';
      echo '<input type="hidden" name="csrf" value="' . vg_h(vg_csrf_token()) . '">';
  }
  if ($canConfirm && $rows): ?>
    <div class="form-bar">
      <?php /* 선택 0개면 비활성 — 예전엔 아무것도 안 고르고 눌러도 서버까지 갔다가 오류로 돌아왔다.
               개수 갱신·활성화는 app.js 의 위임 핸들러가 한다(인라인 onclick 을 쓰지 않는다). */ ?>
      <?php /* 개수는 라벨 틀({n})로 준다 — .btn 은 display:flex 라 개수만 <span> 으로 감싸면
               그게 별개 플렉스 항목이 되어 gap 만큼 '선택 3 개' 로 벌어진다(실측). */ ?>
      <?php /* 처음엔 선택이 0개라 비활성이므로 ghost 톤으로 낸다 — 비활성인데 primary(파란) 톤이면
               opacity 만 낮아진 채 여전히 눌릴 것처럼 보인다. 고른 것이 생기면 app.js 가
               primary 로 올린다(같은 함수가 disabled·라벨도 함께 갱신한다). */ ?>
      <?php /* "표에서 고르라" 는 버튼 라벨이 이미 말한다 — 옆에 안내문을 두지 않는다.
               남길 값은 **선택 범위가 이 페이지뿐** 이라는 사실뿐이라 버튼 title 로 내린다. */ ?>
      <button type="button" class="btn btn--sm btn--ghost" data-modal="bulkGrade"
              title="선택은 지금 보고 있는 페이지 안에서만 유효하다"
              data-bulk-open="host_ids[]" data-bulk-label="선택 {n}개 등급 확정" disabled>선택 0개 등급 확정</button>
      <noscript>
        <?php /* 스크립트가 꺼져 있으면 이 버튼이 아예 안 먹는다 — 대체 경로는 값이라 남긴다. */ ?>
        <span class="why">스크립트가 꺼져 있어 일괄 확정을 쓸 수 없다 — 호스트 상세에서 한 대씩 확정한다.</span>
      </noscript>
    </div>
  <?php endif; ?>
  <?php
  vg_assets_render_table($rows, $sevByScan, $canConfirm, $filtered, $stateHelp, $stateTone, $gradeTone);
  if ($rows) { vg_page_nav($total, $perPage, $page); }
  ?>

  <?php if ($canConfirm && $rows) { vg_assets_render_grade_modal($gradeTone); } ?>
  <?php if ($canConfirm) { echo '</form>'; } ?>

  <?php vg_assets_render_install_modal($ingest); ?>
<?php vg_footer();
