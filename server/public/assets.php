<?php
declare(strict_types=1);

/**
 * assets.php — 자산(호스트) 관리. 로그인 + assets 메뉴 권한 필요.
 *   목록: 에이전트가 등록한 호스트 + 최신 수집 상태(정상/지연/오프라인/수집없음).
 *   삭제: admin·operator 만. 소프트삭제(is_deleted=1) 라 대시보드·취약점 집계에서 빠진다.
 *   스캔 이력은 호스트 상세(host.php)의 "스캔 이력" 카드에서 본다.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require_once __DIR__ . '/../src/assetgrade.php';   // 등급 어휘·뱃지·최고등급 승계
vg_require_menu('assets');

// 연결 상태 판정 기준과 vg_asset_state() 는 format.php 에 있다(호스트 상세와 공유).

$err = null; $msg = null; $rows = []; $total = 0; $sevByScan = [];
$stateCounts = ['ok' => 0, 'stale' => 0, 'offline' => 0, 'none' => 0];
$q     = trim((string) ($_GET['q'] ?? ''));
$state = trim((string) ($_GET['state'] ?? ''));
// 등급 필터. 허용값은 VG_ASSET_GRADES(단일 출처) + 'none'(아직 확정 안 된 자산 찾기).
$grade = trim((string) ($_GET['grade'] ?? ''));
if ($grade !== 'none' && !isset(VG_ASSET_GRADES[$grade])) { $grade = ''; }
/* 담당 부서 필터. 어휘를 코드에 박지 않는다 — 부서명은 기관마다 다르고 등급 검토 폼이
 *   자유 입력으로 받는 값이라, 옵션은 **DB 에 실제로 들어 있는 값**에서만 뽑는다. */
$dept = trim((string) ($_GET['dept'] ?? ''));
$deptOptions = [];
$systemGrade = null;   // 함대 전체를 하나의 정보시스템으로 볼 때의 승계 등급
$unconfirmed = 0;      // 아직 사람이 등급을 확정하지 않은 자산 수
$page  = vg_page();
$perPage = vg_perpage();

// 연결 상태 어휘. 최신 수집 시각은 별도 열에서 보여준다.
const VG_ASSET_STATES = ['ok' => '정상', 'stale' => '지연', 'offline' => '오프라인', 'none' => '수집없음'];
if (!isset(VG_ASSET_STATES[$state])) { $state = ''; }

/* 호스트 한 대의 연결 상태를 SQL 안에서 판정하는 식(format.php 의 vg_asset_state_sql_expr() —
 * compliance.php 와 공유하는 SSOT). 목록 필터·KPI 집계가 같은 식을 써야 "지연 3대" 를 눌렀을 때
 * 3대가 나온다. */
$stateExpr = vg_asset_state_sql_expr();

// 호스트 + 최신 스캔. LEFT JOIN 이라 등록만 되고 아직 수집이 없는 호스트도 남는다.
$fromSql = 'FROM tb_host h
            LEFT JOIN ' . vg_latest_scan_subq() . ' t ON t.host_id = h.host_id
            LEFT JOIN tb_scan s ON s.scan_id = t.mid
            LEFT JOIN (
                SELECT host_fqdn, MAX(last_seen_at) AS last_seen_at
                  FROM tb_agent_token
                 WHERE is_revoked = 0 AND is_deleted = 0
                 GROUP BY host_fqdn
            ) agent_seen ON agent_seen.host_fqdn = h.fqdn
            LEFT JOIN tb_asset_grade_review gr ON gr.host_id = h.host_id';

$pdo = vg_pdo();

/* 자산 등급 **일괄 확정** — 함대가 커지면 호스트를 한 대씩 열어 확정하는 건 현실적이지 않다.
 *   경계는 상세 화면과 같다:
 *     · 확정은 **사람이 고른 등급**으로만 한다 — "제안값 그대로 승인" 버튼은 두지 않는다.
 *       그 버튼이 있으면 사실상 시스템이 등급을 정한 것이 된다.
 *     · 검증·기록·감사로그는 host.php 와 같은 vg_asset_grade_confirm() 이 한다(증적이 갈리면 안 된다).
 *     · 일괄로는 **확정만** 한다. 해제는 되돌리기 어려운 조작이라 상세 화면에서 한 대씩 한다.
 *   POST 를 그대로 그리면 새로고침이 재전송되므로 PRG(303)로 돌린다. */
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    if (!vg_csrf_check($_POST['csrf'] ?? null)) {
        vg_redirect_flash(['assetErr' => '세션이 만료되었습니다.']);
    }
    // 인가는 클라이언트 숨김이 아니라 여기서 정해진다(폼이 안 보여도 POST 는 올 수 있다).
    if (!vg_has_role('admin')) {
        vg_redirect_flash(['assetErr' => '자산 등급을 확정할 권한이 없습니다.']);
    }
    $me = vg_current_user();
    $ids = array_values(array_unique(array_filter(
        array_map('intval', (array) ($_POST['host_ids'] ?? [])),
        static fn(int $id): bool => $id > 0
    )));
    $bulkGrade  = (string) ($_POST['grade'] ?? '');
    $bulkCrit   = (string) ($_POST['criticality'] ?? '');   // '' = 이번엔 중요도를 안 건드린다
    $bulkReason = (string) ($_POST['grade_reason'] ?? '');
    try {
        if (!$ids) { throw new RuntimeException('확정할 자산을 하나 이상 고르세요.'); }
        if ($bulkGrade === '') { throw new RuntimeException('확정할 등급을 고르세요.'); }
        // 한 페이지에서 고른 것만 오므로 정상 경로에선 못 넘는 수다. 조작된 POST 의 상한선.
        if (count($ids) > 500) { throw new RuntimeException('한 번에 확정할 수 있는 자산은 500대까지입니다.'); }

        // 한 건이라도 실패하면 전부 되돌린다 — "몇 대는 확정되고 몇 대는 아닌" 상태가 제일 나쁘다.
        $pdo->beginTransaction();
        foreach ($ids as $id) {
            vg_asset_grade_confirm(
                $pdo, $id, $bulkGrade, $bulkCrit === '' ? null : $bulkCrit, $bulkReason, $me['id'] ?? null
            );
        }
        $pdo->commit();
        vg_redirect_flash([
            'assetMsg' => '자산 ' . count($ids) . '대의 등급을 ' . $bulkGrade . ' 로 확정했습니다.',
        ]);
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) { $pdo->rollBack(); }
        error_log('[assets] ' . $e->getMessage());
        // 사람이 고칠 수 있는 입력 오류는 그대로 보여주고, 그 밖의 내부 오류는 감춘다.
        vg_redirect_flash([
            'assetErr' => $e instanceof RuntimeException ? $e->getMessage() : '처리 중 오류가 발생했습니다.',
        ]);
    }
}

$assetFlash = vg_flash_take();
$msg = $assetFlash['assetMsg'] ?? null;
$err = $assetFlash['assetErr'] ?? null;

try {
    /* 부서 드롭다운 옵션 — 살아 있는 자산에 실제로 붙어 있는 값만. 검토 정보는 호스트당 1행이라
     *   행 수가 자산 수를 넘지 않는다(별도 집계 테이블이 필요한 규모가 아니다). */
    $deptOptions = $pdo->query(
        'SELECT DISTINCT gr.owning_department
           FROM tb_asset_grade_review gr
           JOIN tb_host h ON h.host_id = gr.host_id AND h.is_deleted = 0
          WHERE gr.owning_department IS NOT NULL AND gr.owning_department <> \'\'
          ORDER BY gr.owning_department'
    )->fetchAll(PDO::FETCH_COLUMN);
    $deptOptions = array_combine($deptOptions, $deptOptions) ?: [];
    // 목록에 없는 값이 오면 필터를 건 것으로 치지 않는다(조작된 쿼리스트링).
    if ($dept !== '' && !isset($deptOptions[$dept])) { $dept = ''; }

    // KPI — 검색어·상태 필터와 무관하게 전체 기준(필터를 걸어도 전체 그림은 유지된다).
    $kpi = $pdo->query("SELECT $stateExpr AS st, COUNT(*) c $fromSql WHERE h.is_deleted = 0 GROUP BY st")->fetchAll();
    foreach ($kpi as $k) {
        if (isset($stateCounts[$k['st']])) { $stateCounts[$k['st']] = (int) $k['c']; }
    }

    $where  = 'h.is_deleted = 0';
    $params = [];
    if ($q !== '') {
        $where .= " AND (h.fqdn LIKE ? OR h.last_seen_ip LIKE ? OR EXISTS (
            SELECT 1 FROM tb_package search_pkg
             WHERE search_pkg.scan_id=s.scan_id AND search_pkg.is_deleted=0
               AND search_pkg.container_id=0 AND search_pkg.manager IN ('dpkg','rpm','apk')
               AND (search_pkg.name LIKE ? OR search_pkg.source_pkg LIKE ?)
        ))";
        $like = '%' . $q . '%';
        array_push($params, $like, $like, $like, $like);
    }
    if ($state !== '') {
        // KPI 와 같은 식을 쓴다 — 다른 식을 쓰면 "지연 3대" 를 눌렀는데 2대가 나오는 일이 생긴다.
        $where .= " AND $stateExpr = ?";
        $params[] = $state;
    }
    if ($grade === 'none') {
        $where .= ' AND h.grade IS NULL';
    } elseif ($grade !== '') {
        $where .= ' AND h.grade = ?';
        $params[] = $grade;
    }
    if ($dept !== '') {
        $where .= ' AND gr.owning_department = ?';
        $params[] = $dept;
    }

    // COUNT 도 목록과 같은 FROM 을 써야 한다. 상태 필터가 최신 스캔(s)을 참조하기 때문이다.
    $st = $pdo->prepare("SELECT COUNT(*) $fromSql WHERE $where");
    $st->execute($params);
    $total = (int) $st->fetchColumn();

    $offset = ($page - 1) * $perPage;

    $st = $pdo->prepare(
        /* 목록에서 뺀 값(OS·IP·패키지 수·에이전트 버전·담당 부서)은 SELECT 에서도 뺀다 —
         *   화면이 안 쓰는 값을 페이지마다 실어 오지 않는다. 검색·필터가 쓰는 컬럼
         *   (h.last_seen_ip · gr.owning_department)은 WHERE 절에 그대로 남아 있어 영향이 없다. */
        "SELECT h.host_id, h.fqdn,
                s.scan_id, s.collected_at,
                h.poll_schedule_seconds,
                h.criticality, h.grade, h.grade_reason,
                h.grade_suggested, h.grade_suggested_reason,
                TIMESTAMPDIFF(MINUTE, s.collected_at, NOW()) AS age_min,
                TIMESTAMPDIFF(MINUTE, agent_seen.last_seen_at, NOW()) AS poll_age_min
           $fromSql
          WHERE $where
          ORDER BY h.fqdn
          LIMIT $perPage OFFSET $offset"
    );
    $st->execute($params);
    $rows = $st->fetchAll();

    // 이 페이지에 보이는 최신 스캔들의 심각도 카운트
    $ids = [];
    foreach ($rows as $r) { if ($r['scan_id'] !== null) { $ids[] = (int) $r['scan_id']; } }
    $sevByScan = vg_sev_by_scan_ids($pdo, $ids);

    /* 함대 최신 에이전트 버전 조회는 여기서 걷어냈다 — 에이전트 버전 열이 호스트 상세로
     *   옮겨 갔고(vg_agent_fleet_latest() 를 그쪽에서 부른다), 목록이 안 쓰는 값을 위해
     *   전 스캔의 DISTINCT 를 매 요청 돌릴 이유가 없다. '구버전' 신호 자체는 그대로 살아 있다. */
    /* 정보시스템 등급 — 여러 업무정보 등급이 한 시스템에 있으면 **최고등급을 승계**한다.
     *   여기서 "정보시스템"은 이 함대(자산 전체)다. 확정된 등급만 센다 — 제안값을 섞으면
     *   "시스템이 등급을 정했다"가 되어 사람 확정과의 경계가 무너진다.
     *   필터와 무관하게 전체 기준(KPI 와 같은 성격). */
    $confirmed = $pdo->query(
        'SELECT grade FROM tb_host WHERE is_deleted = 0 AND grade IS NOT NULL'
    )->fetchAll(PDO::FETCH_COLUMN);
    $systemGrade = vg_asset_grade_max($confirmed);

    /* 미확정 자산 수 — 심사 관점에선 "정보시스템 등급이 무엇인가" 보다 **아직 아무도 판정하지 않은
     *   자산이 몇 대인가** 가 먼저 나오는 질문이다. 승계 등급만 보이면 미확정이 몇 대든 숫자 하나가
     *   떠 있어 다 정해진 것처럼 읽힌다. 제안값이 붙어 있어도 확정은 아니므로 여기 포함된다. */
    $unconfirmed = (int) $pdo->query(
        'SELECT COUNT(*) FROM tb_host WHERE is_deleted = 0 AND grade IS NULL'
    )->fetchColumn();

} catch (Throwable $e) {
    error_log('[assets] ' . $e->getMessage());
    $err = '처리 중 오류가 발생했습니다.';
}

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
  <?php vg_page_title('자산', 'ASSETS', '에이전트가 등록한 호스트별 수집 상태와 탐지 결과입니다.', [
      'suffix_html' => vg_help('시스템 제안은 초안이며, 자산 등급은 사람이 확정합니다.'),
      'actions' => vg_capture(static function (): void {
          vg_modal_btn('agentInstall', '에이전트 설치 안내', 'btn btn--sm btn--ghost');
      }),
  ]); ?>
  <?php
  /* 자산 한 대가 화면에 뜨기까지의 순서 — 에이전트가 붙고, 수집이 오고, 인벤토리가 쌓이고,
   *   마지막에 사람이 등급을 확정한다. 마지막 칸만 사람 몫이라 그 칸을 active 로 세운다
   *   (미확정이 0 이면 전부 끝난 것이므로 done). 숫자는 이미 위에서 센 값을 그대로 쓴다. */
  vg_explain_flow([
      ['icon' => 'feed',    'label' => '등록', 'state' => 'done'],
      ['icon' => 'clock',   'label' => '수집', 'value' => number_format($stateCounts['ok']) . '대', 'state' => 'done'],
      ['icon' => 'package', 'label' => '인벤토리', 'value' => number_format(array_sum($stateCounts)) . '대', 'state' => 'done'],
      ['icon' => 'shield',  'label' => '등급', 'value' => $unconfirmed > 0 ? '미확정 ' . number_format($unconfirmed) : '확정 완료',
       'state' => $unconfirmed > 0 ? 'active' : 'done'],
  ], ['label' => '자산이 등록되어 등급이 확정되기까지']);
  ?>
  <?php vg_subtabs([
      'assets' => ['label' => '자산 목록', 'href' => '/assets.php'],
      'packages' => ['label' => '전체 설치 패키지', 'href' => '/asset-packages.php'],
  ], 'assets'); ?>

  <?php vg_alert($msg, 'ok'); vg_alert($err !== null ? '오류 · ' . $err : null); ?>

  <?php
  /* 수집 상태 KPI. 눌러서 그 상태만 거른다 — 예전엔 오프라인 자산을 찾으려면
   * 목록을 눈으로 훑는 수밖에 없었다. 이미 선택된 걸 다시 누르면 필터가 풀린다. */
  $stateTone = ['ok' => 'ok', 'stale' => 'high', 'offline' => 'crit', 'none' => 'muted'];
  $totalHosts = array_sum($stateCounts);
  ?>
  <div class="cards">
    <div class="kpi kpi--sm"><b><?= number_format($totalHosts) ?></b><span>전체 자산</span></div>
    <?php /* 정보시스템 등급 — 확정 등급의 최고값 승계. 확정이 하나도 없으면 값이 대시 하나뿐인데,
             그것만 떠 있으면 "미설정인지 권한이 없어 못 보는 것인지" 를 알 수 없다.
             왜 비었는지를 카드 안에 적는다(권한 문제는 아니다 — 이 화면 자체가 assets 권한이다). */ ?>
    <div class="kpi kpi--sm" title="<?= $systemGrade !== null ? '확정 자산 중 최고 등급' : '확정 등급 없음' ?>">
      <b><?= vg_h($systemGrade['grade'] ?? '–') ?></b><span>정보시스템 등급</span>
      <?php if ($systemGrade === null): ?>
        <span>확정된 자산 등급이 없어 승계할 값이 없습니다</span>
      <?php endif; ?>
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

  // 폭 배분: 목록 표는 table-layout:fixed 다(app.css 의 '목록 화면' 구역).
  //   단위를 두 가지로 나눠 쓴다 — 이 표가 표 모드로 처음 뜨는 1061px 에서 실측한 값이 기준이다.
  //   · 줄바꿈이 불가능한 고정 크기 값(뱃지·<code>·버튼)이 담기는 열은 rem 이다. % 로 주면 표가
  //     좁아질 때 그 값보다 좁아지는데, 값은 안 줄어드니 그대로 옆 열 위에 그려진다. 실제로
  //     '상태' 6.5%(1061px 에서 48px)가 오프라인 뱃지(65px)를 못 담아 OS 열을 32px 덮었고,
  //     '에이전트' 는 구버전 뱃지가 13px 덮었다(가로 스크롤은 안 생겨 #377 의 넘침 검사엔 안 잡혔다).
  //     필요한 폭 = 값의 폭 + 칸 여백(.6rem×2): 뱃지 65+19=84 → 5.5rem, 구버전 뱃지 53+19=72 → 5rem.
  //   · 접거나 잘라도 되는 텍스트 열(OS·리소스·수치·수집시각·심각도 건수)은 그대로 % 다.
  //   · 남는 폭은 호스트명이 갖는다(폭을 안 준 열). 예전엔 심각도가 남는 폭을 다 가져가
  //     1920px 에서 건수 뱃지 4개에 344px 를 썼다 — 그 폭은 잘려 나가던 식별자 쪽이 써야 한다.
  /* 등급 확정은 관리자만 한다 — 체크박스 열도 관리자에게만 보인다.
   *   (인가 자체는 위 POST 처리부가 정한다. 여기서 숨기는 건 안 되는 조작을 보여주지 않기 위해서다.) */
  $canConfirm = vg_has_role('admin');
  $headers = [];
  if ($canConfirm) {
      // 체크박스만 담는 열이라 폭이 늘 같다 → % 가 아니라 rem(아래 폭 배분 기준 그대로).
      //   머리글은 글자가 아니라 **이 페이지 전체 선택** 체크박스다 — 무엇을 고르는 건지는
      //   고르는 자리(표 머리)에서 읽혀야 한다. 예전엔 목록·페이지네이션 아래 카드에 있어서
      //   체크는 위에서 하고 전체선택은 저 아래에 있었다.
      $headers[] = [
          'label' => '', 'key' => 'pick', 'width' => '2.5rem', 'align' => 'center',
          'label_html' => '<input type="checkbox" data-checkall="host_ids[]"'
              . ' aria-label="이 페이지 전체 선택" title="이 페이지 전체 선택">',
      ];
  }
  /* 열은 "이 행을 열어볼지 말지" 를 정하는 것만 남긴다(docs/dev/ui-design-system.md 의 목록·상세 분담).
   *   여기서 뺀 다섯 열은 지운 게 아니라 호스트 상세(host.php)로 옮긴 것이다:
   *     담당 부서 → 자산 설정 탭의 등급 검토 카드 · OS/IP/패키지 수/에이전트 버전 → 식별부(히어로) 메타.
   *   에이전트 '구버전' 신호도 그 히어로 메타가 그대로 이어받는다(신호를 잃지 않는다). */
  $headers = array_merge($headers, [
      // 뺀 열들의 폭은 남는 폭을 갖는 식별자(호스트)와 위험(심각도)이 가져간다.
      ['label' => '호스트', 'key' => 'fqdn', 'class' => 'col-id', 'width' => '34%'],
      ['label' => '상태', 'key' => 'state', 'width' => '5.5rem', 'title' => $stateHelp],
      // 등급 열도 뱃지(고정 크기)라 % 가 아니라 rem 이다 — 위 주석의 기준을 그대로 따른다.
      //   'C · 기밀'(약 62px) + 칸 여백(.6rem×2 ≈ 19px) → 5.5rem.
      //   C/S/O 기호만 떠 있으면 뜻을 알 수 없어 열 이름에 한 줄 범례를 단다(어휘는 assetgrade.php 소유).
      ['label' => '등급', 'key' => 'grade', 'width' => '5.5rem'],
      ['label' => '심각도', 'key' => 'sev', 'width' => '22%'],
      ['label' => '최신 수집', 'key' => 'collected_at', 'width' => '14%', 'nowrap' => true],
  ]);
  // 액션 열만 % 가 아니라 rem 이다. 삭제 버튼은 폭이 늘 같은 고정 크기 조작부라 비율로 줄 이유가 없고,
  //   비율로 주면 표가 좁아질 때 버튼보다 좁아진다 — 실제로 900px 에서 9%(=51px)가 68px 버튼을
  //   못 담아 카드를 16.7px 밀어냈다(가로 스크롤). 5rem 이면 어느 폭에서도 버튼이 들어간다.

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
      <button type="button" class="btn btn--sm btn--ghost" data-modal="bulkGrade"
              data-bulk-open="host_ids[]" data-bulk-label="선택 {n}개 등급 확정" disabled>선택 0개 등급 확정</button>
      <span class="why">표에서 등급을 확정할 자산을 고르세요. 선택은 지금 보고 있는 페이지 안에서만 유효합니다.</span>
      <noscript>
        <span class="why">이 브라우저는 스크립트가 꺼져 있어 일괄 확정 창을 열 수 없습니다 —
          호스트 이름을 눌러 상세 화면에서 한 대씩 확정하세요.</span>
      </noscript>
    </div>
  <?php endif; ?>
  <?php
  /* 표의 '상태'·'등급' 열은 색으로 등급을 말하는데 그 색의 뜻이 화면 어디에도 없었다.
   *   어휘는 VG_ASSET_STATES·VG_ASSET_GRADES 가 소유한다 — 여기서 분류표를 다시 적지 않는다.
   *   톤은 위 KPI 카드($stateTone)·등급 뱃지와 같은 값을 쓴다(같은 값을 두 색으로 부르지 않는다). */
  $gradeTone = ['C' => 'crit', 'S' => 'high', 'O' => 'low'];
  vg_legend(array_map(
      fn(string $k): array => ['label' => VG_ASSET_STATES[$k], 'tone' => $stateTone[$k]],
      array_keys(VG_ASSET_STATES)
  ), ['inline' => true, 'caption' => '수집 상태']);
  vg_legend(array_map(
      fn(string $g): array => ['label' => VG_ASSET_GRADES[$g], 'tone' => $gradeTone[$g]],
      array_keys(VG_ASSET_GRADES)
  ), ['inline' => true, 'caption' => '보안등급']);

  vg_table(
      $headers,
      $rows,
      [
          // 빈 이유가 셋이라 메시지도 셋 — "필터 때문에 빈 것" 과 "자산이 없는 것" 은 다른 상황이다.
          'empty' => ($q !== '' || $state !== '' || $grade !== '' || $dept !== '')
              ? [
                  'icon'  => '🔍',
                  'title' => '조건에 맞는 자산이 없습니다.',
                  'hint'  => '검색어나 상태·등급·부서 필터를 바꿔 보세요.',
                  'cta'   => ['href' => '/assets.php', 'label' => '필터 초기화'],
              ]
              : [
                  'icon'  => '🖥️',
                  'title' => '등록된 자산이 없습니다.',
                  'hint'  => '자산은 에이전트가 수집을 보내면 자동 등록됩니다. 상단의 [에이전트 설치 안내]를 따르세요.',
              ],
          'cell' => [
              // 일괄 확정 대상 선택. 폼 안에 표가 들어 있어 그대로 같이 전송된다.
              //   data-name 은 모달의 "무엇을 확정하는가" 요약이 읽는다(app.js 가 textContent 로만 쓴다).
              'pick' => fn($r) => '<input type="checkbox" name="host_ids[]" value="' . (int) $r['host_id']
                  . '" data-name="' . vg_h($r['fqdn']) . '" aria-label="' . vg_h($r['fqdn']) . ' 선택">',
              // 칸을 넘치는 긴 FQDN 은 col-id 가 말줄임으로 접는다 — 전체 이름은 title 로 남긴다.
              'fqdn'  => fn($r) => '<strong><a href="/host.php?id=' . (int) $r['host_id'] . '" title="' . vg_h($r['fqdn']) . '">' . vg_h($r['fqdn']) . '</a></strong>',
              'state' => fn($r) => vg_asset_state(
                  $r['scan_id'] !== null,
                  $r['poll_age_min'],
                  $r['age_min'],
                  (int) $r['poll_schedule_seconds']
              ),
              // 확정 등급이 있으면 그것만 보여준다. 없을 때만 제안값을 '제안' 꼬리표와 함께 —
              //   둘을 나란히 두면 어느 쪽이 확정인지 흐려진다("판정은 사람이, 초안은 시스템이").
              'grade' => fn($r) => $r['grade'] !== null
                  ? vg_asset_grade_badge((string) $r['grade'], false, (string) ($r['grade_reason'] ?? ''))
                  : vg_asset_grade_badge(
                      $r['grade_suggested'], true, (string) ($r['grade_suggested_reason'] ?? '')
                  ),
              // 뱃지를 누르면 그 호스트·등급의 취약점 목록으로.
              'sev' => fn($r) => vg_sev_counts(
                  $sevByScan[(int) $r['scan_id']] ?? [],
                  fn(string $s) => '/findings.php?host=' . (int) $r['host_id'] . '&sev=' . $s
              ),
              /* 12% 로는 'YYYY-MM-DD HH:MM:SS'(19자)가 안 들어가 '2026-08-11 23:2…' 로 잘려
               *   시각을 못 읽었다. 열을 넓히는 대신 **형식을 줄인다** — 이 목록에서 필요한 건
               *   분까지고(초 단위 판단을 여기서 하지 않는다), 전체 값은 title 로 남긴다. */
              'collected_at' => function ($r) {
                  $at = (string) ($r['collected_at'] ?? '');
                  if ($at === '') { return '<span class="why">–</span>'; }
                  return '<span class="why" title="' . vg_h($at) . '">' . vg_h(substr($at, 0, 16)) . '</span>';
              },
          ],
      ]
  );
  if ($rows) { vg_page_nav($total, $perPage, $page); }
  ?>

  <?php if ($canConfirm && $rows): ?>
    <?php /* 확정 입력창. **폼 안**에 둔다 — 네이티브 dialog 는 렌더링만 top-layer 로 올라가고
             DOM 상 폼 소속은 그대로라, 표의 host_ids[] 와 이 안의 등급·근거가 한 번에 전송된다.
             (밖에 두면 체크한 자산이 하나도 안 실려 간다.) */ ?>
    <?php vg_modal_open('bulkGrade', '선택 자산 등급 일괄 확정'); ?>
      <p class="why" data-bulk-summary>선택한 자산이 없습니다.</p>

      <?php /* 등급 셋의 뜻은 문장이 아니라 세 칸으로 세운다 — 고르는 자리 바로 위에서
               "무엇을 고르는 것인지" 가 색과 함께 읽혀야 한다. 칸의 순서 자체가 승계 규칙
               (O < S < C — 오른쪽이 더 강한 보호)이고, 색은 등급 뱃지와 같은 톤을 쓴다.
               어휘는 assetgrade.php(VG_ASSET_GRADES)가 소유한다 — 여기서 다시 적지 않는다.
               두 번째 vg_explain_flow() 를 세우지 않는 건 도식은 화면당 하나라는 규칙 때문이다
               (docs/dev/ui-design-system.md) — 상단 흐름 도식이 이미 이 화면의 하나다. */ ?>
      <div class="cards">
        <?php foreach (['O' => '공개해도 되는 정보', 'S' => '제한적으로 다루는 정보',
                        'C' => '「정보공개법」 제9조 비공개 대상'] as $g => $note): ?>
          <div class="kpi kpi--sm tone-<?= vg_h($gradeTone[$g]) ?>">
            <b><?= vg_h($g) ?></b><span><?= vg_h(VG_ASSET_GRADES[$g]) ?></span>
            <span class="why"><?= vg_h($note) ?></span>
          </div>
        <?php endforeach; ?>
      </div>
      <p class="why">한 정보시스템에 여러 등급이 섞이면 오른쪽(더 강한 보호)을 승계합니다.</p>

      <label for="bulk-criticality">중요도</label>
      <select id="bulk-criticality" name="criticality">
        <option value="">변경 안 함</option>
        <?php foreach (VG_ASSET_CRITICALITY as $v => $label): ?>
          <option value="<?= vg_h($v) ?>"><?= vg_h($label) ?></option>
        <?php endforeach; ?>
      </select>

      <label for="bulk-grade">보안등급 (N2SF)</label>
      <select id="bulk-grade" name="grade" required>
        <option value="">선택</option>
        <?php foreach (VG_ASSET_GRADES as $v => $label): ?>
          <option value="<?= vg_h($v) ?>"><?= vg_h($label) ?></option>
        <?php endforeach; ?>
      </select>

      <label for="bulk-grade-reason">확정 근거</label>
      <input id="bulk-grade-reason" type="text" name="grade_reason" maxlength="255"
             placeholder="예: 「정보공개법」 제9조 제6호 해당 업무정보 보유">

      <?php /* 판정 기준은 산문이 아니라 정의목록으로 준다 — 등급 어휘는 assetgrade.php 가 소유하고
               (같은 문자열을 화면마다 다시 적지 않는다), 나머지는 이 폼이 실제로 하는 일이다. */ ?>
      <dl class="criteria">
        <?php /* 등급 어휘·기준은 바로 위 세 칸이 색과 함께 말한다 — 같은 말을 두 번 하지 않고,
                 여기엔 그 칸에 못 담는 것(누가 확정하는가)만 남긴다. */ ?>
        <dt>보안등급</dt>
        <dd>N2SF 등급 확정은 기관의 법적 처분이라 시스템이 대신하지 않습니다.</dd>
        <dt>중요도</dt>
        <dd>상 / 중 / 하 — 등급과 별개로 사람이 지정합니다. ‘변경 안 함’ 이면 지금 값을 그대로 둡니다.</dd>
        <dt>확정 범위</dt>
        <dd>지금 보고 있는 페이지에서 고른 자산만, 한 번에 500대까지. 자산마다 확정자·시각이 감사로그에 남습니다.</dd>
        <dt>구조화 검토 정보</dt>
        <dd>호스트마다 달라 일괄 입력하지 않습니다. 기존 정보는 재검토 필요 상태가 되며, 확정 후 각 자산 상세에서 제9조 해당 호, 업무·데이터 유형, 소유 부서, 공개 상태, 검토 문서와 재검토일을 다시 확인하세요.</dd>
      </dl>
      <?php vg_modal_foot('등급 확정', ['loading' => '확정 중…', 'cancel' => '취소']); ?>
    <?php vg_modal_close(); ?>
  <?php endif; ?>
  <?php if ($canConfirm) { echo '</form>'; } ?>

  <?php
  /* 설치 안내는 자산을 처음 붙일 때 한 번 보는 것이다. 목록 아래 늘 펼쳐두면
   * 매일 보는 화면이 그만큼 길어진다 → 버튼 뒤 모달로. */
  vg_modal_open('agentInstall', '에이전트 설치 안내', 'modal--wide');
  ?>
    <div class="install-stepper" data-stepper>
      <div class="install-stepper__tabs" role="tablist" aria-label="에이전트 설치 단계">
        <?php foreach (['키 발급', '파일·CA', '설치 실행', '연결 확인'] as $i => $label): ?>
          <button type="button" role="tab" data-install-step="<?= $i ?>"
                  aria-controls="agentInstallStep<?= $i + 1 ?>"><?= $i + 1 ?>. <?= vg_h($label) ?></button>
        <?php endforeach; ?>
      </div>

      <section id="agentInstallStep1" role="tabpanel" data-install-step-panel="1">
        <h3>1. 호스트 전용 키 발급</h3>
        <p>대상 서버의 FQDN으로 <a href="/agent-tokens.php">에이전트 키</a>를 발급하고, 한 번만 보이는 원문을 복사합니다.</p>
        <p class="why"><strong>완료 조건:</strong> 토큰 원문을 안전한 임시 위치에 복사했습니다. 같은 FQDN의 기존 활성 키는 자동 폐기됩니다.</p>
        <div class="actions"><a class="btn btn--sm btn--ghost" href="/agent-tokens.php">키 발급 화면</a><button type="button" class="btn btn--sm btn--primary" data-step-next="1">다음: 파일 받기</button></div>
      </section>

      <section id="agentInstallStep2" role="tabpanel" data-install-step-panel="2">
        <h3>2. 설치 파일과 루트 CA 받기</h3>
        <p>레포 체크아웃 없이 기존 다운로드 경로에서 세 파일을 받아 대상 서버로 옮깁니다.</p>
        <div class="actions">
          <a class="btn btn--sm btn--ghost" href="/agent-dl.php?f=install-agent.sh" download>install-agent.sh</a>
          <a class="btn btn--sm btn--ghost" href="/agent-dl.php?f=vuln-inventory-agent.sh" download>vuln-inventory-agent.sh</a>
          <a class="btn btn--sm btn--ghost" href="/agent-dl.php?f=caddy-root.crt" download>caddy-root.crt</a>
        </div>
        <pre class="code">scp install-agent.sh vuln-inventory-agent.sh caddy-root.crt 대상서버:~/</pre>
        <p class="why"><strong>완료 조건:</strong> 대상 서버의 같은 디렉터리에 세 파일이 있습니다. CA가 503이면 중앙 관리자에게 추출을 요청한 뒤 다시 시도합니다.</p>
        <div class="actions"><button type="button" class="btn btn--sm btn--ghost" data-step-prev="0">이전</button><button type="button" class="btn btn--sm btn--primary" data-step-next="2">다음: 설치 실행</button></div>
      </section>

      <section id="agentInstallStep3" role="tabpanel" data-install-step-panel="3">
        <h3>3. 대상 서버에서 설치 실행</h3>
        <p>대상 서버에는 POSIX <code>awk</code>와 HTTPS 전송용 <code>curl</code> 또는 <code>wget</code> 중 하나가 필요합니다. <code>jq</code>는 선택 사항입니다.</p>
        <pre class="code">sudo mkdir -p /opt/vuln-agent &amp;&amp; sudo cp ~/install-agent.sh ~/vuln-inventory-agent.sh ~/caddy-root.crt /opt/vuln-agent/
cd /opt/vuln-agent
sudo bash install-agent.sh
  중앙 서버 주소: <?= vg_h($ingest) ?>
  전송 토큰: ********
  수집 주기 [hourly]:</pre>
        <div class="actions"><?php vg_copy_btn('sudo bash install-agent.sh', '실행 명령 복사'); ?></div>
        <p class="why"><strong>완료 조건:</strong> 설치기가 성공으로 끝났습니다. systemd는 10초마다 명령을 확인하며, systemd가 없으면 cron 정기수집만 지원합니다.</p>
        <p class="why">실패하면 파일·CA 위치와 중앙 주소를 확인하고 같은 명령으로 <strong>다시 시도</strong>합니다. 제거는 <code>sudo bash install-agent.sh --uninstall</code>입니다.</p>
        <div class="actions"><button type="button" class="btn btn--sm btn--ghost" data-step-prev="1">이전</button><button type="button" class="btn btn--sm btn--primary" data-step-next="3">다음: 연결 확인</button></div>
      </section>

      <section id="agentInstallStep4" role="tabpanel" data-install-step-panel="4">
        <h3>4. 연결과 첫 자산 스캔 확인</h3>
        <p>이 모달을 닫고 자산 목록에서 FQDN을 검색합니다. <strong>최신 수집</strong> 시각과 첫 탐지 결과가 보이면 완료입니다.</p>
        <p class="why"><strong>완료 조건:</strong> 자산이 자동 등록되고 상태가 수집없음이 아니며 최신 수집 시각이 표시됩니다.</p>
        <p class="why">미수신이면 키의 FQDN·만료/폐기 상태, 대상 서버의 아웃바운드 HTTPS와 서비스 로그를 확인한 뒤 자산 스캔을 다시 시도합니다.</p>
        <div class="actions"><button type="button" class="btn btn--sm btn--ghost" data-step-prev="2">이전</button><a class="btn btn--sm btn--primary" href="/assets.php">자산 목록에서 확인</a></div>
      </section>
    </div>
    <?php vg_modal_foot(null); ?>
  <?php vg_modal_close(); ?>
<?php vg_footer();
