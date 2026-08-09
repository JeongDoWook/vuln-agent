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
            ) agent_seen ON agent_seen.host_fqdn = h.fqdn';

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

    // COUNT 도 목록과 같은 FROM 을 써야 한다. 상태 필터가 최신 스캔(s)을 참조하기 때문이다.
    $st = $pdo->prepare("SELECT COUNT(*) $fromSql WHERE $where");
    $st->execute($params);
    $total = (int) $st->fetchColumn();

    $offset = ($page - 1) * $perPage;

    $st = $pdo->prepare(
        "SELECT h.host_id, h.fqdn, h.os_id, h.os_version, h.last_seen_ip,
                s.scan_id, s.collected_at, s.package_count, s.agent_version,
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

    // 함대에서 가장 높은 에이전트 버전 — 이보다 낮은 호스트는 옛 에이전트가 돌고 있다.
    //   중앙은 노드에 아무것도 내려보내지 않으므로(노드가 밀어 올리기만 한다) 에이전트를 고쳐도
    //   **각 노드에 다시 깔 때까지 옛 코드가 계속 돈다.** 실제로 master 가 2.1 로 몇 주를 돌았는데
    //   화면에 숫자만 있고 "이게 구버전" 이라는 신호가 없어 아무도 못 알아챘다.
    //   기준을 코드에 박지 않고 **관측된 최댓값**으로 잡는다 — 웹 컨테이너는 agent/ 를 마운트하지
    //   않으므로 저장소의 버전을 읽을 수 없고, 박아 두면 배포 때마다 두 곳을 고쳐야 한다.
    //   (버전은 '2.10' > '2.9' 라 문자열 비교로는 틀린다 → version_compare)
    $seen = $pdo->query(
        "SELECT DISTINCT agent_version FROM tb_scan
          WHERE agent_version IS NOT NULL AND agent_version <> '' AND is_deleted = 0"
    )->fetchAll(PDO::FETCH_COLUMN);
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

    $latestAgent = (string) array_reduce(
        $seen,
        static fn(?string $max, string $v) => ($max === null || version_compare($v, $max, '>')) ? $v : $max
    );
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
  $stateHelp = '상태는 수집 주기가 아니라 10초 poll 통신 기준입니다. '
      . '1분 초과 시 지연, 5분 초과 시 오프라인이며 최신 수집 시각은 별도로 표시합니다.';
  ?>
  <?php /* 제목 옆 '?' 는 이 화면 전체에 걸리는 규칙만 담는다 — 열별 기준은 각 열 머리글이 갖는다.
           등급 확정 경계는 관리자용 일괄 확정 카드 밖에는 적혀 있지 않아 여기로 올린다. */ ?>
  <?php vg_page_title('자산', 'ASSETS', '에이전트가 등록한 호스트별 수집 상태와 탐지 결과입니다.', [
      'suffix_html' => vg_help('자산 등급은 사람이 확정합니다 — 시스템 제안값은 초안이며 확정이 아닙니다. '
          . '확정 해제는 자산 상세에서 한 대씩 합니다.'),
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
  $stateTone = ['ok' => 'ok', 'stale' => 'high', 'offline' => 'crit', 'none' => 'muted'];
  $totalHosts = array_sum($stateCounts);
  ?>
  <div class="cards">
    <div class="kpi kpi--sm"><b><?= number_format($totalHosts) ?></b><span>전체 자산</span></div>
    <?php /* 정보시스템 등급 — 확정 등급의 최고값 승계. 확정이 하나도 없으면 '미지정'. */ ?>
    <div class="kpi kpi--sm" title="<?= vg_h($systemGrade['reason'] ?? '확정된 자산 등급이 아직 없습니다.') ?>">
      <b><?= vg_h($systemGrade['grade'] ?? '–') ?></b><span>정보시스템 등급</span>
    </div>
    <?php /* 미확정 — 눌러서 그 자산만 거른다(등급 필터의 '미지정'과 같은 조건). 0 이면 톤을 뺀다. */ ?>
    <a class="kpi kpi--sm<?= $unconfirmed > 0 ? ' tone-med' : '' ?><?= $grade === 'none' ? ' is-selected' : '' ?>"
       title="아직 사람이 등급을 확정하지 않은 자산입니다. 시스템 제안값은 확정이 아닙니다."
       href="<?= vg_h(vg_qs(['grade' => $grade === 'none' ? '' : 'none', 'page' => null])) ?>">
      <b><?= number_format($unconfirmed) ?></b><span>등급 미확정</span>
    </a>
    <?php foreach (VG_ASSET_STATES as $key => $label): ?>
      <a class="kpi kpi--sm tone-<?= vg_h($stateTone[$key]) ?><?= $state === $key ? ' is-selected' : '' ?>"
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
      $headers[] = ['label' => '', 'key' => 'pick', 'width' => '2.5rem', 'align' => 'center'];
  }
  $headers = array_merge($headers, [
      // '노출' 열을 걷어내며 그 폭을 여기로 옮겼다(이 파일의 폭 배분 원칙: 남는 폭은 식별자가 갖는다).
      ['label' => '호스트', 'key' => 'fqdn', 'class' => 'col-id', 'width' => '22%'],
      ['label' => '상태', 'key' => 'state', 'width' => '5.5rem', 'title' => $stateHelp],
      // 등급 열도 뱃지(고정 크기)라 % 가 아니라 rem 이다 — 위 주석의 기준을 그대로 따른다.
      //   'C · 기밀'(약 62px) + 칸 여백(.6rem×2 ≈ 19px) → 5.5rem.
      //   C/S/O 기호만 떠 있으면 뜻을 알 수 없어 열 이름에 한 줄 범례를 단다(어휘는 assetgrade.php 소유).
      ['label' => '등급', 'key' => 'grade', 'width' => '5.5rem', 'title' => vg_asset_grade_legend()],
      ['label' => 'OS', 'key' => 'os', 'width' => '9%'],
      ['label' => 'IP', 'key' => 'ip', 'width' => '9%', 'nowrap' => true],
      ['label' => '에이전트', 'key' => 'agent_version', 'width' => '5rem'],
      /* '노출'(리스닝 소켓 개수) 열은 뺐다 — 이 목록은 "어느 자산을 먼저 볼 것인가" 를 정하는
       *   자리인데, 소켓 개수는 그 판단에 못 쓴다. 3개든 30개든 위험은 **어느 범위로 열렸는가**
       *   (EXTERNAL/LAN/…)에서 갈리고 그 값은 여기 없다. 위험은 옆의 '심각도' 열이 말하고,
       *   범위별 목록은 호스트 상세의 런타임 탭이 답한다. */
      // 값은 짧은 숫자지만 **열 이름**('패키지', 약 45px)이 줄바꿈 불가라 폭 기준은 그쪽이다 —
      //   5%(1440px 에서 66px)면 칸 여백(.6rem×2 ≈ 19px)까지 못 담아 머리글이 '패키 / 지' 로 접혔다.
      ['label' => '패키지', 'key' => 'package_count', 'align' => 'right', 'width' => '4.5rem'],
      ['label' => '심각도', 'key' => 'sev', 'width' => '13%'],
      ['label' => '최신 수집', 'key' => 'collected_at', 'width' => '12%', 'nowrap' => true],
  ]);
  // 액션 열만 % 가 아니라 rem 이다. 삭제 버튼은 폭이 늘 같은 고정 크기 조작부라 비율로 줄 이유가 없고,
  //   비율로 주면 표가 좁아질 때 버튼보다 좁아진다 — 실제로 900px 에서 9%(=51px)가 68px 버튼을
  //   못 담아 카드를 16.7px 밀어냈다(가로 스크롤). 5rem 이면 어느 폭에서도 버튼이 들어간다.

  /* 표 전체를 일괄 확정 폼으로 감싼다 — 행의 체크박스와 아래 확정 바가 한 폼이어야 같이 전송된다.
   *   선택은 **지금 보고 있는 페이지** 안에서만 유효하다(페이지를 넘기면 체크가 풀린다).
   *   "필터에 걸린 전체"를 대상으로 삼지 않는 건 의도다 — 눈에 안 보이는 자산까지 확정되면 안 된다. */
  if ($canConfirm) {
      echo '<form method="post" data-confirm="선택한 자산의 등급을 확정할까요? 자산마다 확정자와 시각이 감사로그에 기록됩니다.">';
      echo '<input type="hidden" name="csrf" value="' . vg_h(vg_csrf_token()) . '">';
  }

  vg_table(
      $headers,
      $rows,
      [
          // 빈 이유가 셋이라 메시지도 셋 — "필터 때문에 빈 것" 과 "자산이 없는 것" 은 다른 상황이다.
          'empty' => ($q !== '' || $state !== '' || $grade !== '')
              ? [
                  'icon'  => '🔍',
                  'title' => '조건에 맞는 자산이 없습니다.',
                  'hint'  => '검색어나 상태·등급 필터를 바꿔 보세요.',
                  'cta'   => ['href' => '/assets.php', 'label' => '필터 초기화'],
              ]
              : [
                  'icon'  => '🖥️',
                  'title' => '등록된 자산이 없습니다.',
                  'hint'  => '자산은 에이전트가 수집을 보내면 자동 등록됩니다. 상단의 [에이전트 설치 안내]를 따르세요.',
              ],
          'cell' => [
              // 일괄 확정 대상 선택. 아래 폼 안에 표가 들어 있어 그대로 같이 전송된다.
              'pick' => fn($r) => '<input type="checkbox" name="host_ids[]" value="' . (int) $r['host_id']
                  . '" aria-label="' . vg_h($r['fqdn']) . ' 선택">',
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
              'os'            => fn($r) => vg_h(trim($r['os_id'] . ' ' . $r['os_version'])) ?: '<span class="why">–</span>',
              'ip'            => fn($r) => !empty($r['last_seen_ip'])
                  ? '<code>' . vg_h((string) $r['last_seen_ip']) . '</code>'
                  : '<span class="why">–</span>',
              // 구버전 뱃지: 이 호스트만 옛 에이전트가 돈다는 뜻이다(중앙은 노드에 내려보내지 않는다).
              //   갱신은 master 에서 `deploy/agent_push.sh <노드>` — 토큰·타이머는 건드리지 않는다.
              'agent_version' => function ($r) use ($latestAgent) {
                  if (!$r['agent_version']) { return '<span class="why">–</span>'; }
                  $v   = (string) $r['agent_version'];
                  $old = $latestAgent !== '' && version_compare($v, $latestAgent, '<');
                  return '<code>' . vg_h($v) . '</code>'
                       . ($old ? ' ' . vg_badge('구버전', 'med',
                             "함대 최신은 {$latestAgent} — master 에서 deploy/agent_push.sh 로 갱신하세요") : '');
              },
              'package_count' => fn($r) => $r['scan_id'] !== null
                  ? '<a href="/host.php?id=' . (int)$r['host_id'] . '&amp;tab=packages">' . number_format((int)$r['package_count']) . '</a>'
                  : '<span class="why">–</span>',
              // 뱃지를 누르면 그 호스트·등급의 취약점 목록으로.
              'sev' => fn($r) => vg_sev_counts(
                  $sevByScan[(int) $r['scan_id']] ?? [],
                  fn(string $s) => '/findings.php?host=' . (int) $r['host_id'] . '&sev=' . $s
              ),
              'collected_at' => fn($r) => $r['collected_at'] ? '<span class="why">' . vg_h($r['collected_at']) . '</span>' : '<span class="why">–</span>',
          ],
      ]
  );
  if ($rows) { vg_page_nav($total, $perPage, $page); }
  ?>

  <?php if ($canConfirm && $rows): ?>
    <div class="card mt-lg">
      <strong>선택 자산 등급 일괄 확정</strong>
      <div class="card__body">
        <?php /* 컨트롤이 넷뿐이라 세로 스택(.setting-form)은 화면 높이만 먹는다 — 한 줄로 흐르고
                 좁아지면 접히는 .form-bar 를 쓴다. 전체 선택은 체크박스라 라벨과 같은 줄이어야
                 해서 이 저장소에 이미 있는 label.inline 패턴을 그대로 따른다(connectors.php). */ ?>
        <div class="form-bar">
          <label class="inline" for="bulk-pick-all">
            <input id="bulk-pick-all" type="checkbox" data-checkall="host_ids[]">
            <span>이 페이지 전체 선택</span>
          </label>

          <label class="field" for="bulk-criticality">중요도
            <select id="bulk-criticality" name="criticality">
              <option value="">변경 안 함</option>
              <?php foreach (VG_ASSET_CRITICALITY as $v => $label): ?>
                <option value="<?= vg_h($v) ?>"><?= vg_h($label) ?></option>
              <?php endforeach; ?>
            </select>
          </label>

          <label class="field" for="bulk-grade">보안등급 (N2SF)
            <select id="bulk-grade" name="grade" required>
              <option value="">고르세요</option>
              <?php foreach (VG_ASSET_GRADES as $v => $label): ?>
                <option value="<?= vg_h($v) ?>"><?= vg_h($label) ?></option>
              <?php endforeach; ?>
            </select>
          </label>

          <label class="field field--grow" for="bulk-grade-reason">확정 근거
            <input id="bulk-grade-reason" type="text" name="grade_reason" maxlength="255"
                   placeholder="예: 「정보공개법」 제9조 제6호 해당 업무정보 보유">
          </label>

          <button class="btn btn--primary" type="submit" data-loading="확정 중…">선택 자산 등급 확정</button>
        </div>

        <?php /* 판정 기준은 산문이 아니라 정의목록으로 준다 — 등급 어휘는 assetgrade.php 가 소유하고
                 (같은 문자열을 화면마다 다시 적지 않는다), 나머지는 이 폼이 실제로 하는 일이다. */ ?>
        <dl class="criteria">
          <dt>보안등급</dt>
          <dd>N2SF <?= vg_h(vg_asset_grade_legend()) ?> — 「정보공개법」 제9조 비공개 대상정보 해당 여부로 가릅니다.
            등급 확정은 기관의 법적 처분이라 시스템이 대신하지 않습니다.</dd>
          <dt>중요도</dt>
          <dd>상 / 중 / 하 — 등급과 별개로 사람이 지정합니다. ‘변경 안 함’ 이면 지금 값을 그대로 둡니다.</dd>
          <dt>확정 범위</dt>
          <dd>지금 보고 있는 페이지에서 고른 자산만, 한 번에 500대까지. 자산마다 확정자·시각이 감사로그에 남습니다.</dd>
        </dl>
      </div>
    </div>
  <?php endif; ?>
  <?php if ($canConfirm) { echo '</form>'; } ?>

  <?php
  /* 설치 안내는 자산을 처음 붙일 때 한 번 보는 것이다. 목록 아래 늘 펼쳐두면
   * 매일 보는 화면이 그만큼 길어진다 → 버튼 뒤 모달로. */
  vg_modal_open('agentInstall', '에이전트 설치', 'modal--wide');
  ?>
    <div class="why">자산은 에이전트가 수집을 보내면 <strong>자동 등록</strong>됩니다.
      중앙에서 대상 서버로 접속하지 않습니다(아웃바운드 push).</div>

    <div class="why mt"><strong>1) 설치 스크립트 두 개와 이 배포의 루트 CA를 받습니다.</strong>
      레포 체크아웃 없이 버튼으로 받아 대상 서버로 옮깁니다.</div>

    <div class="mt">
      <a class="btn btn--sm btn--ghost" href="/agent-dl.php?f=install-agent.sh" download>⬇ install-agent.sh</a>
      <a class="btn btn--sm btn--ghost" href="/agent-dl.php?f=vuln-inventory-agent.sh" download>⬇ vuln-inventory-agent.sh</a>
      <a class="btn btn--sm btn--ghost" href="/agent-dl.php?f=caddy-root.crt" download>⬇ caddy-root.crt</a>
    </div>

    <pre class="code">scp install-agent.sh vuln-inventory-agent.sh caddy-root.crt 대상서버:~/</pre>

    <div class="why mt"><strong>2) 대상 서버(Linux)</strong>의 <code>/opt/vuln-agent/</code> 에 두고 한 번 실행합니다.
      인자 없이 실행하면 주소·토큰·주기를 물어봅니다.</div>

    <pre class="code">ssh 대상서버
sudo mkdir -p /opt/vuln-agent &amp;&amp; sudo cp ~/install-agent.sh ~/vuln-inventory-agent.sh ~/caddy-root.crt /opt/vuln-agent/
cd /opt/vuln-agent
sudo bash install-agent.sh
  중앙 서버 주소 (예: vulnagent.example.com:8080): <?= vg_h($ingest) ?>

  전송 토큰 (입력은 화면에 보이지 않습니다): ********
  수집 주기 [hourly] (daily / '*:0/30'=30분마다):</pre>

    <ul class="hint-list why">
      <li><code>caddy-root.crt</code> 는 현재 자체서명 Caddy(HTTPS)를 신뢰하기 위한 공개 인증서입니다. <code>install-agent.sh</code> 옆에 두면 설치 시 자동 등록됩니다. 이 파일은 배포마다 다르며, 503 안내가 뜨면 중앙 관리자가 아직 추출하지 않은 것입니다.</li>
      <li>수집 엔드포인트: <code class="selectable"><?= vg_h($ingest) ?></code> — 대상 서버 → 중앙 아웃바운드 1개면 충분합니다.</li>
      <li>대상 서버에는 POSIX <code>awk</code>와 HTTPS 전송용 <code>curl</code> 또는 <code>wget</code> 중 하나가 필요합니다. <code>jq</code>는 선택 사항이며 설치기가 패키지를 추가로 설치하지 않습니다.</li>
      <li><code>chmod</code>/<code>chown</code> 은 필요 없습니다. <code>sudo bash &lt;파일&gt;</code>로 실행하면 설치물이 root 소유·적정 권한으로 배치됩니다.</li>
      <li>systemd 환경은 상시 서비스가 10초마다 명령을 확인해 정기·즉시·예약 실행과 중단을 지원합니다. systemd가 없으면 cron 정기수집만 지원합니다.</li>
      <li>토큰은 <a href="/agent-tokens.php">에이전트 토큰</a> 화면에서 이 호스트(fqdn)용으로 발급받아 넣습니다 —
        그 호스트만 갱신할 수 있어 다른 호스트로 위조하는 요청을 막습니다.</li>
      <li>제거: <code>sudo bash install-agent.sh --uninstall</code></li>
    </ul>
    <?php vg_modal_foot(null); ?>
  <?php vg_modal_close(); ?>
<?php vg_footer();
