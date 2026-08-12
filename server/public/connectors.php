<?php
declare(strict_types=1);

/**
 * connectors.php — CVE 피드 커넥터 관리 (admin 전용).
 *   목록/추가/편집/삭제, 즉시 실행(수동), 최근 수집 이력.
 *   활성 여부는 편집 폼의 '활성' 체크박스 하나로만 바꾼다.
 */

require_once __DIR__ . '/../src/auth.php';
require_once __DIR__ . '/../src/view.php';
require_once __DIR__ . '/../src/feeds.php';
require_once __DIR__ . '/../src/matcher.php';
require_once __DIR__ . '/../src/audit.php';   // vg_soft_delete / vg_log_activity
require_once __DIR__ . '/../src/connector_actions.php';   // POST 액션(save/run/delete) 처리
vg_require_menu('connectors');   // 피드 커넥터: 설정형 권한

// 범용 API 커넥터(generic_api)의 역할 라벨 — 단일 소스. <select id="gRole"> 옵션과
//   connectors.js 가 각자 하드코딩해 두 곳이 따로 놀던 것을 여기로 합친다. $roleGroups(아래)
//   카드 타이틀과 뜻은 겹치지만 "취약점 정체 — 무엇인가" 처럼 부가설명이 붙어 있어 옵션 라벨
//   (설명 없는 짧은 형태)로 그대로 못 쓴다 — 억지로 문자열을 자르지 않고 새 상수로 둔다.
const VG_GENERIC_ROLE_LABELS = [
    'identity' => '취약점 정체', 'priority' => '우선순위 신호',
    'vendor' => '벤더 패치 판정',
];

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

$connectors = $pdo->query('SELECT * FROM tb_feed_connector WHERE is_deleted = 0 ORDER BY feed_connector_id')->fetchAll();

/* 수집 이력. 목록의 [상세]에서 ?conn=N 으로 들어오면 해당 커넥터 정보와 전체 이력을
 * 한곳에 보여준다. 최근 이력 모달과 전체 이력 화면이 같은 내용을 중복하던 경로는 합쳤다. */
$perPage  = vg_perpage();
$page     = vg_page();
$connFilter = (int) ($_GET['conn'] ?? 0);

$logCountByConn = [];
foreach ($pdo->query(
    'SELECT feed_connector_id, COUNT(*) AS total
       FROM tb_feed_collection_log GROUP BY feed_connector_id'
)->fetchAll() as $r) {
    $logCountByConn[(int) $r['feed_connector_id']] = (int) $r['total'];
}

// ?conn=N — 그 커넥터의 전체 이력(페이지네이션)
$logs = []; $logTotal = 0; $connName = ''; $connDetail = null;
if ($connFilter > 0) {
    foreach ($connectors as $c) {
        if ((int) $c['feed_connector_id'] === $connFilter) {
            $connName = (string) $c['name'];
            $connDetail = $c;
            break;
        }
    }
    $logTotal = $logCountByConn[$connFilter] ?? 0;
    $offset   = ($page - 1) * $perPage;
    $st = $pdo->prepare(
        "SELECT status, trigger_by, items_fetched, items_upserted, message, started_at
           FROM tb_feed_collection_log WHERE feed_connector_id = ?
          ORDER BY started_at DESC
          LIMIT $perPage OFFSET $offset"
    );
    $st->execute([$connFilter]);
    $logs = $st->fetchAll();
}

$csrf = vg_csrf_token();

// 편집 대상 — ?edit=N 이면 추가/편집 모달을 그 값으로 채워 자동으로 연다.
$edit = null;
if (isset($_GET['edit'])) {
    foreach ($connectors as $c) { if ((int) $c['feed_connector_id'] === (int) $_GET['edit']) { $edit = $c; } }
}
$saveFailed = $err !== null && ($_POST['action'] ?? '') === 'save';
if ($saveFailed) {
    $submittedId = (int) ($_POST['id'] ?? 0);
    $submitted = null;
    foreach ($connectors as $c) {
        if ((int) $c['feed_connector_id'] === $submittedId) { $submitted = $c; break; }
    }
    $edit = $submitted ?? ['feed_connector_id' => $submittedId];
    $edit['name'] = (string) ($_POST['name'] ?? '');
    $edit['connector_type'] = (string) ($_POST['connector_type'] ?? 'kev');
    $edit['enabled'] = isset($_POST['enabled']) ? 1 : 0;
    $edit['connection_json'] = $edit['connector_type'] === 'generic_api'
        ? (string) ($_POST['g_config_json'] ?? '{}')
        : json_encode([
            'url' => (string) ($_POST['url'] ?? ''),
            'api_key' => (string) ($_POST['api_key'] ?? ''),
            'ecosystem' => (string) ($_POST['ecosystem'] ?? ''),
            'days' => (string) ($_POST['days'] ?? ''),
        ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    $edit['schedule_json'] = json_encode([
        'mode' => (string) ($_POST['schedule_mode'] ?? 'manual'),
        'interval_minutes' => (string) ($_POST['interval_minutes'] ?? ''),
        'time' => (string) ($_POST['schedule_time'] ?? ''),
        'expr' => (string) ($_POST['schedule_cron'] ?? ''),
    ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
}
$econn = $edit ? vg_json_col($edit['connection_json']) : [];
$esched = $edit ? vg_json_col($edit['schedule_json']) : [];

/* 수집 상태 → 한글 라벨 + 뱃지 톤(색은 CSS 가 결정).
 * 라벨과 톤을 한 표에 둔다 — 전엔 톤만 있고 뱃지 글자는 DB 값(success/never)이 그대로 나갔다. */
const VG_COLLECT_STATUS = [
    'success' => ['성공', 'ok'], 'error' => ['실패', 'danger'],
    'running' => ['수집 중', 'warn'], 'never' => ['미실행', 'muted'],
];
$statusBadge = static function (?string $s): string {
    $s = (string) ($s ?: 'never');
    [$label, $tone] = VG_COLLECT_STATUS[$s] ?? [$s, 'muted'];
    return vg_badge($label, $tone);
};
// 실행 계기 — DB 값(manual/schedule)을 그대로 보여주지 않는다.
const VG_COLLECT_TRIGGER = ['manual' => '직접 실행', 'schedule' => '예약'];

vg_header('데이터 수집', 'connectors');
?>
  <?php vg_page_title('데이터 수집', 'DATA SOURCES', '외부 취약점 데이터와 수집 상태를 관리합니다.', [
      'actions' => vg_capture(static fn() => vg_modal_btn('connModal', '+ 데이터 소스 추가')),
  ]); ?>

  <?php vg_alert($msg, 'ok'); vg_alert($err); ?>

  <?php
  // 표시용 부가값(스케줄 라벨/다음 실행) 을 미리 계산해 각 행에 얹는다.
  foreach ($connectors as &$c) {
      $sc = vg_json_col($c['schedule_json']);
      $mode = $sc['mode'] ?? 'manual';
      switch ($mode) {
          case 'interval':
              // 분으로만 적으면 "매 10080분" 처럼 사람이 계산해야 읽힌다 — 나누어떨어지는 단위로 올린다.
              $m = (int) ($sc['interval_minutes'] ?? 0);
              if ($m >= 1440 && $m % 1440 === 0) {
                  $d = intdiv($m, 1440);
                  $c['_sched_label'] = $d === 1 ? '매일' : '매 ' . $d . '일';
              } elseif ($m >= 60 && $m % 60 === 0) {
                  $c['_sched_label'] = '매 ' . intdiv($m, 60) . '시간';
              } else {
                  $c['_sched_label'] = '매 ' . $m . '분';
              }
              break;
          case 'daily':    $c['_sched_label'] = '매일 ' . ($sc['time'] ?? '?'); break;
          case 'cron':     $c['_sched_label'] = 'cron: ' . ($sc['expr'] ?? '?'); break;
          default:         $c['_sched_label'] = '수동';
      }
      $c['_next_run'] = ($c['enabled'] && $mode !== 'manual') ? ($c['next_run_at'] ?: vg_schedule_next($sc)) : '–';
      if ((int) $c['feed_connector_id'] === $connFilter) { $connDetail = $c; }
  }
  unset($c);

  // 커넥터를 역할별로 나눠 보여준다. 11종이 한 표에 평평하게 있으면 "무엇이 취약점을
  // 가져오고 무엇이 벤더 패치버전을 가져오는지" 가 안 보인다. 분류 기준은 docs/dev/피드소스-역할.md.
  //   타입 → 그룹 매핑은 아래 목록이 유일한 근거다(새 타입은 여기 한 줄 추가). 목록에 없는
  //   타입은 맨 아래 '기타' 로 떨어져 화면에서 사라지지 않는다.
  $roleGroups = [
      ['title' => '취약점 정보',
       'desc'  => 'CVE 설명, CVSS, 영향 버전의 기준 데이터입니다.',
       'types' => ['nvd', 'osv', 'kisa']],
      ['title' => '위험 신호',
       'desc'  => 'KEV의 실제 악용 여부와 EPSS 악용 확률입니다.',
       'types' => ['kev', 'epss']],
      ['title' => '벤더 판정',
       'desc'  => '배포판별 수정 버전과 미수정 상태를 확인합니다.',
       'types' => ['debtracker', 'rhoval', 'rhunfixed', 'ubuntuoval', 'kcve']],
      ['title' => '보안 기준',
       'desc'  => 'CIS·NIST·STIG 기반의 보안 설정 점검 기준입니다.',
       'types' => ['ssg']],
  ];

  $tableHeaders = [
      ['label' => '소스'], ['label' => '주기'], ['label' => '실행 시각', 'nowrap' => true],
      ['label' => '상태'], ['label' => '작업', 'align' => 'right'],
  ];
  $tableCells = [
      0 => fn($c) => '<strong><a href="?conn=' . (int) $c['feed_connector_id']
          . '#collection-history">' . vg_h($c['name']) . '</a></strong>',
      1 => fn($c) => '<span class="why">' . vg_h($c['_sched_label']) . '</span>',
      2 => fn($c) => '<span class="why">최근 ' . vg_h($c['last_run_at'] ?? '–')
          . '<br>다음 ' . vg_h($c['_next_run'] ?: '–') . '</span>',
      // 상태 칸은 "지금 어떤 상태인가" 만 보여준다 — 켜기/끄기는 편집 폼의 '활성' 체크박스 하나로
      //   한다(전엔 여기 토글 버튼이 하나 더 있어 같은 일을 하는 경로가 둘이었다).
      //   꺼진 커넥터는 수집 결과 뱃지만 보면 "왜 안 도는지" 를 알 수 없으므로 '중지' 를 앞에 붙인다.
      3 => function ($c) use ($statusBadge) {
          return '<div class="stack-sm">'
          . ($c['enabled'] ? '' : vg_badge('중지', 'muted'))
          . $statusBadge($c['last_status'] !== null ? (string) $c['last_status'] : null) . '</div>';
      },
      4 => function ($c) use ($csrf, $logCountByConn) {
          $html = '';
          if ($c['last_message']) {
              $html .= '<span class="sr-only">' . vg_h($c['last_message']) . '</span>';
          }
          $id = (int) $c['feed_connector_id'];
          $n  = $logCountByConn[$id] ?? 0;
          /* 버튼 서열: 주작업(실행)만 채운 색, 그 다음이 편집(btn--secondary — 강조색 외곽선),
           * 나머지는 중립 외곽선(ghost). 크기는 표 안이라 전부 btn--xs 로 맞춘다 —
           * btn--sm 은 행 높이를 키워 한 화면에 보이는 소스 수를 줄인다. 파괴작업(삭제)은 색을 빼고
           * 구분점 뒤로 밀어 자주 쓰는 것(실행·상세·편집)과 눈으로 갈리게 한다 — 확인창은
           * data-confirm 으로 그대로 살아 있다. 예전엔 삭제가 화면에서 가장 강한 요소였고,
           * 소스가 늘수록 빨간 점이 표를 덮었다.
           * 개수는 <span> 으로 감싸지 않는다 — .btn 은 display:flex 라 별개 항목이 되어
           * gap 만큼 '상세 149' 가 벌어져 이 버튼만 폭이 달라 보였다(assets.php 와 같은 함정). */
          return $html . '<div class="actions">'
              . '<form method="post"><input type="hidden" name="csrf" value="' . vg_h($csrf) . '"><input type="hidden" name="action" value="run"><input type="hidden" name="id" value="' . $id . '">'
              . '<button class="btn btn--xs btn--primary" data-loading="수집 중…">실행</button></form>'
              . '<a class="btn btn--xs btn--ghost" href="?conn=' . $id . '#collection-history">'
              . '상세 ' . number_format($n) . '</a>'
              . '<a class="btn btn--xs btn--secondary" href="?edit=' . $id . '">편집</a>'
              . '<span class="why" aria-hidden="true">·</span>'
              . '<form method="post" data-confirm="이 데이터 소스를 삭제할까요? 예약 수집은 중단되며 기존 이력은 남습니다."><input type="hidden" name="csrf" value="' . vg_h($csrf) . '"><input type="hidden" name="action" value="delete"><input type="hidden" name="id" value="' . $id . '">'
              . '<button class="btn btn--xs btn--ghost">삭제</button></form>'
              . '</div>';
      },
  ];

  if (!$connectors) {
      // 등록된 게 하나도 없으면 그룹 헤딩 없이 안내만.
      vg_table($tableHeaders, [], ['empty' => [
          'icon'  => '🔌',
          'title' => '등록된 데이터 소스가 없습니다.',
          'hint'  => '[+ 데이터 소스 추가]에서 수집 대상을 등록합니다.',
      ]]);
  } else {
      // 타입 → 그룹 인덱스. 그룹에 담고, 매핑에 없는 타입은 '기타' 로.
      $typeGroup = [];
      foreach ($roleGroups as $gi => $g) { foreach ($g['types'] as $t) { $typeGroup[$t] = $gi; } }
      // generic_api 는 타입이 하나뿐이라 위 표로 그룹을 못 정한다 — connection_json.role 로 정한다
      // (VG_GENERIC_ROLES 순서와 앞의 세 roleGroups 카드가 그대로 대응: identity/priority/vendor).
      $genericRoleGroup = ['identity' => 0, 'priority' => 1, 'vendor' => 2];
      $grouped = []; $others = [];
      foreach ($connectors as $c) {
          if ($c['connector_type'] === 'generic_api') {
              $gc = vg_json_col($c['connection_json']);
              $gi = $genericRoleGroup[$gc['role'] ?? ''] ?? null;
          } else {
              $gi = $typeGroup[$c['connector_type']] ?? null;
          }
          if ($gi === null) { $others[] = $c; } else { $grouped[$gi][] = $c; }
      }
      foreach ($roleGroups as $gi => $g) {
          if (empty($grouped[$gi])) { continue; }
          echo '<div class="card"><strong>' . vg_h($g['title']) . '</strong>'
             . ' <span class="why">— ' . vg_h($g['desc']) . '</span>'
             . '<div class="card__body">';
          vg_table($tableHeaders, $grouped[$gi], ['card' => false, 'cell' => $tableCells]);
          echo '</div></div>';
      }
      if ($others) {
          echo '<div class="card"><strong>기타</strong><div class="card__body">';
          vg_table($tableHeaders, $others, ['card' => false, 'cell' => $tableCells]);
          echo '</div></div>';
      }
  }
  ?>

  <?php
  // 추가·편집 폼은 목록 아래 늘 펼쳐두던 것 → 버튼 뒤 모달로.
  // ?edit=N 으로 들어오면(행의 [편집]) 값이 채워진 채 자동으로 열린다.
  vg_modal_open('connModal', $edit ? '데이터 소스 편집' : '데이터 소스 추가', '', $edit !== null);

  /* 타입 → 수집 방식·노출 필드. 근거는 src/feeds.php 의 카탈로그 하나다 — PHP 가 첫 화면을
   * 그리고(JS 없이도 맞다), 같은 표를 JSON 으로 넘겨 JS 가 타입 변경 때 다시 그린다.
   * 표를 JS 에 복붙하면 커넥터가 늘 때 한쪽만 고쳐진다(data-edit-generic 이 쓰는 것과 같은 수법). */
  $typeMeta = [];
  foreach (VG_CONNECTOR_TYPES as $tv => $m) {
      $tr = VG_TRANSPORTS[$m['transport']];
      $typeMeta[$tv] = [
          'transport' => $tr['label'], 'tone' => $tr['tone'], 'desc' => $m['desc'],
          'fields'    => $m['fields'], 'urlLabel' => $m['url_label'] ?? '',
      ];
  }
  $curType = (string) ($edit['connector_type'] ?? 'kev');
  if (!isset($typeMeta[$curType])) { $curType = 'kev'; }
  $curMeta = $typeMeta[$curType];
  // 이 타입이 안 읽는 필드는 아예 숨긴다 — 예전엔 전 타입에 다 띄우고 라벨의 괄호로 변명했다.
  $fieldOn = fn(string $f): string => in_array($f, $curMeta['fields'], true) ? '' : ' hidden';
  ?>
    <?php /* .setting-form + .field — 라벨과 입력이 한 칸(.45rem) 안에서 붙고 항목끼리는 1rem 으로
             벌어진다(host.php 자산등급 폼과 같은 규약). 두 가지를 지킨다:
               · 라벨은 <label> 그대로 두고 감싸는 div 에만 .field 를 준다 — connectors.js 가
                 #urlLabel 의 textContent 를 갈아치우므로 라벨이 입력을 품으면 그 순간 입력이 사라진다.
               · JS/PHP 가 hidden 속성으로 껐다 켜는 상자(#stdFields·#genericFields·[data-field]·
                 [data-schedule-field])에는 .field/.setting-form 을 주지 않는다 — app.css 에
                 [hidden] 규칙이 없어서 display 를 정하는 클래스가 붙는 순간 hidden 이 무력해진다. */ ?>
    <form id="connForm" method="post" class="setting-form"
          data-edit-generic="<?= ($edit['connector_type'] ?? '') === 'generic_api' ? vg_h(json_encode($econn)) : '' ?>"
          data-type-meta="<?= vg_h(json_encode($typeMeta, JSON_UNESCAPED_UNICODE)) ?>"
          data-role-labels="<?= vg_h(json_encode(VG_GENERIC_ROLE_LABELS, JSON_UNESCAPED_UNICODE)) ?>">
      <input type="hidden" name="csrf" value="<?= vg_h($csrf) ?>">
      <input type="hidden" name="action" value="save">
      <input type="hidden" name="id" value="<?= (int) ($edit['feed_connector_id'] ?? 0) ?>">
      <?php /* 짧은 입력(이름·종류)은 2열로 눕힌다 — 한 줄씩 쌓으면 모달이 세로로만 길어져
               스케줄·활성이 스크롤 아래로 밀렸다. 감싸는 상자는 hidden 으로 껐다 켜지 않는
               것만 고른다(.form-grid 는 display:grid 라, 토글되는 상자에 붙이면 hidden 이 무력해진다
               — 위 주석의 같은 함정). */ ?>
      <div class="form-grid">
        <div class="field">
          <label for="connName">이름</label>
          <input type="text" id="connName" name="name" value="<?= vg_h($edit['name'] ?? '') ?>" required>
        </div>
        <div class="field">
          <label for="connType">소스 종류</label>
          <select name="connector_type" id="connType">
            <?php foreach (VG_CONNECTOR_TYPES as $tv => $m): ?>
              <option value="<?= vg_h($tv) ?>" <?= $curType===$tv?'selected':'' ?>><?= vg_h($m['label']) ?></option>
            <?php endforeach; ?>
          </select>
        </div>
      </div>
      <?php /* 수집 방식 — 이 커넥터가 데이터를 어떻게 가져오는가(역할이 아니다. 역할은 목록의 그룹 카드). */ ?>
      <div class="connmeta" id="connTransport">
        <?= vg_badge($curMeta['transport'], $curMeta['tone']) ?>
        <div class="sub" id="connTransportDesc"><?= vg_h($curMeta['desc']) ?></div>
      </div>
      <?php /* #stdFields 자신에는 .form-grid 를 못 준다(JS 가 이 상자를 hidden 으로 통째로 껐다 켠다).
               안쪽에 격자 상자를 하나 더 둔다 — connectors.js 는 std.querySelectorAll('[data-field]')
               로 후손을 찾으므로 한 겹이 늘어도 그대로 동작한다. URL 은 값이 길어 한 줄을 다 쓴다. */ ?>
      <div id="stdFields">
        <div class="form-grid">
          <div class="form-grid__full" data-field="url"<?= $fieldOn('url') ?>>
            <label id="urlLabel" for="connUrl"><?= vg_h($curMeta['urlLabel'] ?: 'URL') ?></label>
            <input type="text" id="connUrl" name="url" value="<?= vg_h($econn['url'] ?? '') ?>" placeholder="비우면 기본 주소를 씁니다">
          </div>
          <div class="form-grid__full" data-field="api_key"<?= $fieldOn('api_key') ?>>
            <label for="connApiKey">API Key</label>
            <input type="text" id="connApiKey" name="api_key" value="<?= vg_h($econn['api_key'] ?? '') ?>">
          </div>
          <div data-field="ecosystem"<?= $fieldOn('ecosystem') ?>>
            <label for="connEcosystem">Ecosystem</label>
            <input type="text" id="connEcosystem" name="ecosystem" value="<?= vg_h($econn['ecosystem'] ?? '') ?>" placeholder="예: Rocky Linux">
          </div>
          <div data-field="days"<?= $fieldOn('days') ?>>
            <label for="connDays">최근 N일</label>
            <input type="text" id="connDays" name="days" value="<?= vg_h((string) ($econn['days'] ?? '')) ?>" placeholder="7">
          </div>
        </div>
      </div>
      <?php /* #stdFields 와 같은 이유로 안쪽에 격자 상자를 둔다(이 상자도 JS 가 통째로 토글한다).
               긴 값(URL 템플릿·헤더·아이템 경로·필드 매핑)만 한 줄을 다 쓰고, 짧은 것은 2열. */ ?>
      <div id="genericFields" hidden>
       <div class="form-grid">
        <div class="field">
          <label for="gRole">역할</label>
          <select id="gRole">
            <?php foreach (VG_GENERIC_ROLE_LABELS as $rv => $rl): ?>
              <option value="<?= vg_h($rv) ?>"><?= vg_h($rl) ?></option>
            <?php endforeach; ?>
          </select>
        </div>
        <div class="alert alert--warn form-grid__full" id="gRoleNotice" hidden>
          <strong>기존 설정의 역할은 더 이상 지원하지 않습니다.</strong>
          <ul class="hint-list"><li>지원되는 역할을 다시 선택해야 저장할 수 있습니다.</li></ul>
        </div>

        <div class="field">
          <label for="gMethod">HTTP 메서드</label>
          <select id="gMethod">
            <option value="GET">GET</option>
            <option value="POST">POST</option>
          </select>
        </div>

        <div class="field form-grid__full">
          <label for="gUrlTemplate">URL 템플릿</label>
          <input type="text" id="gUrlTemplate" placeholder="https://api.example.com/vulns?page={page}">
          <div class="sub">플레이스홀더: <code>{page}</code>(1부터) · <code>{offset}</code>(0부터) · <code>{today}</code> · <code>{days_ago_N}</code></div>
        </div>

        <div class="field form-grid__full">
          <label>인증 헤더</label>
          <div id="gHeaders" class="kvrows"></div>
          <div><button type="button" class="btn btn--sm btn--ghost" id="gHeaderAdd">+ 헤더 추가</button></div>
        </div>

        <div class="field">
          <label for="gPageType">페이징 타입</label>
          <select id="gPageType">
            <option value="none">없음</option>
            <option value="offset">offset</option>
          </select>
        </div>
        <div class="field">
          <label for="gPageSize">페이지 크기</label>
          <input type="text" id="gPageSize" placeholder="100">
        </div>
        <div class="field">
          <label for="gTotalPath">총 건수 경로 (선택)</label>
          <input type="text" id="gTotalPath" placeholder="meta.total">
        </div>

        <div class="field form-grid__full">
          <label for="gItemsPath">응답 아이템 경로</label>
          <input type="text" id="gItemsPath" placeholder="data.vulnerabilities">
          <div class="sub">응답 JSON 안에서 목록 배열의 dot-notation 경로. 최상위 배열이면 비워둔다.</div>
        </div>

        <div class="field form-grid__full">
          <label>필드 매핑 <span id="gRoleLabel" class="why"></span></label>
          <div id="gFieldMap" class="kvrows"></div>
          <div class="sub">응답 JSON의 dot-notation 경로를 입력합니다. * 표시는 필수입니다.</div>
        </div>
       </div>

        <input type="hidden" name="g_config_json" id="gConfigJson">
      </div>
      <?php $sm = $esched['mode'] ?? 'manual'; ?>
      <?php /* 스케줄은 항상 "방식 + 그 방식의 값 하나" 라 2열이 정확히 맞는다(나머지 둘은 hidden).
               격자 상자 자체는 토글되지 않으므로 여기엔 .form-grid 를 바로 줘도 된다. */ ?>
      <div class="form-grid">
        <div class="field">
          <label for="connSchedule">스케줄</label>
          <select name="schedule_mode" id="connSchedule">
            <?php foreach (['manual'=>'수동 (직접 실행)','interval'=>'주기 실행','daily'=>'매일 지정 시각','cron'=>'cron 표현식'] as $mv=>$ml): ?>
              <option value="<?= $mv ?>" <?= $sm===$mv?'selected':'' ?>><?= $ml ?></option>
            <?php endforeach; ?>
          </select>
        </div>
        <div data-schedule-field="interval"<?= $sm === 'interval' ? '' : ' hidden' ?>>
          <label for="connInterval">주기(분)</label>
          <input type="text" id="connInterval" name="interval_minutes" value="<?= vg_h((string) ($esched['interval_minutes'] ?? '1440')) ?>">
        </div>
        <div data-schedule-field="daily"<?= $sm === 'daily' ? '' : ' hidden' ?>>
          <label for="connTime">시각 (HH:MM)</label>
          <input type="text" id="connTime" name="schedule_time" value="<?= vg_h((string) ($esched['time'] ?? '03:00')) ?>" placeholder="03:00">
        </div>
        <div data-schedule-field="cron"<?= $sm === 'cron' ? '' : ' hidden' ?>>
          <label for="connCron">cron (분 시 일 월 요일)</label>
          <input type="text" id="connCron" name="schedule_cron" value="<?= vg_h((string) ($esched['expr'] ?? '')) ?>" placeholder="0 3 * * *">
        </div>
      </div>
      <label class="inline">
        <input type="checkbox" name="enabled" value="1" <?= ($edit['enabled'] ?? 0) ? 'checked' : '' ?>> 활성
      </label>
      <?php if ($edit): ?>
        <div class="sub center"><a href="/connectors.php">+ 새 데이터 소스</a></div>
      <?php endif; ?>
      <pre id="vgPrev" class="out" hidden></pre>
      <?php vg_modal_foot($edit ? '저장' : '추가', ['extra' =>
          // "API 미리보기" 였는데 12종 중 절반은 API 가 아니다(정적 파일·gz/bz2 덤프·RSS).
          // 주작업(저장)은 아니지만 저장 전에 눌러 보라고 권하는 버튼이라, ghost 보다 분명한 btn--secondary.
          '<button type="button" id="vgPrevBtn" class="btn btn--secondary" data-loading="조회 중…" data-feed-preview>미리보기 (10건)</button>']); ?>
    </form>
  <?php vg_modal_close(); ?>

  <?php
  // API 미리보기 동작(vgPreview)은 assets/app.js 가 소유한다(전역 노출). PHP 안에 인라인 JS 를 두지 않는다.
  ?>

  <?php
  /* 수집 이력 표 — ?conn=N 상세에서 커넥터 하나의 이력을 보여준다. */
  $logHeaders = [
      ['label' => '상태',      'width' => '7rem',  'nowrap' => true],
      ['label' => '실행 계기', 'width' => '7rem'],
      ['label' => '수집/저장', 'width' => '9rem', 'align' => 'right'],
      ['label' => '메시지'],
      ['label' => '시각',      'width' => '11rem', 'nowrap' => true],
  ];
  $logCells = [
      0 => fn($l) => $statusBadge($l['status'] !== null ? (string) $l['status'] : null),
      1 => fn($l) => '<span class="why">'
          . vg_h(VG_COLLECT_TRIGGER[(string) $l['trigger_by']] ?? (string) $l['trigger_by']) . '</span>',
      2 => fn($l) => '<span class="why">' . ($l['items_fetched'] !== null
              ? number_format((int) $l['items_fetched']) . ' / ' . number_format((int) $l['items_upserted'])
              : '–') . '</span>',
      // 실패 메시지가 이 표의 존재 이유다 — 잘라내되 title 로 원문을 남긴다.
      3 => fn($l) => '<span class="why">' . vg_trunc((string) ($l['message'] ?? ''), 60) . '</span>',
      4 => fn($l) => '<span class="why">' . vg_h((string) $l['started_at']) . '</span>',
  ];
  $logEmpty = [
      'icon'  => '🕘',
      'title' => '아직 실행 이력이 없습니다.',
      'hint'  => '[실행]을 누르거나 예약 시각이 되면 여기에 쌓입니다.',
  ];
  ?>

  <?php if ($connFilter > 0 && $connName !== '' && $connDetail !== null): ?>
    <div class="card" id="collection-history">
      <strong><?= vg_h($connName) ?> · 상세</strong>
      <span class="why">— <?= vg_h(VG_CONNECTOR_TYPES[(string) $connDetail['connector_type']]['label'] ?? (string) $connDetail['connector_type']) ?>
        · <?= $connDetail['enabled'] ? '활성' : '중지' ?>
        · <?= vg_h((string) $connDetail['_sched_label']) ?>
        · <a href="?edit=<?= $connFilter ?>">설정 편집</a>
        · <a href="/connectors.php">목록으로</a></span>
      <div class="card__body">
        <div class="sub">최근 실행 <?= vg_h((string) ($connDetail['last_run_at'] ?? '–')) ?> · 다음 실행 <?= vg_h((string) ($connDetail['_next_run'] ?: '–')) ?> · 수집 이력 <?= number_format($logTotal) ?>건</div>
        <?php
        vg_table($logHeaders, $logs, ['card' => false, 'empty' => $logEmpty, 'cell' => $logCells]);
        vg_page_nav($logTotal, $perPage, $page);
        ?>
      </div>
    </div>
  <?php endif; ?>

<?php vg_footer();
