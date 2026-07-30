<?php
declare(strict_types=1);

/**
 * connectors.php — CVE 피드 커넥터 관리 (admin 전용).
 *   목록/추가/편집/삭제, 즉시 실행(수동), 활성 토글, 최근 수집 이력.
 */

require_once __DIR__ . '/../src/auth.php';
require_once __DIR__ . '/../src/view.php';
require_once __DIR__ . '/../src/feeds.php';
require_once __DIR__ . '/../src/matcher.php';
require_once __DIR__ . '/../src/audit.php';   // vg_soft_delete / vg_log_activity
require_once __DIR__ . '/../src/connector_actions.php';   // POST 액션(save/run/toggle/delete) 처리
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

/* 수집 이력.
 * 전엔 전 커넥터의 로그를 목록 아래 한 표에 쏟아 놨는데, 정작 "이 커넥터가 왜 실패했나" 를
 * 보려면 남의 로그 사이에서 눈으로 골라야 했다. 커넥터마다 [이력] 버튼 → 그 커넥터 로그만.
 *   · 모달엔 최근 $logPeek 건. 그보다 많으면 "전체 이력" 링크로 넘긴다.
 *   · ?conn=N 이면 그 커넥터의 전체 이력을 페이지네이션해서 아래에 편다.
 */
$logPeek = vg_ui_detail_preview_limit();

$perPage  = vg_perpage();
$page     = vg_page();
$connFilter = (int) ($_GET['conn'] ?? 0);

$peek = $pdo->prepare(
    'SELECT status, trigger_by, items_fetched, items_upserted, message, started_at
       FROM tb_feed_collection_log WHERE feed_connector_id = ?
      ORDER BY started_at DESC LIMIT ' . $logPeek
);
$cnt = $pdo->prepare('SELECT COUNT(*) FROM tb_feed_collection_log WHERE feed_connector_id = ?');

$logsByConn = []; $logCountByConn = [];
foreach ($connectors as $c) {
    $id = (int) $c['feed_connector_id'];
    $peek->execute([$id]);
    $logsByConn[$id] = $peek->fetchAll();
    $cnt->execute([$id]);
    $logCountByConn[$id] = (int) $cnt->fetchColumn();
}

// ?conn=N — 그 커넥터의 전체 이력(페이지네이션)
$logs = []; $logTotal = 0; $connName = '';
if ($connFilter > 0) {
    foreach ($connectors as $c) { if ((int) $c['feed_connector_id'] === $connFilter) { $connName = (string) $c['name']; } }
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
$econn = $edit ? vg_json_col($edit['connection_json']) : [];
$esched = $edit ? vg_json_col($edit['schedule_json']) : [];

// 수집 상태 → 뱃지 톤(색은 CSS 가 결정).
$statusTone = ['success' => 'ok', 'error' => 'danger', 'running' => 'warn', 'never' => 'muted'];

vg_header('데이터 수집', 'connectors');
?>
  <?php vg_page_title('데이터 수집', 'DATA SOURCES', '취약점 판정에 쓰는 외부 데이터와 수집 상태입니다.', [
      'suffix_html' => vg_info_icon('수집이 끝나면 기존 스캔의 판정도 자동으로 갱신됩니다.'),
      'actions' => vg_capture(static fn() => vg_modal_btn('connModal', '+ 데이터 소스')),
  ]); ?>

  <?php vg_alert($msg, 'ok'); vg_alert($err); ?>

  <?php
  // 표시용 부가값(스케줄 라벨/다음 실행) 을 미리 계산해 각 행에 얹는다.
  foreach ($connectors as &$c) {
      $sc = vg_json_col($c['schedule_json']);
      $mode = $sc['mode'] ?? 'manual';
      switch ($mode) {
          case 'interval': $c['_sched_label'] = '매 ' . (int) ($sc['interval_minutes'] ?? 0) . '분'; break;
          case 'daily':    $c['_sched_label'] = '매일 ' . ($sc['time'] ?? '?'); break;
          case 'cron':     $c['_sched_label'] = 'cron: ' . ($sc['expr'] ?? '?'); break;
          default:         $c['_sched_label'] = '수동';
      }
      $c['_next_run'] = ($c['enabled'] && $mode !== 'manual') ? ($c['next_run_at'] ?: vg_schedule_next($sc)) : '–';
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
      ['label' => '상태'], ['label' => '작업'],
  ];
  $tableCells = [
      0 => fn($c) => '<strong>' . vg_h($c['name']) . '</strong>',
      1 => fn($c) => '<span class="why">' . vg_h($c['_sched_label']) . '</span>',
      2 => fn($c) => '<span class="why">최근 ' . vg_h($c['last_run_at'] ?? '–')
          . '<br>다음 ' . vg_h($c['_next_run'] ?: '–') . '</span>',
      3 => function ($c) use ($csrf, $statusTone) {
          $status = (string) ($c['last_status'] ?? 'never');
          return '<div class="stack-sm"><form method="post">'
          . '<input type="hidden" name="csrf" value="' . vg_h($csrf) . '"><input type="hidden" name="action" value="toggle"><input type="hidden" name="id" value="' . (int) $c['feed_connector_id'] . '">'
          . '<button class="btn btn--sm ' . ($c['enabled'] ? 'btn--ok' : 'btn--ghost') . '">' . ($c['enabled'] ? '사용' : '중지') . '</button></form>'
          . vg_badge($status, $statusTone[$status] ?? 'muted') . '</div>';
      },
      4 => function ($c) use ($csrf, $logCountByConn) {
          $html = '';
          if ($c['last_message']) {
              $html .= '<span class="sr-only">' . vg_h($c['last_message']) . '</span>';
          }
          $id = (int) $c['feed_connector_id'];
          $n  = $logCountByConn[$id] ?? 0;
          return $html . '<div class="actions">'
              . '<form method="post"><input type="hidden" name="csrf" value="' . vg_h($csrf) . '"><input type="hidden" name="action" value="run"><input type="hidden" name="id" value="' . $id . '">'
              . '<button class="btn btn--sm btn--primary" data-loading="수집 중…">실행</button></form>'
              // 이력은 그 커넥터 것만 모달로 — 전엔 전 커넥터 로그가 한 표에 섞여 있었다.
              . '<button type="button" class="btn btn--sm btn--ghost" data-modal="log' . $id . '">'
              . '이력 <span class="why">' . number_format($n) . '</span></button>'
              . '<a class="btn btn--sm btn--ghost" href="?edit=' . $id . '">편집</a>'
              . '<form method="post" data-confirm="이 데이터 소스를 삭제할까요? 예약 수집은 중단되며 기존 이력은 남습니다."><input type="hidden" name="csrf" value="' . vg_h($csrf) . '"><input type="hidden" name="action" value="delete"><input type="hidden" name="id" value="' . $id . '">'
              . '<button class="btn btn--sm btn--danger">삭제</button></form>'
              . '</div>';
      },
  ];

  if (!$connectors) {
      // 등록된 게 하나도 없으면 그룹 헤딩 없이 안내만.
      vg_table($tableHeaders, [], ['empty' => [
          'icon'  => '🔌',
          'title' => '등록된 데이터 소스가 없습니다.',
          'hint'  => '[+ 데이터 소스]에서 수집 대상을 추가하세요.',
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
             . vg_info_icon($g['desc'])
             . '<div class="card__body">';
          vg_table($tableHeaders, $grouped[$gi], ['card' => false, 'cell' => $tableCells]);
          echo '</div></div>';
      }
      if ($others) {
          echo '<div class="card"><strong>기타</strong>'
             . ' <span class="why">— 분류되지 않은 데이터 소스입니다.</span><div class="card__body">';
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
  $curMeta = $typeMeta[$curType];
  // 이 타입이 안 읽는 필드는 아예 숨긴다 — 예전엔 전 타입에 다 띄우고 라벨의 괄호로 변명했다.
  $fieldOn = fn(string $f): string => in_array($f, $curMeta['fields'], true) ? '' : ' hidden';
  ?>
    <form id="connForm" method="post"
          data-edit-generic="<?= ($edit['connector_type'] ?? '') === 'generic_api' ? vg_h(json_encode($econn)) : '' ?>"
          data-type-meta="<?= vg_h(json_encode($typeMeta, JSON_UNESCAPED_UNICODE)) ?>"
          data-role-labels="<?= vg_h(json_encode(VG_GENERIC_ROLE_LABELS, JSON_UNESCAPED_UNICODE)) ?>">
      <input type="hidden" name="csrf" value="<?= vg_h($csrf) ?>">
      <input type="hidden" name="action" value="save">
      <input type="hidden" name="id" value="<?= (int) ($edit['feed_connector_id'] ?? 0) ?>">
      <label>이름</label>
      <input type="text" name="name" value="<?= vg_h($edit['name'] ?? '') ?>" required>
      <label>소스 종류</label>
      <select name="connector_type" id="connType">
        <?php foreach (VG_CONNECTOR_TYPES as $tv => $m): ?>
          <option value="<?= vg_h($tv) ?>" <?= $curType===$tv?'selected':'' ?>><?= vg_h($m['label']) ?></option>
        <?php endforeach; ?>
      </select>
      <?php /* 수집 방식 — 이 커넥터가 데이터를 어떻게 가져오는가(역할이 아니다. 역할은 목록의 그룹 카드). */ ?>
      <div class="connmeta" id="connTransport">
        <?= vg_badge($curMeta['transport'], $curMeta['tone']) ?>
        <div class="sub" id="connTransportDesc"><?= vg_h($curMeta['desc']) ?></div>
      </div>
      <div id="stdFields">
        <div data-field="url"<?= $fieldOn('url') ?>>
          <label id="urlLabel"><?= vg_h($curMeta['urlLabel'] ?: 'URL') ?></label>
          <input type="text" name="url" value="<?= vg_h($econn['url'] ?? '') ?>" placeholder="비우면 기본 주소를 쓴다">
        </div>
        <div data-field="api_key"<?= $fieldOn('api_key') ?>>
          <label>API Key (선택)</label>
          <input type="text" name="api_key" value="<?= vg_h($econn['api_key'] ?? '') ?>" placeholder="비워도 됨">
        </div>
        <div data-field="ecosystem"<?= $fieldOn('ecosystem') ?>>
          <label>Ecosystem (예: Rocky Linux)</label>
          <input type="text" name="ecosystem" value="<?= vg_h($econn['ecosystem'] ?? '') ?>">
        </div>
        <div data-field="days"<?= $fieldOn('days') ?>>
          <label>최근 N일</label>
          <input type="text" name="days" value="<?= vg_h((string) ($econn['days'] ?? '')) ?>" placeholder="7">
        </div>
      </div>
      <div id="genericFields" hidden>
        <label>역할</label>
        <select id="gRole">
          <?php foreach (VG_GENERIC_ROLE_LABELS as $rv => $rl): ?>
            <option value="<?= vg_h($rv) ?>"><?= vg_h($rl) ?></option>
          <?php endforeach; ?>
        </select>
        <div class="alert alert--warn" id="gRoleNotice" hidden>
          <strong>기존 설정의 역할은 더 이상 지원하지 않습니다.</strong>
          <ul class="hint-list"><li>지원되는 역할을 다시 선택해야 저장할 수 있습니다.</li></ul>
        </div>

        <label>HTTP 메서드</label>
        <select id="gMethod">
          <option value="GET">GET</option>
          <option value="POST">POST</option>
        </select>

        <label>URL 템플릿</label>
        <input type="text" id="gUrlTemplate" placeholder="https://api.example.com/vulns?page={page}">
        <div class="sub">플레이스홀더: <code>{page}</code>(1부터) · <code>{offset}</code>(0부터) · <code>{today}</code> · <code>{days_ago_N}</code></div>

        <label>인증 헤더</label>
        <div id="gHeaders" class="kvrows"></div>
        <button type="button" class="btn btn--sm btn--ghost" id="gHeaderAdd">+ 헤더 추가</button>

        <label>페이징 타입</label>
        <select id="gPageType">
          <option value="none">없음</option>
          <option value="offset">offset</option>
        </select>
        <label>페이지 크기</label>
        <input type="text" id="gPageSize" placeholder="100">
        <label>총 건수 경로 (선택)</label>
        <input type="text" id="gTotalPath" placeholder="meta.total">

        <label>응답 아이템 경로</label>
        <input type="text" id="gItemsPath" placeholder="data.vulnerabilities">
        <div class="sub">응답 JSON 안에서 목록 배열의 dot-notation 경로. 최상위 배열이면 비워둔다.</div>

        <label>필드 매핑 <span id="gRoleLabel" class="why"></span></label>
        <div id="gFieldMap" class="kvrows"></div>
        <div class="sub">각 대상 필드에 응답 JSON 안의 경로(dot-notation, 예: <code>data.cve</code>)를 입력한다. <strong>굵게</strong> 표시된 필드는 필수.</div>

        <input type="hidden" name="g_config_json" id="gConfigJson">
      </div>
      <label>스케줄</label>
      <select name="schedule_mode">
        <?php $sm = $esched['mode'] ?? 'manual'; foreach (['manual'=>'수동 (직접 실행)','interval'=>'주기 실행(N분)','daily'=>'매일 지정 시각','cron'=>'cron 표현식'] as $mv=>$ml): ?>
          <option value="<?= $mv ?>" <?= $sm===$mv?'selected':'' ?>><?= $ml ?></option>
        <?php endforeach; ?>
      </select>
      <label>주기(분) — "주기 실행" 시</label>
      <input type="text" name="interval_minutes" value="<?= vg_h((string) ($esched['interval_minutes'] ?? '1440')) ?>">
      <label>시각 HH:MM — "매일 지정 시각" 시</label>
      <input type="text" name="schedule_time" value="<?= vg_h((string) ($esched['time'] ?? '03:00')) ?>" placeholder="03:00">
      <label>cron (분 시 일 월 요일) — "cron 표현식" 시</label>
      <input type="text" name="schedule_cron" value="<?= vg_h((string) ($esched['expr'] ?? '')) ?>" placeholder="0 3 * * *  (매일 03:00)">
      <label class="inline">
        <input type="checkbox" name="enabled" value="1" <?= ($edit['enabled'] ?? 0) ? 'checked' : '' ?>> 활성(enabled)
      </label>
      <?php if ($edit): ?>
        <div class="sub center"><a href="/connectors.php">+ 새 데이터 소스</a></div>
      <?php endif; ?>
      <pre id="vgPrev" class="out" hidden></pre>
      <?php vg_modal_foot($edit ? '저장' : '추가', ['extra' =>
          // "API 미리보기" 였는데 12종 중 절반은 API 가 아니다(정적 파일·gz/bz2 덤프·RSS).
          '<button type="button" id="vgPrevBtn" class="btn btn--ghost" data-loading="조회 중…" data-feed-preview>미리보기 (10건)</button>']); ?>
    </form>
  <?php vg_modal_close(); ?>

  <?php
  // API 미리보기 동작(vgPreview)은 assets/app.js 가 소유한다(전역 노출). PHP 안에 인라인 JS 를 두지 않는다.
  ?>

  <?php
  /* 수집 이력 표 — 커넥터 하나에 대한 것. 모달(최근 8건)과 ?conn=N 전체보기가 공유한다. */
  $logHeaders = [
      ['label' => '상태',      'width' => '7rem',  'nowrap' => true],
      ['label' => '트리거',    'width' => '7rem'],
      ['label' => '수집/저장', 'width' => '9rem'],
      ['label' => '메시지'],
      ['label' => '시각',      'width' => '11rem', 'nowrap' => true],
  ];
  $logCells = [
      0 => fn($l) => vg_badge((string) $l['status'], $statusTone[$l['status']] ?? 'muted'),
      1 => fn($l) => '<span class="why">' . vg_h((string) $l['trigger_by']) . '</span>',
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
      'hint'  => '[지금 실행]을 누르거나 스케줄이 돌면 여기에 쌓입니다.',
  ];
  ?>

  <?php if ($connFilter > 0 && $connName !== ''): ?>
    <div class="card">
      <strong><?= vg_h($connName) ?> · 수집 이력</strong>
      <span class="why">— 총 <?= number_format($logTotal) ?>건 · <a href="/connectors.php">목록으로</a></span>
      <div class="card__body">
        <?php
        vg_table($logHeaders, $logs, ['card' => false, 'empty' => $logEmpty, 'cell' => $logCells]);
        vg_page_nav($logTotal, $perPage, $page);
        ?>
      </div>
    </div>
  <?php endif; ?>

  <?php
  /* 커넥터마다 이력 모달. 전엔 전 커넥터 로그를 목록 아래 한 표에 쏟아놔서,
   * "이 커넥터가 왜 실패했나" 를 보려면 남의 로그 사이에서 눈으로 골라야 했다. */
  foreach ($connectors as $c):
      $cid = (int) $c['feed_connector_id'];
      $n   = $logCountByConn[$cid] ?? 0;
      vg_modal_open('log' . $cid, $c['name'] . ' · 수집 이력', 'modal--wide');
  ?>
      <?php if ($n > $logPeek): ?>
        <div class="sub">총 <?= number_format($n) ?>건 중 최근 <?= $logPeek ?>건 ·
          <a href="?conn=<?= $cid ?>">전체 이력 보기 →</a></div>
      <?php elseif ($n > 0): ?>
        <div class="sub">총 <?= number_format($n) ?>건</div>
      <?php endif; ?>
      <?php vg_table($logHeaders, $logsByConn[$cid] ?? [], ['card' => false, 'empty' => $logEmpty, 'cell' => $logCells]); ?>
      <?php vg_modal_foot(null); ?>
  <?php
      vg_modal_close();
  endforeach;
  ?>
<?php vg_footer();
