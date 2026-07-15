<?php
declare(strict_types=1);

/**
 * connectors.php — CVE 피드 커넥터 관리 (admin 전용).
 *   목록/추가/편집/삭제, 즉시 실행(수동), 활성 토글, 최근 수집 이력.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require __DIR__ . '/../src/feeds.php';
require __DIR__ . '/../src/matcher.php';
require_once __DIR__ . '/../src/audit.php';   // vg_soft_delete / vg_log_activity
vg_require_menu('connectors');   // 피드 커넥터: 설정형 권한

$pdo = vg_pdo();
$msg = null; $err = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!vg_csrf_check($_POST['csrf'] ?? null)) {
        $err = '세션이 만료되었습니다.';
    } else {
        $action = $_POST['action'] ?? '';
        try {
            if ($action === 'save') {
                $id    = (int) ($_POST['id'] ?? 0);
                $name  = trim((string) ($_POST['name'] ?? ''));
                $type  = (string) ($_POST['connector_type'] ?? '');
                if ($name === '' || !in_array($type, ['kev','osv','nvd','kisa','epss','debtracker','rhoval','rhunfixed','ssg','kcve','ubuntuoval'], true)) {
                    throw new RuntimeException('이름과 커넥터 타입을 확인하세요.');
                }
                $conn = ['url' => trim((string) ($_POST['url'] ?? ''))];
                if (($_POST['api_key'] ?? '') !== '')   { $conn['api_key']   = trim((string) $_POST['api_key']); }
                if (($_POST['ecosystem'] ?? '') !== '') { $conn['ecosystem'] = trim((string) $_POST['ecosystem']); }
                if (($_POST['days'] ?? '') !== '')      { $conn['days']      = (int) $_POST['days']; }
                $mode = (string) ($_POST['schedule_mode'] ?? 'manual');
                if (!in_array($mode, ['interval', 'daily', 'cron', 'manual'], true)) { $mode = 'manual'; }
                $sched = ['mode' => $mode];
                if ($mode === 'interval') {
                    $sched['interval_minutes'] = max(1, (int) ($_POST['interval_minutes'] ?? 1440));
                } elseif ($mode === 'daily') {
                    $t = (string) ($_POST['schedule_time'] ?? '');
                    $sched['time'] = preg_match('/^\d{1,2}:\d{2}$/', $t) ? $t : '03:00';
                } elseif ($mode === 'cron') {
                    $expr = trim((string) ($_POST['schedule_cron'] ?? ''));
                    if ($expr === '' || count(preg_split('/\s+/', $expr)) !== 5) {
                        throw new RuntimeException('cron 은 5필드(분 시 일 월 요일)로 입력하세요. 예: 0 3 * * *');
                    }
                    $sched['expr'] = $expr;
                }
                $enabled = isset($_POST['enabled']) ? 1 : 0;

                // 저장 즉시 next_run_at 을 새 스케줄로 다시 계산한다.
                //   이 컬럼은 표시 전용 캐시인데 vg_feed_run() 안에서만 갱신됐다. 그래서 스케줄을
                //   바꿔도 다음 실행이 한 번 돌기 전까지 화면에 옛 시각이 남았다(05:00 → 12:11 로
                //   고쳐도 "다음 실행 05:00"). 실제 due 판정은 vg_feed_due() 가 schedule_json 과
                //   last_run_at 로 매번 새로 하므로 실행 시각 자체는 원래 정상이었다.
                //   interval 은 "마지막 실행 + N분" 이라야 due 판정과 같은 값이 나온다.
                $lastRun = null;
                if ($id > 0) {
                    $q = $pdo->prepare('SELECT last_run_at FROM tb_feed_connectors WHERE id=?');
                    $q->execute([$id]);
                    $lastRun = $q->fetchColumn() ?: null;
                }
                $from = ($mode === 'interval' && $lastRun !== null) ? strtotime((string) $lastRun) : time();
                $next = ($enabled && $mode !== 'manual') ? vg_schedule_next($sched, $from) : null;

                if ($id > 0) {
                    $st = $pdo->prepare('UPDATE tb_feed_connectors SET name=?, connector_type=?, connection_json=?, schedule_json=?, enabled=?, next_run_at=? WHERE id=?');
                    $st->execute([$name, $type, json_encode($conn), json_encode($sched), $enabled, $next, $id]);
                    $msg = "커넥터 '$name' 수정됨.";
                } else {
                    $st = $pdo->prepare('INSERT INTO tb_feed_connectors (name, connector_type, connection_json, schedule_json, enabled, last_status, next_run_at) VALUES (?,?,?,?,?,?,?)');
                    $st->execute([$name, $type, json_encode($conn), json_encode($sched), $enabled, 'never', $next]);
                    $id = (int) $pdo->lastInsertId();
                    $msg = "커넥터 '$name' 추가됨.";
                }
                vg_log_activity($pdo, 'CONNECTOR', $id, 'connector_save', "커넥터 '$name' 저장", ['type' => $type, 'enabled' => $enabled]);
            } elseif ($action === 'run') {
                $id = (int) ($_POST['id'] ?? 0);
                // 수동 실행은 apache 요청 안에서 동기로 돈다. NVD lastMod 수집은 실측 432초가
                // 걸린다(4,632건). max_execution_time=30 을 넘겨도 리눅스에서는 CPU 시간만
                // 세기에 네트워크 대기가 빠져 우연히 통과할 뿐이다. 파싱·upsert 가 무거워져
                // CPU 30초를 넘기면 그 순간 죽고, catch 가 안 돌아 로그가 'running' 으로 굳는다.
                set_time_limit(0);
                ignore_user_abort(true);   // 브라우저를 닫아도 수집은 끝까지 마친다
                // CLI 경로(bin/sync.php · scheduler.php)는 512M 을 쓰는데 웹만
                // 기본 256M 이었다. 같은 수집을 부르는 경로이니 한도도 같아야 한다.
                //
                // 실측(2026-07-10): 가장 무거운 EPSS 도 운영 규모(CVE 40만)에서 피크 74MB 다
                // — 보유 CVE 해시 34MB + CSV 평문 10MB + explode 배열 28MB. 지금은 256M 으로도
                // 넉넉하다. 터진 적은 없고, 호스트가 늘어 USN 캐시가 커질 때 UI 경로만 먼저
                // 죽는 함정을 막아두는 것이다(죽으면 로그가 'running' 으로 굳는다).
                ini_set('memory_limit', '512M');
                // 세션 파일 락을 먼저 놓는다. PHP 는 session_start 부터 스크립트 끝까지 세션
                // 파일을 배타 잠그는데, 이 실행은 위 주석대로 수 분(NVD 432초)이 걸린다. 락을
                // 쥔 채 돌면 같은 세션(같은 브라우저)의 다른 탭·페이지가 그 시간 내내
                // session_start 에서 막혀 UI 전체가 얼어붙는다. 아래는 세션에 쓰지 않고
                // ($msg/$err 로 인라인 렌더, csrf 는 이미 검증됨) 읽기만 하므로 지금 닫아도 안전하다.
                session_write_close();
                $r = vg_feed_run($pdo, $id, 'manual');
                if (!empty($r['ok'])) {
                    foreach (array_map('intval', $pdo->query('SELECT id FROM tb_scans')->fetchAll(PDO::FETCH_COLUMN)) as $sid) {
                        vg_match_scan($pdo, $sid);
                    }
                    $msg = "실행 완료: {$r['upserted']} 건 수집 · 재매칭됨.";
                    // OSV 면 조치안(fixed_version)까지 이어서 보강한다(findings 를 읽으므로 재매칭 뒤에).
                    if (vg_feed_has_type($pdo, [$id], 'osv')) {
                        $s = vg_osv_enrich_fixed($pdo);
                        $msg .= " 조치안 {$s['filled']}건 보강.";
                        // OSV 로 affected_packages 가 바뀌었으니 packages.php 요약을 다시 만든다.
                        vg_rebuild_package_summary($pdo);
                    }
                } else {
                    $err = "실행 실패: {$r['error']}";
                }
            } elseif ($action === 'toggle') {
                $id = (int) ($_POST['id'] ?? 0);
                $pdo->prepare('UPDATE tb_feed_connectors SET enabled = 1 - enabled WHERE id = ?')->execute([$id]);
                vg_log_activity($pdo, 'CONNECTOR', $id, 'connector_toggle', '활성 상태 변경');
                $msg = '활성 상태 변경됨.';
            } elseif ($action === 'delete') {
                $id = (int) ($_POST['id'] ?? 0);
                vg_soft_delete($pdo, 'tb_feed_connectors', $id);
                vg_log_activity($pdo, 'CONNECTOR', $id, 'connector_delete', '커넥터 삭제');
                $msg = '커넥터 삭제됨.';
            }
        } catch (Throwable $e) {
            $err = $e->getMessage();
        }
    }
}

$connectors = $pdo->query('SELECT * FROM tb_feed_connectors WHERE is_deleted = 0 ORDER BY id')->fetchAll();

/* 수집 이력.
 * 전엔 전 커넥터의 로그를 목록 아래 한 표에 쏟아 놨는데, 정작 "이 커넥터가 왜 실패했나" 를
 * 보려면 남의 로그 사이에서 눈으로 골라야 했다. 커넥터마다 [이력] 버튼 → 그 커넥터 로그만.
 *   · 모달엔 최근 VG_LOG_PEEK 건. 그보다 많으면 "전체 이력" 링크로 넘긴다.
 *   · ?conn=N 이면 그 커넥터의 전체 이력을 페이지네이션해서 아래에 편다.
 */
const VG_LOG_PEEK = 8;

$perPage  = vg_perpage();
$page     = max(1, (int) ($_GET['page'] ?? 1));
$connFilter = (int) ($_GET['conn'] ?? 0);

$peek = $pdo->prepare(
    'SELECT status, trigger_by, items_fetched, items_upserted, message, started_at
       FROM tb_feed_collection_logs WHERE connector_id = ?
      ORDER BY started_at DESC LIMIT ' . VG_LOG_PEEK
);
$cnt = $pdo->prepare('SELECT COUNT(*) FROM tb_feed_collection_logs WHERE connector_id = ?');

$logsByConn = []; $logCountByConn = [];
foreach ($connectors as $c) {
    $id = (int) $c['id'];
    $peek->execute([$id]);
    $logsByConn[$id] = $peek->fetchAll();
    $cnt->execute([$id]);
    $logCountByConn[$id] = (int) $cnt->fetchColumn();
}

// ?conn=N — 그 커넥터의 전체 이력(페이지네이션)
$logs = []; $logTotal = 0; $connName = '';
if ($connFilter > 0) {
    foreach ($connectors as $c) { if ((int) $c['id'] === $connFilter) { $connName = (string) $c['name']; } }
    $logTotal = $logCountByConn[$connFilter] ?? 0;
    $offset   = ($page - 1) * $perPage;
    $st = $pdo->prepare(
        "SELECT status, trigger_by, items_fetched, items_upserted, message, started_at
           FROM tb_feed_collection_logs WHERE connector_id = ?
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
    foreach ($connectors as $c) { if ((int) $c['id'] === (int) $_GET['edit']) { $edit = $c; } }
}
$econn = $edit ? (json_decode((string) $edit['connection_json'], true) ?: []) : [];
$esched = $edit ? (json_decode((string) $edit['schedule_json'], true) ?: []) : [];

// 수집 상태 → 뱃지 톤(색은 CSS 가 결정).
$statusTone = ['success' => 'ok', 'error' => 'danger', 'running' => 'warn', 'never' => 'muted'];

vg_header('피드 커넥터', 'connectors');
?>
  <h1>CVE 피드 커넥터</h1>
  <div class="sub">외부 소스를 <strong>역할별</strong>로 묶어 설정·스케줄·수집한다 — 취약점 정체 · 우선순위 신호 · 벤더 패치 판정 · 보안설정 룰셋. 결과는 매처가 자동 재계산.</div>

  <?php vg_alert($msg, 'ok'); vg_alert($err); ?>

  <div class="toolbar">
    <?php // 모달 id 는 connModal — 폼 자체의 id(connForm)와 겹치면 미리보기 JS 가 폼 대신 dialog 를 잡는다.
    vg_modal_btn('connModal', '+ 커넥터 추가'); ?>
  </div>

  <?php
  // 표시용 부가값(스케줄 라벨/다음 실행) 을 미리 계산해 각 행에 얹는다.
  foreach ($connectors as &$c) {
      $sc = json_decode((string) $c['schedule_json'], true) ?: [];
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
  // 가져오고 무엇이 벤더 패치버전을 가져오는지" 가 안 보인다. 분류 기준은 docs/피드소스-역할.md.
  //   타입 → 그룹 매핑은 아래 목록이 유일한 근거다(새 타입은 여기 한 줄 추가). 목록에 없는
  //   타입은 맨 아래 '기타' 로 떨어져 화면에서 사라지지 않는다.
  $roleGroups = [
      ['title' => '취약점 정체 — 무엇인가',
       'desc'  => 'CVE 원본 정보·설명·CVSS·영향 버전의 기준.',
       'types' => ['nvd', 'osv', 'kisa']],
      ['title' => '우선순위 신호 — 얼마나 급한가',
       'desc'  => 'KEV(실제 악용 중)로 등급 상향, EPSS(악용 확률)로 같은 등급 내 정렬.',
       'types' => ['kev', 'epss']],
      ['title' => '배포판 벤더 판정 — 고쳐졌나 / 고칠 수 있나',
       'desc'  => '어느 버전에서 고쳤는지 벤더가 답한다 → 백포트 오탐 억제 + 수정본 없는 건 조치 불가로 분리.',
       'types' => ['debtracker', 'rhoval', 'rhunfixed', 'ubuntuoval', 'kcve']],
      ['title' => '보안설정 룰셋 — 설정이 기준에 맞나',
       'desc'  => 'CVE 가 아니라 보안설정 점검(CCE). CIS·NIST·STIG 참조 룰셋.',
       'types' => ['ssg']],
  ];

  $tableHeaders = [
      ['label' => '이름'], ['label' => '타입'], ['label' => '스케줄'], ['label' => '활성'],
      ['label' => '마지막 실행', 'nowrap' => true], ['label' => '다음 실행', 'nowrap' => true], ['label' => '상태'], ['label' => '작업'],
  ];
  $tableCells = [
      0 => fn($c) => '<strong>' . vg_h($c['name']) . '</strong>',
      1 => fn($c) => '<span class="pill">' . vg_h($c['connector_type']) . '</span>',
      2 => fn($c) => '<span class="why">' . vg_h($c['_sched_label']) . '</span>',
      3 => fn($c) => '<form method="post">'
          . '<input type="hidden" name="csrf" value="' . vg_h($csrf) . '"><input type="hidden" name="action" value="toggle"><input type="hidden" name="id" value="' . (int) $c['id'] . '">'
          . '<button class="btn btn--sm ' . ($c['enabled'] ? 'btn--ok' : 'btn--ghost') . '">' . ($c['enabled'] ? 'ON' : 'OFF') . '</button></form>',
      4 => fn($c) => '<span class="why">' . vg_h($c['last_run_at'] ?? '–') . '</span>',
      5 => fn($c) => '<span class="why">' . vg_h($c['_next_run'] ?: '–') . '</span>',
      6 => function ($c) use ($statusTone) {
          $status = (string) ($c['last_status'] ?? 'never');
          $html = vg_badge($status, $statusTone[$status] ?? 'muted');
          if ($c['last_message']) {
              $html .= '<div class="why" title="' . vg_h($c['last_message']) . '">' . vg_h(mb_strimwidth((string) $c['last_message'], 0, 40, '…')) . '</div>';
          }
          return $html;
      },
      // "지금 실행" 은 외부 수집 + 전 스캔 재매칭이라 수십 초 걸린다 → 스피너 + 이중제출 차단(app.js).
      7 => function ($c) use ($csrf, $logCountByConn) {
          $id = (int) $c['id'];
          $n  = $logCountByConn[$id] ?? 0;
          return '<div class="actions">'
              . '<form method="post"><input type="hidden" name="csrf" value="' . vg_h($csrf) . '"><input type="hidden" name="action" value="run"><input type="hidden" name="id" value="' . $id . '">'
              . '<button class="btn btn--sm btn--primary" data-loading="수집 중…">지금 실행</button></form>'
              // 이력은 그 커넥터 것만 모달로 — 전엔 전 커넥터 로그가 한 표에 섞여 있었다.
              . '<button type="button" class="btn btn--sm btn--ghost" data-modal="log' . $id . '">'
              . '이력 <span class="why">' . number_format($n) . '</span></button>'
              . '<a class="btn btn--sm btn--ghost" href="?edit=' . $id . '">편집</a>'
              . '<form method="post" onsubmit="return confirm(\'삭제할까요?\');"><input type="hidden" name="csrf" value="' . vg_h($csrf) . '"><input type="hidden" name="action" value="delete"><input type="hidden" name="id" value="' . $id . '">'
              . '<button class="btn btn--sm btn--danger">삭제</button></form>'
              . '</div>';
      },
  ];

  if (!$connectors) {
      // 등록된 게 하나도 없으면 그룹 헤딩 없이 안내만.
      vg_table($tableHeaders, [], ['empty' => [
          'icon'  => '🔌',
          'title' => '등록된 커넥터가 없습니다.',
          'hint'  => '아래 [+ 커넥터 추가] 로 피드(CISA KEV · OSV · NVD · KISA · EPSS)를 추가하세요.',
      ]]);
  } else {
      // 타입 → 그룹 인덱스. 그룹에 담고, 매핑에 없는 타입은 '기타' 로.
      $typeGroup = [];
      foreach ($roleGroups as $gi => $g) { foreach ($g['types'] as $t) { $typeGroup[$t] = $gi; } }
      $grouped = []; $others = [];
      foreach ($connectors as $c) {
          $gi = $typeGroup[$c['connector_type']] ?? null;
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
          echo '<div class="card"><strong>기타</strong>'
             . ' <span class="why">— 역할 미분류 커넥터.</span><div class="card__body">';
          vg_table($tableHeaders, $others, ['card' => false, 'cell' => $tableCells]);
          echo '</div></div>';
      }
  }
  ?>

  <?php
  // 추가·편집 폼은 목록 아래 늘 펼쳐두던 것 → 버튼 뒤 모달로.
  // ?edit=N 으로 들어오면(행의 [편집]) 값이 채워진 채 자동으로 열린다.
  vg_modal_open('connModal', $edit ? '커넥터 편집' : '커넥터 추가', '', $edit !== null);
  ?>
    <form id="connForm" method="post">
      <input type="hidden" name="csrf" value="<?= vg_h($csrf) ?>">
      <input type="hidden" name="action" value="save">
      <input type="hidden" name="id" value="<?= (int) ($edit['id'] ?? 0) ?>">
      <label>이름</label>
      <input type="text" name="name" value="<?= vg_h($edit['name'] ?? '') ?>" required>
      <label>커넥터 타입</label>
      <select name="connector_type">
        <?php foreach (['kev'=>'CISA KEV','osv'=>'OSV.dev','nvd'=>'NVD 2.0','kisa'=>'KISA 보안공지','epss'=>'FIRST EPSS','debtracker'=>'데비안 보안 트래커','rhoval'=>'RHEL 계열 벤더 권고(OVAL)','rhunfixed'=>'Red Hat 미수정 CVE(조치 불가)','ssg'=>'SCAP Security Guide(보안설정 룰셋)','kcve'=>'리눅스 커널 CNA(kernel.org)','ubuntuoval'=>'우분투 보안 OVAL'] as $tv=>$tl): ?>
          <option value="<?= $tv ?>" <?= ($edit['connector_type'] ?? 'kev')===$tv?'selected':'' ?>><?= $tl ?></option>
        <?php endforeach; ?>
      </select>
      <label>API URL</label>
      <input type="text" name="url" value="<?= vg_h($econn['url'] ?? '') ?>" placeholder="https://...">
      <label>API Key (NVD 선택)</label>
      <input type="text" name="api_key" value="<?= vg_h($econn['api_key'] ?? '') ?>" placeholder="비워도 됨">
      <label>Ecosystem (OSV용, 예: Rocky Linux)</label>
      <input type="text" name="ecosystem" value="<?= vg_h($econn['ecosystem'] ?? '') ?>">
      <label>최근 N일 (NVD용)</label>
      <input type="text" name="days" value="<?= vg_h((string) ($econn['days'] ?? '')) ?>" placeholder="7">
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
        <div class="sub center"><a href="/connectors.php">+ 새 커넥터로 비우기</a></div>
      <?php endif; ?>
      <pre id="vgPrev" class="out" hidden></pre>
      <?php vg_modal_foot($edit ? '저장' : '추가', ['extra' =>
          '<button type="button" id="vgPrevBtn" class="btn btn--ghost" data-loading="조회 중…" onclick="vgPreview(this)">API 미리보기 (10건)</button>']); ?>
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
      <span class="why">— 총 <?= number_format($logTotal) ?>건 · <a href="/connectors.php">커넥터 목록으로</a></span>
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
      $cid = (int) $c['id'];
      $n   = $logCountByConn[$cid] ?? 0;
      vg_modal_open('log' . $cid, $c['name'] . ' · 수집 이력', 'modal--wide');
  ?>
      <?php if ($n > VG_LOG_PEEK): ?>
        <div class="sub">총 <?= number_format($n) ?>건 중 최근 <?= VG_LOG_PEEK ?>건 ·
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
