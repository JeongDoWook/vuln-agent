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
                if ($name === '' || !in_array($type, ['kev','osv','nvd','kisa','epss'], true)) {
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

                if ($id > 0) {
                    $st = $pdo->prepare('UPDATE tb_feed_connectors SET name=?, connector_type=?, connection_json=?, schedule_json=?, enabled=? WHERE id=?');
                    $st->execute([$name, $type, json_encode($conn), json_encode($sched), $enabled, $id]);
                    $msg = "커넥터 '$name' 수정됨.";
                } else {
                    $st = $pdo->prepare('INSERT INTO tb_feed_connectors (name, connector_type, connection_json, schedule_json, enabled, last_status) VALUES (?,?,?,?,?,?)');
                    $st->execute([$name, $type, json_encode($conn), json_encode($sched), $enabled, 'never']);
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
$logs = $pdo->query(
    'SELECT l.*, c.name FROM tb_feed_collection_logs l JOIN tb_feed_connectors c ON c.id = l.connector_id
     ORDER BY l.started_at DESC LIMIT 15'
)->fetchAll();
$csrf = vg_csrf_token();

// 편집 대상
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
  <div class="sub">외부 취약점 소스(CISA KEV · OSV · NVD)를 설정·스케줄·수집. 결과는 매처가 자동 재계산.</div>

  <?php vg_alert($msg, 'ok'); vg_alert($err); ?>

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

  vg_table(
      [
          ['label' => '이름'], ['label' => '타입'], ['label' => '스케줄'], ['label' => '활성'],
          ['label' => '마지막 실행', 'nowrap' => true], ['label' => '다음 실행', 'nowrap' => true], ['label' => '상태'], ['label' => '작업'],
      ],
      $connectors,
      [
          'empty' => '등록된 커넥터가 없습니다.',
          'cell' => [
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
              7 => fn($c) => '<div class="actions">'
                  . '<form method="post"><input type="hidden" name="csrf" value="' . vg_h($csrf) . '"><input type="hidden" name="action" value="run"><input type="hidden" name="id" value="' . (int) $c['id'] . '">'
                  . '<button class="btn btn--sm btn--primary" data-loading="수집 중…">지금 실행</button></form>'
                  . '<a class="btn btn--sm btn--ghost" href="?edit=' . (int) $c['id'] . '">편집</a>'
                  . '<form method="post" onsubmit="return confirm(\'삭제할까요?\');"><input type="hidden" name="csrf" value="' . vg_h($csrf) . '"><input type="hidden" name="action" value="delete"><input type="hidden" name="id" value="' . (int) $c['id'] . '">'
                  . '<button class="btn btn--sm btn--danger">삭제</button></form>'
                  . '</div>',
          ],
      ]
  );
  ?>

  <div class="card card--narrow">
    <strong><?= $edit ? '커넥터 편집' : '커넥터 추가' ?></strong>
    <form id="connForm" method="post" class="card__body">
      <input type="hidden" name="csrf" value="<?= vg_h($csrf) ?>">
      <input type="hidden" name="action" value="save">
      <input type="hidden" name="id" value="<?= (int) ($edit['id'] ?? 0) ?>">
      <label>이름</label>
      <input type="text" name="name" value="<?= vg_h($edit['name'] ?? '') ?>" required>
      <label>커넥터 타입</label>
      <select name="connector_type">
        <?php foreach (['kev'=>'CISA KEV','osv'=>'OSV.dev','nvd'=>'NVD 2.0','kisa'=>'KISA 보안공지','epss'=>'FIRST EPSS'] as $tv=>$tl): ?>
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
      <button type="submit" class="btn btn--ok btn--block"><?= $edit ? '저장' : '추가' ?></button>
      <button type="button" id="vgPrevBtn" class="btn btn--ghost btn--block" data-loading="조회 중…" onclick="vgPreview(this)">API 미리보기 (10건)</button>
      <?php if ($edit): ?><div class="sub card__body center"><a href="/connectors.php">+ 새 커넥터</a></div><?php endif; ?>
    </form>
    <pre id="vgPrev" class="out" hidden></pre>
  </div>

  <script>
  // 외부 소스를 직접 치는 요청이라 수 초 걸린다 → 버튼 스피너 + 상단 진행바(vgLoading).
  function vgPreview(btn) {
    var f = document.getElementById('connForm');
    var out = document.getElementById('vgPrev');
    var qs = new URLSearchParams({
      type: f.connector_type.value, url: f.url.value,
      api_key: f.api_key.value, ecosystem: f.ecosystem.value, days: f.days.value
    });
    out.hidden = false;
    out.classList.add('is-loading');
    out.textContent = '조회 중…';
    vgLoading(btn, true);
    fetch('/feed_preview.php?' + qs.toString())
      .then(function (r) { return r.json(); })
      .then(function (j) {
        if (!j.ok) { out.textContent = '오류: ' + (j.error || '알 수 없음'); return; }
        var head = '총 ' + (j.count != null ? j.count : '?') + '건' + (j.note ? ' · ' + j.note : '') + ' (아래는 최대 10건)\n\n';
        out.textContent = head + JSON.stringify(j.sample, null, 2);
      })
      .catch(function (e) { out.textContent = '요청 실패: ' + e; })
      .finally(function () {
        out.classList.remove('is-loading');
        vgLoading(btn, false);
      });
  }
  </script>

  <div class="card">
    <strong>최근 수집 이력</strong>
    <div class="card__body">
    <?php
    vg_table(
        [
            ['label' => '커넥터', 'key' => 'name'],
            ['label' => '트리거'],
            ['label' => '상태'],
            ['label' => '수집/저장'],
            ['label' => '메시지'],
            ['label' => '시각', 'nowrap' => true],
        ],
        $logs,
        [
            'card' => false,
            'empty' => '아직 실행 이력이 없습니다.',
            'cell' => [
                1 => fn($l) => '<span class="why">' . vg_h($l['trigger_by']) . '</span>',
                2 => fn($l) => vg_badge((string) $l['status'], $statusTone[$l['status']] ?? 'muted'),
                3 => fn($l) => '<span class="why">' . ($l['items_fetched'] !== null ? (int) $l['items_fetched'] . ' / ' . (int) $l['items_upserted'] : '–') . '</span>',
                4 => fn($l) => '<span class="why">' . vg_h(mb_strimwidth((string) ($l['message'] ?? ''), 0, 50, '…')) . '</span>',
                5 => fn($l) => '<span class="why">' . vg_h($l['started_at']) . '</span>',
            ],
        ]
    );
    ?>
    </div>
  </div>
<?php vg_footer();
