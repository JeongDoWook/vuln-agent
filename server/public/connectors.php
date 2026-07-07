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
vg_require_login();
vg_require_admin();

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
                if ($name === '' || !in_array($type, ['kev','osv','nvd','kisa'], true)) {
                    throw new RuntimeException('이름과 커넥터 타입을 확인하세요.');
                }
                $conn = ['url' => trim((string) ($_POST['url'] ?? ''))];
                if (($_POST['api_key'] ?? '') !== '')   { $conn['api_key']   = trim((string) $_POST['api_key']); }
                if (($_POST['ecosystem'] ?? '') !== '') { $conn['ecosystem'] = trim((string) $_POST['ecosystem']); }
                if (($_POST['days'] ?? '') !== '')      { $conn['days']      = (int) $_POST['days']; }
                $mode = ($_POST['schedule_mode'] ?? 'manual') === 'interval' ? 'interval' : 'manual';
                $sched = ['mode' => $mode];
                if ($mode === 'interval') { $sched['interval_minutes'] = max(1, (int) ($_POST['interval_minutes'] ?? 1440)); }
                $enabled = isset($_POST['enabled']) ? 1 : 0;

                if ($id > 0) {
                    $st = $pdo->prepare('UPDATE feed_connectors SET name=?, connector_type=?, connection_json=?, schedule_json=?, enabled=? WHERE id=?');
                    $st->execute([$name, $type, json_encode($conn), json_encode($sched), $enabled, $id]);
                    $msg = "커넥터 '$name' 수정됨.";
                } else {
                    $st = $pdo->prepare('INSERT INTO feed_connectors (name, connector_type, connection_json, schedule_json, enabled, last_status) VALUES (?,?,?,?,?,?)');
                    $st->execute([$name, $type, json_encode($conn), json_encode($sched), $enabled, 'never']);
                    $msg = "커넥터 '$name' 추가됨.";
                }
            } elseif ($action === 'run') {
                $id = (int) ($_POST['id'] ?? 0);
                $r = vg_feed_run($pdo, $id, 'manual');
                if (!empty($r['ok'])) {
                    foreach (array_map('intval', $pdo->query('SELECT id FROM scans')->fetchAll(PDO::FETCH_COLUMN)) as $sid) {
                        vg_match_scan($pdo, $sid);
                    }
                    $msg = "실행 완료: {$r['upserted']} 건 수집 · 재매칭됨.";
                } else {
                    $err = "실행 실패: {$r['error']}";
                }
            } elseif ($action === 'toggle') {
                $id = (int) ($_POST['id'] ?? 0);
                $pdo->prepare('UPDATE feed_connectors SET enabled = 1 - enabled WHERE id = ?')->execute([$id]);
                $msg = '활성 상태 변경됨.';
            } elseif ($action === 'delete') {
                $id = (int) ($_POST['id'] ?? 0);
                $pdo->prepare('DELETE FROM feed_connectors WHERE id = ?')->execute([$id]);
                $msg = '커넥터 삭제됨.';
            }
        } catch (Throwable $e) {
            $err = $e->getMessage();
        }
    }
}

$connectors = $pdo->query('SELECT * FROM feed_connectors ORDER BY id')->fetchAll();
$logs = $pdo->query(
    'SELECT l.*, c.name FROM feed_collection_logs l JOIN feed_connectors c ON c.id = l.connector_id
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

$statusColor = ['success'=>'#238636','error'=>'#da3633','running'=>'#9e6a03','never'=>'#6e7681'];

vg_header('피드 커넥터', 'connectors');
?>
  <h1>CVE 피드 커넥터</h1>
  <div class="sub">외부 취약점 소스(CISA KEV · OSV · NVD)를 설정·스케줄·수집. 결과는 매처가 자동 재계산.</div>

  <?php if ($msg): ?><div class="err" style="background:#12261a;border-color:#238636;color:#7ee787;"><?= vg_h($msg) ?></div><?php endif; ?>
  <?php if ($err): ?><div class="err"><?= vg_h($err) ?></div><?php endif; ?>

  <div class="card">
    <table>
      <thead><tr><th>이름</th><th>타입</th><th>스케줄</th><th>활성</th><th>마지막 실행</th><th>상태</th><th>작업</th></tr></thead>
      <tbody>
      <?php foreach ($connectors as $c):
        $sc = json_decode((string) $c['schedule_json'], true) ?: [];
        $schedLabel = ($sc['mode'] ?? 'manual') === 'interval' ? ('매 ' . (int) ($sc['interval_minutes'] ?? 0) . '분') : '수동';
      ?>
        <tr>
          <td><strong><?= vg_h($c['name']) ?></strong></td>
          <td><span class="pill"><?= vg_h($c['connector_type']) ?></span></td>
          <td class="why"><?= vg_h($schedLabel) ?></td>
          <td>
            <form method="post" style="margin:0;display:inline;">
              <input type="hidden" name="csrf" value="<?= vg_h($csrf) ?>"><input type="hidden" name="action" value="toggle"><input type="hidden" name="id" value="<?= (int) $c['id'] ?>">
              <button class="btn-sm" style="background:<?= $c['enabled'] ? '#238636' : '#30363d' ?>;"><?= $c['enabled'] ? 'ON' : 'OFF' ?></button>
            </form>
          </td>
          <td class="why"><?= vg_h($c['last_run_at'] ?? '–') ?></td>
          <td><span class="badge" style="background:<?= $statusColor[$c['last_status']] ?? '#6e7681' ?>;"><?= vg_h($c['last_status'] ?? 'never') ?></span>
            <?php if ($c['last_message']): ?><div class="why" title="<?= vg_h($c['last_message']) ?>"><?= vg_h(mb_strimwidth((string) $c['last_message'], 0, 40, '…')) ?></div><?php endif; ?>
          </td>
          <td style="white-space:nowrap;">
            <form method="post" style="margin:0;display:inline;">
              <input type="hidden" name="csrf" value="<?= vg_h($csrf) ?>"><input type="hidden" name="action" value="run"><input type="hidden" name="id" value="<?= (int) $c['id'] ?>">
              <button class="btn-sm" style="background:#1f6feb;">지금 실행</button>
            </form>
            <a class="btn-sm" style="display:inline-block;background:#30363d;color:#fff;border-radius:8px;" href="?edit=<?= (int) $c['id'] ?>">편집</a>
            <form method="post" style="margin:0;display:inline;" onsubmit="return confirm('삭제할까요?');">
              <input type="hidden" name="csrf" value="<?= vg_h($csrf) ?>"><input type="hidden" name="action" value="delete"><input type="hidden" name="id" value="<?= (int) $c['id'] ?>">
              <button class="btn-sm" style="background:#6e2830;">삭제</button>
            </form>
          </td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
  </div>

  <div class="card" style="max-width:560px;">
    <strong><?= $edit ? '커넥터 편집' : '커넥터 추가' ?></strong>
    <form method="post" style="margin-top:.6rem;">
      <input type="hidden" name="csrf" value="<?= vg_h($csrf) ?>">
      <input type="hidden" name="action" value="save">
      <input type="hidden" name="id" value="<?= (int) ($edit['id'] ?? 0) ?>">
      <label>이름</label>
      <input type="text" name="name" value="<?= vg_h($edit['name'] ?? '') ?>" required>
      <label>커넥터 타입</label>
      <select name="connector_type" style="width:100%;padding:.5rem;background:#0f1115;border:1px solid #30363d;border-radius:8px;color:#e6e6e6;">
        <?php foreach (['kev'=>'CISA KEV','osv'=>'OSV.dev','nvd'=>'NVD 2.0','kisa'=>'KISA 보안공지'] as $tv=>$tl): ?>
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
      <select name="schedule_mode" style="width:100%;padding:.5rem;background:#0f1115;border:1px solid #30363d;border-radius:8px;color:#e6e6e6;">
        <option value="manual"   <?= ($esched['mode'] ?? 'manual')==='manual'?'selected':'' ?>>수동 (직접 실행)</option>
        <option value="interval" <?= ($esched['mode'] ?? '')==='interval'?'selected':'' ?>>주기 실행</option>
      </select>
      <label>주기(분) — 주기 실행 시</label>
      <input type="text" name="interval_minutes" value="<?= vg_h((string) ($esched['interval_minutes'] ?? '1440')) ?>">
      <label style="display:flex;align-items:center;gap:.5rem;margin-top:1rem;">
        <input type="checkbox" name="enabled" value="1" <?= ($edit['enabled'] ?? 0) ? 'checked' : '' ?> style="width:auto;"> 활성(enabled)
      </label>
      <button type="submit"><?= $edit ? '저장' : '추가' ?></button>
      <?php if ($edit): ?><div class="sub" style="margin-top:.6rem;text-align:center;"><a href="/connectors.php">+ 새 커넥터</a></div><?php endif; ?>
    </form>
  </div>

  <div class="card">
    <strong>최근 수집 이력</strong>
    <table style="margin-top:.6rem;">
      <thead><tr><th>커넥터</th><th>트리거</th><th>상태</th><th>수집/저장</th><th>메시지</th><th>시각</th></tr></thead>
      <tbody>
      <?php if (!$logs): ?><tr><td colspan="6" class="why">아직 실행 이력이 없습니다.</td></tr><?php endif; ?>
      <?php foreach ($logs as $l): ?>
        <tr>
          <td><?= vg_h($l['name']) ?></td>
          <td class="why"><?= vg_h($l['trigger_by']) ?></td>
          <td><span class="badge" style="background:<?= $statusColor[$l['status']] ?? '#6e7681' ?>;"><?= vg_h($l['status']) ?></span></td>
          <td class="why"><?= $l['items_fetched'] !== null ? (int) $l['items_fetched'] . ' / ' . (int) $l['items_upserted'] : '–' ?></td>
          <td class="why"><?= vg_h(mb_strimwidth((string) ($l['message'] ?? ''), 0, 50, '…')) ?></td>
          <td class="why"><?= vg_h($l['started_at']) ?></td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
  </div>
<?php vg_footer();
