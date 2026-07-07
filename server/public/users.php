<?php
declare(strict_types=1);

/**
 * users.php — 사용자 관리 (admin 전용). 목록 + 추가 + 삭제.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
vg_require_login();
vg_require_admin();

$pdo = vg_pdo();
$msg = null; $err = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!vg_csrf_check($_POST['csrf'] ?? null)) {
        $err = '세션이 만료되었습니다. 다시 시도하세요.';
    } elseif (($_POST['action'] ?? '') === 'add') {
        $u = trim((string) ($_POST['username'] ?? ''));
        $p = (string) ($_POST['password'] ?? '');
        $role = ($_POST['role'] ?? 'viewer') === 'admin' ? 'admin' : 'viewer';
        if ($u === '' || strlen($p) < 4) {
            $err = '아이디와 4자 이상 비밀번호를 입력하세요.';
        } else {
            try {
                $st = $pdo->prepare('INSERT INTO users (username, password_hash, role) VALUES (?,?,?)');
                $st->execute([$u, password_hash($p, PASSWORD_DEFAULT), $role]);
                $msg = "사용자 '$u' 추가됨.";
            } catch (Throwable $e) {
                $err = '추가 실패(중복 아이디?): ' . $e->getMessage();
            }
        }
    } elseif (($_POST['action'] ?? '') === 'delete') {
        $id = (int) ($_POST['id'] ?? 0);
        $me = vg_current_user();
        if ($id === (int) ($me['id'] ?? 0)) {
            $err = '자기 자신은 삭제할 수 없습니다.';
        } else {
            $pdo->prepare('DELETE FROM users WHERE id = ?')->execute([$id]);
            $msg = '사용자 삭제됨.';
        }
    }
}

$users = $pdo->query('SELECT id, username, role, created_at, last_login FROM users ORDER BY id')->fetchAll();
$csrf = vg_csrf_token();

vg_header('사용자', 'users');
?>
  <h1>사용자 관리</h1>
  <div class="sub">admin 전용 · 계정 추가/삭제</div>

  <?php if ($msg): ?><div class="err" style="background:#12261a;border-color:#238636;color:#7ee787;"><?= vg_h($msg) ?></div><?php endif; ?>
  <?php if ($err): ?><div class="err"><?= vg_h($err) ?></div><?php endif; ?>

  <div class="card">
    <table>
      <thead><tr><th>ID</th><th>아이디</th><th>역할</th><th>생성</th><th>마지막 로그인</th><th></th></tr></thead>
      <tbody>
      <?php foreach ($users as $u): ?>
        <tr>
          <td><?= (int) $u['id'] ?></td>
          <td><strong><?= vg_h($u['username']) ?></strong></td>
          <td><span class="pill"><?= vg_h($u['role']) ?></span></td>
          <td class="why"><?= vg_h($u['created_at']) ?></td>
          <td class="why"><?= vg_h($u['last_login'] ?? '–') ?></td>
          <td>
            <form method="post" style="margin:0;" onsubmit="return confirm('삭제할까요?');">
              <input type="hidden" name="csrf" value="<?= vg_h($csrf) ?>">
              <input type="hidden" name="action" value="delete">
              <input type="hidden" name="id" value="<?= (int) $u['id'] ?>">
              <button class="btn-sm" style="background:#6e2830;">삭제</button>
            </form>
          </td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
  </div>

  <div class="card" style="max-width:520px;">
    <strong>사용자 추가</strong>
    <form method="post" style="margin-top:.6rem;">
      <input type="hidden" name="csrf" value="<?= vg_h($csrf) ?>">
      <input type="hidden" name="action" value="add">
      <label>아이디</label>
      <input type="text" name="username" required>
      <label>비밀번호 (4자 이상)</label>
      <input type="password" name="password" required>
      <label>역할</label>
      <select name="role" style="width:100%;padding:.5rem;background:#0f1115;border:1px solid #30363d;border-radius:8px;color:#e6e6e6;">
        <option value="viewer">viewer (조회)</option>
        <option value="admin">admin (관리)</option>
      </select>
      <button type="submit">추가</button>
    </form>
  </div>
<?php vg_footer();
