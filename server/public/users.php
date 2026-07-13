<?php
declare(strict_types=1);

/**
 * users.php — 사용자 관리 (admin 전용). 목록 + 추가 + 삭제.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require_once __DIR__ . '/../src/audit.php';   // vg_soft_delete / vg_log_activity
vg_require_menu('users');

$pdo = vg_pdo();
$msg = null; $err = null;

// 저장 가능한 역할 3값(화이트리스트).
const VG_ROLES = ['user', 'operator', 'admin'];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $me = vg_current_user();
    if (!vg_csrf_check($_POST['csrf'] ?? null)) {
        $err = '세션이 만료되었습니다. 다시 시도하세요.';
    } elseif (($_POST['action'] ?? '') === 'add') {
        $u = trim((string) ($_POST['username'] ?? ''));
        $p = (string) ($_POST['password'] ?? '');
        $role = in_array($_POST['role'] ?? '', VG_ROLES, true) ? (string) $_POST['role'] : 'user';
        if ($u === '' || strlen($p) < 4) {
            $err = '아이디와 4자 이상 비밀번호를 입력하세요.';
        } else {
            try {
                $st = $pdo->prepare('INSERT INTO tb_users (username, password_hash, role) VALUES (?,?,?)');
                $st->execute([$u, password_hash($p, PASSWORD_DEFAULT), $role]);
                vg_log_activity($pdo, 'USER', (int) $pdo->lastInsertId(), 'user_add', "사용자 '$u' 추가", ['username' => $u, 'role' => $role]);
                $msg = "사용자 '$u' 추가됨.";
            } catch (Throwable $e) {
                $err = '추가 실패(중복 아이디?): ' . $e->getMessage();
            }
        }
    } elseif (($_POST['action'] ?? '') === 'role') {
        $id = (int) ($_POST['id'] ?? 0);
        $role = in_array($_POST['role'] ?? '', VG_ROLES, true) ? (string) $_POST['role'] : '';
        if ($id === (int) ($me['id'] ?? 0)) {
            $err = '자기 자신의 역할은 변경할 수 없습니다.';
        } elseif ($role === '') {
            $err = '유효하지 않은 역할입니다.';
        } else {
            $pdo->prepare('UPDATE tb_users SET role = ? WHERE id = ?')->execute([$role, $id]);
            vg_log_activity($pdo, 'USER', $id, 'user_role', '역할 변경', ['role' => $role]);
            $msg = '역할이 변경되었습니다.';
        }
    } elseif (($_POST['action'] ?? '') === 'reset') {
        $id = (int) ($_POST['id'] ?? 0);
        $p  = (string) ($_POST['password'] ?? '');
        if (strlen($p) < 8) {
            $err = '초기화 비밀번호는 8자 이상이어야 합니다.';
        } else {
            $pdo->prepare('UPDATE tb_users SET password_hash = ? WHERE id = ?')
                ->execute([password_hash($p, PASSWORD_DEFAULT), $id]);
            vg_log_activity($pdo, 'USER', $id, 'user_pw_reset', '비밀번호 초기화');
            $msg = '비밀번호가 초기화되었습니다.';
        }
    } elseif (($_POST['action'] ?? '') === 'delete') {
        $id = (int) ($_POST['id'] ?? 0);
        if ($id === (int) ($me['id'] ?? 0)) {
            $err = '자기 자신은 삭제할 수 없습니다.';
        } else {
            vg_soft_delete($pdo, 'tb_users', $id);
            vg_log_activity($pdo, 'USER', $id, 'user_delete', '사용자 삭제');
            $msg = '사용자 삭제됨.';
        }
    }
}

$me = vg_current_user();

// 목록 페이지네이션 — 계정이 쌓이면 한 화면에 다 쏟지 않는다.
$perPage = vg_perpage();
$page    = max(1, (int) ($_GET['page'] ?? 1));
$total   = (int) $pdo->query('SELECT COUNT(*) FROM tb_users WHERE is_deleted = 0')->fetchColumn();
$offset  = ($page - 1) * $perPage;

$users = $pdo->query(
    "SELECT id, username, role, created_at, last_login
       FROM tb_users WHERE is_deleted = 0 ORDER BY id
      LIMIT $perPage OFFSET $offset"
)->fetchAll();
$csrf = vg_csrf_token();

vg_header('사용자', 'users');
?>
  <h1>사용자 관리 <span class="hint">(<?= number_format($total) ?>명)</span></h1>
  <div class="sub">admin 전용 · 계정 추가 · 역할 변경 · 비번 초기화 · 삭제</div>

  <?php vg_alert($msg, 'ok'); vg_alert($err); ?>

  <?php
  $meId = (int) ($me['id'] ?? 0);
  // 역할 변경 select 옵션(공용).
  $roleOptions = function (string $cur): string {
      $labels = ['user' => '사용자', 'operator' => '운영자', 'admin' => '관리자'];
      $out = '';
      foreach ($labels as $v => $l) {
          $out .= '<option value="' . $v . '"' . ($cur === $v ? ' selected' : '') . '>' . $l . '</option>';
      }
      return $out;
  };

  vg_table(
      [
          ['label' => 'ID'],
          ['label' => '아이디'],
          ['label' => '역할'],
          ['label' => '생성', 'nowrap' => true],
          ['label' => '마지막 로그인', 'nowrap' => true],
          ['label' => '작업'],
      ],
      $users,
      [
          'cell' => [
              0 => fn($u) => vg_h((string) $u['id']),
              1 => fn($u) => '<strong>' . vg_h($u['username']) . '</strong>',
              2 => fn($u) => '<span class="pill">' . vg_h(vg_role_label($u['role'])) . '</span>',
              3 => fn($u) => '<span class="why">' . vg_h($u['created_at']) . '</span>',
              4 => fn($u) => '<span class="why">' . vg_h($u['last_login'] ?? '–') . '</span>',
              5 => function ($u) use ($csrf, $meId, $roleOptions) {
                  $id = (int) $u['id'];
                  // 정규화된 현재 역할(레거시 viewer→user).
                  $cur = $u['role'] === 'viewer' ? 'user' : (string) $u['role'];
                  $html = '<div class="actions">';
                  // 역할 변경(자기 자신 제외 — 자기 역할강등 방지).
                  if ($id !== $meId) {
                      $html .= '<form method="post">'
                          . '<input type="hidden" name="csrf" value="' . vg_h($csrf) . '">'
                          . '<input type="hidden" name="action" value="role">'
                          . '<input type="hidden" name="id" value="' . $id . '">'
                          . '<select name="role">' . $roleOptions($cur) . '</select>'
                          . '<button class="btn btn--sm btn--ghost">역할</button></form>';
                  } else {
                      $html .= '<span class="why">(본인)</span>';
                  }
                  // 비번 초기화.
                  $html .= '<form method="post" onsubmit="return confirm(\'비밀번호를 초기화할까요?\');">'
                      . '<input type="hidden" name="csrf" value="' . vg_h($csrf) . '">'
                      . '<input type="hidden" name="action" value="reset">'
                      . '<input type="hidden" name="id" value="' . $id . '">'
                      . '<input type="password" name="password" placeholder="새 비번(8자+)">'
                      . '<button class="btn btn--sm btn--warn">초기화</button></form>';
                  // 삭제(자기 자신 제외).
                  if ($id !== $meId) {
                      $html .= '<form method="post" onsubmit="return confirm(\'삭제할까요?\');">'
                          . '<input type="hidden" name="csrf" value="' . vg_h($csrf) . '">'
                          . '<input type="hidden" name="action" value="delete">'
                          . '<input type="hidden" name="id" value="' . $id . '">'
                          . '<button class="btn btn--sm btn--danger">삭제</button></form>';
                  }
                  $html .= '</div>';
                  return $html;
              },
          ],
      ]
  );
  vg_page_nav($total, $perPage, $page);
  ?>

  <div class="card card--narrow">
    <strong>사용자 추가</strong>
    <form method="post" class="card__body">
      <input type="hidden" name="csrf" value="<?= vg_h($csrf) ?>">
      <input type="hidden" name="action" value="add">
      <label>아이디</label>
      <input type="text" name="username" required>
      <label>비밀번호 (4자 이상)</label>
      <input type="password" name="password" required>
      <label>역할</label>
      <select name="role">
        <option value="user">사용자 (조회)</option>
        <option value="operator">운영자 (피드)</option>
        <option value="admin">관리자 (전체)</option>
      </select>
      <button type="submit" class="btn btn--ok btn--block">추가</button>
    </form>
  </div>
<?php vg_footer();
