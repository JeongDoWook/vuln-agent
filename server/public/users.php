<?php
declare(strict_types=1);

/**
 * users.php — 사용자 관리 (admin 전용). 목록 + 추가.
 *   역할변경·비번초기화·삭제는 상세 페이지(user.php?id=)에서 처리한다 — 여기는 조회 전용.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require_once __DIR__ . '/../src/audit.php';   // vg_soft_delete / vg_log_activity
vg_require_menu('users');

$pdo = vg_pdo();
$msg = null; $err = null;

/* 추가 모달을 다시 열어야 하는지 + 입력값 되살리기.
 * 추가에 실패했는데 모달이 닫혀 버리면 사용자는 뭐가 틀렸는지 못 보고 입력도 잃는다.
 * 비밀번호는 되살리지 않는다(폼에 평문으로 다시 심지 않는다). */
$addFailed = false; $addUsername = ''; $addRole = 'user';

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
        if ($err !== null) {
            $addFailed = true; $addUsername = $u; $addRole = $role;
        }
    }
}

$me = vg_current_user();

// 목록 페이지네이션 — 계정이 쌓이면 한 화면에 다 쏟지 않는다.
$perPage = vg_perpage();
$page    = vg_page();
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
  <div class="page-head">
    <h1>사용자 관리 <span class="hint">(<?= number_format($total) ?>명)</span></h1>
    <div class="toolbar"><?php vg_modal_btn('addUser', '+ 사용자 추가'); ?></div>
  </div>
  <div class="sub">admin 전용 · 계정 추가 · 역할 변경/초기화/삭제는 상세 페이지에서</div>

  <?php vg_alert($msg, 'ok'); vg_alert($err); ?>

  <?php
  $meId = (int) ($me['id'] ?? 0);

  vg_table(
      [
          ['label' => 'ID'],
          ['label' => '아이디'],
          ['label' => '역할'],
          ['label' => '생성', 'nowrap' => true],
          ['label' => '마지막 로그인', 'nowrap' => true],
      ],
      $users,
      [
          'cell' => [
              0 => fn($u) => vg_h((string) $u['id']),
              1 => function ($u) use ($meId) {
                  $html = '<strong><a href="/user.php?id=' . (int) $u['id'] . '">' . vg_h($u['username']) . '</a></strong>';
                  if ((int) $u['id'] === $meId) { $html .= ' <span class="pill">본인</span>'; }
                  return $html;
              },
              2 => fn($u) => '<span class="pill">' . vg_h(vg_role_label($u['role'])) . '</span>',
              3 => fn($u) => '<span class="why">' . vg_h($u['created_at']) . '</span>',
              4 => fn($u) => '<span class="why">' . vg_h($u['last_login'] ?? '–') . '</span>',
          ],
      ]
  );
  vg_page_nav($total, $perPage, $page);
  ?>

  <?php
  // 추가 폼은 자주 쓰는 게 아니라 목록 아래 펼쳐둘 이유가 없다 → 버튼 뒤 모달로.
  // 추가에 실패했으면(중복 아이디·짧은 비번) 다시 열어 준다 — 안 그러면 뭐가 틀렸는지 못 보고 입력도 잃는다.
  vg_modal_open('addUser', '사용자 추가', '', $addFailed);
  ?>
    <form method="post">
      <input type="hidden" name="csrf" value="<?= vg_h($csrf) ?>">
      <input type="hidden" name="action" value="add">
      <label>아이디</label>
      <input type="text" name="username" value="<?= vg_h($addUsername) ?>" required autocomplete="off">
      <label>비밀번호 <span class="why">(4자 이상)</span></label>
      <input type="password" name="password" required autocomplete="new-password">
      <label>역할</label>
      <select name="role">
        <option value="user"<?= $addRole === 'user' ? ' selected' : '' ?>>사용자 (조회)</option>
        <option value="operator"<?= $addRole === 'operator' ? ' selected' : '' ?>>운영자 (피드)</option>
        <option value="admin"<?= $addRole === 'admin' ? ' selected' : '' ?>>관리자 (전체)</option>
      </select>
      <?php vg_modal_foot('추가'); ?>
    </form>
  <?php vg_modal_close(); ?>
<?php vg_footer();
