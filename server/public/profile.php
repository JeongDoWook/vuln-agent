<?php
declare(strict_types=1);

/**
 * profile.php — 내 프로필 (로그인 사용자 모두).
 *   현재 사용자명·역할 표시 + 본인 비밀번호 변경.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
vg_require_login();

$pdo = vg_pdo();
$me  = vg_current_user();
$msg = null; $err = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!vg_csrf_check($_POST['csrf'] ?? null)) {
        $err = '세션이 만료되었습니다. 다시 시도하세요.';
    } else {
        $cur  = (string) ($_POST['current'] ?? '');
        $new  = (string) ($_POST['new'] ?? '');
        $conf = (string) ($_POST['confirm'] ?? '');
        if ($new !== $conf) {
            $err = '새 비밀번호가 일치하지 않습니다.';
        } else {
            $err = vg_change_own_password($pdo, (int) $me['id'], $cur, $new);
            if ($err === null) {
                $msg = '비밀번호가 변경되었습니다.';
            }
        }
    }
}

$csrf = vg_csrf_token();

vg_header('내 프로필', 'profile');
?>
  <header class="page-title"><div><span class="page-title__eyebrow">MY ACCOUNT</span><h1>내 프로필</h1><p><strong><?= vg_h($me['username']) ?></strong> · <?= vg_h(vg_role_label(vg_role())) ?></p></div></header>

  <div class="card card--sm">
    <strong>비밀번호 변경</strong>
    <form method="post" class="card__body">
      <?php vg_alert($msg, 'ok'); vg_alert($err); ?>
      <input type="hidden" name="csrf" value="<?= vg_h($csrf) ?>">
      <label for="current">현재 비밀번호</label>
      <input type="password" id="current" name="current" autocomplete="current-password" required>
      <label for="new">새 비밀번호 (8자 이상)</label>
      <input type="password" id="new" name="new" autocomplete="new-password" required>
      <label for="confirm">새 비밀번호 확인</label>
      <input type="password" id="confirm" name="confirm" autocomplete="new-password" required>
      <button type="submit" class="btn btn--primary btn--block">변경</button>
    </form>
  </div>
<?php vg_footer();
