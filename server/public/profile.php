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
$st = $pdo->prepare('SELECT user_id, username, role, created_at, last_login FROM tb_user WHERE user_id = ? AND is_deleted = 0');
$st->execute([(int) $me['id']]);
$profile = $st->fetch() ?: $me;

vg_header('내 프로필', 'profile');
?>
  <?php vg_page_title('내 프로필', 'MY ACCOUNT'); ?>

  <?php /* 계정 값은 부제 한 줄로 이어 붙여 뒀는데, 부제는 화면 해설 자리라 값이 거기 얹혀
           있었다. 값은 값 자리(.kv)로 내린다 — 사용자 상세(user.php)가 같은 값을 세우는 방식이다. */ ?>
  <div class="card card--sm">
    <strong>계정</strong>
    <div class="card__body">
      <dl class="kv">
        <dt>아이디</dt><dd><?= vg_h((string) ($profile['username'] ?? $me['username'])) ?></dd>
        <dt>역할</dt><dd><?= vg_h(vg_role_label((string) ($profile['role'] ?? vg_role()))) ?></dd>
        <dt>계정 번호</dt><dd>#<?= (int) ($profile['user_id'] ?? $me['id']) ?></dd>
        <dt>생성</dt><dd><?= vg_h((string) ($profile['created_at'] ?? '–')) ?></dd>
        <dt>최근 로그인</dt><dd><?= vg_h((string) ($profile['last_login'] ?? '–')) ?></dd>
      </dl>
    </div>
  </div>

  <div class="card card--sm">
    <strong>비밀번호 변경</strong>
    <?php /* 라벨-입력 짝은 .setting-form/.field 규약으로 묶는다(다른 관리 화면과 동일). */ ?>
    <form method="post" class="card__body setting-form">
      <?php vg_alert($msg, 'ok'); vg_alert($err); ?>
      <input type="hidden" name="csrf" value="<?= vg_h($csrf) ?>">
      <label class="field" for="current">현재 비밀번호
        <input type="password" id="current" name="current" autocomplete="current-password" required>
      </label>
      <label class="field" for="new">새 비밀번호 (8자 이상)
        <input type="password" id="new" name="new" autocomplete="new-password" required>
      </label>
      <label class="field" for="confirm">새 비밀번호 확인
        <input type="password" id="confirm" name="confirm" autocomplete="new-password" required>
      </label>
      <button type="submit" class="btn btn--primary btn--block">변경</button>
    </form>
  </div>
<?php vg_footer();
