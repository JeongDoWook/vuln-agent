<?php
declare(strict_types=1);

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';

$err = null;
try {
    $pdo = vg_pdo();
    vg_bootstrap_admin($pdo);   // 최초 접근 시 admin 생성
} catch (Throwable $e) {
    error_log('[login] ' . $e->getMessage());
    $err = 'DB 연결 오류가 발생했습니다.';
}

// 이미 로그인 → 대시보드 (세션이 다른 곳에서 재로그인으로 무효화됐다면 vg_current_user() 가
// 여기서 감지해 $_SESSION['login_kicked'] 를 세우고 null 을 반환한다)
if (vg_current_user()) {
    header('Location: /');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $err === null) {
    if (!vg_csrf_check($_POST['csrf'] ?? null)) {
        $err = '세션이 만료되었습니다. 다시 시도하세요.';
    } else {
        $u = trim((string) ($_POST['username'] ?? ''));
        $p = (string) ($_POST['password'] ?? '');
        $result = vg_login($pdo, $u, $p);
        if ($result === null) {
            header('Location: /');
            exit;
        }
        // 'locked:{남은분}' — 실제 남은 대기시간(설정값이 아니라 locked_until 기준 계산값)을 보여준다.
        if (str_starts_with($result, 'locked:')) {
            $remainMinutes = (int) substr($result, strlen('locked:'));
            $err = "계정이 잠시 잠겼습니다. {$remainMinutes}분 후 다시 시도하세요.";
        } else {
            $err = '아이디 또는 비밀번호가 올바르지 않습니다.';
        }
    }
} elseif ($err === null && (($_GET['reason'] ?? '') === 'kicked' || !empty($_SESSION['login_kicked']))) {
    $err = '다른 곳에서 로그인되어 세션이 종료되었습니다.';
}
unset($_SESSION['login_kicked']);

vg_header('로그인');
?>
  <form class="card" method="post" action="/login.php">
    <div class="login-badge" aria-hidden="true">🛡️</div>
    <h1>vuln-agent</h1>
    <div class="sub">로그인이 필요합니다</div>
    <?php vg_alert($err); ?>
    <input type="hidden" name="csrf" value="<?= vg_h(vg_csrf_token()) ?>">
    <label for="username">아이디</label>
    <input type="text" id="username" name="username" autofocus autocomplete="username" required>
    <label for="password">비밀번호</label>
    <input type="password" id="password" name="password" autocomplete="current-password" required>
    <button type="submit" class="btn btn--primary btn--block" data-loading="확인 중…">로그인</button>
  </form>
<?php
vg_footer();
