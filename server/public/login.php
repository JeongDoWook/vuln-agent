<?php
declare(strict_types=1);

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';

$err = null;
try {
    $pdo = vg_pdo();
    vg_bootstrap_admin($pdo);   // 최초 접근 시 admin 생성
} catch (Throwable $e) {
    $err = 'DB 연결 오류: ' . $e->getMessage();
}

// 이미 로그인 → 대시보드
if (vg_current_user()) {
    header('Location: /');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $err === null) {
    if (!vg_csrf_check($_POST['csrf'] ?? null)) {
        $err = '세션이 만료되었습니다. 다시 시도하세요.';
    } else {
        // 브루트포스 완화: 실패가 누적될수록 지연(최대 5초)
        $fails = (int) ($_SESSION['login_fails'] ?? 0);
        if ($fails > 0) {
            sleep(min($fails, 5));
        }
        $u = trim((string) ($_POST['username'] ?? ''));
        $p = (string) ($_POST['password'] ?? '');
        if (vg_login($pdo, $u, $p)) {
            unset($_SESSION['login_fails']);
            header('Location: /');
            exit;
        }
        $_SESSION['login_fails'] = $fails + 1;
        $err = '아이디 또는 비밀번호가 올바르지 않습니다.';
    }
}

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
    <?php // 로그인 실패가 누적되면 서버가 최대 5초 지연시킨다 → 스피너로 "멈춘 게 아님" 을 보여준다. ?>
    <button type="submit" class="btn btn--primary btn--block" data-loading="확인 중…">로그인</button>
  </form>
<?php
vg_footer();
