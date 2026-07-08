<?php
declare(strict_types=1);

/**
 * auth.php — 세션 기반 로그인/권한.
 *   - 최초 접근 시 users 가 비어있으면 secrets/admin_password 로 admin 자동 생성.
 *   - vg_require_login() 으로 페이지 보호, vg_current_user() 로 현재 사용자.
 */

require_once __DIR__ . '/config.php';   // vg_env / vg_secret 정의
require_once __DIR__ . '/db.php';       // vg_pdo
require_once __DIR__ . '/audit.php';    // vg_log_activity

if (session_status() === PHP_SESSION_NONE) {
    // HTTPS(또는 리버스프록시 X-Forwarded-Proto)면 Secure 쿠키
    $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
          || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
    session_set_cookie_params(['httponly' => true, 'samesite' => 'Lax', 'secure' => $https]);
    session_start();
}

// users 비어있으면 admin 부트스트랩 (secrets/admin_password → 없으면 'admin')
function vg_bootstrap_admin(PDO $pdo): void {
    $n = (int) $pdo->query('SELECT COUNT(*) FROM tb_users')->fetchColumn();
    if ($n > 0) {
        return;
    }
    $pw = (string) vg_secret('ADMIN_PASSWORD', '');
    if ($pw === '') {
        $pw = 'admin'; // dev 대비 최후 기본값
    }
    $st = $pdo->prepare('INSERT INTO tb_users (username, password_hash, role) VALUES (?,?,?)');
    $st->execute(['admin', password_hash($pw, PASSWORD_DEFAULT), 'admin']);
}

function vg_login(PDO $pdo, string $user, string $pass): bool {
    $st = $pdo->prepare('SELECT id, username, password_hash, role FROM tb_users WHERE username = ? AND is_deleted = 0');
    $st->execute([$user]);
    $row = $st->fetch();
    if (!$row || !password_verify($pass, $row['password_hash'])) {
        return false;
    }
    session_regenerate_id(true);
    $_SESSION['uid']   = (int) $row['id'];
    $_SESSION['uname'] = $row['username'];
    $_SESSION['role']  = $row['role'];
    $pdo->prepare('UPDATE tb_users SET last_login = NOW() WHERE id = ?')->execute([(int) $row['id']]);
    // 로그인 성공 감사로그(누가·언제·어디서).
    vg_log_activity($pdo, 'USER', (int) $row['id'], 'login', null, null, (int) $row['id'], 'USER', $_SERVER['REMOTE_ADDR'] ?? null);
    return true;
}

function vg_logout(): void {
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $p = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $p['path'], $p['domain'], $p['secure'], $p['httponly']);
    }
    session_destroy();
}

function vg_current_user(): ?array {
    if (empty($_SESSION['uid'])) {
        return null;
    }
    return ['id' => (int) $_SESSION['uid'], 'username' => $_SESSION['uname'] ?? '', 'role' => $_SESSION['role'] ?? 'viewer'];
}

function vg_require_login(): void {
    if (!vg_current_user()) {
        header('Location: /login.php');
        exit;
    }
}

function vg_require_admin(): void {
    $u = vg_current_user();
    if (!$u || ($u['role'] ?? '') !== 'admin') {
        http_response_code(403);
        echo 'forbidden (admin only)';
        exit;
    }
}

// --- CSRF ---
function vg_csrf_token(): string {
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(16));
    }
    return $_SESSION['csrf'];
}

function vg_csrf_check(?string $t): bool {
    return !empty($_SESSION['csrf']) && is_string($t) && hash_equals($_SESSION['csrf'], $t);
}
