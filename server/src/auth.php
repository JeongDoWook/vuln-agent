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
    return ['id' => (int) $_SESSION['uid'], 'username' => $_SESSION['uname'] ?? '', 'role' => $_SESSION['role'] ?? 'user'];
}

function vg_require_login(): void {
    if (!vg_current_user()) {
        header('Location: /login.php');
        exit;
    }
}

// --- 역할(RBAC) 3단계: admin / operator / user (레거시 viewer→user 취급) ---

// 현재 세션 role. 없으면 'user'. 레거시 'viewer' 는 'user' 로 정규화.
function vg_role(): string {
    $r = $_SESSION['role'] ?? 'user';
    return $r === 'viewer' ? 'user' : $r;
}

// 정규화된 현재 role 이 인자로 준 역할 중 하나에 포함되면 true.
function vg_has_role(string ...$roles): bool {
    return in_array(vg_role(), $roles, true);
}

// 현재 role 이 허용 역할이 아니면 403 종료.
function vg_require_role(string ...$roles): void {
    if (!vg_current_user() || !vg_has_role(...$roles)) {
        http_response_code(403);
        echo 'forbidden';
        exit;
    }
}

// admin 전용(하위호환). 내부는 vg_require_role('admin') 로 위임.
function vg_require_admin(): void {
    vg_require_role('admin');
}

// 역할 한글 라벨. viewer 는 user 와 동일 취급.
function vg_role_label(string $role): string {
    $m = ['admin' => '관리자', 'operator' => '운영자', 'user' => '사용자', 'viewer' => '사용자'];
    return $m[$role] ?? '사용자';
}

// --- 설정형 메뉴 접근권한 (tb_role_permissions 기반) ---

// 메뉴코드→한글라벨 SSOT. nav/권한설정 화면이 공유한다.
function vg_menus(): array {
    return [
        'dashboard'   => '대시보드',
        'findings'    => '취약점',
        'advisories'  => '국내공지',
        'connectors'  => '피드',
        'users'       => '사용자',
        'activity'    => '감사로그',
        'permissions' => '권한설정',
    ];
}

// 현재 사용자가 $menuCode 메뉴에 접근 가능한가.
//   - 비로그인: false
//   - admin: 항상 true (잠금방지 — DB 에 admin 행을 두지 않는다)
//   - 그 외: tb_role_permissions 에서 (현재role) 전 메뉴를 요청당 1회 로드해 캐시.
function vg_can(string $menuCode): bool {
    if (!vg_current_user()) {
        return false;
    }
    $role = vg_role();
    if ($role === 'admin') {
        return true;
    }
    static $cache = [];               // role → [menu_code => bool]
    if (!array_key_exists($role, $cache)) {
        $allowed = [];
        try {
            $st = vg_pdo()->prepare(
                'SELECT menu_code, allowed FROM tb_role_permissions WHERE role = ? AND is_deleted = 0'
            );
            $st->execute([$role]);
            foreach ($st->fetchAll() as $r) {
                $allowed[(string) $r['menu_code']] = (int) $r['allowed'] === 1;
            }
        } catch (Throwable $e) {
            // 권한 테이블 조회 실패 시 안전하게 전부 거부(로그만 남기고 흐름 유지).
            error_log('[role_permissions] ' . $e->getMessage());
        }
        $cache[$role] = $allowed;
    }
    return $cache[$role][$menuCode] ?? false;
}

// 로그인 확인 후, 메뉴 접근권한이 없으면 403 종료.
function vg_require_menu(string $menuCode): void {
    vg_require_login();
    if (!vg_can($menuCode)) {
        http_response_code(403);
        echo 'forbidden';
        exit;
    }
}

/**
 * 본인 비밀번호 변경. 성공시 null, 실패시 한글 에러메시지 반환.
 *   - 현재 비번 불일치 / 8자 미만 / 아이디 포함 / 이전과 동일 을 순서대로 검증.
 */
function vg_change_own_password(PDO $pdo, int $uid, string $current, string $new): ?string {
    $st = $pdo->prepare('SELECT username, password_hash FROM tb_users WHERE id = ? AND is_deleted = 0');
    $st->execute([$uid]);
    $row = $st->fetch();
    if (!$row) {
        return '사용자를 찾을 수 없습니다.';
    }
    if (!password_verify($current, $row['password_hash'])) {
        return '현재 비밀번호가 일치하지 않습니다.';
    }
    if (strlen($new) < 8) {
        return '새 비밀번호는 8자 이상이어야 합니다.';
    }
    if (stripos($new, (string) $row['username']) !== false) {
        return '비밀번호에 아이디를 포함할 수 없습니다.';
    }
    if (password_verify($new, $row['password_hash'])) {
        return '이전과 다른 비밀번호를 사용하세요.';
    }
    $pdo->prepare('UPDATE tb_users SET password_hash = ? WHERE id = ?')
        ->execute([password_hash($new, PASSWORD_DEFAULT), $uid]);
    vg_log_activity($pdo, 'USER', $uid, 'password_change', '비밀번호 변경', null, $uid);
    return null;
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
