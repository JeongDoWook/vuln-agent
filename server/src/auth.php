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

// users 비어있으면 admin 부트스트랩 (secrets/admin_password 필요 — 없으면 계정을 만들지 않는다).
//   예전엔 시크릿이 없을 때 비번 'admin' 으로 조용히 계정을 열었다. compose.yml 은 항상
//   ADMIN_PASSWORD_FILE 을 주입하므로(dev·prod 공통) 정상 경로엔 영향 없다.
function vg_bootstrap_admin(PDO $pdo): void {
    $n = (int) $pdo->query('SELECT COUNT(*) FROM tb_user')->fetchColumn();
    if ($n > 0) {
        return;
    }
    $pw = (string) vg_secret('ADMIN_PASSWORD', '');
    if ($pw === '') {
        error_log('[auth] ADMIN_PASSWORD 시크릿이 없어 admin 부트스트랩을 거부했습니다.');
        return;
    }
    $st = $pdo->prepare('INSERT INTO tb_user (username, password_hash, role) VALUES (?,?,?)');
    $st->execute(['admin', password_hash($pw, PASSWORD_DEFAULT), 'admin']);
}

/**
 * 로그인 시도. 성공하면 null, 실패하면 실패 사유를 반환한다 — 'invalid' 또는
 * 'locked:{남은분}'(호출부인 login.php 가 이 값으로 잠금/일반실패 메시지를 분기·표시한다).
 *   - 이미 잠긴 계정: 비밀번호 검증 없이 즉시 'locked:{남은분}' — 실패 카운트는 건드리지 않는다.
 *   - 비밀번호 불일치: failed_login_count 를 원자적으로 1 증가(SELECT ... FOR UPDATE 로 행을
 *     잠근 뒤 같은 트랜잭션에서 UPDATE — 동시(브루트포스) 요청이 같은 옛 값을 읽어 서로
 *     덮어쓰는 lost-update 를 막는다). LOGIN_MAX_FAILS(env, 기본 5) 도달 시
 *     LOGIN_LOCK_MINUTES(env, 기본 15)분 잠금 + account_lock 감사로그.
 *   - 성공: session_token 을 새로 발급해 DB/세션에 함께 저장 — 이 컬럼을 덮어쓰는 것 자체가
 *     "기존 세션 강제 종료" 메커니즘이다(vg_current_user() 가 대조해 이전 세션을 끊는다).
 */
function vg_login(PDO $pdo, string $user, string $pass): ?string {
    $pdo->beginTransaction();
    try {
        $st = $pdo->prepare(
            'SELECT user_id, username, password_hash, role, locked_until, failed_login_count
               FROM tb_user WHERE username = ? AND is_deleted = 0 FOR UPDATE'
        );
        $st->execute([$user]);
        $row = $st->fetch();

        // 잠금 기간이 지났으면 이번 시도부터 실패 카운트를 0 부터 다시 센다 — 그렇지 않으면
        // 만료 직후 첫 실패(count=maxFails+1)가 조건을 즉시 재충족해 그대로 재잠금되고, 공격자는
        // 잠금주기마다 실패 요청 1건만 보내 계정을 사실상 영구 잠글 수 있었다(admin 자기잠금 위험).
        $lockExpired = false;
        if ($row && $row['locked_until'] !== null) {
            $lockedUntilTs = strtotime((string) $row['locked_until']);
            if ($lockedUntilTs > time()) {
                $pdo->commit();
                $remainMinutes = max(1, (int) ceil(($lockedUntilTs - time()) / 60));
                return 'locked:' . $remainMinutes;
            }
            $lockExpired = true;
        }

        if (!$row || !password_verify($pass, $row['password_hash'])) {
            if ($row) {
                $uid = (int) $row['user_id'];
                $fails = ($lockExpired ? 0 : (int) $row['failed_login_count']) + 1;
                $maxFails = (int) vg_env('LOGIN_MAX_FAILS', '5');
                $locked = $fails >= $maxFails;
                if ($locked) {
                    $lockMinutes = (int) vg_env('LOGIN_LOCK_MINUTES', '15');
                    $pdo->prepare(
                        'UPDATE tb_user SET failed_login_count = ?, locked_until = DATE_ADD(NOW(), INTERVAL ? MINUTE) WHERE user_id = ?'
                    )->execute([$fails, $lockMinutes, $uid]);
                } else {
                    // locked_until 도 함께 NULL 로 — 만료된 잠금 시각이 그대로 남아있으면
                    // (DB 를 직접 보는 사람에게) 여전히 잠긴 것처럼 오인될 수 있다.
                    $pdo->prepare('UPDATE tb_user SET failed_login_count = ?, locked_until = NULL WHERE user_id = ?')
                        ->execute([$fails, $uid]);
                }
                $pdo->commit();
                // 미인증 상태의 시도라 행위자는 세션 사용자가 아니다 — SYSTEM 으로 남겨 대상
                // 계정(scope_id) 을 행위자처럼 오인하지 않게 한다.
                if ($locked) {
                    vg_log_activity($pdo, 'USER', $uid, 'account_lock', '로그인 실패 누적으로 계정 잠금', null, null, 'SYSTEM');
                    return 'locked:' . $lockMinutes;
                }
                vg_log_activity($pdo, 'USER', $uid, 'login_fail', null, null, null, 'SYSTEM');
            } else {
                $pdo->commit();
            }
            return 'invalid';
        }

        session_regenerate_id(true);
        $uid = (int) $row['user_id'];
        $token = bin2hex(random_bytes(32));
        $_SESSION['uid']    = $uid;
        $_SESSION['uname']  = $row['username'];
        $_SESSION['role']   = $row['role'];
        $_SESSION['stoken'] = $token;
        $pdo->prepare(
            'UPDATE tb_user SET last_login = NOW(), session_token = ?, failed_login_count = 0, locked_until = NULL WHERE user_id = ?'
        )->execute([$token, $uid]);
        $pdo->commit();
        // 로그인 성공 감사로그(누가·언제·어디서).
        vg_log_activity($pdo, 'USER', $uid, 'login', null, null, $uid, 'USER', $_SERVER['REMOTE_ADDR'] ?? null);
        return null;
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        throw $e;
    }
}

function vg_logout(): void {
    // 이미 다른 로그인이 덮어쓴 토큰을 실수로 지우지 않도록 반드시 토큰 값도 WHERE 에 넣는다.
    if (!empty($_SESSION['uid']) && !empty($_SESSION['stoken'])) {
        try {
            vg_pdo()->prepare('UPDATE tb_user SET session_token = NULL WHERE user_id = ? AND session_token = ?')
                ->execute([(int) $_SESSION['uid'], (string) $_SESSION['stoken']]);
        } catch (Throwable $e) {
            error_log('[auth] logout session_token 정리 실패: ' . $e->getMessage());
        }
    }
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $p = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $p['path'], $p['domain'], $p['secure'], $p['httponly']);
    }
    session_destroy();
}

/**
 * 현재 로그인 사용자. $_SESSION['stoken'] 을 DB session_token(PK 조회, 저렴함)과 대조해
 *   불일치하면(다른 곳에서 재로그인되어 이 세션이 무효화된 것) 세션을 비우고 null 을 반환한다
 *   — 사유는 $_SESSION['login_kicked'] 플래그로 남겨 login.php 가 안내 문구를 보여준다.
 *   요청당 1회만 DB 조회하도록 결과를 static 캐시한다(여러 곳에서 반복 호출되므로).
 */
function vg_current_user(): ?array {
    if (empty($_SESSION['uid'])) {
        return null;
    }
    static $cached = false;   // false = 미검증, null = 무효화됨, array = 유효
    if ($cached !== false) {
        return $cached;
    }
    try {
        $st = vg_pdo()->prepare('SELECT session_token FROM tb_user WHERE user_id = ?');
        $st->execute([(int) $_SESSION['uid']]);
        $dbTok = $st->fetchColumn();
        $dbTok = is_string($dbTok) ? $dbTok : '';
        $sessTok = (string) ($_SESSION['stoken'] ?? '');
        if ($dbTok === '' || $sessTok === '' || !hash_equals($dbTok, $sessTok)) {
            unset($_SESSION['uid'], $_SESSION['uname'], $_SESSION['role'], $_SESSION['stoken']);
            $_SESSION['login_kicked'] = true;
            return $cached = null;
        }
    } catch (Throwable $e) {
        // DB 오류 시 세션을 강제로 끊지 않는다(가용성 우선) — 로그만 남긴다.
        error_log('[auth] 세션 토큰 검증 실패: ' . $e->getMessage());
    }
    return $cached = ['id' => (int) $_SESSION['uid'], 'username' => $_SESSION['uname'] ?? '', 'role' => $_SESSION['role'] ?? 'user'];
}

function vg_require_login(): void {
    if (!vg_current_user()) {
        $q = !empty($_SESSION['login_kicked']) ? '?reason=kicked' : '';
        unset($_SESSION['login_kicked']);
        header('Location: /login.php' . $q);
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

// 역할 한글 라벨. viewer 는 user 와 동일 취급.
function vg_role_label(string $role): string {
    $m = ['admin' => '관리자', 'operator' => '운영자', 'user' => '사용자', 'viewer' => '사용자'];
    return $m[$role] ?? '사용자';
}

// 역할 선택 UI 부가 설명(SSOT) — vg_role_label() 라벨만으론 화면에 필요한 용도 설명
//   ("(조회)"/"(피드)"/"(전체)")이 빠진다. users.php 신규 계정 추가 폼이 라벨+설명을
//   조합해 쓴다 — 화면 코드에 문구를 반복 작성하지 않기 위해 여기 하나로 묶는다.
const VG_ROLE_DESCRIPTIONS = ['admin' => '전체', 'operator' => '피드', 'user' => '조회'];

// --- 설정형 메뉴 접근권한 (tb_role_permission 기반) ---

/**
 * 메뉴코드→한글라벨. 권한설정 화면(permissions.php)의 행 라벨 SSOT.
 *   사이드바 라벨은 vg_nav_sections() 가 따로 갖는다 — 코드 하나가 링크 둘을 여는
 *   경우(findings → 취약점 현황 + CVE 목록)가 있어 1:1 로 못 묶기 때문이다.
 *   그래서 여기 라벨은 "그 코드를 체크하면 열리는 메뉴들"을 그대로 적는다.
 *
 *   이 목록은 nav.php 의 'perm' 코드와 반드시 일치해야 하는 **메뉴코드 정본**이다 —
 *   어긋나면 사이드바에 보이는데 눌러보면 403 나는 링크가 생긴다. admin 전용 메뉴
 *   (permissions·apitokens)도 여기엔 남기고, 권한 매트릭스에서만 뺀다(permissions.php).
 */
function vg_menus(): array {
    return [
        'dashboard'   => '대시보드',
        'assets'      => '자산 관리',
        'findings'    => '취약점 현황 · CVE 목록',
        'advisories'  => '국내 보안공지',
        'connectors'  => '피드 커넥터',
        'users'       => '사용자',
        'agenttokens' => '에이전트 토큰',
        'apitokens'   => 'API 토큰',
        'activity'    => '감사 로그',
        'permissions' => '권한 설정',
    ];
}

// 현재 사용자가 $menuCode 메뉴에 접근 가능한가.
//   - 비로그인: false
//   - admin: 항상 true (잠금방지 — DB 에 admin 행을 두지 않는다)
//   - 그 외: tb_role_permission 에서 (현재role) 전 메뉴를 요청당 1회 로드해 캐시.
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
                'SELECT menu_code, allowed FROM tb_role_permission WHERE role = ? AND is_deleted = 0'
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
    $st = $pdo->prepare('SELECT username, password_hash FROM tb_user WHERE user_id = ? AND is_deleted = 0');
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
    $pdo->prepare('UPDATE tb_user SET password_hash = ? WHERE user_id = ?')
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
