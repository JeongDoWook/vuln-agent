<?php
declare(strict_types=1);

/**
 * audit.php — 감사(audit) 헬퍼 2종.
 *   - vg_soft_delete(): 하드삭제 대신 is_deleted=1 로 표시(복구 가능). 테이블명은 화이트리스트만.
 *   - vg_log_activity(): 의미있는 행위를 tb_activity_log 에 시계열로 남긴다(실패해도 본 흐름 유지).
 *
 * 웹 모듈화(view.php 계열)와 충돌을 피하려고 별도 파일로 둔다. 로깅이 필요한
 * 페이지에서 이 파일을 require 한다.
 */

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/ui_config.php';

/** 감사 데이터에서 인증정보 원문을 재귀적으로 제거한다. */
function vg_audit_sanitize($data) {
    if (!is_array($data)) { return $data; }
    $sensitive = ['password', 'password_hash', 'pass', 'token', 'token_hash', 'secret', 'csrf', 'authorization'];
    $clean = [];
    foreach ($data as $key => $value) {
        $normalized = strtolower((string) $key);
        $blocked = false;
        foreach ($sensitive as $needle) {
            if (str_contains($normalized, $needle)) { $blocked = true; break; }
        }
        $clean[$key] = $blocked ? '[REDACTED]' : vg_audit_sanitize($value);
    }
    return $clean;
}

/**
 * 수행업무(action) 어휘 — 접속기록 5요소의 "수행업무" 자리에 들어가는 정규화 동사.
 *   activity_type(세부 이벤트 코드)은 그대로 두고 그 위에 얹는 계층이다. 라벨은 vg_activity_action_labels().
 */
const VG_ACTIVITY_ACTIONS = ['READ', 'CREATE', 'UPDATE', 'DELETE', 'EXPORT', 'LOGIN', 'EXECUTE', 'OTHER'];

/**
 * activity_type → 수행업무 동사. 호출지점 54곳을 전부 고치지 않고도 새 컬럼이 채워지도록,
 *   vg_log_activity() 가 action 을 안 받으면 이 함수로 유도한다.
 *   알려진 코드는 표로, 나머지는 접미/접두 규칙으로. 어느 쪽에도 안 걸리면 OTHER(추측하지 않는다).
 */
function vg_activity_action(string $type): string {
    static $map = [
        'login'                 => 'LOGIN',
        'login_fail'            => 'LOGIN',
        'account_lock'          => 'UPDATE',
        'account_unlock'        => 'UPDATE',
        'password_change'       => 'UPDATE',
        'user_role'             => 'UPDATE',
        'user_pw_reset'         => 'UPDATE',
        'permission_update'     => 'UPDATE',
        'connector_save'        => 'UPDATE',
        'connector_toggle'      => 'UPDATE',
        'host_set_grade'        => 'UPDATE',
        'host_grade_review_save'=> 'UPDATE',
        'host_grade_review_clear' => 'DELETE',
        'host_perimeter_update' => 'UPDATE',
        'agent_schedule_change' => 'UPDATE',
        'agent_speed_tier_change' => 'UPDATE',
        'agent_auto_update'     => 'UPDATE',
        'export_data'           => 'EXPORT',
        'ingest'                => 'EXECUTE',
        'ingest_spoof_blocked'  => 'EXECUTE',
        'feed_run'              => 'EXECUTE',
        'page_view'             => 'READ',
    ];
    if (isset($map[$type])) { return $map[$type]; }
    if (str_starts_with($type, 'view_')) { return 'READ'; }
    if (str_starts_with($type, 'agent_command_')) { return 'EXECUTE'; }
    if (str_ends_with($type, '_delete') || str_ends_with($type, '_revoke')) { return 'DELETE'; }
    if (str_ends_with($type, '_add') || str_ends_with($type, '_issue') || str_ends_with($type, '_save')) { return 'CREATE'; }
    return 'OTHER';
}

/**
 * 자유 텍스트에서 인증정보를 지운다 — vg_audit_sanitize() 는 배열(키 기준)만 훑으므로,
 *   문자열로 들어오는 경로(subject·점검 비고 등)에는 그 마스킹이 안 걸린다.
 *   'password=xxx' 처럼 키=값 형태가 보이면 값 쪽을 [REDACTED] 로 덮고 제어문자를 없앤다.
 *   $max 로 저장 컬럼 길이에 맞춰 자른다.
 */
function vg_audit_redact_text(?string $text, int $max): ?string {
    if ($text === null) { return null; }
    $s = trim(preg_replace('/[\x00-\x1F\x7F]+/u', ' ', $text) ?? '');
    if ($s === '') { return null; }
    $s = preg_replace(
        '/(password[_a-z]*|pass|token[_a-z]*|secret|csrf|authorization)\s*[=:]\s*\S+/iu',
        '$1=[REDACTED]',
        $s
    ) ?? $s;
    return mb_substr($s, 0, $max);
}

/**
 * subject(처리 대상 자원) 정리 — 컬럼 길이(VARCHAR(255))에 맞추고, data JSON 에만 걸려 있던
 *   인증정보 마스킹이 이 새 경로로 우회되지 않게 한 번 더 거른다.
 */
function vg_audit_subject(?string $subject): ?string {
    return vg_audit_redact_text($subject, 255);
}

/**
 * 소프트 삭제: 실제 DELETE 대신 is_deleted/deleted_at 를 세운다.
 *   $table 은 SQL 에 그대로 들어가므로 반드시 화이트리스트로만 허용(주입 방지).
 *   PK 이름이 테이블마다 다르므로(`<단수 테이블명>_id`) 화이트리스트가 PK 도 함께 갖는다 —
 *   SQL 에 들어가는 두 이름 모두 이 표에서만 나오므로 주입 경로는 그대로 없다.
 */
function vg_soft_delete(PDO $pdo, string $table, int $id): void {
    // is_deleted/deleted_at 를 가진 삭제 대상 테이블만 허용. 값은 그 테이블의 PK 컬럼명.
    static $allowed = [
        'tb_user'           => 'user_id',
        'tb_feed_connector' => 'feed_connector_id',
        'tb_advisory'       => 'advisory_id',
        'tb_host'           => 'host_id',
        'tb_scan'           => 'scan_id',
        'tb_discovery_target' => 'discovery_target_id',   // 자산 탐색 대역(discovery.php)
    ];
    $pk = $allowed[$table] ?? null;
    if ($pk === null) {
        throw new InvalidArgumentException("soft-delete 불가 테이블: $table");
    }
    $pdo->prepare("UPDATE $table SET is_deleted = 1, deleted_at = NOW() WHERE $pk = ?")->execute([$id]);
}

/**
 * 활동 로그 기록. 전체 CRUD 자동로깅이 아니라 "의미있는 이벤트"만 호출한다.
 *   user_name/ip 는 지정 없으면 세션·요청에서 스냅샷. data 는 배열이면 JSON 으로 저장.
 *   감사 로깅 실패가 본 기능을 깨지 않도록 try/catch 로 감싼다.
 *
 *   접속기록 5요소(ISMS-P 2.9.4): 식별자(user_id/user_name) · 접속일시(created_at) ·
 *   접속지 IP(ip_address) · 처리한 정보주체(subject) · 수행업무(action).
 *   뒤의 두 인자는 **선택적**이라 기존 호출은 그대로 동작한다 — action 을 안 주면
 *   vg_activity_action($type) 이 유도하고, subject 는 알려주는 호출지점만 채운다.
 *   새 인자는 맨 뒤라 명명인자로 주는 편이 읽기 쉽다: `subject: $fqdn`.
 */
function vg_log_activity(
    PDO $pdo,
    string $scope,
    ?int $scopeId,
    string $type,
    ?string $message = null,
    $data = null,
    ?int $userId = null,
    string $actorType = 'USER',
    ?string $ip = null,
    ?string $subject = null,
    ?string $action = null,
    bool $strict = false
): void {
    try {
        $uid   = $userId ?? (isset($_SESSION['uid']) ? (int) $_SESSION['uid'] : null);
        $uname = isset($_SESSION['uname']) ? (string) $_SESSION['uname'] : null;
        $ip    = $ip ?? ($_SERVER['REMOTE_ADDR'] ?? null);
        $dataJson = null;
        if (is_array($data)) {
            $dataJson = json_encode(vg_audit_sanitize($data), JSON_UNESCAPED_UNICODE);
        } elseif (is_object($data)) {
            $dataJson = json_encode(vg_audit_sanitize((array) $data), JSON_UNESCAPED_UNICODE);
        } elseif (is_string($data) && $data !== '') {
            $dataJson = $data;
        }
        // 수행업무는 화이트리스트 밖 값을 저장하지 않는다 — 호출부 오타·자유문자열이
        // 5요소 컬럼으로 새는 걸 막는다(모르는 값은 OTHER).
        $action = $action !== null && in_array($action, VG_ACTIVITY_ACTIONS, true)
            ? $action
            : vg_activity_action($type);
        $subject = vg_audit_subject($subject);
        $st = $pdo->prepare(
            'INSERT INTO tb_activity_log
                (user_id, user_name, actor_type, scope, scope_id, activity_type, message, subject, action, data, ip_address)
             VALUES (?,?,?,?,?,?,?,?,?,?,?)'
        );
        $st->execute([$uid, $uname, $actorType, $scope, $scopeId, $type, $message, $subject, $action, $dataJson, $ip]);
    } catch (Throwable $e) {
        error_log('[activity_log] ' . $e->getMessage());
        if ($strict) { throw $e; }
    }
}

/**
 * 인증된 HTML 페이지 열람을 요청당 한 번 기록한다. 쿼리 값은 저장하지 않는다.
 *   $GLOBALS['vg_suppress_page_view'] 가 true 면 건너뛴다 — 그 페이지가 이미 더 구체적인
 *   view_* 이벤트(호스트/컨테이너/자산 범위 포함)를 남겨서, 이 범용 기록이 같은 열람 1회를
 *   2건으로 중복 기록하는 경우를 위한 탈출구다(sbom.php 시각화 보기). 기본은 false 라
 *   기존 페이지 동작은 그대로다.
 */
function vg_log_page_view(PDO $pdo, string $page, string $title, string $menuCode): void {
    if (!vg_audit_page_views_enabled() || ($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET') { return; }
    if (!empty($GLOBALS['vg_suppress_page_view'])) { return; }
    static $logged = false;
    if ($logged) { return; }
    $logged = true;
    $queryKeys = array_values(array_filter(array_map(
        static fn($key): string => preg_replace('/[^a-zA-Z0-9_-]/', '', (string) $key),
        array_keys($_GET)
    )));
    vg_log_activity($pdo, 'PAGE', null, 'page_view', $title, [
        'page' => basename($page),
        'menu' => $menuCode,
        'query_keys' => $queryKeys,
    ], subject: basename($page), action: 'READ');
}
