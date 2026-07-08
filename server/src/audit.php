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

/**
 * 소프트 삭제: 실제 DELETE 대신 is_deleted/deleted_at 를 세운다.
 *   $table 은 SQL 에 그대로 들어가므로 반드시 화이트리스트로만 허용(주입 방지).
 */
function vg_soft_delete(PDO $pdo, string $table, int $id): void {
    // is_deleted/deleted_at 를 가진 삭제 대상 테이블만 허용.
    static $allowed = [
        'tb_users'           => true,
        'tb_feed_connectors' => true,
        'tb_advisories'      => true,
        'tb_hosts'           => true,
        'tb_scans'           => true,
    ];
    if (empty($allowed[$table])) {
        throw new InvalidArgumentException("soft-delete 불가 테이블: $table");
    }
    $pdo->prepare("UPDATE $table SET is_deleted = 1, deleted_at = NOW() WHERE id = ?")->execute([$id]);
}

/**
 * 활동 로그 기록. 전체 CRUD 자동로깅이 아니라 "의미있는 이벤트"만 호출한다.
 *   user_name/ip 는 지정 없으면 세션·요청에서 스냅샷. data 는 배열이면 JSON 으로 저장.
 *   감사 로깅 실패가 본 기능을 깨지 않도록 try/catch 로 감싼다.
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
    ?string $ip = null
): void {
    try {
        $uid   = $userId ?? (isset($_SESSION['uid']) ? (int) $_SESSION['uid'] : null);
        $uname = isset($_SESSION['uname']) ? (string) $_SESSION['uname'] : null;
        $ip    = $ip ?? ($_SERVER['REMOTE_ADDR'] ?? null);
        $dataJson = null;
        if (is_array($data) || is_object($data)) {
            $dataJson = json_encode($data, JSON_UNESCAPED_UNICODE);
        } elseif (is_string($data) && $data !== '') {
            $dataJson = $data;
        }
        $st = $pdo->prepare(
            'INSERT INTO tb_activity_log
                (user_id, user_name, actor_type, scope, scope_id, activity_type, message, data, ip_address)
             VALUES (?,?,?,?,?,?,?,?,?)'
        );
        $st->execute([$uid, $uname, $actorType, $scope, $scopeId, $type, $message, $dataJson, $ip]);
    } catch (Throwable $e) {
        error_log('[activity_log] ' . $e->getMessage());
    }
}
