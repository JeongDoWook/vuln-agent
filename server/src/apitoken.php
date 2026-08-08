<?php
declare(strict_types=1);

/**
 * apitoken.php — Export API 읽기 토큰의 발급·검증.
 *   원문은 발급 시 1회만 노출하고 DB 에는 SHA-256 해시만 저장한다.
 *   export.php(검증) 와 api-tokens.php(발급/폐기) 가 공용으로 쓴다.
 */

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/audit.php';        // vg_log_activity (만료 토큰 사용 시도 기록)
require_once __DIR__ . '/tokenexpiry.php';  // vg_token_is_expired / vg_token_expires_at

const VG_API_TOKEN_PREFIX = 'vga_';   // vuln-agent api. 목록에서 알아보기 쉽게.

/** 새 토큰 원문 생성. 형식: vga_ + hex40 (충돌·추측 불가능한 길이). */
function vg_api_token_new(): string {
    return VG_API_TOKEN_PREFIX . bin2hex(random_bytes(20));
}

/** 검증·저장에 쓰는 해시(SHA-256 hex). */
function vg_api_token_hash(string $token): string {
    return hash('sha256', $token);
}

/**
 * 토큰 발급 → DB 저장. 원문은 저장하지 않으므로 호출자가 화면에 1회만 보여줘야 한다.
 *   $expiresDays 는 vg_token_expiry_days_input() 으로 검증된 값(0 = 무기한).
 * @return array{token:string,prefix:string,expires_at:?string} 원문·표시용 prefix·만료시각
 */
function vg_api_token_issue(PDO $pdo, string $label, ?int $userId, int $expiresDays = 0): array {
    $token     = vg_api_token_new();
    $prefix    = substr($token, 0, 12);              // vga_ + 앞 8자
    $expiresAt = vg_token_expires_at($expiresDays);
    $pdo->prepare(
        'INSERT INTO tb_api_token (label, token_hash, token_prefix, created_by, expires_at)
         VALUES (?, ?, ?, ?, ?)'
    )->execute([$label, vg_api_token_hash($token), $prefix, $userId, $expiresAt]);
    return ['token' => $token, 'prefix' => $prefix, 'expires_at' => $expiresAt];
}

/**
 * 토큰 검증. 유효하면 last_used_at 갱신 후 토큰 행 api_token_id 반환, 아니면 null.
 *   해시 컬럼이 UNIQUE 라 인덱스 조회 1회. (해시 자체는 비밀이 아니므로 직접 조회해도 안전)
 *   expires_at 이 지난 토큰은 **인증 실패**로 처리하고 감사로그(api_token_expired)를 남긴다 —
 *   "없는 토큰"과 "만료된 토큰"은 운영자에게 다른 사건이라 구분해 기록한다.
 *   만료 토큰은 last_used_at 을 갱신하지 않는다(사용된 적 없는 것으로 남긴다).
 */
function vg_api_token_verify(PDO $pdo, string $provided): ?int {
    $provided = trim($provided);
    if ($provided === '') { return null; }
    $st = $pdo->prepare(
        'SELECT api_token_id, token_prefix, expires_at FROM tb_api_token
          WHERE token_hash = ? AND is_deleted = 0 LIMIT 1'
    );
    $st->execute([vg_api_token_hash($provided)]);
    $row = $st->fetch();
    if (!$row) { return null; }
    $id = (int) $row['api_token_id'];
    if (vg_token_is_expired($row['expires_at'] !== null ? (string) $row['expires_at'] : null)) {
        vg_log_activity($pdo, 'API_TOKEN', $id, 'api_token_expired',
            '만료된 API 토큰으로 접근 시도 → 거부',
            ['prefix' => (string) $row['token_prefix'], 'expires_at' => (string) $row['expires_at']],
            null, 'SYSTEM');
        return null;
    }
    $pdo->prepare('UPDATE tb_api_token SET last_used_at = NOW() WHERE api_token_id = ?')->execute([$id]);
    return $id;
}
