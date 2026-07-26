<?php
declare(strict_types=1);

/**
 * apitoken.php — Export API 읽기 토큰의 발급·검증.
 *   원문은 발급 시 1회만 노출하고 DB 에는 SHA-256 해시만 저장한다.
 *   export.php(검증) 와 api-tokens.php(발급/폐기) 가 공용으로 쓴다.
 */

require_once __DIR__ . '/db.php';

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
 * @return array{token:string,prefix:string} 원문과 표시용 prefix
 */
function vg_api_token_issue(PDO $pdo, string $label, ?int $userId): array {
    $token  = vg_api_token_new();
    $prefix = substr($token, 0, 12);                 // vga_ + 앞 8자
    $pdo->prepare(
        'INSERT INTO tb_api_token (label, token_hash, token_prefix, created_by)
         VALUES (?, ?, ?, ?)'
    )->execute([$label, vg_api_token_hash($token), $prefix, $userId]);
    return ['token' => $token, 'prefix' => $prefix];
}

/**
 * 토큰 검증. 유효하면 last_used_at 갱신 후 토큰 행 api_token_id 반환, 아니면 null.
 *   해시 컬럼이 UNIQUE 라 인덱스 조회 1회. (해시 자체는 비밀이 아니므로 직접 조회해도 안전)
 */
function vg_api_token_verify(PDO $pdo, string $provided): ?int {
    $provided = trim($provided);
    if ($provided === '') { return null; }
    $st = $pdo->prepare(
        'SELECT api_token_id FROM tb_api_token WHERE token_hash = ? AND is_deleted = 0 LIMIT 1'
    );
    $st->execute([vg_api_token_hash($provided)]);
    $id = $st->fetchColumn();
    if ($id === false) { return null; }
    $pdo->prepare('UPDATE tb_api_token SET last_used_at = NOW() WHERE api_token_id = ?')->execute([(int) $id]);
    return (int) $id;
}
