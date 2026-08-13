<?php
declare(strict_types=1);

/**
 * agenttoken.php — 에이전트별 개별 수집 토큰의 발급·검증·폐기.
 *   토큰은 발급 시 정한 host_fqdn 에 1:1 로 묶인다. ingest.php 가 이 바인딩을 강제해,
 *   침해된 대상 1대가 남의 fqdn 을 위조해 스캔을 덮어쓰는 것을 막는다.
 *   원문은 발급 시 1회만 노출하고 DB 엔 SHA-256 해시만 저장한다.
 *   ingest.php(검증) 와 agent-tokens.php(발급/폐기) 가 공용으로 쓴다.
 */

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/audit.php';        // vg_log_activity (만료 토큰 사용 시도 기록)
require_once __DIR__ . '/tokenexpiry.php';  // vg_token_is_expired / vg_token_expires_at

const VG_AGENT_TOKEN_PREFIX = 'vgt_';   // vuln-agent token. 목록·로그에서 알아보기 쉽게.

/** 새 토큰 원문 생성. 형식: vgt_ + hex40 (충돌·추측 불가능한 길이). */
function vg_agent_token_new(): string {
    return VG_AGENT_TOKEN_PREFIX . bin2hex(random_bytes(20));
}

/** 검증·저장에 쓰는 해시(SHA-256 hex). */
function vg_agent_token_hash(string $token): string {
    return hash('sha256', $token);
}

/**
 * 토큰 발급 → DB 저장. 원문은 저장하지 않으므로 호출자가 화면에 1회만 보여줘야 한다.
 *   같은 host_fqdn 에 활성 토큰이 이미 있으면 자동 폐기하고 새로 발급한다(활성 토큰 1:1 보장).
 *   폐기된 기존 토큰 수를 함께 돌려줘 호출자가 감사 로그·안내에 쓸 수 있게 한다.
 *   $expiresDays 는 vg_token_expiry_days_input() 으로 검증된 값(0 = 무기한).
 * @return array{token:string,prefix:string,revoked:int,expires_at:?string} 원문·prefix·자동폐기 수·만료시각
 */
function vg_agent_token_issue(PDO $pdo, string $fqdn, string $label, ?int $userId, int $expiresDays = 0): array {
    $fqdn = trim($fqdn);
    if ($fqdn === '') {
        throw new RuntimeException('바인딩할 호스트(fqdn)를 입력하세요.');
    }
    // 기존 활성 토큰을 폐기(활성은 호스트당 하나) — 재발급이 곧 로테이션이 되도록.
    $st = $pdo->prepare(
        'UPDATE tb_agent_token SET is_revoked = 1
          WHERE host_fqdn = ? AND is_revoked = 0 AND is_deleted = 0'
    );
    $st->execute([$fqdn]);
    $revoked = $st->rowCount();

    $token     = vg_agent_token_new();
    $prefix    = substr($token, 0, 12);              // vgt_ + 앞 8자
    $expiresAt = vg_token_expires_at($expiresDays);
    $pdo->prepare(
        'INSERT INTO tb_agent_token (host_fqdn, label, token_hash, token_prefix, created_by, expires_at)
         VALUES (?, ?, ?, ?, ?, ?)'
    )->execute([$fqdn, $label, vg_agent_token_hash($token), $prefix, $userId, $expiresAt]);
    return ['token' => $token, 'prefix' => $prefix, 'revoked' => $revoked, 'expires_at' => $expiresAt];
}

/**
 * 토큰 검증(수집 인증용). 유효하면 last_seen_at 갱신 후 바인딩 정보를 반환, 아니면 null.
 *   폐기(is_revoked)·소프트삭제된 토큰은 매칭하지 않으며 호출자는 요청을 거부한다.
 *   해시 컬럼이 UNIQUE 라 인덱스 조회 1회.
 *   expires_at 이 지난 토큰도 **인증 실패**로 처리하고 감사로그(agent_token_expired)를 남긴다 —
 *   "없는 토큰"과 "만료된 토큰"은 운영자에게 다른 사건이라 구분해 기록한다.
 *   만료 토큰은 last_seen_at 을 갱신하지 않는다(수신된 적 없는 것으로 남긴다).
 * @return array{id:int,fqdn:string}|null
 */
function vg_agent_token_verify(PDO $pdo, string $provided): ?array {
    $provided = trim($provided);
    if ($provided === '') { return null; }
    $st = $pdo->prepare(
        'SELECT agent_token_id, host_fqdn, token_prefix, expires_at FROM tb_agent_token
          WHERE token_hash = ? AND is_revoked = 0 AND is_deleted = 0 LIMIT 1'
    );
    $st->execute([vg_agent_token_hash($provided)]);
    $row = $st->fetch();
    if (!$row) { return null; }
    $id = (int) $row['agent_token_id'];
    if (vg_token_is_expired($row['expires_at'] !== null ? (string) $row['expires_at'] : null)) {
        vg_log_activity($pdo, 'AGENT_TOKEN', $id, 'agent_token_expired',
            '만료된 에이전트 토큰으로 접근 시도 → 거부',
            ['fqdn' => (string) $row['host_fqdn'], 'prefix' => (string) $row['token_prefix'],
             'expires_at' => (string) $row['expires_at']],
            null, 'SYSTEM');
        return null;
    }
    $pdo->prepare('UPDATE tb_agent_token SET last_seen_at = NOW() WHERE agent_token_id = ?')->execute([$id]);
    return ['id' => $id, 'fqdn' => (string) $row['host_fqdn']];
}

/** 폐기(즉시 무효). soft-delete 가 아니라 is_revoked 로 — 이력은 남기고 사용만 막는다. */
function vg_agent_token_revoke(PDO $pdo, int $id): void {
    $pdo->prepare('UPDATE tb_agent_token SET is_revoked = 1 WHERE agent_token_id = ?')->execute([$id]);
}

/**
 * 목록에서 삭제(soft). **폐기된 토큰만** 지울 수 있다 — 활성 토큰은 폐기가 먼저다.
 *   폐기/재발급을 반복하면 죽은 행이 목록에 계속 쌓이는데, 지울 방법이 없었다.
 *   공용 vg_soft_delete() 는 조건(is_revoked=1)을 못 실어 별도 조회가 필요해진다.
 *   여기선 UPDATE 한 방에 조건을 넣어 검사와 삭제를 원자적으로 처리한다.
 */
function vg_agent_token_delete(PDO $pdo, int $id): void {
    $st = $pdo->prepare(
        'UPDATE tb_agent_token SET is_deleted = 1, deleted_at = NOW()
          WHERE agent_token_id = ? AND is_revoked = 1 AND is_deleted = 0'
    );
    $st->execute([$id]);
    if ($st->rowCount() === 0) {
        throw new RuntimeException('폐기된 토큰만 삭제할 수 있습니다. 활성 토큰은 먼저 폐기하세요.');
    }
}

/** Reject stale or repeated signed transport metadata for individual agent tokens. */
function vg_agent_nonce_accept(PDO $pdo, int $tokenId, string $nonce, int $sentAt): bool {
    $maxSkew = max(60, (int) vg_env('AGENT_NONCE_MAX_SKEW_SECONDS', '600'));
    if ($nonce === '' || strlen($nonce) > 200 || abs(time() - $sentAt) > $maxSkew) { return false; }
    $pdo->prepare('DELETE FROM tb_agent_replay_nonce WHERE expires_at < NOW()')->execute();
    try {
        $pdo->prepare('INSERT INTO tb_agent_replay_nonce (agent_token_id,nonce_hash,expires_at) VALUES (?,?,DATE_ADD(NOW(),INTERVAL ? SECOND))')
            ->execute([$tokenId, hash('sha256', $nonce), $maxSkew]);
        return true;
    } catch (PDOException $e) {
        if ($e->getCode() === '23000') { return false; }
        throw $e;
    }
}
