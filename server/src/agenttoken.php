<?php
declare(strict_types=1);

/**
 * agenttoken.php — 에이전트별 개별 수집 토큰의 발급·검증·폐기.
 *   토큰은 발급 시 정한 host_fqdn 에 1:1 로 묶인다. ingest.php 가 이 바인딩을 강제해,
 *   침해된 대상 1대가 남의 fqdn 을 위조해 스캔을 덮어쓰는 것을 막는다.
 *   원문은 발급 시 1회만 노출하고 DB 엔 SHA-256 해시만 저장한다(api-tokens 와 같은 패턴).
 *   ingest.php(검증) 와 agent-tokens.php(발급/폐기) 가 공용으로 쓴다.
 */

require_once __DIR__ . '/db.php';

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
 * @return array{token:string,prefix:string,revoked:int} 원문·표시용 prefix·자동폐기된 기존 토큰 수
 */
function vg_agent_token_issue(PDO $pdo, string $fqdn, string $label, ?int $userId): array {
    $fqdn = trim($fqdn);
    if ($fqdn === '') {
        throw new RuntimeException('바인딩할 호스트(fqdn)를 입력하세요.');
    }
    // 기존 활성 토큰을 폐기(활성은 호스트당 하나) — 재발급이 곧 로테이션이 되도록.
    $st = $pdo->prepare(
        'UPDATE tb_agent_tokens SET is_revoked = 1
          WHERE host_fqdn = ? AND is_revoked = 0 AND is_deleted = 0'
    );
    $st->execute([$fqdn]);
    $revoked = $st->rowCount();

    $token  = vg_agent_token_new();
    $prefix = substr($token, 0, 12);                 // vgt_ + 앞 8자
    $pdo->prepare(
        'INSERT INTO tb_agent_tokens (host_fqdn, label, token_hash, token_prefix, created_by)
         VALUES (?, ?, ?, ?, ?)'
    )->execute([$fqdn, $label, vg_agent_token_hash($token), $prefix, $userId]);
    return ['token' => $token, 'prefix' => $prefix, 'revoked' => $revoked];
}

/**
 * 토큰 검증(수집 인증용). 유효하면 last_seen_at 갱신 후 바인딩 정보를 반환, 아니면 null.
 *   폐기(is_revoked)·소프트삭제된 토큰은 매칭하지 않는다 → 호출자는 다음 인증수단(공유토큰)으로
 *   넘어가거나 거부한다. 해시 컬럼이 UNIQUE 라 인덱스 조회 1회.
 * @return array{id:int,fqdn:string}|null
 */
function vg_agent_token_verify(PDO $pdo, string $provided): ?array {
    $provided = trim($provided);
    if ($provided === '') { return null; }
    $st = $pdo->prepare(
        'SELECT id, host_fqdn FROM tb_agent_tokens
          WHERE token_hash = ? AND is_revoked = 0 AND is_deleted = 0 LIMIT 1'
    );
    $st->execute([vg_agent_token_hash($provided)]);
    $row = $st->fetch();
    if (!$row) { return null; }
    $pdo->prepare('UPDATE tb_agent_tokens SET last_seen_at = NOW() WHERE id = ?')->execute([(int) $row['id']]);
    return ['id' => (int) $row['id'], 'fqdn' => (string) $row['host_fqdn']];
}

/** 폐기(즉시 무효). soft-delete 가 아니라 is_revoked 로 — 이력은 남기고 사용만 막는다. */
function vg_agent_token_revoke(PDO $pdo, int $id): void {
    $pdo->prepare('UPDATE tb_agent_tokens SET is_revoked = 1 WHERE id = ?')->execute([$id]);
}

/**
 * 목록에서 삭제(soft). **폐기된 토큰만** 지울 수 있다 — 활성 토큰은 폐기가 먼저다.
 *   폐기/재발급을 반복하면 죽은 행이 목록에 계속 쌓이는데, 지울 방법이 없었다.
 *   공용 vg_soft_delete() 는 조건(is_revoked=1)을 못 실어 별도 조회가 필요해진다.
 *   여기선 UPDATE 한 방에 조건을 넣어 검사와 삭제를 원자적으로 처리한다.
 */
function vg_agent_token_delete(PDO $pdo, int $id): void {
    $st = $pdo->prepare(
        'UPDATE tb_agent_tokens SET is_deleted = 1, deleted_at = NOW()
          WHERE id = ? AND is_revoked = 1 AND is_deleted = 0'
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
    $pdo->prepare('DELETE FROM tb_agent_replay_nonces WHERE expires_at < NOW()')->execute();
    try {
        $pdo->prepare('INSERT INTO tb_agent_replay_nonces (token_id,nonce_hash,expires_at) VALUES (?,?,DATE_ADD(NOW(),INTERVAL ? SECOND))')
            ->execute([$tokenId, hash('sha256', $nonce), $maxSkew]);
        return true;
    } catch (PDOException $e) {
        if ($e->getCode() === '23000') { return false; }
        throw $e;
    }
}