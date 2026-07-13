-- vuln-agent 에이전트별 개별 수집 토큰 — 호스트(fqdn)에 1:1 바인딩.
--   기존 수집 인증은 단일 공유 토큰이라, 대상 1대가 침해되면 그 토큰으로 다른 호스트의
--   fqdn 을 위조해 남의 스캔을 덮어쓸 수 있었다(인벤토리 신뢰 붕괴).
--   개별 토큰은 발급 시 정한 host_fqdn 만 갱신할 수 있어(ingest.php 가 바인딩을 강제),
--   본문이 다른 호스트를 주장하면 거부한다.
--
--   원문은 저장하지 않는다 — 발급 시 1회만 화면에 보여주고 DB 엔 SHA-256 해시만 둔다
--   (api-tokens 와 동일한 패턴). 검증은 입력 토큰을 해시해 대조.
--   폐기는 is_revoked=1(즉시 무효). 감사 4컬럼 통일: created_at/updated_at/is_deleted/deleted_at.
--   활성 토큰(is_revoked=0)은 host_fqdn 당 하나만 — 발급 시 기존 활성분을 자동 폐기해 보장한다.
SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS tb_agent_tokens (
  id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  host_fqdn    VARCHAR(255) NOT NULL,             -- 이 토큰이 갱신할 수 있는 유일한 호스트
  label        VARCHAR(100) NOT NULL,             -- 사람이 알아볼 용도(예: "web01 수집 에이전트")
  token_hash   CHAR(64) NOT NULL,                 -- SHA-256(hex) — 검증용, 원문 미저장
  token_prefix VARCHAR(16) NOT NULL,              -- 앞 12자(vgt_xxxxxxxx) — 목록 식별용
  last_seen_at DATETIME NULL,                     -- 이 토큰으로 마지막 수신한 시각
  is_revoked   TINYINT(1) NOT NULL DEFAULT 0,     -- 폐기(즉시 무효)
  created_by   BIGINT UNSIGNED NULL,              -- 발급한 관리자(tb_users.id)
  created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted   TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at   DATETIME NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_agent_token_hash (token_hash),
  INDEX idx_agent_tokens_fqdn (host_fqdn),
  INDEX idx_agent_tokens_revoked (is_revoked)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 발급/폐기 화면(agent-tokens.php) 메뉴 권한 — admin 은 코드에서 항상 허용(행 없음).
--   operator: 허용(에이전트 배포·토큰 관리) / user: 불가.
INSERT IGNORE INTO tb_role_permissions (role, menu_code, allowed) VALUES
  ('operator', 'agenttokens', 1),
  ('user',     'agenttokens', 0);
