-- vuln-agent Export API 토큰 — 외부 시스템(예: AI 보고서 생성기)이 export.php 로
--   스캔 결과를 읽어갈 때 쓰는 읽기 전용 토큰. 웹(api-tokens.php)에서 발급/폐기한다.
--
--   원문은 저장하지 않는다. 발급 시 1회만 화면에 보여주고 DB 에는 SHA-256 해시만 둔다
--   (DB 가 유출돼도 토큰 원문은 복원 불가). 검증은 입력 토큰을 해시해 대조한다.
--   prefix(앞 12자)는 목록에서 어떤 토큰인지 식별하는 용도.
-- 감사 4컬럼 통일: created_at/updated_at/is_deleted/deleted_at. 폐기는 soft-delete.
SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS tb_api_tokens (
  id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  label        VARCHAR(100) NOT NULL,             -- 사람이 알아볼 용도(예: "AI 보고서 생성기")
  token_hash   CHAR(64) NOT NULL,                 -- SHA-256(hex) — 검증용, 원문 미저장
  token_prefix VARCHAR(16) NOT NULL,              -- 앞 12자(vga_xxxxxxxx) — 목록 식별용
  last_used_at DATETIME NULL,                     -- 마지막으로 이 토큰이 쓰인 시각
  created_by   BIGINT UNSIGNED NULL,              -- 발급한 관리자(tb_users.id)
  created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted   TINYINT(1) NOT NULL DEFAULT 0,     -- 폐기(revoke)
  deleted_at   DATETIME NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_api_token_hash (token_hash),
  INDEX idx_api_tokens_is_deleted (is_deleted)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
