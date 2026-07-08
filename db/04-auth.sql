-- vuln-agent 웹 인증(3단계) : 사용자 계정
-- 최초 관리자(admin)는 secrets/admin_password.txt 로 자동 부트스트랩된다(auth.php).
-- 감사 4컬럼 통일: created_at 은 기존 보유, updated_at/is_deleted/deleted_at 추가.
SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS tb_users (
  id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  username      VARCHAR(64)  NOT NULL,
  password_hash VARCHAR(255) NOT NULL,   -- password_hash() (bcrypt)
  role          VARCHAR(16)  NOT NULL DEFAULT 'viewer',  -- admin | viewer
  created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_login    DATETIME NULL,
  updated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted    TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at    DATETIME NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_users_username (username),
  INDEX idx_users_is_deleted (is_deleted)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
