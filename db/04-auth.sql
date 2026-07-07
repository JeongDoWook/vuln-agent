-- vuln-agent 웹 인증(3단계) : 사용자 계정
-- 최초 관리자(admin)는 secrets/admin_password.txt 로 자동 부트스트랩된다(auth.php).
SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS users (
  id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  username      VARCHAR(64)  NOT NULL,
  password_hash VARCHAR(255) NOT NULL,   -- password_hash() (bcrypt)
  role          VARCHAR(16)  NOT NULL DEFAULT 'viewer',  -- admin | viewer
  created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_login    DATETIME NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_users_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
