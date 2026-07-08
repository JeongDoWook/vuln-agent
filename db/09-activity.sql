-- vuln-agent 활동 로그(감사 추적) — 사용자/시스템 행위를 시계열로 기록.
--   누가(user) 무엇을(activity_type) 어느 대상(scope, scope_id)에 했는지 남긴다.
--   data(JSON) 에 행위별 부가정보, ip_address 로 출처 추적.
SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS tb_activity_log (
  id            BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id       BIGINT UNSIGNED NULL,
  user_name     VARCHAR(100) NULL,
  actor_type    VARCHAR(20) NOT NULL DEFAULT 'USER',
  scope         VARCHAR(50) NOT NULL,
  scope_id      BIGINT UNSIGNED NULL,
  activity_type VARCHAR(70) NOT NULL,
  message       TEXT NULL,
  data          JSON NULL,
  ip_address    VARCHAR(45) NULL,
  created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted    TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at    DATETIME NULL,
  INDEX idx_activity_user (user_id),
  INDEX idx_activity_scope (scope, scope_id),
  INDEX idx_activity_type (activity_type),
  INDEX idx_activity_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
