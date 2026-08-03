-- 에이전트 명령 큐 — 웹에서 즉시실행/예약실행 명령을 tb_agent_command 에 넣고,
--   상시 데몬화된 에이전트가 주기적으로 poll 해가는 구조(agent-daemon-poll-loop 워커와 병렬 설계).
--   host_id 별 수집 주기는 tb_host.poll_schedule_seconds 로 별도 관리(에이전트가 poll 간격을 여기서 읽는다).
-- 멱등: 새 테이블은 CREATE TABLE IF NOT EXISTS 로 충분, 컬럼 추가는 information_schema 가드.
SET NAMES utf8mb4;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_host' AND COLUMN_NAME = 'poll_schedule_seconds');
SET @s := IF(@c = 0,
             'ALTER TABLE tb_host ADD COLUMN poll_schedule_seconds INT UNSIGNED NOT NULL DEFAULT 3600 AFTER last_seen',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

CREATE TABLE IF NOT EXISTS tb_agent_command (
  agent_command_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  host_id      BIGINT UNSIGNED NOT NULL,
  run_at       DATETIME NULL,                          -- NULL=즉시 실행
  status       VARCHAR(16) NOT NULL DEFAULT 'pending',  -- pending/done/failed/cancelled
  created_by   BIGINT UNSIGNED NULL,                    -- 등록한 관리자(tb_user.user_id)
  created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (agent_command_id),
  CONSTRAINT fk_agent_command_host FOREIGN KEY (host_id) REFERENCES tb_host(host_id) ON DELETE CASCADE,
  INDEX idx_agent_command_host_status (host_id, status, run_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
