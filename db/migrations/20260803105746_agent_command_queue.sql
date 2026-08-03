-- 에이전트 명령 큐 — 상시 데몬(agent-daemon-poll-loop)이 폴링할 명령 저장소.
--   중앙→노드 인바운드 경로는 만들지 않는다(README 설계 제약). 중앙은 큐에 넣기만 하고,
--   에이전트가 자기 토큰으로 agent-poll.php 를 아웃바운드로 호출해 pull 해간다.
SET NAMES utf8mb4;

-- 호스트별 폴링 주기(초). 기본 3600 = 기존 1시간 timer 와 동일 동작 유지.
SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_host' AND COLUMN_NAME = 'poll_schedule_seconds');
SET @s := IF(@c = 0, 'ALTER TABLE tb_host ADD COLUMN poll_schedule_seconds INT NOT NULL DEFAULT 3600', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

CREATE TABLE IF NOT EXISTS tb_agent_command (
  agent_command_id BIGINT AUTO_INCREMENT PRIMARY KEY,
  host_id BIGINT NOT NULL,
  run_at DATETIME NULL,               -- NULL=즉시, 값 있으면 그 시각 1회
  status ENUM('pending','done','failed') NOT NULL DEFAULT 'pending',
  created_by BIGINT NULL,             -- tb_user.user_id (FK 미설정 — 이 저장소 감사 관련 테이블 관례)
  executed_at DATETIME NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at DATETIME NULL,
  KEY idx_host_status_runat (host_id, status, run_at),
  CONSTRAINT fk_agent_command_host FOREIGN KEY (host_id) REFERENCES tb_host(host_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
