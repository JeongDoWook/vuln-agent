-- 에이전트 명령 실행 진행 상태 — 단계 기반 heartbeat와 실행 시각.
SET NAMES utf8mb4;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='tb_agent_command' AND COLUMN_NAME='progress_percent');
SET @s := IF(@c=0, 'ALTER TABLE tb_agent_command ADD COLUMN progress_percent TINYINT UNSIGNED NULL AFTER status', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='tb_agent_command' AND COLUMN_NAME='progress_stage');
SET @s := IF(@c=0, 'ALTER TABLE tb_agent_command ADD COLUMN progress_stage VARCHAR(40) NULL AFTER progress_percent', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='tb_agent_command' AND COLUMN_NAME='progress_message');
SET @s := IF(@c=0, 'ALTER TABLE tb_agent_command ADD COLUMN progress_message VARCHAR(255) NULL AFTER progress_stage', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='tb_agent_command' AND COLUMN_NAME='started_at');
SET @s := IF(@c=0, 'ALTER TABLE tb_agent_command ADD COLUMN started_at DATETIME NULL AFTER created_by', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='tb_agent_command' AND COLUMN_NAME='heartbeat_at');
SET @s := IF(@c=0, 'ALTER TABLE tb_agent_command ADD COLUMN heartbeat_at DATETIME NULL AFTER started_at', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
