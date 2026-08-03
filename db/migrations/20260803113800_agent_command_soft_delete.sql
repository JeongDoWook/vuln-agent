-- tb_agent_command 스키마 보정.
--   agent-command-web-ui 워커가 같은 테이블을 CREATE TABLE IF NOT EXISTS 로 먼저 만들었는데
--   (공용 dev DB — 두 워크트리가 나란히 migrate 를 돌리면 먼저 실행된 쪽이 CREATE 를 이긴다),
--   그 버전엔 이 워커(agent-command-queue-api)의 스펙에 있던 executed_at/is_deleted/deleted_at 이
--   빠져 있다. CREATE TABLE IF NOT EXISTS 는 이미 있는 테이블엔 아무 효과가 없으므로, 실행 순서와
--   무관하게 최종 스키마가 수렴하도록 ALTER 로 누락분만 보정한다.
SET NAMES utf8mb4;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_agent_command' AND COLUMN_NAME = 'executed_at');
SET @s := IF(@c = 0, 'ALTER TABLE tb_agent_command ADD COLUMN executed_at DATETIME NULL AFTER created_by', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_agent_command' AND COLUMN_NAME = 'is_deleted');
SET @s := IF(@c = 0, 'ALTER TABLE tb_agent_command ADD COLUMN is_deleted TINYINT(1) NOT NULL DEFAULT 0', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_agent_command' AND COLUMN_NAME = 'deleted_at');
SET @s := IF(@c = 0, 'ALTER TABLE tb_agent_command ADD COLUMN deleted_at DATETIME NULL', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
