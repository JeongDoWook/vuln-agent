-- 실제 읽기·갱신 경로가 없는 중복 시각 컬럼 제거.
-- advisory.updated_at/content_fetched_at, replay_nonce.expires_at가 각각 필요한 역할을 담당한다.
SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='tb_advisory' AND COLUMN_NAME='fetched_at');
SET @s := IF(@c=1, 'ALTER TABLE tb_advisory DROP COLUMN fetched_at', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='tb_agent_replay_nonce' AND COLUMN_NAME='seen_at');
SET @s := IF(@c=1, 'ALTER TABLE tb_agent_replay_nonce DROP COLUMN seen_at', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
