-- 에이전트 명령에 "패키지 무결성 검사 포함" 옵션.
--   rpm -Va / dpkg --verify 는 설치된 모든 파일을 해시해 수 분 + 무거운 디스크 IO 라
--   기본은 꺼짐(0)이다. 중앙에서 필요할 때만 이 컬럼을 1 로 걸어 그 실행에서만 돈다.
--   기존 행·기존 호출부는 DEFAULT 0 으로 그대로 동작한다(하위호환).
SET NAMES utf8mb4;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='tb_agent_command' AND COLUMN_NAME='verify_files');
SET @s := IF(@c=0, 'ALTER TABLE tb_agent_command ADD COLUMN verify_files TINYINT(1) NOT NULL DEFAULT 0 AFTER run_at', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
