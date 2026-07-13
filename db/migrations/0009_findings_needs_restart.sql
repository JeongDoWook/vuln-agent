-- tb_findings.needs_restart — "패치됐지만 프로세스가 옛 라이브러리를 물고 있음" 표시.
--   왜 컬럼이 필요한가: 호스트 상세는 CRITICAL/HIGH 만 보여준다. 재시작 필요 건은 노출도가
--   낮아 MEDIUM 인 경우가 많아 화면에서 통째로 빠진다 — 정작 "패치했다고 안심하는" 바로 그
--   항목인데. 플래그로 두면 등급과 무관하게 끌어올려 보여주고 필터도 걸 수 있다.
--   멱등: information_schema 로 존재 확인 후에만 ADD COLUMN.
SET NAMES utf8mb4;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE()
             AND TABLE_NAME   = 'tb_findings'
             AND COLUMN_NAME  = 'needs_restart');
SET @s := IF(@c = 0,
             'ALTER TABLE tb_findings ADD COLUMN needs_restart TINYINT(1) NOT NULL DEFAULT 0 AFTER in_kev',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
