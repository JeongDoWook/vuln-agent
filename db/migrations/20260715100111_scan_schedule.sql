-- 수집 주기(에이전트 타이머 OnCalendar) — 노드별 스케줄을 중앙에서 읽기전용으로 보여주기 위해.
--   에이전트가 meta.schedule(=agent.env 의 SCHEDULE)을 실어 오면 최신 스캔에 기록한다.
--   agent_version 옆에 형제 컬럼 하나를 얹는다(새 배관 아님).
--   멱등: information_schema 확인 후에만 추가(0020 과 동일 패턴).
SET NAMES utf8mb4;

-- 수집 주기 문자열(systemd OnCalendar 값: 'hourly' · 'daily' · '*:0/30' 등).
SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_scans' AND COLUMN_NAME = 'schedule');
SET @s := IF(@c = 0,
             'ALTER TABLE tb_scans ADD COLUMN schedule VARCHAR(64) NULL AFTER agent_version',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
