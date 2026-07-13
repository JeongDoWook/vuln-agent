-- 에이전트 자기계측 — 실행당 리소스 발자국(피크 메모리·CPU 시간).
--   서버 담당자가 "이 에이전트가 내 서버에 얼마나 부담을 주나"를 자기 대시보드에서
--   직접 확인할 수 있게, 매 수집이 자기 peak RSS·CPU 초를 페이로드에 실어 온다.
--   기존 elapsed_seconds 배관 옆에 형제 컬럼 2개를 얹는다(새 배관 아님).
--   멱등: information_schema 확인 후에만 추가(0013 과 동일 패턴).
SET NAMES utf8mb4;

-- 피크 메모리(MB). 프로세스 트리 전체 최댓값 — jq·dpkg 자식 피크까지 포함.
SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_scans' AND COLUMN_NAME = 'peak_rss_mb');
SET @s := IF(@c = 0,
             'ALTER TABLE tb_scans ADD COLUMN peak_rss_mb DECIMAL(8,1) NULL AFTER elapsed_seconds',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- CPU 시간(초, 자식 포함). 벽시계(elapsed_seconds)와 달리 실제 점유 비용.
SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_scans' AND COLUMN_NAME = 'cpu_seconds');
SET @s := IF(@c = 0,
             'ALTER TABLE tb_scans ADD COLUMN cpu_seconds DECIMAL(8,2) NULL AFTER peak_rss_mb',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
