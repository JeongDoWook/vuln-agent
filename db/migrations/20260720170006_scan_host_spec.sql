-- 에이전트 호스트 스펙 — 시스템 총 메모리·CPU 코어수.
--   대시보드 "에이전트 리소스 사용량" 카드를 절대치(MB, 초)에서 서버 스펙 대비
--   퍼센트로 바꾸려면 그 호스트의 총 메모리·코어수가 스캔마다 같이 필요하다.
--   0020(peak_rss_mb/cpu_seconds)과 동일하게 tb_scans 에 싣는다 — tb_hosts 를
--   건드리지 않고 기존 meta→scan 배관을 그대로 재사용한다.
--   멱등: information_schema 확인 후에만 추가(0020 과 동일 패턴).
SET NAMES utf8mb4;

-- 시스템 총 메모리(MB). /proc/meminfo MemTotal 을 그대로 MB 로 환산한 값.
SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_scans' AND COLUMN_NAME = 'mem_total_mb');
SET @s := IF(@c = 0,
             'ALTER TABLE tb_scans ADD COLUMN mem_total_mb DECIMAL(10,1) NULL AFTER cpu_seconds',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- CPU 코어수. nproc 값.
SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_scans' AND COLUMN_NAME = 'cpu_cores');
SET @s := IF(@c = 0,
             'ALTER TABLE tb_scans ADD COLUMN cpu_cores SMALLINT UNSIGNED NULL AFTER mem_total_mb',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
