-- findings.php 의 기본(통합) 목록이 여러 스캔(각 호스트 최신 1건씩, 실측 230개)을 IN() 으로
--   묶어 severity 별 COUNT 를 집계하는데, tb_findings 에 (scan_id) 선두 인덱스(uq_find)와
--   (severity) 단독 인덱스(idx_find_sev) 만 있으면 옵티마이저가 GROUP BY severity 를 정렬
--   없이 풀려고 idx_find_sev 전체 스캔(운영 실측 632,205행 — 테이블 거의 전체)을 골라버린다.
--   실제로 걸러지는 행은 IN() 대상 스캔들뿐(실측 41,554행)인데, 인덱스가 없어 옵티마이저가
--   그 선택성을 못 살린다 — 운영 실측 findings.php 첫 로드 10초 이상.
--   (scan_id, severity) 복합 인덱스를 추가하면 IN() 필터와 GROUP BY 를 한 인덱스로 같이
--   커버해 옵티마이저가 굳이 전체 스캔을 고를 이유가 없어진다.
-- 멱등: information_schema 확인 후에만 추가(0020/0015 와 동일 패턴).
SET NAMES utf8mb4;

SET @k := (SELECT COUNT(*) FROM information_schema.STATISTICS
           WHERE TABLE_SCHEMA = DATABASE()
             AND TABLE_NAME   = 'tb_findings'
             AND INDEX_NAME   = 'idx_find_scan_sev');
SET @s := IF(@k = 0,
             'ALTER TABLE tb_findings ADD INDEX idx_find_scan_sev (scan_id, severity)',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
