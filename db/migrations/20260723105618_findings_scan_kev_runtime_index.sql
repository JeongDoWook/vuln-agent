-- index.php 의 "대응 우선순위" 카드 $urgent 쿼리가 tb_findings 을
--   scan_id 로 먼저 거르고 그 다음 (in_kev = 1 OR runtime_status = 'EXTERNAL') 조건으로
--   필터링한다. 현재는 uq_find(scan_id) 만으로 range scan 후 나머지 필터가 인덱스 외부에서
--   처리되어, 실측 ~11초 걸린다.
--   (scan_id, in_kev, runtime_status) 복합 인덱스를 추가하면 두 필터링까지 인덱스에서
--   커버해 스캔 행을 대폭 줄일 수 있다.
-- 멱등: information_schema 확인 후에만 추가 (PR #315 와 동일 패턴).
SET NAMES utf8mb4;

SET @k := (SELECT COUNT(*) FROM information_schema.STATISTICS
           WHERE TABLE_SCHEMA = DATABASE()
             AND TABLE_NAME   = 'tb_findings'
             AND INDEX_NAME   = 'idx_find_scan_kev_runtime');
SET @s := IF(@k = 0,
             'ALTER TABLE tb_findings ADD INDEX idx_find_scan_kev_runtime (scan_id, in_kev, runtime_status)',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
