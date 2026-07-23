-- 억제 근거를 호스트/컨테이너별로 분리한다.
-- 기존 자연키에는 container_id가 없어 동일 스캔의 같은 CVE·패키지가 서로 덮어써졌다.
SET NAMES utf8mb4;

SET @has_col := (SELECT COUNT(*) FROM information_schema.COLUMNS
                  WHERE TABLE_SCHEMA = DATABASE()
                    AND TABLE_NAME = 'tb_suppressed_findings'
                    AND COLUMN_NAME = 'container_id');
SET @sql := IF(@has_col = 0,
  'ALTER TABLE tb_suppressed_findings ADD COLUMN container_id BIGINT UNSIGNED NOT NULL DEFAULT 0 AFTER scan_id',
  'DO 0');
PREPARE st FROM @sql; EXECUTE st; DEALLOCATE PREPARE st;

SET @has_uq := (SELECT COUNT(*) FROM information_schema.STATISTICS
                 WHERE TABLE_SCHEMA = DATABASE()
                   AND TABLE_NAME = 'tb_suppressed_findings'
                   AND INDEX_NAME = 'uq_supp');
SET @sql := IF(@has_uq > 0,
  'ALTER TABLE tb_suppressed_findings DROP INDEX uq_supp',
  'DO 0');
PREPARE st FROM @sql; EXECUTE st; DEALLOCATE PREPARE st;

ALTER TABLE tb_suppressed_findings
  ADD UNIQUE KEY uq_supp (scan_id, container_id, cve_id, package_name);

SET @has_idx := (SELECT COUNT(*) FROM information_schema.STATISTICS
                  WHERE TABLE_SCHEMA = DATABASE()
                    AND TABLE_NAME = 'tb_suppressed_findings'
                    AND INDEX_NAME = 'idx_supp_container');
SET @sql := IF(@has_idx = 0,
  'ALTER TABLE tb_suppressed_findings ADD KEY idx_supp_container (container_id)',
  'DO 0');
PREPARE st FROM @sql; EXECUTE st; DEALLOCATE PREPARE st;