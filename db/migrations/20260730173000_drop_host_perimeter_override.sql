-- 자산별 경계 방화벽 외부노출 오버라이드를 제거한다.
-- 에이전트가 수집한 호스트/컨테이너 방화벽 판정(tb_exposure.scope)은 그대로 보존한다.
DROP TABLE IF EXISTS tb_host_ext_port;

SET @has_perimeter_column := (
  SELECT COUNT(*)
    FROM information_schema.COLUMNS
   WHERE TABLE_SCHEMA = DATABASE()
     AND TABLE_NAME = 'tb_host'
     AND COLUMN_NAME = 'perimeter_firewalled'
);
SET @drop_perimeter_column := IF(
  @has_perimeter_column = 1,
  'ALTER TABLE tb_host DROP COLUMN perimeter_firewalled',
  'DO 0'
);
PREPARE stmt FROM @drop_perimeter_column;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
