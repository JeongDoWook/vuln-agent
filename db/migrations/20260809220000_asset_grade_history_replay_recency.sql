-- #542 후속: 동일 결과 replay의 마지막 관찰시각을 행 증가 없이 보존한다.
-- 앞 migration이 개발/배포 환경에 이미 적용됐을 수 있어 ALTER를 별도 파일로 둔다.
SET NAMES utf8mb4;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='tb_asset_grade_suggestion_history'
    AND COLUMN_NAME='last_source_collected_at');
SET @s := IF(@c=0,
  'ALTER TABLE tb_asset_grade_suggestion_history ADD COLUMN last_source_collected_at DATETIME NULL AFTER observed_at',
  'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='tb_asset_grade_suggestion_history'
    AND COLUMN_NAME='last_observed_at');
SET @s := IF(@c=0,
  'ALTER TABLE tb_asset_grade_suggestion_history ADD COLUMN last_observed_at DATETIME NULL AFTER last_source_collected_at',
  'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

UPDATE tb_asset_grade_suggestion_history
   SET last_source_collected_at = COALESCE(last_source_collected_at, source_collected_at),
       last_observed_at = COALESCE(last_observed_at, observed_at);

-- generated 식과 인덱스는 기존 정의가 있어도 최종형으로 수렴시킨다.
SET @c := (SELECT COUNT(*) FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='tb_asset_grade_suggestion_history'
    AND INDEX_NAME='idx_asset_grade_suggestion_host_time');
SET @s := IF(@c>0,
  'ALTER TABLE tb_asset_grade_suggestion_history DROP INDEX idx_asset_grade_suggestion_host_time',
  'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='tb_asset_grade_suggestion_history'
    AND COLUMN_NAME='effective_at');
SET @s := IF(@c>0,
  'ALTER TABLE tb_asset_grade_suggestion_history DROP COLUMN effective_at',
  'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

ALTER TABLE tb_asset_grade_suggestion_history
  MODIFY last_observed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  ADD COLUMN effective_at DATETIME GENERATED ALWAYS AS
    (LEAST(GREATEST(COALESCE(last_source_collected_at,last_observed_at),
      DATE_SUB(last_observed_at, INTERVAL 7 DAY)),last_observed_at)) STORED,
  ADD INDEX idx_asset_grade_suggestion_host_time
    (host_id,effective_at,last_observed_at,suggestion_history_id);
