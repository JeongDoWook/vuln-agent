-- 재매칭 결과의 지문. 판정 결과가 그대로면 findings 를 다시 쓰지 않기 위한 비교값이다.
-- NULL 이면 "아직 모른다" → 최초 1회는 반드시 재작성한다.
-- 인덱스는 붙이지 않는다 — 항상 WHERE id=? 로만 접근한다.
SET NAMES utf8mb4;

SET @has_col := (SELECT COUNT(*) FROM information_schema.COLUMNS
                  WHERE TABLE_SCHEMA = DATABASE()
                    AND TABLE_NAME = 'tb_scans'
                    AND COLUMN_NAME = 'match_fingerprint');
SET @sql := IF(@has_col = 0,
  'ALTER TABLE tb_scans ADD COLUMN match_fingerprint CHAR(40) NULL',
  'DO 0');
PREPARE st FROM @sql; EXECUTE st; DEALLOCATE PREPARE st;
