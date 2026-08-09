-- 자산 등급 확정의 낙관 잠금 버전. DATETIME 초 정밀도만으로는 같은 초 변경을 구분할 수 없다.
SET NAMES utf8mb4;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_host' AND COLUMN_NAME = 'grade_version');
SET @s := IF(@c = 0,
  "ALTER TABLE tb_host ADD COLUMN grade_version BIGINT UNSIGNED NOT NULL DEFAULT 0 COMMENT '등급 확정 동시 수정 충돌 검출용 버전' AFTER approved_at",
  'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
