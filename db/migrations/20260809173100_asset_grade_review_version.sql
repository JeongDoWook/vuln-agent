-- 최초 자산 등급 검토 마이그레이션의 초기본이 먼저 적용된 환경도 최종 스키마로 수렴시킨다.
-- 신규 환경에서는 두 컬럼이 이미 존재하므로 두 구문 모두 DO 0 이다.
SET NAMES utf8mb4;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_asset_grade_review' AND COLUMN_NAME = 'is_stale');
SET @s := IF(@c = 0,
  "ALTER TABLE tb_asset_grade_review ADD COLUMN is_stale TINYINT(1) NOT NULL DEFAULT 0 COMMENT '일괄 등급 변경 뒤 호스트별 재검토 필요 여부' AFTER next_review_date",
  'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_asset_grade_review' AND COLUMN_NAME = 'review_version');
SET @s := IF(@c = 0,
  "ALTER TABLE tb_asset_grade_review ADD COLUMN review_version BIGINT UNSIGNED NOT NULL DEFAULT 1 COMMENT '동시 수정 충돌 검출용 버전' AFTER is_stale",
  'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
