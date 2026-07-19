-- LibreTranslate 기능 완전 제거에 따라 번역 저장 컬럼도 함께 삭제한다(20260718113107_cve_summary_ko.sql
--   에서 추가한 컬럼). 원문(summary/note)은 그대로 둔다 — 번역만 없앤다.
--   멱등: information_schema 확인 후에만 DROP(기존 파일과 동일 패턴).
SET NAMES utf8mb4;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_cves' AND COLUMN_NAME = 'summary_ko');
SET @s := IF(@c > 0,
             'ALTER TABLE tb_cves DROP COLUMN summary_ko',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_kev_catalog' AND COLUMN_NAME = 'note_ko');
SET @s := IF(@c > 0,
             'ALTER TABLE tb_kev_catalog DROP COLUMN note_ko',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
