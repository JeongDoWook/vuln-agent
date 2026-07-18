-- CVE/KEV 요약 한글 번역 저장 컬럼 — LibreTranslate 자체 호스팅 배치(server/bin/translate_ko.php)가
--   채운다. 원문(summary/note)은 그대로 두고 옆에 번역만 얹는다(원문 손실 없음).
--   멱등: information_schema 확인 후에만 추가(0020·package_summary 마이그레이션과 동일 패턴).
SET NAMES utf8mb4;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_cves' AND COLUMN_NAME = 'summary_ko');
SET @s := IF(@c = 0,
             'ALTER TABLE tb_cves ADD COLUMN summary_ko MEDIUMTEXT NULL AFTER summary',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_kev_catalog' AND COLUMN_NAME = 'note_ko');
SET @s := IF(@c = 0,
             'ALTER TABLE tb_kev_catalog ADD COLUMN note_ko MEDIUMTEXT NULL AFTER note',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
