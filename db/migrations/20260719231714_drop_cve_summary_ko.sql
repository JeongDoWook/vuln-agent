-- LibreTranslate 기능 완전 제거에 따라 번역 저장 컬럼도 함께 삭제한다(20260718113107_cve_summary_ko.sql
--   에서 추가한 컬럼). 원문(summary/note)은 그대로 둔다 — 번역만 없앤다.
--   멱등: information_schema 확인 후에만 DROP(기존 파일과 동일 패턴).
--   전제: tb_cves/tb_kev_catalog 는 initdb(db/*.sql)가 만드는 핵심 테이블이라 이 마이그레이션이
--     도는 시점엔 항상 존재한다(테이블 자체 부재는 스키마 초기화 실패이지 이 마이그레이션의 책임 밖).
--   인덱스: 20260718113107 은 컬럼만 추가했고 summary_ko/note_ko 위에 인덱스를 만든 적이 없다
--     (FULLTEXT 는 원문 summary 에만 걸려 있다, 20260719105602) — DROP COLUMN 만으로 충분하다.
--   운영 반영 전 롤백 대비 백업(선택, 필요 시 배포자가 실행):
--     CREATE TABLE tb_cves_summary_ko_bak AS SELECT cve_id, summary_ko FROM tb_cves WHERE summary_ko IS NOT NULL;
--     CREATE TABLE tb_kev_note_ko_bak     AS SELECT cve_id, note_ko    FROM tb_kev_catalog WHERE note_ko IS NOT NULL;
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
