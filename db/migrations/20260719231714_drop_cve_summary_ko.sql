-- LibreTranslate 기능 완전 제거에 따라 번역 저장 컬럼도 함께 삭제한다(20260718113107_cve_summary_ko.sql
--   에서 추가한 컬럼). 원문(summary/note)은 그대로 둔다 — 번역만 없앤다.
--   멱등: information_schema 확인 후에만 DROP(기존 파일과 동일 패턴).
--   전제: tb_cves/tb_kev_catalog 는 initdb(db/*.sql)가 만드는 핵심 테이블이라 이 마이그레이션이
--     도는 시점엔 항상 존재한다(테이블 자체 부재는 스키마 초기화 실패이지 이 마이그레이션의 책임 밖).
--   인덱스: DROP COLUMN 은 해당 컬럼이 포함된 인덱스를 MySQL 이 함께 정리하므로 별도 DROP INDEX
--     불필요(참고: FULLTEXT 는 원문 summary 에만 걸려 있다, 20260719105602).
--   백업: 이 마이그레이션은 compose_runner.sh 의 `up` 경로에서 migrate.sh 로 자동 실행되어
--     배포자가 손으로 개입할 기회가 없다(CLAUDE.md "수동 apply 금지"). translate 컨테이너 자체를
--     같이 없애 재번역(재생성) 경로도 사라지므로, DROP 전에 *_bak 테이블로 데이터를 멱등 백업해
--     둔다(컬럼이 이미 없는 재실행에서는 게이트가 막아 스킵). *_bak 은 이번 마이그레이션이
--     정리하지 않는다 — 필요 없어지면 별도 마이그레이션으로 DROP.
SET NAMES utf8mb4;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_cves' AND COLUMN_NAME = 'summary_ko');
SET @b := IF(@c > 0,
             'CREATE TABLE IF NOT EXISTS tb_cves_summary_ko_bak AS SELECT cve_id, summary_ko FROM tb_cves WHERE summary_ko IS NOT NULL',
             'DO 0');
PREPARE st FROM @b; EXECUTE st; DEALLOCATE PREPARE st;
SET @s := IF(@c > 0,
             'ALTER TABLE tb_cves DROP COLUMN summary_ko',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_kev_catalog' AND COLUMN_NAME = 'note_ko');
SET @b := IF(@c > 0,
             'CREATE TABLE IF NOT EXISTS tb_kev_note_ko_bak AS SELECT * FROM tb_kev_catalog WHERE note_ko IS NOT NULL',
             'DO 0');
PREPARE st FROM @b; EXECUTE st; DEALLOCATE PREPARE st;
SET @s := IF(@c > 0,
             'ALTER TABLE tb_kev_catalog DROP COLUMN note_ko',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
