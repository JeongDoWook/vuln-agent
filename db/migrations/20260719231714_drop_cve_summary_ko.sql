-- LibreTranslate 기능 완전 제거에 따라 번역 저장 컬럼도 함께 삭제한다(20260718113107_cve_summary_ko.sql
--   에서 추가한 컬럼). 원문(summary/note)은 그대로 둔다 — 번역만 없앤다.
--   멱등: information_schema 확인 후에만 DROP(기존 파일과 동일 패턴).
--   전제: tb_cves/tb_kev_catalog 는 initdb(db/*.sql)가 만드는 핵심 테이블이라 이 마이그레이션이
--     도는 시점엔 항상 존재한다(테이블 자체 부재는 스키마 초기화 실패이지 이 마이그레이션의 책임 밖).
--   인덱스: DROP COLUMN 은 해당 컬럼이 포함된 인덱스를 MySQL 이 함께 정리하므로 별도 DROP INDEX
--     불필요(참고: FULLTEXT 는 원문 summary 에만 걸려 있다, 20260719105602).
--   백업: 이 마이그레이션은 배포 러너의 `up` 경로에서 migrate.sh 로 자동 실행되어 배포자가
--     손으로 개입할 기회가 없다(CLAUDE.md "수동 apply 금지"). translate 컨테이너 자체를 같이
--     없애 재번역(재생성) 경로도 사라지므로, DROP 전에 *_bak 테이블로 키+번역 컬럼만 백업해
--     둔다. CREATE TABLE ... AS SELECT(CTAS) 는 안 쓴다 — GTID_MODE=ON + ENFORCE_GTID_CONSISTENCY
--     인 MySQL 8.0(8.0.21 미만이거나 binlog_format 이 ROW 가 아니면)에서 CTAS 자체가
--     ER_GTID_UNSAFE_CREATE_SELECT 로 거부된다. 이 마이그레이션이 자동 실행 경로라 여기서
--     막히면 배포가 통째로 멈추고 DROP 도 안 된 채 남는다 — 그 구성을 안 쓴다는 보장이 없으니
--     대신 스키마를 명시한 CREATE TABLE(PK 포함) + INSERT IGNORE ... SELECT 2단계로 쪼갠다.
--     이 조합은 GTID 세이프하다. IGNORE 를 붙인 이유: "백업은 됐는데 DROP 직전에 죽은" 재실행
--     에서는 컬럼이 아직 있어 게이트(@c>0)를 다시 통과하는데, PK 가 이미 채워진 채로 순수
--     INSERT 를 쓰면 중복키 에러로 마이그레이션이 실패한다 — IGNORE 로 그 경우 조용히 건너뛰고
--     DROP 까지 이어지게 한다(컬럼이 이미 없는 정상 재실행에서는 게이트가 INSERT 자체를 스킵).
--   복원 예시(운영 반영 후 문제 발견 시):
--     UPDATE tb_cves t JOIN tb_cves_summary_ko_bak b ON b.cve_id = t.cve_id
--       SET t.summary_ko = b.summary_ko;  -- summary_ko 컬럼을 되살렸다면
--   정리: *_bak 은 이번 마이그레이션이 정리하지 않는다 — 정리 시점은 아직 정해지지 않았다.
--     배포 후 한동안(예: 다음 정기 배포 검토) 문제 없다고 확인되면 배포자가 판단해 별도
--     마이그레이션으로 DROP TABLE 한다. 그 전까지는 의도적으로 남겨 둔 백업이다.
SET NAMES utf8mb4;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_cves' AND COLUMN_NAME = 'summary_ko');
CREATE TABLE IF NOT EXISTS tb_cves_summary_ko_bak (
  cve_id     VARCHAR(32) NOT NULL PRIMARY KEY,
  summary_ko MEDIUMTEXT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
SET @b := IF(@c > 0,
             'INSERT IGNORE INTO tb_cves_summary_ko_bak (cve_id, summary_ko) SELECT cve_id, summary_ko FROM tb_cves WHERE summary_ko IS NOT NULL',
             'DO 0');
PREPARE st FROM @b; EXECUTE st; DEALLOCATE PREPARE st;
SET @s := IF(@c > 0,
             'ALTER TABLE tb_cves DROP COLUMN summary_ko',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_kev_catalog' AND COLUMN_NAME = 'note_ko');
CREATE TABLE IF NOT EXISTS tb_kev_note_ko_bak (
  cve_id  VARCHAR(32) NOT NULL PRIMARY KEY,
  note_ko MEDIUMTEXT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
SET @b := IF(@c > 0,
             'INSERT IGNORE INTO tb_kev_note_ko_bak (cve_id, note_ko) SELECT cve_id, note_ko FROM tb_kev_catalog WHERE note_ko IS NOT NULL',
             'DO 0');
PREPARE st FROM @b; EXECUTE st; DEALLOCATE PREPARE st;
SET @s := IF(@c > 0,
             'ALTER TABLE tb_kev_catalog DROP COLUMN note_ko',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
