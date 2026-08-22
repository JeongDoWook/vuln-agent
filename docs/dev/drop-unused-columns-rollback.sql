-- 미사용 컬럼 3개 제거 되돌리기(down) — `db/migrations/20260809162209_drop_unused_columns.sql` 의 역방향.
--
--   왜 여기 있나: deploy/migrate.sh 는 up 만 적용한다(down 개념이 없다). 그래서 되돌리는 SQL 을
--   저장소에 문서로 남긴다(docs/dev/drop-unused-precision-columns-rollback.sql 과 같은 자리·같은 방식).
--
--   언제 쓰나: 사실상 필요 없다. 지운 3개는 읽는 코드가 0곳이다 —
--     · tb_finding.matched_at / tb_suppressed_finding.matched_at 은 INSERT 에 명시된 적도,
--       SELECT 된 적도 없다(DB 기본값으로만 채워지던 컬럼).
--     · tb_setting.value_type 은 settings.php 의 INSERT 에만 있던 쓰기 전용 컬럼이고,
--       타입 구분의 정본은 코드의 vg_setting_defs()['type'] 이다.
--   그래서 옛 코드로 롤백해도 컬럼이 없다고 깨지는 곳이 없다. 그래도 스키마를 원상복구해야
--   할 때를 위해 정의를 남긴다.
--
--   되돌려도 **값은 돌아오지 않는다.** DROP COLUMN 은 데이터를 버린다 — matched_at 은 다시 ADD 하면
--   전 행이 그 시점 CURRENT_TIMESTAMP 가 되고, value_type 은 전 행이 기본값 'int' 가 된다.
--
--   컬럼 정의·위치(AFTER)는 원본 그대로다
--   (db/02-matcher.sql · db/13-changelog.sql · db/migrations/20260808110238_setting.sql 기준).
--
--   적용:
--     docker exec -i vulnagent-db sh -c \
--       'MYSQL_PWD="$(cat /run/secrets/mysql_root_password)" mysql -uroot vulnagent' \
--       < docs/dev/drop-unused-columns-rollback.sql
--
--   되돌린 뒤에는 tb_schema_migrations 에서 해당 파일명을 지워야 다음 배포 때 다시 적용된다:
--     DELETE FROM tb_schema_migrations WHERE filename = '20260809162209_drop_unused_columns.sql';
--
--   멱등성: 정방향과 같은 information_schema 가드를 쓴다. 두 번 돌아도 안전하고,
--   이미 컬럼이 있는 DB 에 돌려도 아무 일도 하지 않는다.
SET NAMES utf8mb4;

-- ── 1) tb_finding.matched_at 복원 (rationale 뒤) ───────────────────────────
SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='tb_finding' AND COLUMN_NAME='matched_at');
SET @s := IF(@c=0,
             'ALTER TABLE tb_finding ADD COLUMN matched_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP AFTER rationale',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- ── 2) tb_suppressed_finding.matched_at 복원 (suppress_reason 뒤) ──────────
SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='tb_suppressed_finding' AND COLUMN_NAME='matched_at');
SET @s := IF(@c=0,
             'ALTER TABLE tb_suppressed_finding ADD COLUMN matched_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP AFTER suppress_reason',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- ── 3) tb_setting.value_type 복원 (setting_value 뒤) ───────────────────────
SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='tb_setting' AND COLUMN_NAME='value_type');
SET @s := IF(@c=0,
             'ALTER TABLE tb_setting ADD COLUMN value_type ENUM(''int'',''string'') NOT NULL DEFAULT ''int'' AFTER setting_value',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
