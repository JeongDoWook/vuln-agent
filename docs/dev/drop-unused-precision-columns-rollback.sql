-- 미사용 컬럼 4개 제거 되돌리기(down) — `db/migrations/20260726201244_drop_unused_precision_columns.sql` 의 역방향.
--
--   왜 여기 있나: deploy/migrate.sh 는 up 만 적용한다(down 개념이 없다). 그래서 되돌리는 SQL 을
--   저장소에 문서로 남긴다(docs/dev/pk-naming-rollback.sql 과 같은 자리·같은 방식).
--
--   언제 쓰나: 사실상 필요 없다. 지운 4개는 코드 참조가 0회고 운영에서 non-null 이 하나도
--   없었으므로, 옛 코드로 롤백해도 컬럼이 없다고 깨지는 곳이 없다(INSERT/SELECT 어디에도
--   등장하지 않는다). 그래도 스키마를 원상복구해야 할 때를 위해 정의를 남긴다.
--
--   되돌려도 **값은 돌아오지 않는다.** DROP COLUMN 은 데이터를 버린다 — 다만 원본이 전부
--   NULL 이었으므로(운영 실측) 잃은 것이 없다. 다시 ADD 하면 전 행이 NULL 인 원래 상태다.
--
--   컬럼 정의는 `db/migrations/20260724010000_precision_platform.sql` 의 원본 그대로다
--   (같은 타입·NULL 허용·기본값 없음). 위치(AFTER)도 원래 순서로 복원한다.
--
--   적용:
--     docker exec -i vulnagent-db sh -c \
--       'MYSQL_PWD="$(cat /run/secrets/mysql_root_password)" mysql -uroot vulnagent' \
--       < docs/dev/drop-unused-precision-columns-rollback.sql
--
--   되돌린 뒤에는 tb_schema_migrations 에서 해당 파일명을 지워야 다음 배포 때 다시 적용된다:
--     DELETE FROM tb_schema_migrations WHERE filename = '20260726201244_drop_unused_precision_columns.sql';
--
--   멱등성: 정방향과 같은 information_schema 가드를 쓴다. 두 번 돌아도 안전하고,
--   이미 컬럼이 있는 DB 에 돌려도 아무 일도 하지 않는다.
--
--   정방향과 달리 여기엔 `LOCK=NONE` 을 붙이지 않는다. 되돌리기는 이미 뭔가 잘못됐을 때
--   쓰는 비상 경로라, "락 없이 못 하겠으면 에러" 보다 **느려도 반드시 끝나는** 쪽이 낫다.
--   대신 ADD COLUMN 이 재구축으로 떨어지면 그동안 해당 테이블 쓰기가 막힌다는 점을 감안해
--   배포창 안에서 돌린다(tb_finding_evidence 58만 행 기준 재구축은 십수 초 규모).
SET NAMES utf8mb4;

-- ── 1) tb_finding_evidence.suppression_evidence 복원 ───────────────────────
--   원본: suppression_evidence TEXT NULL   (network_evidence 와 feed_updated_at 사이)
SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_finding_evidence'
             AND COLUMN_NAME = 'suppression_evidence');
SET @s := IF(@c = 0,
             'ALTER TABLE tb_finding_evidence ADD COLUMN suppression_evidence TEXT NULL AFTER network_evidence',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- ── 2) tb_collection_stage 의 3개 복원 ─────────────────────────────────────
--   원본 순서: status → duration_ms → item_count → error_code → error_message → created_at
--   ADD 를 한 ALTER 로 묶으려면 AFTER 가 서로 얽히므로(error_code 는 item_count 뒤),
--   컬럼별로 나눠 각각 존재 가드를 둔다. 되돌리기는 빈도가 0에 가깝고 대상 행이 215행이라
--   재구축 비용이 문제되지 않는다 — 부분 적용 상태에서 다시 돌려도 안전한 쪽을 택한다.
SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_collection_stage'
             AND COLUMN_NAME = 'duration_ms');
SET @s := IF(@c = 0,
             'ALTER TABLE tb_collection_stage ADD COLUMN duration_ms INT UNSIGNED NULL AFTER status',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_collection_stage'
             AND COLUMN_NAME = 'error_code');
SET @s := IF(@c = 0,
             'ALTER TABLE tb_collection_stage ADD COLUMN error_code VARCHAR(64) NULL AFTER item_count',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_collection_stage'
             AND COLUMN_NAME = 'error_message');
SET @s := IF(@c = 0,
             'ALTER TABLE tb_collection_stage ADD COLUMN error_message VARCHAR(500) NULL AFTER error_code',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
