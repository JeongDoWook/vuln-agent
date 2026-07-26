-- 미사용 컬럼 4개 제거 — `20260724010000_precision_platform.sql` 이 만들었지만 아무도 안 쓴 것들.
--
--   484개 컬럼을 코드 참조와 전수 대조한 결과 실제로 죽은 컬럼은 아래 4개뿐이었다.
--   `server/**`·`tests/**` 어디에도 참조가 0회고, 운영 실측으로도 non-null 이 하나도 없다:
--     tb_finding_evidence.suppression_evidence  — 583,675행 중 non-null 0
--     tb_collection_stage.duration_ms           — 215행 중 non-null 0
--     tb_collection_stage.error_code            — 동일
--     tb_collection_stage.error_message         — 동일
--   (tb_collection_stage 에 실제로 쓰는 건 ingest_store.php:358 의 scan_id·stage_code·
--    status·item_count 넷뿐이다.)
--
--   왜 옛 파일을 안 고치나: migrate.sh 는 파일명으로 이력을 추적한다. 과거 파일을 고쳐도
--   이미 적용된 DB 엔 반영되지 않고 빈 볼륨에서만 달라져 두 환경 스키마가 갈라진다.
--   → 새 마이그레이션으로 DROP 한다. 최상위 db/*.sql(initdb)엔 두 테이블이 아예 없으므로
--     그쪽은 손댈 게 없다(마이그레이션만이 만든다).
--
--   되돌리기: docs/dev/drop-unused-precision-columns-rollback.sql
--
--   `LOCK=NONE` 만 붙이고 **ALGORITHM 은 일부러 지정하지 않는다.** DROP COLUMN 은 rename 과
--   달리 테이블을 실제로 재구축할 수 있어(tb_finding_evidence 는 58만 행) 그냥 두면 쓰기가
--   오래 막힌다. LOCK=NONE 은 "동시 DML 을 막지 않고 못 하겠으면 에러를 내라"는 뜻이라,
--   말없이 테이블을 잠근 채 재구축하는 사고를 원천 차단한다.
--
--   왜 ALGORITHM 을 안 박나 — 실측(mysql:8.0.46, 583,675행 · 157MB 복제 테이블):
--     ALGORITHM=INPLACE, LOCK=NONE  → 12,240 ms / 12,194 ms   (전체 재구축)
--     LOCK=NONE (알고리즘 미지정)    →      353 ms             (서버가 INSTANT 선택)
--   ALGORITHM 을 INPLACE 로 박으면 서버가 더 빠른 INSTANT 를 쓸 수 있는데도 **재구축을
--   강제해** 35배 느려진다. 미지정이면 서버가 그때 쓸 수 있는 가장 싼 알고리즘을 고른다 —
--   8.0.29+ 는 INSTANT(메타데이터만), 그 이전은 INPLACE 재구축. 어느 쪽이든 LOCK=NONE 이
--   보장되므로 쓰기는 안 막힌다. 버전을 가정하지 않아서 배포가 버전 때문에 깨질 일도 없다.
--   (두 테이블 다 FULLTEXT·파티션이 없어 LOCK=NONE 제약에 걸리지 않는다.)
SET NAMES utf8mb4;

-- ── 1) tb_finding_evidence.suppression_evidence ────────────────────────────
SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_finding_evidence'
             AND COLUMN_NAME = 'suppression_evidence');
SET @s := IF(@c = 1,
             'ALTER TABLE tb_finding_evidence DROP COLUMN suppression_evidence, LOCK=NONE',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- ── 2) tb_collection_stage 의 3개 — 한 ALTER 로 묶는다 ──────────────────────
--   왜 묶나: INSTANT 를 못 쓰는 서버(8.0.29 미만)에서 DROP COLUMN 은 테이블 재구축이라
--   3번 나누면 3번 재구축한다. 한 ALTER 로 묶으면 어느 서버에서든 한 번으로 끝난다.
--   왜 개수 가드(@c = 3)가 아니라 "있는 것만 골라 조립"인가: 개수 가드는 부분 적용 상태
--   (예: 앞선 실행이 중간에 죽어 duration_ms 만 남은 경우)에서 영영 아무 일도 안 하고
--   컬럼을 남긴 채 성공한 척한다. 실제 존재하는 컬럼으로 DROP 절을 만들면
--     · 3개 다 있음  → 한 번의 ALTER 로 3개 제거
--     · 일부만 남음  → 남은 것만 제거(재실행으로 수렴)
--     · 하나도 없음  → @parts 가 NULL 이라 'DO 0' (재실행해도 안전)
--   어느 상태에서 다시 돌려도 같은 최종 스키마에 도달한다.
SELECT GROUP_CONCAT(CONCAT('DROP COLUMN ', COLUMN_NAME) ORDER BY COLUMN_NAME SEPARATOR ', ')
  INTO @parts
  FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_collection_stage'
   AND COLUMN_NAME IN ('duration_ms', 'error_code', 'error_message');
SET @s := IF(@parts IS NULL, 'DO 0',
             CONCAT('ALTER TABLE tb_collection_stage ', @parts, ', LOCK=NONE'));
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
