-- tb_advisory.cve_ids CSV 제거 — expand→contract 의 contract 단계(이슈 #520).
--   20260713192700_advisory_cves.sql 가 정션(tb_advisory_cve)을 신설하며 CSV 를 호환용으로
--   남겨 뒀다. 같은 사실이 두 곳에 있어 동기화를 한 번 놓치면 조용히 갈라진다. 읽기 정본은
--   이미 정션이고, 이 마이그레이션이 도는 코드에는 cve_ids 를 읽거나 쓰는 경로가 없다.
--
--   순서: (1) 남아 있는 CSV 를 정션으로 마지막 백필 → (2) 컬럼 DROP.
--   백필을 SQL 로 하는 이유: PHP 백필 스크립트(bin/backfill_advisory_cves.php)는 이 컬럼이
--   사라지는 순간 실행 자체가 불가능해진다. 드롭은 되돌릴 수 없으므로 "스크립트를 먼저
--   돌렸겠지" 를 전제하지 않고 이 파일 안에서 끝낸다.
--
--   멱등: 컬럼이 이미 없으면 두 단계 모두 건너뛴다(information_schema 확인 + 동적 SQL).
--   백필 INSERT 는 UNIQUE(advisory_id, cve_id) 에 걸리므로 여러 번 돌아도 안전하다.
SET NAMES utf8mb4;

SET @has_col := (
  SELECT COUNT(*) FROM information_schema.COLUMNS
   WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_advisory' AND COLUMN_NAME = 'cve_ids'
);

-- (1) CSV → 정션 마지막 백필. 재귀 CTE 로 콤마를 분해하고, 형식이 맞는 것만 넣는다
--     (PHP vg_is_cve_id 와 같은 기준: 4자리는 선행 0 허용, 5자리 이상은 금지).
--     과거에 soft-delete 된 행은 되살린다 — 정션과 CSV 가 갈라졌다면 CSV 쪽 값도 근거다.
SET @sql := IF(@has_col > 0, '
INSERT INTO tb_advisory_cve (advisory_id, cve_id)
WITH RECURSIVE split AS (
  SELECT advisory_id,
         UPPER(TRIM(SUBSTRING_INDEX(cve_ids, '','', 1))) AS cve_id,
         CAST(IF(LOCATE('','', cve_ids) > 0, SUBSTRING(cve_ids, LOCATE('','', cve_ids) + 1), NULL)
              AS CHAR(20000)) AS rest
    FROM tb_advisory
   WHERE is_deleted = 0 AND cve_ids IS NOT NULL AND cve_ids <> ''''
  UNION ALL
  SELECT advisory_id,
         UPPER(TRIM(SUBSTRING_INDEX(rest, '','', 1))),
         CAST(IF(LOCATE('','', rest) > 0, SUBSTRING(rest, LOCATE('','', rest) + 1), NULL)
              AS CHAR(20000))
    FROM split
   WHERE rest IS NOT NULL
)
SELECT DISTINCT advisory_id, cve_id FROM split
 WHERE cve_id REGEXP ''^CVE-(19|20)[0-9]{2}-([0-9]{4}|[1-9][0-9]{4,6})$''
ON DUPLICATE KEY UPDATE is_deleted = 0, deleted_at = NULL
', 'DO 0');
PREPARE st FROM @sql; EXECUTE st; DEALLOCATE PREPARE st;

-- (2) 컬럼 DROP.
SET @sql := IF(@has_col > 0, 'ALTER TABLE tb_advisory DROP COLUMN cve_ids', 'DO 0');
PREPARE st FROM @sql; EXECUTE st; DEALLOCATE PREPARE st;
