-- 전 화면 응답시간 측정에서 나온 "필터 선택지를 만드느라 테이블을 통째로 훑는" 두 자리를 고친다.
-- 측정·근거 전문: docs/dev/web-perf-audit.md
--
-- 공통 증상: 화면 상단 필터 셀렉트를 채우려고 DISTINCT 를 던지는데, 그 컬럼이 어느 인덱스의
--   **선두**도 아니라 MySQL 이 느슨한 인덱스 스캔(loose index scan)을 못 쓰고 테이블 전체 크기의
--   인덱스를 처음부터 끝까지 읽는다. 결과는 고작 몇 개~수십 개짜리 목록인데 읽는 양은 수십만 행이다.
--
-- ① tb_activity_log — activity.php 의 "범위" 셀렉트
--    SELECT DISTINCT scope FROM tb_activity_log WHERE is_deleted = 0 ORDER BY scope
--    idx_activity_scope 는 (scope, scope_id) 라 is_deleted 가 없다 → 76,189행을 인덱스로 훑고
--    행마다 is_deleted 를 다시 본다(filtered=10%). 결과는 15개.
--    (is_deleted, scope) 로 두 컬럼을 한 인덱스에 담으면 조건이 인덱스 안에서 끝난다.
--      dev 실측(77,333행): 85.59ms → 16.99ms (5.0배) · type=index→ref · Using where→Using index
--      같은 인덱스가 옆 질의 COUNT(*) WHERE is_deleted=0 도 18.61ms → 11.35ms 로 줄인다.
--
-- ② tb_vendor_errata — vendor.php 의 "릴리스" 셀렉트
--    SELECT DISTINCT release_major FROM tb_vendor_errata  (5-way UNION 의 한 갈래)
--    release_major 는 uq_vendor_errata 의 **2번째** 컬럼이고 idx_vendor_errata_cve 의 4번째라
--    선두가 아니다 → 564,541행 커버링 스캔 + 임시테이블. 결과는 2개(!).
--    (release_major, is_deleted) 로 선두에 놓으면 "Using index for group-by" 로 값 목록만 훑는다.
--      dev 실측(569,803행): 릴리스 옵션 질의 단독 162.53ms → 0.38ms (428배)
--                           5-way UNION 전체        167.54ms → 1.30ms (129배)
--                           EXPLAIN  type=index rows=564541 → type=range rows=2
--    is_deleted 를 뒤에 붙인 이유: 이 테이블의 다른 인덱스와 결이 같고(전부 is_deleted 를 담는다),
--      COUNT(*) WHERE is_deleted = 0 이 원본 조회 없이 인덱스로 끝나게 남겨 둔다.
--
-- 검색 경로에는 영향이 없다: vendor.php 의 CVE·패키지 접두 LIKE 는 여전히
--   idx_vendor_errata_cve(cve_id, pkg_name, is_deleted, release_major) 를 탄다 — 그 인덱스는
--   그대로 두고 새 인덱스를 **추가만** 한다. 화면 출력값은 바뀌지 않는다(선택지 목록 동일 확인).
--
-- 되돌리기: DROP INDEX idx_activity_del_scope ON tb_activity_log;
--           DROP INDEX idx_vendor_errata_rel  ON tb_vendor_errata;
--
-- 멱등: 이미 있으면 만들지 않는다(information_schema 확인 후 동적 실행).

SET @db := DATABASE();

SET @sql := (
  SELECT IF(COUNT(*) = 0,
    'CREATE INDEX idx_activity_del_scope ON tb_activity_log (is_deleted, scope)',
    'DO 0')
  FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'tb_activity_log'
    AND INDEX_NAME = 'idx_activity_del_scope'
);
PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;

SET @sql := (
  SELECT IF(COUNT(*) = 0,
    'CREATE INDEX idx_vendor_errata_rel ON tb_vendor_errata (release_major, is_deleted)',
    'DO 0')
  FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'tb_vendor_errata'
    AND INDEX_NAME = 'idx_vendor_errata_rel'
);
PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;
