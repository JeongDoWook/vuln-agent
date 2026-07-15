-- tb_cve_affected_packages 그룹 집계용 복합 인덱스.
--   packages.php 는 (package_name, ecosystem) 로 GROUP BY 하며 COUNT(DISTINCT cve_id)·
--   SUM(fixed_version IS NOT NULL) 를 계산한다. 이를 지원하는 인덱스가 없어 92만 행(운영 실측)에
--   임시테이블+filesort 가 걸려 메인 쿼리가 20초였다. is_deleted 를 앞에 둬 필터를 인덱스로
--   만족하고, 이어 그룹 컬럼(package_name,ecosystem)·집계 컬럼(cve_id,fixed_version)까지 담아
--   커버링 스캔이 되게 한다(EXPLAIN: Using index — 격리 92만행 실측 5.5초→1.0초).
--   멱등: 이미 있으면 스킵. 보조 인덱스 추가는 InnoDB 에서 INPLACE·LOCK=NONE 로 온라인 처리.
--   빈 볼륨은 db/02-matcher.sql(initdb)이 같은 인덱스를 갖도록 갱신했다.
SET NAMES utf8mb4;

SET @c := (SELECT COUNT(*) FROM information_schema.STATISTICS
           WHERE TABLE_SCHEMA = DATABASE()
             AND TABLE_NAME   = 'tb_cve_affected_packages'
             AND INDEX_NAME   = 'idx_cap_group');
SET @s := IF(@c = 0,
             'ALTER TABLE tb_cve_affected_packages ADD KEY idx_cap_group (is_deleted, package_name, ecosystem, cve_id, fixed_version), ALGORITHM=INPLACE, LOCK=NONE',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
