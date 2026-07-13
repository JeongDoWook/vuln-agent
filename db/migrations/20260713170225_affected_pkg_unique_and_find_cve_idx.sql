-- tb_cve_affected_packages 자연키 UNIQUE + tb_findings.cve_id 인덱스.
--   [2NF 실버그] 이 테이블은 surrogate id PK 만 있고 (cve_id,package_name,ecosystem)
--   자연키에 UNIQUE 가 없었다. feeds.php 의 upsert 가 (cve_id,package_name)로만 중복을
--   찾고 ecosystem 을 무시해(vg_upsert_affected), 같은 패키지의 배포판별 조치버전이 서로
--   덮어쓰였다(실측: nginx CVE-2021-23017 이 'Rocky Linux:9' 와 'Debian:12' 로 공존).
--   DB 유니크가 없어 동시 수집 시 중복행도 쌓이고, 매처의 LEFT JOIN 이 후보 CVE 를
--   중복 생성했다. → ecosystem 을 키에 넣은 UNIQUE 로 바로잡는다.
--
--   빈 볼륨은 db/02-matcher.sql(initdb)이 같은 UNIQUE·인덱스를 갖도록 갱신했다.
--   멱등: 각 단계는 재실행해도 깨지지 않게 작성(information_schema 가드 / 조건부 DELETE).
SET NAMES utf8mb4;

-- 1) ecosystem NULL 정규화 — 자연키에 들어가므로 '' 로 통일한다.
--    (MySQL UNIQUE 는 NULL 을 중복 허용하므로 NULL 이 있으면 유니크가 무의미해진다.)
UPDATE tb_cve_affected_packages SET ecosystem = '' WHERE ecosystem IS NULL;

-- 2) ecosystem 을 NOT NULL DEFAULT '' 로. MODIFY 는 같은 정의로 재실행해도 안전(멱등).
ALTER TABLE tb_cve_affected_packages MODIFY ecosystem VARCHAR(32) NOT NULL DEFAULT '';

-- 3) UNIQUE 추가 전에 기존 중복행 정리(운영 볼륨 대비).
--    (cve_id,package_name,ecosystem) 그룹에서 fixed_version 이 채워진 행을 우선 남기고,
--    같은 경우 작은 id 를 남긴다. 나머지를 삭제. 중복이 없으면 아무것도 안 지운다(멱등).
DELETE FROM tb_cve_affected_packages
 WHERE id IN (
   SELECT id FROM (
     SELECT id,
            ROW_NUMBER() OVER (
              PARTITION BY cve_id, package_name, ecosystem
              ORDER BY (fixed_version IS NOT NULL AND fixed_version <> '') DESC, id ASC
            ) AS rn
       FROM tb_cve_affected_packages
   ) d WHERE d.rn > 1
 );

-- 4) 자연키 UNIQUE 추가(멱등: 이미 있으면 스킵).
SET @c := (SELECT COUNT(*) FROM information_schema.STATISTICS
           WHERE TABLE_SCHEMA = DATABASE()
             AND TABLE_NAME   = 'tb_cve_affected_packages'
             AND INDEX_NAME   = 'uq_cap');
SET @s := IF(@c = 0,
             'ALTER TABLE tb_cve_affected_packages ADD UNIQUE KEY uq_cap (cve_id, package_name, ecosystem)',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- 5) tb_findings.cve_id 인덱스 — 라이브 조인(LEFT JOIN tb_cves)과 cve.php(특정 CVE의
--    발견 위치)가 f.cve_id 로 조인/조회하는데 인덱스가 없었다. 보조 인덱스 추가는
--    InnoDB 에서 INPLACE·LOCK=NONE 로 온라인 처리된다. 멱등: 이미 있으면 스킵.
SET @c := (SELECT COUNT(*) FROM information_schema.STATISTICS
           WHERE TABLE_SCHEMA = DATABASE()
             AND TABLE_NAME   = 'tb_findings'
             AND INDEX_NAME   = 'idx_find_cve');
SET @s := IF(@c = 0,
             'ALTER TABLE tb_findings ADD KEY idx_find_cve (cve_id), ALGORITHM=INPLACE, LOCK=NONE',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
