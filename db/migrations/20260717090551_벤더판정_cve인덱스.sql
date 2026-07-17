-- 벤더 판정 조회 페이지(vendor.php)가 쓰는 CVE 인덱스.
--   왜: 5개 테이블 전부 기존 인덱스가 `(vendor, release_major, pkg_name)` /
--   `(release_codename, pkg_name)` 라 **cve_id 가 선두가 아니다.** 그래서 "이 CVE 를 벤더들이
--   각각 뭐라 했나" 를 묻는 순간 rhoval 51만 행·ubuntuoval 43만 행이 풀스캔이 된다.
--   packages.php 가 같은 이유(그룹 컬럼이 인덱스에 없음)로 운영에서 20초까지 갔던 전례가 있다.
--
--   컬럼 순서 (cve_id, pkg_name, is_deleted, release_*) 는 페이지의 네 가지 질의를 다 덮는다:
--     · cve_id 선두   — CVE 검색(접두 범위)과 목록 정렬(ORDER BY cve_id DESC)을 함께 만족한다.
--     · pkg_name      — 정렬 동률 처리 + 패키지 접두 필터(LIKE 'x%')를 인덱스 안에서 끝낸다.
--     · is_deleted    — 페이지가 항상 `is_deleted = 0` 으로 거른다.
--     · release_*     — 릴리스 필터. 이 둘이 인덱스에 없으면 COUNT(*) 가 원본을 행마다 뒤진다.
--   뒤 두 컬럼은 범위 검색용이 아니라 **커버링용**이다 — 있어야 COUNT 가 인덱스만 읽고 끝난다.
--   릴리스 필터가 기존 인덱스를 못 타는 이유도 이것이다: `(vendor, release_major, pkg_name)` 은
--   vendor 가 선두인데 이 페이지는 벤더를 묻지 않는다(소스를 고르면 테이블이 정해질 뿐).
--   실측(tb_vendor_errata 55만 행, `is_deleted=0 AND pkg_name LIKE 'openssl%' AND release_major='9'`):
--     인덱스 없음/릴리스 빠진 인덱스 → type=ALL 풀 테이블 스캔 3.23초
--     이 인덱스                      → 커버링 skip scan 0.34초
--
--   **is_deleted 를 선두에 두면 안 된다.** packages.php 의 `idx_cap_group (is_deleted, …)` 을
--   그대로 흉내 냈다가 매처를 망가뜨렸다 — 매처의 조회는
--     `WHERE is_deleted = 0 AND release_codename = ? AND pkg_name IN (…500개…)`
--   인데, is_deleted 가 선두면 옵티마이저가 그 등호 하나(key_len=1)만 보고 이 인덱스를 골라
--   릴리스 전량을 훑는다(실측: 계획이 `uq_debtracker` ref 203행 → `idx_debtracker_cve` 3만 행으로
--   바뀌고 rematch.php 가 180초 안에 응답하지 못했다). cve_id 를 선두에 두면 매처의 조회엔
--   선두 컬럼 조건이 없어 이 인덱스가 후보에서 빠지고, 기존 계획이 그대로 유지된다.
--   (packages.php 는 그 쿼리 자신이 is_deleted 로 시작하는 GROUP BY 라 사정이 달랐다.)
--
--   커널 두 테이블(tb_kernel_cves · tb_kernel_cve_fixes)은 PK 가 이미 cve_id 로 시작해
--   CVE 검색·정렬에 추가 인덱스가 필요 없다. 다만 릴리스(stream) 필터 옵션을 매 페이지 로드마다
--   `DISTINCT stream` 으로 뽑는데 stream 은 PK 의 둘째 컬럼이라 선두가 아니다 → 전용 인덱스를 준다.
--   매처의 커널 조회는 `WHERE cve_id IN (…)` 이라 이 인덱스를 고를 수 없다(선두 조건 없음).
--
--   멱등: information_schema 로 존재 확인 후 PREPARE/EXECUTE(기존 마이그레이션 관례).
--   보조 인덱스 추가는 InnoDB 에서 INPLACE·LOCK=NONE 로 온라인 처리된다.
SET NAMES utf8mb4;

-- 데비안 보안 트래커
SET @c := (SELECT COUNT(*) FROM information_schema.STATISTICS
           WHERE TABLE_SCHEMA = DATABASE()
             AND TABLE_NAME   = 'tb_debian_tracker'
             AND INDEX_NAME   = 'idx_debtracker_cve');
SET @s := IF(@c = 0,
             'ALTER TABLE tb_debian_tracker ADD KEY idx_debtracker_cve (cve_id, pkg_name, is_deleted, release_codename), ALGORITHM=INPLACE, LOCK=NONE',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- RHEL 계열 벤더 권고(OVAL) — 51만 행
SET @c := (SELECT COUNT(*) FROM information_schema.STATISTICS
           WHERE TABLE_SCHEMA = DATABASE()
             AND TABLE_NAME   = 'tb_vendor_errata'
             AND INDEX_NAME   = 'idx_vendor_errata_cve');
SET @s := IF(@c = 0,
             'ALTER TABLE tb_vendor_errata ADD KEY idx_vendor_errata_cve (cve_id, pkg_name, is_deleted, release_major), ALGORITHM=INPLACE, LOCK=NONE',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- Red Hat 미수정 CVE — 판정 단위가 바이너리 패키지가 아니라 컴포넌트(소스 패키지)다.
SET @c := (SELECT COUNT(*) FROM information_schema.STATISTICS
           WHERE TABLE_SCHEMA = DATABASE()
             AND TABLE_NAME   = 'tb_vendor_unfixed'
             AND INDEX_NAME   = 'idx_vendor_unfixed_cve');
SET @s := IF(@c = 0,
             'ALTER TABLE tb_vendor_unfixed ADD KEY idx_vendor_unfixed_cve (cve_id, component, is_deleted, release_major), ALGORITHM=INPLACE, LOCK=NONE',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- 우분투 보안 OVAL — 43만 행
SET @c := (SELECT COUNT(*) FROM information_schema.STATISTICS
           WHERE TABLE_SCHEMA = DATABASE()
             AND TABLE_NAME   = 'tb_ubuntu_oval'
             AND INDEX_NAME   = 'idx_ubuntu_oval_cve');
SET @s := IF(@c = 0,
             'ALTER TABLE tb_ubuntu_oval ADD KEY idx_ubuntu_oval_cve (cve_id, pkg_name, is_deleted, release_codename), ALGORITHM=INPLACE, LOCK=NONE',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- 리눅스 커널 CNA — stream 목록 뽑기용(PK 는 (cve_id, stream) 이라 stream 이 선두가 아니다).
SET @c := (SELECT COUNT(*) FROM information_schema.STATISTICS
           WHERE TABLE_SCHEMA = DATABASE()
             AND TABLE_NAME   = 'tb_kernel_cve_fixes'
             AND INDEX_NAME   = 'idx_kcve_fix_stream');
SET @s := IF(@c = 0,
             'ALTER TABLE tb_kernel_cve_fixes ADD KEY idx_kcve_fix_stream (stream), ALGORITHM=INPLACE, LOCK=NONE',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
