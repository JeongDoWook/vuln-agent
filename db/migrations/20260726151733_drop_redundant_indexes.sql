-- 다른 인덱스의 왼쪽 접두사(leftmost prefix)에 완전히 덮이는 중복 인덱스 17개를 제거한다.
--
--   왜 지우나
--     B-tree 인덱스 (a) 는 (a,b,c) 인덱스의 왼쪽 접두사다 — 옵티마이저는 WHERE a=? 를 (a,b,c)
--     로 그대로 처리하므로 좁은 쪽은 조회에 전혀 안 쓰이는 순수 중복이다. 그런데도 INSERT/
--     UPDATE/DELETE 마다 갱신되고 디스크를 차지한다. 아래 대상 다수(tb_debsecan·
--     tb_applied_errata·tb_pkg_changelog_cve·tb_container·tb_stale_lib)는 스캔마다 대량
--     INSERT 되는 수집 테이블이라 ingest 비용에 그대로 얹힌다. tb_cve_affected_package 는
--     411MB 라 디스크도 준다. (선례: 20260718000026_drop_idx_find_scan.sql — 같은 이유로
--     tb_findings.idx_find_scan 을 제거했다.)
--
--   대상 (지울 인덱스 → 덮는 인덱스). 스키마 전체 156개 인덱스를
--     information_schema.STATISTICS 로 훑어 접두사 관계를 기계로 확인한 결과다.
--       tb_applied_errata      idx_errata_scan            (scan_id)                       → uq_errata (scan_id,package_name,cve_id)
--       tb_applied_errata      idx_errata_lookup          (scan_id,package_name)          → uq_errata
--       tb_cce_finding         idx_cce_scan               (scan_id)                       → uq_cce (scan_id,code)
--       tb_container           idx_container_scan         (scan_id)                       → uq_container (scan_id,cid)
--       tb_cve                 idx_cves_is_deleted        (is_deleted)                    → idx_cves_pub/idx_cves_cvss/idx_cves_epss (is_deleted,…)
--       tb_cve_affected_package idx_cap_cve               (cve_id)                        → uq_cap (cve_id,package_name,ecosystem)
--       tb_cve_affected_package idx_cve_affected_packages_is_deleted (is_deleted)         → idx_cap_group (is_deleted,package_name,ecosystem,cve_id,fixed_version)
--       tb_debian_tracker      idx_debtracker_lookup      (release_codename,pkg_name)     → uq_debtracker (release_codename,pkg_name,is_binary,cve_id)
--       tb_debsecan            idx_debsecan_scan          (scan_id)                       → uq_debsecan (scan_id,cve_id,package_name)
--       tb_pkg_change          idx_pkgchg_scan            (scan_id)                       → uq_pkgchg (scan_id,manager,package_name)
--       tb_pkg_changelog_cve   idx_clog_scan              (scan_id)                       → uq_clog (scan_id,package_name,cve_id)
--       tb_pkg_changelog_cve   idx_clog_lookup            (scan_id,package_name)          → uq_clog
--       tb_stale_lib           idx_stale_scan             (scan_id)                       → idx_stale_lookup (scan_id,package_name)
--       tb_suppressed_finding  idx_supp_scan              (scan_id)                       → uq_supp (scan_id,container_id,cve_id,package_name)
--       tb_ubuntu_oval         idx_ubuntu_oval_lookup     (release_codename,pkg_name)     → uq_ubuntu_oval (release_codename,pkg_name,cve_id)
--       tb_vendor_errata       idx_vendor_errata_lookup   (vendor,release_major,pkg_name) → uq_vendor_errata (…,cve_id,fixed_evr)
--       tb_vendor_unfixed      idx_vendor_unfixed_lookup  (vendor,release_major,component)→ uq_vendor_unfixed (…,cve_id)
--
--   남기는 것(접두사가 아니라 덮이지 않는다 — 헷갈리기 쉬운 자리다)
--     tb_debsecan.idx_debsecan_lookup (scan_id,package_name) 은 uq_debsecan
--     (scan_id,cve_id,package_name) 의 접두사가 아니다(2번째 컬럼이 다르다). 그대로 둔다.
--     tb_stale_lib.idx_stale_lookup 도 남긴다 — idx_stale_scan 을 덮는 쪽이다.
--
--   외래키(FK)
--     지우는 scan_id 단일 인덱스 8개(errata/cce/container/debsecan/pkgchg/clog/stale/supp)는
--     각 테이블의 fk_*_scan → tb_scan 제약을 뒷받침하던 인덱스처럼 보이지만, InnoDB 는 넓은
--     인덱스의 왼쪽 접두사로도 FK 를 만족시킨다 — 위 "덮는 인덱스"가 모두 scan_id 로 시작하므로
--     DROP 후에도 제약이 유지된다(MySQL 이 자동으로 그 인덱스로 옮겨 붙는다). 만약 어떤 인덱스가
--     errno 1553(Cannot drop index … needed in a foreign key constraint)으로 거부되면 FK 를
--     건드려 억지로 지우지 않는다 — 그 블록만 빼고 그대로 둔다.
--
--   되돌리는 법
--     데이터 손실이 없는 되돌릴 수 있는 변경이다. 인덱스는 값의 사본일 뿐이라 원래 컬럼 데이터는
--     그대로 남는다. 특정 인덱스를 되살리려면 위 표의 컬럼 구성 그대로 다시 만들면 된다. 예:
--       CREATE INDEX idx_cve_affected_packages_is_deleted ON tb_cve_affected_package (is_deleted);
--       CREATE INDEX idx_debtracker_lookup ON tb_debian_tracker (release_codename, pkg_name);
--     (대상 테이블이 크면 재생성에 시간이 걸린다는 점만 감안한다.)
--
--   initdb(db/*.sql)는 건드리지 않는다
--     최상위 db/*.sql 은 빈 볼륨 전용이고 아직 개명 전 이름(tb_cves·tb_cve_affected_packages …)을
--     쓴다 — 실제 이름은 20260726115611_pk_naming_unification.sql 이 바꾼다. 빈 볼륨에서도
--     initdb 다음에 마이그레이션이 순서대로 도니 이 파일이 결국 같은 인덱스를 지운다(결과 동일).
--     initdb 쪽 정의를 같이 손대면 개명 마이그레이션과 이름이 어긋날 여지만 생기므로 두 곳을
--     맞추는 대신 이 파일 하나로 끝낸다.
--
--   멱등: MySQL 8 의 DROP INDEX 에는 IF EXISTS 가 없다. 기존 파일과 같은 패턴으로
--     information_schema.STATISTICS 에 존재할 때만 실행하는 동적 SQL 을 쓴다 — 두 번 돌려도
--     두 번째는 'DO 0' 이라 무동작이다.
SET NAMES utf8mb4;

-- tb_applied_errata ----------------------------------------------------------
SET @k := (SELECT COUNT(*) FROM information_schema.STATISTICS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_applied_errata' AND INDEX_NAME = 'idx_errata_scan');
SET @s := IF(@k > 0, 'ALTER TABLE tb_applied_errata DROP INDEX idx_errata_scan', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @k := (SELECT COUNT(*) FROM information_schema.STATISTICS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_applied_errata' AND INDEX_NAME = 'idx_errata_lookup');
SET @s := IF(@k > 0, 'ALTER TABLE tb_applied_errata DROP INDEX idx_errata_lookup', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- tb_cce_finding -------------------------------------------------------------
SET @k := (SELECT COUNT(*) FROM information_schema.STATISTICS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_cce_finding' AND INDEX_NAME = 'idx_cce_scan');
SET @s := IF(@k > 0, 'ALTER TABLE tb_cce_finding DROP INDEX idx_cce_scan', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- tb_container ---------------------------------------------------------------
SET @k := (SELECT COUNT(*) FROM information_schema.STATISTICS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_container' AND INDEX_NAME = 'idx_container_scan');
SET @s := IF(@k > 0, 'ALTER TABLE tb_container DROP INDEX idx_container_scan', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- tb_cve ---------------------------------------------------------------------
SET @k := (SELECT COUNT(*) FROM information_schema.STATISTICS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_cve' AND INDEX_NAME = 'idx_cves_is_deleted');
SET @s := IF(@k > 0, 'ALTER TABLE tb_cve DROP INDEX idx_cves_is_deleted', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- tb_cve_affected_package ----------------------------------------------------
SET @k := (SELECT COUNT(*) FROM information_schema.STATISTICS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_cve_affected_package' AND INDEX_NAME = 'idx_cap_cve');
SET @s := IF(@k > 0, 'ALTER TABLE tb_cve_affected_package DROP INDEX idx_cap_cve', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @k := (SELECT COUNT(*) FROM information_schema.STATISTICS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_cve_affected_package' AND INDEX_NAME = 'idx_cve_affected_packages_is_deleted');
SET @s := IF(@k > 0, 'ALTER TABLE tb_cve_affected_package DROP INDEX idx_cve_affected_packages_is_deleted', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- tb_debian_tracker ----------------------------------------------------------
SET @k := (SELECT COUNT(*) FROM information_schema.STATISTICS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_debian_tracker' AND INDEX_NAME = 'idx_debtracker_lookup');
SET @s := IF(@k > 0, 'ALTER TABLE tb_debian_tracker DROP INDEX idx_debtracker_lookup', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- tb_debsecan (idx_debsecan_lookup 은 접두사가 아니라 남긴다) -----------------
SET @k := (SELECT COUNT(*) FROM information_schema.STATISTICS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_debsecan' AND INDEX_NAME = 'idx_debsecan_scan');
SET @s := IF(@k > 0, 'ALTER TABLE tb_debsecan DROP INDEX idx_debsecan_scan', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- tb_pkg_change --------------------------------------------------------------
SET @k := (SELECT COUNT(*) FROM information_schema.STATISTICS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_pkg_change' AND INDEX_NAME = 'idx_pkgchg_scan');
SET @s := IF(@k > 0, 'ALTER TABLE tb_pkg_change DROP INDEX idx_pkgchg_scan', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- tb_pkg_changelog_cve -------------------------------------------------------
SET @k := (SELECT COUNT(*) FROM information_schema.STATISTICS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_pkg_changelog_cve' AND INDEX_NAME = 'idx_clog_scan');
SET @s := IF(@k > 0, 'ALTER TABLE tb_pkg_changelog_cve DROP INDEX idx_clog_scan', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @k := (SELECT COUNT(*) FROM information_schema.STATISTICS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_pkg_changelog_cve' AND INDEX_NAME = 'idx_clog_lookup');
SET @s := IF(@k > 0, 'ALTER TABLE tb_pkg_changelog_cve DROP INDEX idx_clog_lookup', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- tb_stale_lib (idx_stale_lookup 이 덮는 쪽 — 남긴다) -------------------------
SET @k := (SELECT COUNT(*) FROM information_schema.STATISTICS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_stale_lib' AND INDEX_NAME = 'idx_stale_scan');
SET @s := IF(@k > 0, 'ALTER TABLE tb_stale_lib DROP INDEX idx_stale_scan', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- tb_suppressed_finding ------------------------------------------------------
SET @k := (SELECT COUNT(*) FROM information_schema.STATISTICS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_suppressed_finding' AND INDEX_NAME = 'idx_supp_scan');
SET @s := IF(@k > 0, 'ALTER TABLE tb_suppressed_finding DROP INDEX idx_supp_scan', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- tb_ubuntu_oval -------------------------------------------------------------
SET @k := (SELECT COUNT(*) FROM information_schema.STATISTICS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_ubuntu_oval' AND INDEX_NAME = 'idx_ubuntu_oval_lookup');
SET @s := IF(@k > 0, 'ALTER TABLE tb_ubuntu_oval DROP INDEX idx_ubuntu_oval_lookup', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- tb_vendor_errata -----------------------------------------------------------
SET @k := (SELECT COUNT(*) FROM information_schema.STATISTICS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_vendor_errata' AND INDEX_NAME = 'idx_vendor_errata_lookup');
SET @s := IF(@k > 0, 'ALTER TABLE tb_vendor_errata DROP INDEX idx_vendor_errata_lookup', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- tb_vendor_unfixed ----------------------------------------------------------
SET @k := (SELECT COUNT(*) FROM information_schema.STATISTICS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_vendor_unfixed' AND INDEX_NAME = 'idx_vendor_unfixed_lookup');
SET @s := IF(@k > 0, 'ALTER TABLE tb_vendor_unfixed DROP INDEX idx_vendor_unfixed_lookup', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
