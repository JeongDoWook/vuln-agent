-- 안 쓰이는 `is_deleted` **단독** 인덱스 10개를 제거한다. **컬럼은 건드리지 않는다.**
--
--   무엇을 지우나 (오해 금지)
--     `is_deleted` 는 소프트삭제 플래그이고 거의 모든 조회가 `WHERE is_deleted = 0` 을 건다 —
--     컬럼을 지우면 제품이 통째로 깨진다. 이 파일이 지우는 것은 **그 컬럼 하나만 걸어 둔
--     secondary index** 뿐이다. 데이터·컬럼·애플리케이션 쿼리는 그대로다.
--     `is_deleted` 가 **선두 컬럼인 복합 인덱스**(예: tb_host.idx_host_grade (is_deleted, grade))도
--     대상이 아니다 — 화면이 늘 is_deleted = 0 을 함께 걸기 때문에 의도적으로 그 순서로 만든 것이다.
--
--   왜 지우나
--     운영 DB(2026-08-20) 기준 전 대상이 **카디널리티 1**(모든 행이 is_deleted=0)이라 선택도가
--     없다. 그런데도 INSERT/UPDATE/DELETE 마다 갱신되고 디스크를 차지한다. 대상 다수
--     (tb_finding·tb_suppressed_finding·tb_pkg_changelog_cve·tb_container·tb_stale_lib·
--     tb_debsecan·tb_exposure·tb_process)는 스캔마다 전량 DELETE+INSERT 되는 수집 테이블이라
--     ingest·재매칭 비용에 그대로 얹힌다. 회수 용량은 운영 기준 약 **98 MB**.
--     (선례: 20260726151733_drop_redundant_indexes.sql — 같은 이유로 tb_cve.idx_cves_is_deleted
--      와 tb_cve_affected_package.idx_cve_affected_packages_is_deleted 를 이미 제거했다.)
--
--   "카디널리티 1이면 안 쓰인다"는 틀렸다 — 그래서 전건을 EXPLAIN 으로 확인했다
--     선택도가 없어도 MySQL 은 is_deleted = 0 이 **선두 컬럼 등치조건**이라는 이유로 ref 접근을
--     고를 수 있고, COUNT(*) 처럼 커버링이 되는 질의에서는 테이블보다 좁아 실제로 고른다.
--     그래서 운영 performance_schema(최근 72h 미사용)만 믿지 않고, **각 테이블을 읽는 실제
--     코드 쿼리를 모아 dev DB 에서 EXPLAIN 으로 확인**했다. 아래 각 블록의 주석이 그 결과다.
--     확인 기준: 실제 쿼리가 그 인덱스를 key 로 고르지 않고, IGNORE INDEX 를 걸어도(=DROP 후와
--     같은 상황) 실행계획이 동일할 것.
--
--   남긴 것 — 후보였지만 EXPLAIN 이 "쓴다"고 말한 3개
--     tb_cce_finding.idx_cce_findings_is_deleted (0.3 MB)
--       server/public/control.php:68 `FROM tb_cce_finding WHERE is_deleted = 0 AND code IN (...)`
--       가 이 인덱스를 key 로 고른다(ref, rows=9709). code 단독 인덱스가 없어서(uq_cce 는
--       scan_id,code) DROP 하면 type=ALL 전체 스캔(rows=19419)으로 떨어진다. 운영 72h 통계는
--       미사용이라지만 EXPLAIN 이 반대로 말하므로 **확신이 없어 남긴다.** 이득도 0.3 MB뿐이다.
--     tb_feed_connector.idx_feed_connectors_is_deleted (0.0 MB)
--       server/src/connectors/queries.php:13 `SELECT * FROM tb_feed_connector WHERE is_deleted = 0`
--       과 server/src/feeds.php:301 이 이 인덱스를 key 로 고른다. 11행짜리 표라 어느 계획이든
--       무의미하지만, 회수 용량이 0.0 MB 라 지울 이유 자체가 없다.
--     tb_applied_errata.idx_errata_is_deleted (0행)
--       "72h 미사용"이 데이터가 0행이라 안 쓰인 것뿐이라 증거가 되지 않는다. 회수 용량도 0.0 MB.
--
--   운영 적용 — 겁내지 않아도 된다
--     MySQL 8 의 secondary index DROP 은 **ALGORITHM=INPLACE, 테이블 재구축 없음**이다
--     (데이터 파일을 다시 쓰지 않고 인덱스 정의만 떼어낸다). 큰 표(tb_suppressed_finding 380만행,
--     tb_finding 159만행)라도 잠깐의 메타데이터 잠금으로 끝나며 온라인 DML 도 막히지 않는다.
--
--   되돌리는 법
--     데이터 손실이 없는 되돌릴 수 있는 변경이다. 인덱스는 값의 사본일 뿐이라 원래 컬럼 데이터는
--     그대로 남는다. 되살리려면 같은 이름으로 다시 만들면 된다. 예:
--       CREATE INDEX idx_supp_is_deleted ON tb_suppressed_finding (is_deleted);
--     (표가 크면 재생성에 시간이 걸린다는 점만 감안한다.)
--
--   initdb(db/*.sql)는 건드리지 않는다
--     최상위 db/*.sql 은 빈 볼륨 전용이고 아직 개명 전 테이블명(tb_findings·tb_containers …)을
--     쓴다 — 실제 이름은 20260726115611_pk_naming_unification.sql 이 바꾼다. 빈 볼륨에서도
--     initdb 다음에 마이그레이션이 순서대로 도니 이 파일이 결국 같은 인덱스를 지운다(결과 동일).
--     두 곳을 맞추는 대신 이 파일 하나로 끝낸다(20260726151733 과 같은 판단).
--
--   멱등: MySQL 8 의 DROP INDEX 에는 IF EXISTS 가 없다. 기존 파일(20260718000026·20260726151733)
--     과 같은 패턴으로 information_schema.STATISTICS 에 존재할 때만 실행하는 동적 SQL 을 쓴다 —
--     두 번 돌려도 두 번째는 'DO 0' 이라 무동작이다.
SET NAMES utf8mb4;

-- tb_suppressed_finding — 380만행 / 67.1 MB (회수 1순위) --------------------------
--   실제 쿼리는 전부 scan_id 로 들어간다(host/queries.php:173·184, host/summary.php:103,
--   suppression.php:129, finding_history.php:56·72) → EXPLAIN key=uq_supp(scan_id,…).
--   is_deleted 는 그 뒤에 붙는 잔여 조건일 뿐 인덱스 선택에 관여하지 않는다.
SET @k := (SELECT COUNT(*) FROM information_schema.STATISTICS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_suppressed_finding' AND INDEX_NAME = 'idx_supp_is_deleted');
SET @s := IF(@k > 0, 'ALTER TABLE tb_suppressed_finding DROP INDEX idx_supp_is_deleted', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- tb_finding — 159만행 / 29.1 MB (회수 2순위) -------------------------------------
--   is_deleted 단독으로 좁히는 것처럼 보이는 쿼리 4개를 실제 형태 그대로 EXPLAIN 했다:
--     dashboard/queries.php:117(KEV 기한초과) · advisories.php:46(mine 범위) ·
--     findings/queries/cve.php:169(due 정렬 서브쿼리) · finding_sla.php:67(최초발견)
--   넷 다 최신스캔 파생표·tb_advisory_cve 같은 **작은 쪽에서 출발**해 uq_find/
--   idx_find_scan_kev_runtime/idx_find_cve 로 들어가고, IGNORE INDEX 를 걸어도 계획이 동일했다.
SET @k := (SELECT COUNT(*) FROM information_schema.STATISTICS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_finding' AND INDEX_NAME = 'idx_findings_is_deleted');
SET @s := IF(@k > 0, 'ALTER TABLE tb_finding DROP INDEX idx_findings_is_deleted', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- tb_pkg_changelog_cve — 2.7만행 / 0.5 MB -----------------------------------------
--   읽는 곳은 matcher/evidence.php:24 와 suppression.php:189 둘뿐이고 둘 다 scan_id 로 들어간다
--   → EXPLAIN key=uq_clog(scan_id,package_name,cve_id).
SET @k := (SELECT COUNT(*) FROM information_schema.STATISTICS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_pkg_changelog_cve' AND INDEX_NAME = 'idx_clog_is_deleted');
SET @s := IF(@k > 0, 'ALTER TABLE tb_pkg_changelog_cve DROP INDEX idx_clog_is_deleted', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- tb_exposure — 2.3만행 / 0.3 MB --------------------------------------------------
--   findings/queries/exposure.php·host/queries.php:88·container/queries.php:79·
--   segment-map.php:136·assetgrade/signals.php:35 전부 scan_id(+scope) 로 들어간다
--   → EXPLAIN key=idx_exp_scan / idx_exp_scope.
SET @k := (SELECT COUNT(*) FROM information_schema.STATISTICS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_exposure' AND INDEX_NAME = 'idx_exposures_is_deleted');
SET @s := IF(@k > 0, 'ALTER TABLE tb_exposure DROP INDEX idx_exposures_is_deleted', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- tb_advisory_cve — 1.9만행 / 0.3 MB ----------------------------------------------
--   정션 표라 조회가 advisory_id 또는 cve_id 로만 들어간다(advisory.php:60·81,
--   advisories.php:99, src/advisory.php:19) → EXPLAIN key=uq_advisory_cve / idx_advisory_cves_cve.
SET @k := (SELECT COUNT(*) FROM information_schema.STATISTICS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_advisory_cve' AND INDEX_NAME = 'idx_advisory_cves_is_deleted');
SET @s := IF(@k > 0, 'ALTER TABLE tb_advisory_cve DROP INDEX idx_advisory_cves_is_deleted', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- tb_process — 1.7만행 / 0.3 MB ---------------------------------------------------
--   container/queries.php:105·host/queries.php:116·host/summary.php:122·
--   matcher/signals.php:83·assetgrade/signals.php:69 전부 scan_id → EXPLAIN key=idx_proc_scan.
SET @k := (SELECT COUNT(*) FROM information_schema.STATISTICS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_process' AND INDEX_NAME = 'idx_processes_is_deleted');
SET @s := IF(@k > 0, 'ALTER TABLE tb_process DROP INDEX idx_processes_is_deleted', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- tb_stale_lib — 8.6천행 / 0.2 MB -------------------------------------------------
--   읽는 곳은 matcher/evidence.php:34 와 suppression.php:219·229 뿐이고 전부 scan_id
--   → EXPLAIN key=idx_stale_lookup(scan_id,package_name).
SET @k := (SELECT COUNT(*) FROM information_schema.STATISTICS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_stale_lib' AND INDEX_NAME = 'idx_stale_is_deleted');
SET @s := IF(@k > 0, 'ALTER TABLE tb_stale_lib DROP INDEX idx_stale_is_deleted', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- tb_container — 3.0천행 / 0.1 MB -------------------------------------------------
--   is_deleted 를 함께 거는 자리가 많지만(container.php:74, sbom.php:103, patch.php:107 …)
--   전부 scan_id+cid 또는 container_id 와 같이 온다 → EXPLAIN key=uq_container / PRIMARY.
SET @k := (SELECT COUNT(*) FROM information_schema.STATISTICS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_container' AND INDEX_NAME = 'idx_container_is_deleted');
SET @s := IF(@k > 0, 'ALTER TABLE tb_container DROP INDEX idx_container_is_deleted', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- tb_debsecan — 2.2천행 / 0.1 MB --------------------------------------------------
--   matcher/evidence.php:53·suppression.php:198 뿐이고 둘 다 scan_id
--   → EXPLAIN key=uq_debsecan / idx_debsecan_lookup.
SET @k := (SELECT COUNT(*) FROM information_schema.STATISTICS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_debsecan' AND INDEX_NAME = 'idx_debsecan_is_deleted');
SET @s := IF(@k > 0, 'ALTER TABLE tb_debsecan DROP INDEX idx_debsecan_is_deleted', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- tb_feed_collection_log — 641행 / 0.0 MB -----------------------------------------
--   connectors/queries.php:22(GROUP BY feed_connector_id)·:55(feed_connector_id = ?) 뿐이고
--   둘 다 → EXPLAIN key=idx_fcl_conn(feed_connector_id,started_at). 이 표를 is_deleted 로
--   거르는 코드는 없다.
SET @k := (SELECT COUNT(*) FROM information_schema.STATISTICS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_feed_collection_log' AND INDEX_NAME = 'idx_feed_collection_logs_is_deleted');
SET @s := IF(@k > 0, 'ALTER TABLE tb_feed_collection_log DROP INDEX idx_feed_collection_logs_is_deleted', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
