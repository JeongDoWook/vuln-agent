-- DB 명명규칙 통일 — 테이블명 단수화 + PK 를 `<단수 테이블명>_id` 로.
--
--   왜: PK 는 전부 `id` 인데 그걸 가리키는 FK 는 `host_id`/`scan_id`/`container_id` 라
--   JOIN 마다 이름이 어긋났다. `ON h.id = s.host_id` → `ON h.host_id = s.host_id`.
--   FK 이름은 이미 새 PK 이름과 같으므로, 대부분의 FK 는 **손댈 것이 없다**(이 리팩터의 이득).
--
--   범위: 43테이블 중 컬럼 rename 35건(PK 33 + FK 2) · 테이블 rename 31건.
--   손대지 않는 것: tb_kev_catalog(FK-as-PK) · tb_package_summary(복합 자연키) ·
--     tb_finding_evidence(1:1 확장 FK-as-PK) · tb_cves_summary_ko_bak · tb_kev_note_ko_bak ·
--     **tb_schema_migrations**(러너 자신의 이력 테이블 — 바꾸면 51개 마이그레이션이 전부 재실행된다).
--
--   FK 자동 전파(실측, mysql:8.0.46 일회용 컨테이너):
--     ALTER TABLE tb_hosts RENAME COLUMN id TO host_id;  →
--       tb_scans:  CONSTRAINT `fk_scans_host` FOREIGN KEY (`host_id`) REFERENCES `tb_hosts` (`host_id`)
--     RENAME TABLE tb_hosts TO tb_host;                  →
--       tb_scans:  CONSTRAINT `fk_scans_host` FOREIGN KEY (`host_id`) REFERENCES `tb_host`  (`host_id`)
--     → 자식 FK 정의가 자동으로 따라온다. DROP FOREIGN KEY / ADD CONSTRAINT 3단계가 필요 없고
--       부모·자식 적용 순서에도 의존하지 않는다.
--
--   비용: 컬럼·테이블 rename 은 **메타데이터 전용**이라 920만 행 tb_cve_affected_packages 도
--   즉시 끝난다. 그 성질을 지키려고 **인덱스·제약 이름은 바꾸지 않는다**(idx_hosts_is_deleted,
--   fk_scans_host, uq_find …). 인덱스 rename 은 실제 재구축이라 성질이 달라진다.
--
--   멱등성: MySQL 8 은 RENAME COLUMN ... IF EXISTS 가 없다. db/17-changes.sql·0014_containers.sql
--   에 이미 쓰인 information_schema 가드 패턴을 그대로 쓴다. 두 번 돌아도 안전하다.
--
--   되돌리기: 러너에 down 이 없으므로 역방향 SQL 을 docs/dev/pk-naming-rollback.sql 에 둔다.
--
--   ※ 이 파일은 **마이그레이션 사슬의 맨 끝**에 있어야 한다. 최상위 db/*.sql(initdb)은 옛 이름
--     그대로 두고 여기서 한 번만 rename 하는 이유가 그것이다 — initdb 를 새 이름으로 바꾸면
--     빈 볼륨에서 initdb 다음에 도는 옛 마이그레이션 51개가 `tb_hosts` 를 찾다 죽는다.
--     자세한 근거는 db/migrations/README.md "명명규칙 rename 과 initdb" 항 참조.
SET NAMES utf8mb4;

-- ── 1) PK·FK 컬럼 rename (테이블은 아직 옛 이름) ─────────────────────────

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_hosts' AND COLUMN_NAME = 'id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_hosts RENAME COLUMN id TO host_id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_host_ext_ports' AND COLUMN_NAME = 'id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_host_ext_ports RENAME COLUMN id TO host_ext_port_id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_scans' AND COLUMN_NAME = 'id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_scans RENAME COLUMN id TO scan_id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_packages' AND COLUMN_NAME = 'id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_packages RENAME COLUMN id TO package_id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_exposures' AND COLUMN_NAME = 'id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_exposures RENAME COLUMN id TO exposure_id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_cve_affected_packages' AND COLUMN_NAME = 'id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_cve_affected_packages RENAME COLUMN id TO cve_affected_package_id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_findings' AND COLUMN_NAME = 'id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_findings RENAME COLUMN id TO finding_id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_users' AND COLUMN_NAME = 'id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_users RENAME COLUMN id TO user_id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_feed_connectors' AND COLUMN_NAME = 'id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_feed_connectors RENAME COLUMN id TO feed_connector_id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_feed_collection_logs' AND COLUMN_NAME = 'id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_feed_collection_logs RENAME COLUMN id TO feed_collection_log_id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_feed_collection_logs' AND COLUMN_NAME = 'connector_id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_feed_collection_logs RENAME COLUMN connector_id TO feed_connector_id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_advisories' AND COLUMN_NAME = 'id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_advisories RENAME COLUMN id TO advisory_id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_advisory_cves' AND COLUMN_NAME = 'id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_advisory_cves RENAME COLUMN id TO advisory_cve_id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_processes' AND COLUMN_NAME = 'id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_processes RENAME COLUMN id TO process_id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_role_permissions' AND COLUMN_NAME = 'id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_role_permissions RENAME COLUMN id TO role_permission_id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_cce_findings' AND COLUMN_NAME = 'id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_cce_findings RENAME COLUMN id TO cce_finding_id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_pkg_changelog_cves' AND COLUMN_NAME = 'id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_pkg_changelog_cves RENAME COLUMN id TO pkg_changelog_cve_id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_suppressed_findings' AND COLUMN_NAME = 'id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_suppressed_findings RENAME COLUMN id TO suppressed_finding_id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_stale_libs' AND COLUMN_NAME = 'id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_stale_libs RENAME COLUMN id TO stale_lib_id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_pkg_changes' AND COLUMN_NAME = 'id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_pkg_changes RENAME COLUMN id TO pkg_change_id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_containers' AND COLUMN_NAME = 'id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_containers RENAME COLUMN id TO container_id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_agent_tokens' AND COLUMN_NAME = 'id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_agent_tokens RENAME COLUMN id TO agent_token_id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_api_tokens' AND COLUMN_NAME = 'id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_api_tokens RENAME COLUMN id TO api_token_id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_compliance_rules' AND COLUMN_NAME = 'id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_compliance_rules RENAME COLUMN id TO compliance_rule_id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_activity_log' AND COLUMN_NAME = 'id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_activity_log RENAME COLUMN id TO activity_log_id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_applied_errata' AND COLUMN_NAME = 'id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_applied_errata RENAME COLUMN id TO applied_errata_id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_debsecan' AND COLUMN_NAME = 'id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_debsecan RENAME COLUMN id TO debsecan_id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_debian_tracker' AND COLUMN_NAME = 'id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_debian_tracker RENAME COLUMN id TO debian_tracker_id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_ubuntu_oval' AND COLUMN_NAME = 'id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_ubuntu_oval RENAME COLUMN id TO ubuntu_oval_id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_vendor_errata' AND COLUMN_NAME = 'id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_vendor_errata RENAME COLUMN id TO vendor_errata_id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_vendor_unfixed' AND COLUMN_NAME = 'id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_vendor_unfixed RENAME COLUMN id TO vendor_unfixed_id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_sla_policies' AND COLUMN_NAME = 'id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_sla_policies RENAME COLUMN id TO sla_policy_id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_remediation_cases' AND COLUMN_NAME = 'id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_remediation_cases RENAME COLUMN id TO remediation_case_id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_saved_views' AND COLUMN_NAME = 'id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_saved_views RENAME COLUMN id TO saved_view_id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_agent_replay_nonces' AND COLUMN_NAME = 'token_id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_agent_replay_nonces RENAME COLUMN token_id TO agent_token_id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- ── 2) 테이블 rename (복수 → 단수) ───────────────────────────────────────

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_hosts');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_host');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_hosts TO tb_host', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_host_ext_ports');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_host_ext_port');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_host_ext_ports TO tb_host_ext_port', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_scans');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_scan');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_scans TO tb_scan', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_packages');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_package');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_packages TO tb_package', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_exposures');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_exposure');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_exposures TO tb_exposure', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_cves');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_cve');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_cves TO tb_cve', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_cve_affected_packages');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_cve_affected_package');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_cve_affected_packages TO tb_cve_affected_package', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_findings');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_finding');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_findings TO tb_finding', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_users');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_user');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_users TO tb_user', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_feed_connectors');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_feed_connector');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_feed_connectors TO tb_feed_connector', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_feed_collection_logs');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_feed_collection_log');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_feed_collection_logs TO tb_feed_collection_log', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_advisories');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_advisory');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_advisories TO tb_advisory', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_advisory_cves');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_advisory_cve');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_advisory_cves TO tb_advisory_cve', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_processes');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_process');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_processes TO tb_process', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_role_permissions');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_role_permission');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_role_permissions TO tb_role_permission', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_cce_findings');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_cce_finding');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_cce_findings TO tb_cce_finding', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_pkg_changelog_cves');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_pkg_changelog_cve');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_pkg_changelog_cves TO tb_pkg_changelog_cve', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_suppressed_findings');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_suppressed_finding');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_suppressed_findings TO tb_suppressed_finding', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_stale_libs');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_stale_lib');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_stale_libs TO tb_stale_lib', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_pkg_changes');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_pkg_change');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_pkg_changes TO tb_pkg_change', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_containers');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_container');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_containers TO tb_container', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_agent_tokens');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_agent_token');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_agent_tokens TO tb_agent_token', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_api_tokens');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_api_token');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_api_tokens TO tb_api_token', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_compliance_rules');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_compliance_rule');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_compliance_rules TO tb_compliance_rule', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_kernel_cves');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_kernel_cve');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_kernel_cves TO tb_kernel_cve', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_kernel_cve_fixes');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_kernel_cve_fix');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_kernel_cve_fixes TO tb_kernel_cve_fix', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_sla_policies');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_sla_policy');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_sla_policies TO tb_sla_policy', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_remediation_cases');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_remediation_case');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_remediation_cases TO tb_remediation_case', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_saved_views');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_saved_view');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_saved_views TO tb_saved_view', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_agent_replay_nonces');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_agent_replay_nonce');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_agent_replay_nonces TO tb_agent_replay_nonce', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_collection_stages');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_collection_stage');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_collection_stages TO tb_collection_stage', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
