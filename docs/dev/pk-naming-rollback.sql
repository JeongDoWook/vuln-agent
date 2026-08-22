-- 명명규칙 통일 되돌리기(down) — `db/migrations/20260726115611_pk_naming_unification.sql` 의 역방향.
--
--   왜 여기 있나: deploy/migrate.sh 는 up 만 적용한다(down 개념이 없다). 그래서 되돌리는 SQL 을
--   저장소에 문서로 남긴다. rename 은 전부 가역이라 역방향도 메타데이터 전용이고 즉시 끝난다.
--
--   언제 쓰나: 새 스키마 배포 후 옛 코드로 롤백해야 할 때. **코드와 스키마는 함께 되돌려야 한다** —
--   컬럼·테이블 rename 은 하위호환이 없어서 "새 스키마 + 옛 코드" 는 전면 500 이다.
--
--   적용:
--     docker exec -i vulnagent-db sh -c \
--       'MYSQL_PWD="$(cat /run/secrets/mysql_root_password)" mysql -uroot vulnagent' \
--       < docs/dev/pk-naming-rollback.sql
--
--   되돌린 뒤에는 tb_schema_migrations 에서 해당 파일명을 지워야 다음 배포 때 다시 적용된다:
--     DELETE FROM tb_schema_migrations WHERE filename = '20260726115611_pk_naming_unification.sql';
--
--   멱등성: 정방향과 같은 information_schema 가드를 쓴다. 두 번 돌아도 안전하고,
--   이미 옛 이름인 DB 에 돌려도 아무 일도 하지 않는다.
SET NAMES utf8mb4;

-- ── 1) 테이블 rename 되돌리기 (단수 → 복수) ─────────────────────────────

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_host');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_hosts');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_host TO tb_hosts', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_host_ext_port');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_host_ext_ports');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_host_ext_port TO tb_host_ext_ports', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_scan');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_scans');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_scan TO tb_scans', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_package');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_packages');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_package TO tb_packages', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_exposure');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_exposures');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_exposure TO tb_exposures', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_cve');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_cves');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_cve TO tb_cves', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_cve_affected_package');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_cve_affected_packages');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_cve_affected_package TO tb_cve_affected_packages', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_finding');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_findings');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_finding TO tb_findings', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_user');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_users');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_user TO tb_users', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_feed_connector');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_feed_connectors');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_feed_connector TO tb_feed_connectors', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_feed_collection_log');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_feed_collection_logs');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_feed_collection_log TO tb_feed_collection_logs', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_advisory');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_advisories');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_advisory TO tb_advisories', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_advisory_cve');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_advisory_cves');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_advisory_cve TO tb_advisory_cves', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_process');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_processes');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_process TO tb_processes', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_role_permission');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_role_permissions');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_role_permission TO tb_role_permissions', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_cce_finding');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_cce_findings');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_cce_finding TO tb_cce_findings', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_pkg_changelog_cve');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_pkg_changelog_cves');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_pkg_changelog_cve TO tb_pkg_changelog_cves', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_suppressed_finding');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_suppressed_findings');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_suppressed_finding TO tb_suppressed_findings', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_stale_lib');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_stale_libs');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_stale_lib TO tb_stale_libs', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_pkg_change');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_pkg_changes');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_pkg_change TO tb_pkg_changes', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_container');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_containers');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_container TO tb_containers', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_agent_token');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_agent_tokens');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_agent_token TO tb_agent_tokens', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_api_token');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_api_tokens');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_api_token TO tb_api_tokens', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_compliance_rule');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_compliance_rules');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_compliance_rule TO tb_compliance_rules', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_kernel_cve');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_kernel_cves');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_kernel_cve TO tb_kernel_cves', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_kernel_cve_fix');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_kernel_cve_fixes');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_kernel_cve_fix TO tb_kernel_cve_fixes', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_saved_view');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_saved_views');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_saved_view TO tb_saved_views', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_agent_replay_nonce');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_agent_replay_nonces');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_agent_replay_nonce TO tb_agent_replay_nonces', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @o := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_collection_stage');
SET @n := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_collection_stages');
SET @s := IF(@o = 1 AND @n = 0, 'RENAME TABLE tb_collection_stage TO tb_collection_stages', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- ── 2) PK·FK 컬럼 rename 되돌리기 (테이블은 다시 옛 이름) ───────────────

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_agent_replay_nonces' AND COLUMN_NAME = 'agent_token_id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_agent_replay_nonces RENAME COLUMN agent_token_id TO token_id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_saved_views' AND COLUMN_NAME = 'saved_view_id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_saved_views RENAME COLUMN saved_view_id TO id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_vendor_unfixed' AND COLUMN_NAME = 'vendor_unfixed_id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_vendor_unfixed RENAME COLUMN vendor_unfixed_id TO id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_vendor_errata' AND COLUMN_NAME = 'vendor_errata_id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_vendor_errata RENAME COLUMN vendor_errata_id TO id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_ubuntu_oval' AND COLUMN_NAME = 'ubuntu_oval_id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_ubuntu_oval RENAME COLUMN ubuntu_oval_id TO id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_debian_tracker' AND COLUMN_NAME = 'debian_tracker_id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_debian_tracker RENAME COLUMN debian_tracker_id TO id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_debsecan' AND COLUMN_NAME = 'debsecan_id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_debsecan RENAME COLUMN debsecan_id TO id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_applied_errata' AND COLUMN_NAME = 'applied_errata_id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_applied_errata RENAME COLUMN applied_errata_id TO id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_activity_log' AND COLUMN_NAME = 'activity_log_id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_activity_log RENAME COLUMN activity_log_id TO id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_compliance_rules' AND COLUMN_NAME = 'compliance_rule_id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_compliance_rules RENAME COLUMN compliance_rule_id TO id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_api_tokens' AND COLUMN_NAME = 'api_token_id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_api_tokens RENAME COLUMN api_token_id TO id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_agent_tokens' AND COLUMN_NAME = 'agent_token_id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_agent_tokens RENAME COLUMN agent_token_id TO id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_containers' AND COLUMN_NAME = 'container_id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_containers RENAME COLUMN container_id TO id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_pkg_changes' AND COLUMN_NAME = 'pkg_change_id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_pkg_changes RENAME COLUMN pkg_change_id TO id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_stale_libs' AND COLUMN_NAME = 'stale_lib_id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_stale_libs RENAME COLUMN stale_lib_id TO id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_suppressed_findings' AND COLUMN_NAME = 'suppressed_finding_id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_suppressed_findings RENAME COLUMN suppressed_finding_id TO id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_pkg_changelog_cves' AND COLUMN_NAME = 'pkg_changelog_cve_id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_pkg_changelog_cves RENAME COLUMN pkg_changelog_cve_id TO id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_cce_findings' AND COLUMN_NAME = 'cce_finding_id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_cce_findings RENAME COLUMN cce_finding_id TO id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_role_permissions' AND COLUMN_NAME = 'role_permission_id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_role_permissions RENAME COLUMN role_permission_id TO id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_processes' AND COLUMN_NAME = 'process_id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_processes RENAME COLUMN process_id TO id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_advisory_cves' AND COLUMN_NAME = 'advisory_cve_id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_advisory_cves RENAME COLUMN advisory_cve_id TO id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_advisories' AND COLUMN_NAME = 'advisory_id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_advisories RENAME COLUMN advisory_id TO id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_feed_collection_logs' AND COLUMN_NAME = 'feed_connector_id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_feed_collection_logs RENAME COLUMN feed_connector_id TO connector_id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_feed_collection_logs' AND COLUMN_NAME = 'feed_collection_log_id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_feed_collection_logs RENAME COLUMN feed_collection_log_id TO id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_feed_connectors' AND COLUMN_NAME = 'feed_connector_id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_feed_connectors RENAME COLUMN feed_connector_id TO id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_users' AND COLUMN_NAME = 'user_id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_users RENAME COLUMN user_id TO id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_findings' AND COLUMN_NAME = 'finding_id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_findings RENAME COLUMN finding_id TO id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_cve_affected_packages' AND COLUMN_NAME = 'cve_affected_package_id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_cve_affected_packages RENAME COLUMN cve_affected_package_id TO id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_exposures' AND COLUMN_NAME = 'exposure_id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_exposures RENAME COLUMN exposure_id TO id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_packages' AND COLUMN_NAME = 'package_id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_packages RENAME COLUMN package_id TO id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_scans' AND COLUMN_NAME = 'scan_id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_scans RENAME COLUMN scan_id TO id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_host_ext_ports' AND COLUMN_NAME = 'host_ext_port_id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_host_ext_ports RENAME COLUMN host_ext_port_id TO id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_hosts' AND COLUMN_NAME = 'host_id');
SET @s := IF(@c = 1, 'ALTER TABLE tb_hosts RENAME COLUMN host_id TO id', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
