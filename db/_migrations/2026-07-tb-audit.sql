-- vuln-agent 프로덕션 in-place 마이그레이션 : tb_ 접두사 + 감사 4컬럼 + 활동로그
-- ─────────────────────────────────────────────────────────────────────────
-- 이 파일은 db/_migrations/ 하위폴더에 있으므로 MySQL initdb 가 자동 실행하지
-- 않는다(initdb 는 /docker-entrypoint-initdb.d 최상위 *.sql 만 실행). 즉 신규
-- 볼륨에는 01~09 가 이미 최종 스키마이므로 이 파일이 필요 없다.
--
-- 이 스크립트는 **기존 프로덕션 볼륨**(구 이름 13개 테이블 + 07/08 ALTER 가
-- 이미 적용된 상태: cves.epss / findings.runtime_status 존재)에 딱 1회 수동 적용.
--
-- 프로덕션 수동 적용:
--   docker compose -p vulnagent exec -T db sh -c \
--     'mysql -uroot -p$(cat /run/secrets/mysql_root_password) vulnagent' \
--     < db/_migrations/2026-07-tb-audit.sql
--
-- 주의: 이미 적용된 뒤 재실행하면 RENAME/ADD COLUMN 이 에러난다(1회성).
-- ─────────────────────────────────────────────────────────────────────────
SET NAMES utf8mb4;

-- ── 1) 13개 테이블 일괄 리네임 (MySQL 은 RENAME 시 FK 참조도 자동 갱신) ────
RENAME TABLE
  hosts                 TO tb_hosts,
  scans                 TO tb_scans,
  packages              TO tb_packages,
  exposures             TO tb_exposures,
  processes             TO tb_processes,
  findings              TO tb_findings,
  cves                  TO tb_cves,
  kev_catalog           TO tb_kev_catalog,
  cve_affected_packages TO tb_cve_affected_packages,
  users                 TO tb_users,
  feed_connectors       TO tb_feed_connectors,
  feed_collection_logs  TO tb_feed_collection_logs,
  advisories            TO tb_advisories;

-- ── 2) 감사 4컬럼 추가 (없는 것만) + is_deleted 인덱스 ─────────────────────
--   기존 보유 현황: tb_users=created_at 있음 / tb_feed_connectors=created_at+updated_at 있음.
--   그래서 이 둘은 없는 컬럼만 추가하고, 나머지 11개는 4컬럼 전부 추가한다.

-- 나머지 11개 테이블: 4컬럼 전부 추가
ALTER TABLE tb_hosts
  ADD COLUMN created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  ADD COLUMN updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  ADD COLUMN is_deleted TINYINT(1) NOT NULL DEFAULT 0,
  ADD COLUMN deleted_at DATETIME NULL,
  ADD INDEX idx_hosts_is_deleted (is_deleted);

ALTER TABLE tb_scans
  ADD COLUMN created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  ADD COLUMN updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  ADD COLUMN is_deleted TINYINT(1) NOT NULL DEFAULT 0,
  ADD COLUMN deleted_at DATETIME NULL,
  ADD INDEX idx_scans_is_deleted (is_deleted);

ALTER TABLE tb_packages
  ADD COLUMN created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  ADD COLUMN updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  ADD COLUMN is_deleted TINYINT(1) NOT NULL DEFAULT 0,
  ADD COLUMN deleted_at DATETIME NULL,
  ADD INDEX idx_packages_is_deleted (is_deleted);

ALTER TABLE tb_exposures
  ADD COLUMN created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  ADD COLUMN updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  ADD COLUMN is_deleted TINYINT(1) NOT NULL DEFAULT 0,
  ADD COLUMN deleted_at DATETIME NULL,
  ADD INDEX idx_exposures_is_deleted (is_deleted);

ALTER TABLE tb_processes
  ADD COLUMN created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  ADD COLUMN updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  ADD COLUMN is_deleted TINYINT(1) NOT NULL DEFAULT 0,
  ADD COLUMN deleted_at DATETIME NULL,
  ADD INDEX idx_processes_is_deleted (is_deleted);

ALTER TABLE tb_findings
  ADD COLUMN created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  ADD COLUMN updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  ADD COLUMN is_deleted TINYINT(1) NOT NULL DEFAULT 0,
  ADD COLUMN deleted_at DATETIME NULL,
  ADD INDEX idx_findings_is_deleted (is_deleted);

ALTER TABLE tb_cves
  ADD COLUMN created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  ADD COLUMN updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  ADD COLUMN is_deleted TINYINT(1) NOT NULL DEFAULT 0,
  ADD COLUMN deleted_at DATETIME NULL,
  ADD INDEX idx_cves_is_deleted (is_deleted);

ALTER TABLE tb_kev_catalog
  ADD COLUMN created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  ADD COLUMN updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  ADD COLUMN is_deleted TINYINT(1) NOT NULL DEFAULT 0,
  ADD COLUMN deleted_at DATETIME NULL,
  ADD INDEX idx_kev_catalog_is_deleted (is_deleted);

ALTER TABLE tb_cve_affected_packages
  ADD COLUMN created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  ADD COLUMN updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  ADD COLUMN is_deleted TINYINT(1) NOT NULL DEFAULT 0,
  ADD COLUMN deleted_at DATETIME NULL,
  ADD INDEX idx_cve_affected_packages_is_deleted (is_deleted);

ALTER TABLE tb_feed_collection_logs
  ADD COLUMN created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  ADD COLUMN updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  ADD COLUMN is_deleted TINYINT(1) NOT NULL DEFAULT 0,
  ADD COLUMN deleted_at DATETIME NULL,
  ADD INDEX idx_feed_collection_logs_is_deleted (is_deleted);

ALTER TABLE tb_advisories
  ADD COLUMN created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  ADD COLUMN updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  ADD COLUMN is_deleted TINYINT(1) NOT NULL DEFAULT 0,
  ADD COLUMN deleted_at DATETIME NULL,
  ADD INDEX idx_advisories_is_deleted (is_deleted);

-- tb_users: created_at 이미 있음 → updated_at/is_deleted/deleted_at 만 추가
ALTER TABLE tb_users
  ADD COLUMN updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  ADD COLUMN is_deleted TINYINT(1) NOT NULL DEFAULT 0,
  ADD COLUMN deleted_at DATETIME NULL,
  ADD INDEX idx_users_is_deleted (is_deleted);

-- tb_feed_connectors: created_at/updated_at 이미 있음 → is_deleted/deleted_at 만 추가
ALTER TABLE tb_feed_connectors
  ADD COLUMN is_deleted TINYINT(1) NOT NULL DEFAULT 0,
  ADD COLUMN deleted_at DATETIME NULL,
  ADD INDEX idx_feed_connectors_is_deleted (is_deleted);

-- ── 3) 신규 활동 로그 테이블 ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tb_activity_log (
  id            BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id       BIGINT UNSIGNED NULL,
  user_name     VARCHAR(100) NULL,
  actor_type    VARCHAR(20) NOT NULL DEFAULT 'USER',
  scope         VARCHAR(50) NOT NULL,
  scope_id      BIGINT UNSIGNED NULL,
  activity_type VARCHAR(70) NOT NULL,
  message       TEXT NULL,
  data          JSON NULL,
  ip_address    VARCHAR(45) NULL,
  created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted    TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at    DATETIME NULL,
  INDEX idx_activity_user (user_id),
  INDEX idx_activity_scope (scope, scope_id),
  INDEX idx_activity_type (activity_type),
  INDEX idx_activity_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
