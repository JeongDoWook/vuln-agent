-- 백포트 오탐 제거용 테이블 — 기존 볼륨에 자동 증분 적용(migrate.sh 가 관리).
--   빈 볼륨은 db/13-changelog.sql(initdb)이 만들고, 기존 볼륨은 이 파일이 만든다.
--   멱등: CREATE TABLE IF NOT EXISTS 라 재실행/양쪽 적용에도 안전.
SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS tb_pkg_changelog_cves (
  id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  scan_id      BIGINT UNSIGNED NOT NULL,
  package_name VARCHAR(255) NOT NULL,
  cve_id       VARCHAR(32)  NOT NULL,
  evidence     VARCHAR(255) NULL,
  created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted   TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at   DATETIME NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_clog (scan_id, package_name, cve_id),
  KEY idx_clog_scan (scan_id),
  KEY idx_clog_lookup (scan_id, package_name),
  INDEX idx_clog_is_deleted (is_deleted),
  CONSTRAINT fk_clog_scan FOREIGN KEY (scan_id) REFERENCES tb_scans(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS tb_suppressed_findings (
  id                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  scan_id           BIGINT UNSIGNED NOT NULL,
  cve_id            VARCHAR(32) NOT NULL,
  package_name      VARCHAR(255) NOT NULL,
  installed_version VARCHAR(255) NULL,
  in_kev            TINYINT(1) NOT NULL DEFAULT 0,
  cvss              DECIMAL(3,1) NULL,
  base_severity     VARCHAR(12) NOT NULL,
  suppress_reason   VARCHAR(512) NULL,
  matched_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted        TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at        DATETIME NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_supp (scan_id, cve_id, package_name),
  KEY idx_supp_scan (scan_id),
  INDEX idx_supp_is_deleted (is_deleted),
  CONSTRAINT fk_supp_scan FOREIGN KEY (scan_id) REFERENCES tb_scans(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
