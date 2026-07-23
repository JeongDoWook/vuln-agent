-- vuln-agent 백포트 오탐 제거 — "버전은 낮아 보여도 이미 패치됨"을 증명한다.
--   에이전트가 긁는 changelog 섹션(rpm -q --changelog / dpkg changelog 의 CVE 줄)을
--   ingest 가 파싱해 tb_pkg_changelog_cves 에 저장. 매처가 이걸로 finding 을 억제한다.
--   억제된 건은 tb_findings(=실제 위험)에 넣지 않고 tb_suppressed_findings 로 분리 →
--   기존 위험 집계/화면을 하나도 안 건드리고 오탐이 사라진다.
--   최초 기동 시 12-cce.sql 다음에 자동 적용된다(파일명 순).
SET NAMES utf8mb4;

-- ── 패키지별 changelog 에 명시된 CVE(=그 빌드에 백포트된 수정) ──────────
CREATE TABLE IF NOT EXISTS tb_pkg_changelog_cves (
  id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  scan_id      BIGINT UNSIGNED NOT NULL,
  package_name VARCHAR(255) NOT NULL,     -- changelog 를 조회한 패키지명
  cve_id       VARCHAR(32)  NOT NULL,     -- 그 changelog 에 나온 CVE
  evidence     VARCHAR(255) NULL,         -- 근거가 된 changelog 줄(원문 일부)
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

-- ── 억제된 취약점 : "버전상 취약해 보였으나 백포트로 패치됨" ────────────
--   tb_findings 와 스키마가 비슷하나 의도적으로 분리한다(위험 집계에서 자동 제외).
CREATE TABLE IF NOT EXISTS tb_suppressed_findings (
  id                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  scan_id           BIGINT UNSIGNED NOT NULL,
  container_id      BIGINT UNSIGNED NOT NULL DEFAULT 0,
  cve_id            VARCHAR(32) NOT NULL,
  package_name      VARCHAR(255) NOT NULL,
  installed_version VARCHAR(255) NULL,
  in_kev            TINYINT(1) NOT NULL DEFAULT 0,
  cvss              DECIMAL(3,1) NULL,
  base_severity     VARCHAR(12) NOT NULL,           -- 억제 안 됐다면 받았을 등급
  suppress_reason   VARCHAR(512) NULL,              -- 왜 무해로 판정했나(백포트 근거)
  matched_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted        TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at        DATETIME NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_supp (scan_id, container_id, cve_id, package_name),
  KEY idx_supp_scan (scan_id),
  KEY idx_supp_container (container_id),
  INDEX idx_supp_is_deleted (is_deleted),
  CONSTRAINT fk_supp_scan FOREIGN KEY (scan_id) REFERENCES tb_scans(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
