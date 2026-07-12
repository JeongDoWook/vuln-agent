-- 기존 dev/prod 볼륨(이미 초기화된 DB)에 CCE 점검 결과 테이블 추가.
--   initdb 는 빈 볼륨에서만 12-cce.sql 을 돌리므로, 운영 볼륨엔 이 마이그레이션을 수동 적용한다.
--   docker compose -p <프로젝트> exec -T db sh -c 'mysql -uroot -p"$(cat /run/secrets/mysql_root_password)" vulnagent' < db/_migrations/2026-07-cce-findings.sql
SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS tb_cce_findings (
  id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  scan_id    BIGINT UNSIGNED NOT NULL,
  code       VARCHAR(32)  NOT NULL,
  title      VARCHAR(255) NOT NULL,
  result     VARCHAR(8)   NOT NULL,
  severity   VARCHAR(12)  NOT NULL,
  evidence   VARCHAR(512) NULL,
  rationale  VARCHAR(512) NULL,
  checked_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at DATETIME NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_cce (scan_id, code),
  KEY idx_cce_scan (scan_id),
  KEY idx_cce_result (result),
  INDEX idx_cce_findings_is_deleted (is_deleted),
  CONSTRAINT fk_cce_scan FOREIGN KEY (scan_id) REFERENCES tb_scans(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
