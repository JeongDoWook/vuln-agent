-- 데비안 보안 트래커(debsecan)가 이 호스트에 **실제로 해당한다고 판정한** CVE 목록.
--   RHEL 의 errata(tb_applied_errata)에 대응하는 데비안판이지만 방향이 반대다:
--   errata 는 "고쳐진 CVE"를, debsecan 은 "아직 취약한 CVE"를 준다.
--   → 여기 없는 deb 패키지 CVE 는 백포트로 이미 수정된 것(오탐)이므로 억제한다.
--   빈 볼륨은 이 파일(initdb), 기존 볼륨은 db/migrations/0011_debsecan.sql 이 만든다.
SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS tb_debsecan (
  id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  scan_id      BIGINT UNSIGNED NOT NULL,
  cve_id       VARCHAR(32)  NOT NULL,
  package_name VARCHAR(255) NOT NULL,
  created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted   TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at   DATETIME NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_debsecan (scan_id, cve_id, package_name),
  KEY idx_debsecan_scan (scan_id),
  KEY idx_debsecan_lookup (scan_id, package_name),
  INDEX idx_debsecan_is_deleted (is_deleted),
  CONSTRAINT fk_debsecan_scan FOREIGN KEY (scan_id) REFERENCES tb_scans(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
