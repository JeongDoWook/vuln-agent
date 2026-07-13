-- 적용된 벤더 보안권고(errata)가 고친 CVE — 백포트 오탐 제거의 두 번째 근거.
--   `dnf updateinfo list installed --with-cve` 가 주는 "CVE ↔ 이미 설치된 NEVRA" 목록이다.
--   = 벤더가 "이 CVE 는 이 빌드에서 고쳤다"고 확인해 준 것. changelog(핵심 13개 패키지만)와
--   달리 시스템 전체를 덮는다.
--   빈 볼륨은 이 파일(initdb), 기존 볼륨은 db/migrations/0005_applied_errata.sql 이 만든다.
SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS tb_applied_errata (
  id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  scan_id      BIGINT UNSIGNED NOT NULL,
  package_name VARCHAR(255) NOT NULL,
  cve_id       VARCHAR(32)  NOT NULL,
  evidence     VARCHAR(255) NULL,        -- 권고가 지목한 설치 NEVRA (근거 표시용)
  created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted   TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at   DATETIME NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_errata (scan_id, package_name, cve_id),
  KEY idx_errata_scan (scan_id),
  KEY idx_errata_lookup (scan_id, package_name),
  INDEX idx_errata_is_deleted (is_deleted),
  CONSTRAINT fk_errata_scan FOREIGN KEY (scan_id) REFERENCES tb_scans(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
