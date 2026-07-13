-- 재시작 필요 — 업데이트로 교체된 옛 라이브러리를 아직 물고 있는 프로세스.
--   패키지는 패치됐지만 프로세스가 옛 .so 를 메모리에 상주시키고 있으면 **여전히 취약**하다.
--   이건 오탐이 아니라 미탐이라 더 위험하다(대시보드엔 "패치됨"으로 보인다).
--   멱등: CREATE TABLE IF NOT EXISTS. 빈 볼륨은 db/15-stale.sql(initdb)이 만든다.
SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS tb_stale_libs (
  id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  scan_id      BIGINT UNSIGNED NOT NULL,
  pid          INT NULL,
  comm         VARCHAR(255) NULL,
  package_name VARCHAR(255) NOT NULL,
  lib_path     VARCHAR(512) NULL,
  created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted   TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at   DATETIME NULL,
  PRIMARY KEY (id),
  KEY idx_stale_scan (scan_id),
  KEY idx_stale_lookup (scan_id, package_name),
  INDEX idx_stale_is_deleted (is_deleted),
  CONSTRAINT fk_stale_scan FOREIGN KEY (scan_id) REFERENCES tb_scans(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
