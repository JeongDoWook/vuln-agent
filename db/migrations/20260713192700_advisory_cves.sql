-- tb_advisories.cve_ids 콤마 CSV(1NF 위반) 정규화 — tb_advisory_cves 정션 테이블 신설.
--   CSV 는 explode() 로만 파싱되고 CVE→공지 역조회가 안 되며 LIKE 검색은 인덱스를 못 탄다
--   (bin/rebuild_advisory_cveids.php 의 존재 자체가 이 설계의 부채 — CSV 를 주기적으로 재생성).
--   expand→contract: 이 마이그레이션은 junction 만 신설한다. cve_ids 컬럼은 그대로 두고
--   (호환을 위해 이중 유지), 기존 데이터 백필은 별도 1회 스크립트
--   (bin/backfill_advisory_cves.php)로 한다 — CSV 분해는 SQL 재귀 CTE보다 이미 검증된
--   PHP 파서(vg_extract_cve_ids)를 재사용하는 편이 단순하고 안전하다(KISS).
--   빈 볼륨은 db/06-advisories.sql(initdb)에 동일 테이블을 반영한다.
SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS tb_advisory_cves (
  id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  advisory_id BIGINT UNSIGNED NOT NULL,
  cve_id      VARCHAR(32) NOT NULL,
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted  TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at  DATETIME NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_advisory_cve (advisory_id, cve_id),
  INDEX idx_advisory_cves_cve (cve_id),           -- CVE → 공지 역조회
  INDEX idx_advisory_cves_is_deleted (is_deleted),
  CONSTRAINT fk_advisory_cves_advisory FOREIGN KEY (advisory_id) REFERENCES tb_advisories(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
