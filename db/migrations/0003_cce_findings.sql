-- 보안설정 점검(CCE) 결과 테이블 — 기존 볼륨 보정.
--   왜 필요한가: 이 테이블은 db/12-cce.sql 에만 있었다. 최상위 db/*.sql 은 빈 볼륨 initdb
--   전용이라, 이미 데이터가 든 볼륨(운영·기존 dev)에는 끝내 들어가지 않는다. 그 상태에서
--   host.php 가 tb_cce_findings 를 조회하다 렌더 도중 죽는다(실제 발생: 메인 dev 볼륨).
--
--   내용은 db/12-cce.sql 과 동일하다. CREATE TABLE IF NOT EXISTS 라 이미 있는 볼륨에서는
--   아무 일도 하지 않는다(멱등).
SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS tb_cce_findings (
  id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  scan_id    BIGINT UNSIGNED NOT NULL,
  code       VARCHAR(32)  NOT NULL,        -- CCE-SSH-ROOT 등 점검코드
  title      VARCHAR(255) NOT NULL,        -- 점검 항목명(한글)
  result     VARCHAR(8)   NOT NULL,        -- PASS | FAIL | NA
  severity   VARCHAR(12)  NOT NULL,        -- FAIL 시 위험도: HIGH|MEDIUM|LOW
  evidence   VARCHAR(512) NULL,            -- 판정 근거가 된 수집값(원문 일부)
  rationale  VARCHAR(512) NULL,            -- 왜 이 결과인지(설명가능성)
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
