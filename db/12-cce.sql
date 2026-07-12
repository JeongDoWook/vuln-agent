-- vuln-agent 보안설정 점검(CCE) 결과 — "취약한 버전"(CVE)이 아니라 "잘못된 설정"을 본다.
--   에이전트가 이미 수집하던 security/users(sshd) 섹션을 서버(cce.php)가 판정해 여기 저장.
--   스캔 1회 × 점검항목 1개 = 1행. result 는 PASS/FAIL/NA(수집 못함).
--   최초 기동 시 11-assets.sql 다음에 자동 적용된다(파일명 순).
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
