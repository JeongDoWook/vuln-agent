-- 빈 볼륨 initdb용 시스템 자산등급 제안 이력.
-- 이 단계에서는 부모 테이블이 아직 옛 이름이며, 후속 naming migration이 FK 참조도 함께 바꾼다.
SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS tb_asset_grade_suggestion_history (
  suggestion_history_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  host_id                BIGINT UNSIGNED NOT NULL,
  scan_id                BIGINT UNSIGNED NOT NULL,
  suggested_grade        CHAR(1) NULL COMMENT '시스템 제안 C/S/O — 확정값 아님',
  suggested_reason       VARCHAR(255) NULL,
  evaluation_status      ENUM('SUGGESTED','NO_MATCH','NOT_EVALUATED') NOT NULL,
  evidence_snapshot      JSON NOT NULL,
  result_fingerprint     BINARY(32) NOT NULL,
  source_collected_at     DATETIME NULL,
  observed_at            DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_source_collected_at DATETIME NULL,
  last_observed_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  effective_at           DATETIME GENERATED ALWAYS AS
                           (LEAST(GREATEST(COALESCE(last_source_collected_at,last_observed_at),
                             DATE_SUB(last_observed_at, INTERVAL 7 DAY)),last_observed_at)) STORED,
  created_at             DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (suggestion_history_id),
  UNIQUE KEY uq_asset_grade_suggestion_observation (host_id, scan_id, result_fingerprint),
  KEY idx_asset_grade_suggestion_host_time (host_id, effective_at, last_observed_at, suggestion_history_id),
  KEY idx_asset_grade_suggestion_scan (scan_id),
  CONSTRAINT fk_asset_grade_suggestion_host FOREIGN KEY (host_id) REFERENCES tb_hosts(id) ON DELETE CASCADE,
  CONSTRAINT fk_asset_grade_suggestion_scan FOREIGN KEY (scan_id) REFERENCES tb_scans(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
