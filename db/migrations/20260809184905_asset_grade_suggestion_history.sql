-- 시스템 자산등급 제안 관찰 이력. 사람의 확정 등급과는 완전히 분리한다.
-- 같은 scan/result/evidence replay는 유일키로 제거하되, 같은 scan을 새 분류 결과로
-- 재평가하면 fingerprint가 달라져 과거를 덮지 않고 새 행이 남는다.
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
  source_collected_at     DATETIME NULL COMMENT '에이전트가 보고한 수집 시각',
  observed_at            DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '서버가 이 결과를 관찰한 시각',
  effective_at           DATETIME GENERATED ALWAYS AS
                           (LEAST(COALESCE(source_collected_at, observed_at), observed_at)) STORED,
  created_at             DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (suggestion_history_id),
  UNIQUE KEY uq_asset_grade_suggestion_observation (host_id, scan_id, result_fingerprint),
  KEY idx_asset_grade_suggestion_host_time (host_id, effective_at, suggestion_history_id),
  KEY idx_asset_grade_suggestion_scan (scan_id),
  CONSTRAINT fk_asset_grade_suggestion_host
    FOREIGN KEY (host_id) REFERENCES tb_host(host_id) ON DELETE CASCADE,
  CONSTRAINT fk_asset_grade_suggestion_scan
    FOREIGN KEY (scan_id) REFERENCES tb_scan(scan_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
