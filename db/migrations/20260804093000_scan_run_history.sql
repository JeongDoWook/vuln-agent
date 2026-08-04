-- 수집 실행 이력은 매 수신마다 1행을 남기고, 무거운 tb_scan은 변경 스냅샷으로 재사용한다.
SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS tb_scan_run (
  scan_run_id    BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  host_id        BIGINT UNSIGNED NOT NULL,
  scan_id        BIGINT UNSIGNED NOT NULL,
  collected_at   DATETIME NULL,
  received_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  content_changed TINYINT(1) NOT NULL DEFAULT 0,
  package_count  INT NULL,
  exposure_count INT NULL,
  agent_version  VARCHAR(32) NULL,
  schedule       VARCHAR(64) NULL,
  elapsed_seconds INT NULL,
  peak_rss_mb    DECIMAL(8,1) NULL,
  cpu_seconds    DECIMAL(10,2) NULL,
  mem_total_mb   DECIMAL(12,1) NULL,
  cpu_cores      INT NULL,
  PRIMARY KEY (scan_run_id),
  KEY idx_scan_run_host_time (host_id, collected_at, scan_run_id),
  KEY idx_scan_run_scan (scan_id),
  CONSTRAINT fk_scan_run_host FOREIGN KEY (host_id) REFERENCES tb_host(host_id) ON DELETE CASCADE,
  CONSTRAINT fk_scan_run_scan FOREIGN KEY (scan_id) REFERENCES tb_scan(scan_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 과거 실행은 복원할 수 없으므로 기존 변경 스냅샷마다 확인 가능한 1회만 이관한다.
INSERT INTO tb_scan_run
  (host_id, scan_id, collected_at, received_at, content_changed,
   package_count, exposure_count, agent_version, schedule, elapsed_seconds,
   peak_rss_mb, cpu_seconds, mem_total_mb, cpu_cores)
SELECT s.host_id, s.scan_id, s.collected_at, s.received_at, 1,
       s.package_count, s.exposure_count, s.agent_version, s.schedule, s.elapsed_seconds,
       s.peak_rss_mb, s.cpu_seconds, s.mem_total_mb, s.cpu_cores
  FROM tb_scan s
 WHERE NOT EXISTS (SELECT 1 FROM tb_scan_run r WHERE r.scan_id = s.scan_id);
