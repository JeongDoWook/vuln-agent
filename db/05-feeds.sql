-- vuln-agent CVE 피드 커넥터(4단계)
-- claude-pipeline 의 ConnectorSetting/ConnectorCollectionLog 패턴을 참고.
--   feed_connectors      ≈ ConnectorSetting  (설정 인스턴스: 타입/접속/스케줄/상태)
--   feed_collection_logs ≈ ConnectorCollectionLog (수집 실행 이력/상태)
-- 수집 결과는 기존 cves / kev_catalog / cve_affected_packages 로 upsert.
SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS feed_connectors (
  id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  name            VARCHAR(128) NOT NULL,
  connector_type  VARCHAR(32)  NOT NULL,          -- kev | osv | nvd
  connection_json JSON NOT NULL,                  -- {url, api_key, ecosystem, ...}
  schedule_json   JSON NOT NULL,                  -- {mode:'manual'|'interval', interval_minutes:N}
  enabled         TINYINT(1) NOT NULL DEFAULT 0,
  last_run_at     DATETIME NULL,
  last_status     VARCHAR(16) NULL,               -- never | running | success | error
  last_message    VARCHAR(512) NULL,
  next_run_at     DATETIME NULL,                  -- NULL=즉시 대상, 스케줄러가 갱신
  created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_feed_name (name),
  KEY idx_feed_due (enabled, next_run_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS feed_collection_logs (
  id             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  connector_id   BIGINT UNSIGNED NOT NULL,
  trigger_by     VARCHAR(16) NOT NULL DEFAULT 'schedule',  -- schedule | manual
  started_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  finished_at    DATETIME NULL,
  status         VARCHAR(16) NOT NULL DEFAULT 'running',   -- running | success | error
  items_fetched  INT NULL,
  items_upserted INT NULL,
  message        VARCHAR(512) NULL,
  PRIMARY KEY (id),
  KEY idx_fcl_conn (connector_id, started_at),
  CONSTRAINT fk_fcl_conn FOREIGN KEY (connector_id) REFERENCES feed_connectors(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 기본 커넥터 3종 (KEV 만 활성. OSV/NVD 는 UI 에서 켠다)
INSERT INTO feed_connectors (name, connector_type, connection_json, schedule_json, enabled, last_status)
VALUES
  ('CISA KEV', 'kev',
   JSON_OBJECT('url','https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'),
   JSON_OBJECT('mode','interval','interval_minutes',1440), 1, 'never'),
  ('OSV.dev', 'osv',
   JSON_OBJECT('url','https://api.osv.dev/v1/query'),
   JSON_OBJECT('mode','interval','interval_minutes',360), 1, 'never'),
  ('NVD 2.0', 'nvd',
   JSON_OBJECT('url','https://services.nvd.nist.gov/rest/json/cves/2.0','api_key','','days',7),
   JSON_OBJECT('mode','manual'), 0, 'never')
ON DUPLICATE KEY UPDATE name = name;
