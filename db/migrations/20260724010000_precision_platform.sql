-- 정밀 판정 플랫폼: 구조화 근거, 내부 SLA/조치, 컨테이너·SBOM, 수집 신뢰성.
SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS tb_finding_evidence (
  finding_id BIGINT UNSIGNED NOT NULL,
  match_source VARCHAR(32) NOT NULL DEFAULT 'catalog',
  fixed_version VARCHAR(255) NULL,
  source_package VARCHAR(255) NULL,
  source_version VARCHAR(255) NULL,
  process_evidence TEXT NULL,
  network_evidence TEXT NULL,
  suppression_evidence TEXT NULL,
  feed_updated_at DATETIME NULL,
  evidence_json LONGTEXT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (finding_id),
  KEY idx_fe_source (match_source),
  CONSTRAINT fk_fe_finding FOREIGN KEY (finding_id) REFERENCES tb_findings(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS tb_sla_policies (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  name VARCHAR(100) NOT NULL,
  severity VARCHAR(12) NOT NULL,
  exposure_scope VARCHAR(16) NOT NULL DEFAULT 'ANY',
  in_kev TINYINT(1) NOT NULL DEFAULT 0,
  due_days INT UNSIGNED NOT NULL,
  enabled TINYINT(1) NOT NULL DEFAULT 1,
  priority INT NOT NULL DEFAULT 100,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at DATETIME NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_sla_policy (severity, exposure_scope, in_kev),
  KEY idx_sla_match (enabled, severity, in_kev, priority)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT IGNORE INTO tb_sla_policies (name,severity,exposure_scope,in_kev,due_days,priority) VALUES
 ('KEV 외부노출 24시간','CRITICAL','EXTERNAL',1,1,10),
 ('CRITICAL 3일','CRITICAL','ANY',0,3,20),
 ('HIGH 14일','HIGH','ANY',0,14,30),
 ('MEDIUM 30일','MEDIUM','ANY',0,30,40),
 ('LOW 90일','LOW','ANY',0,90,50);

CREATE TABLE IF NOT EXISTS tb_remediation_cases (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  host_id BIGINT UNSIGNED NOT NULL,
  container_ref VARCHAR(255) NOT NULL DEFAULT '',
  cve_id VARCHAR(32) NOT NULL,
  package_name VARCHAR(255) NOT NULL,
  status VARCHAR(20) NOT NULL DEFAULT 'OPEN',
  assignee_user_id BIGINT UNSIGNED NULL,
  due_at DATETIME NULL,
  due_source VARCHAR(20) NOT NULL DEFAULT 'SLA',
  exception_reason VARCHAR(1000) NULL,
  exception_until DATETIME NULL,
  resolution_note TEXT NULL,
  completed_at DATETIME NULL,
  first_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at DATETIME NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_remediation_asset (host_id,container_ref,cve_id,package_name),
  KEY idx_remediation_queue (status,due_at),
  KEY idx_remediation_assignee (assignee_user_id,status),
  CONSTRAINT fk_remediation_host FOREIGN KEY (host_id) REFERENCES tb_hosts(id) ON DELETE CASCADE,
  CONSTRAINT fk_remediation_user FOREIGN KEY (assignee_user_id) REFERENCES tb_users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS tb_saved_views (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id BIGINT UNSIGNED NOT NULL,
  page_code VARCHAR(40) NOT NULL,
  name VARCHAR(100) NOT NULL,
  query_json TEXT NOT NULL,
  is_default TINYINT(1) NOT NULL DEFAULT 0,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at DATETIME NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_saved_view (user_id,page_code,name),
  KEY idx_saved_view_page (user_id,page_code,is_default),
  CONSTRAINT fk_saved_view_user FOREIGN KEY (user_id) REFERENCES tb_users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS tb_agent_replay_nonces (
  token_id BIGINT UNSIGNED NOT NULL,
  nonce_hash CHAR(64) NOT NULL,
  seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at DATETIME NOT NULL,
  PRIMARY KEY (token_id,nonce_hash),
  KEY idx_nonce_expiry (expires_at),
  CONSTRAINT fk_nonce_token FOREIGN KEY (token_id) REFERENCES tb_agent_tokens(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS tb_collection_stages (
  scan_id BIGINT UNSIGNED NOT NULL,
  stage_code VARCHAR(40) NOT NULL,
  status VARCHAR(16) NOT NULL,
  duration_ms INT UNSIGNED NULL,
  item_count INT UNSIGNED NULL,
  error_code VARCHAR(64) NULL,
  error_message VARCHAR(500) NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (scan_id,stage_code),
  KEY idx_collection_status (status,stage_code),
  CONSTRAINT fk_collection_scan FOREIGN KEY (scan_id) REFERENCES tb_scans(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='tb_containers' AND COLUMN_NAME='image_digest');
SET @s := IF(@c=0,'ALTER TABLE tb_containers ADD COLUMN image_digest VARCHAR(128) NULL AFTER image','DO 0'); PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='tb_containers' AND COLUMN_NAME='k8s_namespace');
SET @s := IF(@c=0,'ALTER TABLE tb_containers ADD COLUMN k8s_namespace VARCHAR(255) NULL AFTER image_digest, ADD COLUMN k8s_pod VARCHAR(255) NULL AFTER k8s_namespace, ADD COLUMN k8s_container VARCHAR(255) NULL AFTER k8s_pod, ADD COLUMN workload_ref VARCHAR(255) NULL AFTER k8s_container, ADD COLUMN runtime_state VARCHAR(16) NOT NULL DEFAULT ''running'' AFTER workload_ref, ADD COLUMN sbom_format VARCHAR(32) NULL AFTER runtime_state, ADD COLUMN sbom_hash CHAR(64) NULL AFTER sbom_format','DO 0'); PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

INSERT IGNORE INTO tb_role_permissions (role,menu_code,allowed) VALUES
 ('operator','remediations',1),('user','remediations',1);
