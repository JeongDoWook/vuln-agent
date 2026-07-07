-- vuln-agent 중앙 DB 스키마 (MySQL 8)
-- 컨테이너 최초 기동 시 /docker-entrypoint-initdb.d 로 자동 적용됨.
-- 데이터 흐름: 에이전트 JSON  ──POST──▶ ingest.php ──▶ 아래 테이블
SET NAMES utf8mb4;

-- ── 호스트(서버) : fqdn 으로 식별, 스캔마다 last_seen 갱신 ──────────────
CREATE TABLE IF NOT EXISTS hosts (
  id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  fqdn       VARCHAR(255) NOT NULL,
  hostname   VARCHAR(255) NULL,
  os_id      VARCHAR(64)  NULL,
  os_version VARCHAR(64)  NULL,
  first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_hosts_fqdn (fqdn)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ── 스캔 이력 : 수집 1회 = 1행. 원본 JSON 도 보관(2단계 매처가 재활용) ──
CREATE TABLE IF NOT EXISTS scans (
  id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  host_id         BIGINT UNSIGNED NOT NULL,
  collected_at    DATETIME NULL,
  agent_version   VARCHAR(32)  NULL,
  elapsed_seconds INT NULL,
  os_id           VARCHAR(64)  NULL,
  os_version      VARCHAR(64)  NULL,
  kernel          VARCHAR(255) NULL,
  cpe             VARCHAR(255) NULL,
  package_family  VARCHAR(16)  NULL,   -- rpm | deb
  package_count   INT NULL,
  exposure_count  INT NULL,
  raw_json        JSON NULL,           -- 수신 원본(재처리/감사용)
  received_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_scans_host_time (host_id, collected_at),
  KEY idx_scans_received (received_at),
  CONSTRAINT fk_scans_host FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ── 패키지 목록 : 취약점 매핑의 핵심. 릴리스포함 버전 + 소스패키지 보존 ──
CREATE TABLE IF NOT EXISTS packages (
  id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  scan_id    BIGINT UNSIGNED NOT NULL,
  manager    VARCHAR(16)  NULL,        -- rpm | dpkg
  name       VARCHAR(255) NOT NULL,
  version    VARCHAR(255) NULL,        -- 전체 EVR / dpkg 버전 (릴리스번호 포함)
  arch       VARCHAR(32)  NULL,
  source_pkg VARCHAR(255) NULL,        -- 소스패키지 (백포트 인식 → 오탐 감소)
  vendor     VARCHAR(255) NULL,
  PRIMARY KEY (id),
  KEY idx_pkg_scan (scan_id),
  KEY idx_pkg_name (name),
  KEY idx_pkg_source (source_pkg),
  CONSTRAINT fk_pkg_scan FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ── 런타임 노출 상관 (차별점 ①) : 소켓마다 1행 ───────────────────────
--   pid|proc|proto|bind|port|scope|exe_pkg|loaded_pkgs
CREATE TABLE IF NOT EXISTS exposures (
  id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  scan_id     BIGINT UNSIGNED NOT NULL,
  pid         INT NULL,
  proc        VARCHAR(255) NULL,
  proto       VARCHAR(16)  NULL,
  bind_addr   VARCHAR(128) NULL,
  port        INT NULL,
  scope       VARCHAR(16)  NULL,       -- EXTERNAL | LOCAL | BOUND | -
  exe_pkg     VARCHAR(255) NULL,
  loaded_pkgs TEXT NULL,               -- 프로세스가 로드한 .so 소속 패키지(쉼표구분)
  PRIMARY KEY (id),
  KEY idx_exp_scan (scan_id),
  KEY idx_exp_scope (scope),
  KEY idx_exp_exepkg (exe_pkg),
  CONSTRAINT fk_exp_scan FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
