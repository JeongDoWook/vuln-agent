-- vuln-agent 중앙 DB 스키마 (MySQL 8)
-- 컨테이너 최초 기동 시 /docker-entrypoint-initdb.d 로 자동 적용됨.
-- 데이터 흐름: 에이전트 JSON  ──POST──▶ ingest.php ──▶ 아래 테이블
-- 모든 테이블은 tb_ 접두사 + 감사 4컬럼(created_at/updated_at/is_deleted/deleted_at) 통일.
SET NAMES utf8mb4;

-- ── 호스트(서버) : fqdn 으로 식별, 스캔마다 last_seen 갱신 ──────────────
CREATE TABLE IF NOT EXISTS tb_hosts (
  id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  fqdn       VARCHAR(255) NOT NULL,
  hostname   VARCHAR(255) NULL,
  os_id      VARCHAR(64)  NULL,
  os_version VARCHAR(64)  NULL,
  first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at DATETIME NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_hosts_fqdn (fqdn),
  INDEX idx_hosts_is_deleted (is_deleted)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ── 스캔 이력 : 수집 1회 = 1행. 원본 JSON 도 보관(2단계 매처가 재활용) ──
CREATE TABLE IF NOT EXISTS tb_scans (
  id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  host_id         BIGINT UNSIGNED NOT NULL,
  collected_at    DATETIME NULL,
  agent_version   VARCHAR(32)  NULL,
  elapsed_seconds INT NULL,
  peak_rss_mb     DECIMAL(8,1) NULL,   -- 자기계측: 실행당 피크 메모리(트리 전체)
  cpu_seconds     DECIMAL(8,2) NULL,   -- 자기계측: 실행당 CPU 시간(자식 포함)
  os_id           VARCHAR(64)  NULL,
  os_version      VARCHAR(64)  NULL,
  kernel          VARCHAR(255) NULL,
  cpe             VARCHAR(255) NULL,
  package_family  VARCHAR(16)  NULL,   -- rpm | deb
  package_count   INT NULL,
  exposure_count  INT NULL,
  raw_json        JSON NULL,           -- 수신 원본(재처리/감사용)
  received_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted      TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at      DATETIME NULL,
  PRIMARY KEY (id),
  KEY idx_scans_host_time (host_id, collected_at),
  KEY idx_scans_received (received_at),
  INDEX idx_scans_is_deleted (is_deleted),
  CONSTRAINT fk_scans_host FOREIGN KEY (host_id) REFERENCES tb_hosts(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ── 패키지 목록 : 취약점 매핑의 핵심. 릴리스포함 버전 + 소스패키지 보존 ──
CREATE TABLE IF NOT EXISTS tb_packages (
  id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  scan_id    BIGINT UNSIGNED NOT NULL,
  -- 이 패키지가 어느 컨테이너 것인지. **0 = 호스트 자신**(18-containers.sql 주석 참조).
  --   기존 볼륨은 db/migrations/0014_containers.sql 이 같은 위치(AFTER scan_id)에 추가한다.
  container_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
  manager    VARCHAR(16)  NULL,        -- rpm | dpkg
  name       VARCHAR(255) NOT NULL,
  version    VARCHAR(255) NULL,        -- 전체 EVR / dpkg 버전 (릴리스번호 포함)
  arch       VARCHAR(32)  NULL,
  source_pkg VARCHAR(255) NULL,        -- 소스패키지 (백포트 인식 → 오탐 감소)
  source_version VARCHAR(255) NULL,    -- deb 소스 버전 (OSV 의 deb 조치안이 소스 기준이라 비교에 필요)
  origin     VARCHAR(128) NULL,        -- 출처 라벨(Debian/Ubuntu/Docker/LP-PPA-…/LOCAL). 서드파티 식별용
  vendor     VARCHAR(255) NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at DATETIME NULL,
  PRIMARY KEY (id),
  KEY idx_pkg_scan (scan_id),
  KEY idx_pkg_name (name),
  KEY idx_pkg_source (source_pkg),
  INDEX idx_packages_is_deleted (is_deleted),
  CONSTRAINT fk_pkg_scan FOREIGN KEY (scan_id) REFERENCES tb_scans(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ── 런타임 노출 상관 (차별점 ①) : 소켓마다 1행 ───────────────────────
--   pid|proc|proto|bind|port|scope|exe_pkg|loaded_pkgs
CREATE TABLE IF NOT EXISTS tb_exposures (
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
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted  TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at  DATETIME NULL,
  PRIMARY KEY (id),
  KEY idx_exp_scan (scan_id),
  KEY idx_exp_scope (scope),
  KEY idx_exp_exepkg (exe_pkg),
  INDEX idx_exposures_is_deleted (is_deleted),
  CONSTRAINT fk_exp_scan FOREIGN KEY (scan_id) REFERENCES tb_scans(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
