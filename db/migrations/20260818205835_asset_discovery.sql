-- 자산 탐색(섀도우 IT) — 취약점 스캔과 **별개 파이프라인**의 스키마.
--
--   에이전트를 설치한 서버만 알고 있으면 담당자가 빠뜨린 자산을 구조적으로 못 찾는다.
--   그래서 대역을 훑어 살아있는 IP·열린 포트를 모으는 탐색 파이프라인을 따로 둔다
--   (Nexpose·Nessus 의 Discovery Scan / Vulnerability Scan 분리와 같은 구도).
--   두 파이프라인의 접점은 **IP 대조 한 곳**뿐이다 — tb_discovered_asset.host_id.
--
--   ★ 닫힌 포트는 저장하지 않는다. /24 × 100포트면 run 마다 25,400행이라 금방 수백만 행이 된다.
--     "몇 개를 실제로 시도했는가"는 집계값(tb_discovery_run.port_checked)으로 충분하다.
--
--   ★ 자산 탐색 관련 DDL 은 전부 이 파일 하나에만 넣는다. 공용 dev DB 를 여러 워크트리가
--     함께 쓰는데, 과거에 워커 둘이 같은 테이블을 각자 만들어 스키마가 갈라진 사고가 있었다
--     (2564719f — executed_at/is_deleted/deleted_at 누락).
--
--   PK·FK 타입은 tb_host.host_id(BIGINT UNSIGNED)에 맞춘다. created_by 는 tb_user 를 가리키지만
--   FK 를 걸지 않는다(이 저장소 감사 관련 테이블 관례 — 사용자를 지워도 이력은 남는다).
SET NAMES utf8mb4;

-- ── 스캔할 대역 : 관리자가 등록 ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tb_discovery_target (
  discovery_target_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  cidr                VARCHAR(64)   NOT NULL COMMENT '예: 10.3.142.0/24',
  ports               VARCHAR(1024) NULL     COMMENT '2단계 포트 목록(콤마·범위). NULL=기본 세트',
  label               VARCHAR(255)  NULL,
  enabled             TINYINT(1) NOT NULL DEFAULT 1,
  created_by          BIGINT UNSIGNED NULL   COMMENT 'tb_user.user_id (FK 없음)',
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at DATETIME NULL,
  PRIMARY KEY (discovery_target_id),
  UNIQUE KEY uq_discovery_target_cidr (cidr)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ── 스캔 1회 ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tb_discovery_run (
  discovery_run_id    BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  discovery_target_id BIGINT UNSIGNED NOT NULL,
  status              ENUM('pending','running','done','failed') NOT NULL DEFAULT 'pending',
  started_at          DATETIME NULL,
  finished_at         DATETIME NULL,
  ip_total            INT NOT NULL DEFAULT 0 COMMENT '대역의 IP 수',
  ip_alive            INT NOT NULL DEFAULT 0 COMMENT '1단계에서 살아있다고 판정된 수',
  port_checked        INT NOT NULL DEFAULT 0 COMMENT '실제 시도한 (IP,포트) 조합 수 — 성능 근거',
  open_total          INT NOT NULL DEFAULT 0,
  elapsed_seconds     DECIMAL(8,2) NULL,
  error_text          TEXT NULL,
  created_by          BIGINT UNSIGNED NULL COMMENT 'tb_user.user_id (FK 없음)',
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at DATETIME NULL,
  PRIMARY KEY (discovery_run_id),
  KEY idx_discovery_run_target_time (discovery_target_id, started_at),
  KEY idx_discovery_run_status (status) COMMENT '--pending 집행이 이 인덱스를 탄다',
  CONSTRAINT fk_discovery_run_target FOREIGN KEY (discovery_target_id)
    REFERENCES tb_discovery_target(discovery_target_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ── 발견된 IP : 대역 기준 **누적**(run 마다 갈아엎지 않는다) ────────────
--   state: known=tb_host 와 IP 매칭됨 · new=섀도우 IT 후보 · ignored=사람이 제외
CREATE TABLE IF NOT EXISTS tb_discovered_asset (
  discovered_asset_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  discovery_target_id BIGINT UNSIGNED NOT NULL,
  ip                  VARCHAR(45) NOT NULL,
  first_seen          DATETIME NOT NULL,
  last_seen           DATETIME NOT NULL,
  last_run_id         BIGINT UNSIGNED NULL,
  host_id             BIGINT UNSIGNED NULL COMMENT '매칭된 기존 자산(없으면 NULL=섀도우 IT 후보)',
  state               ENUM('new','known','ignored') NOT NULL DEFAULT 'new',
  note                VARCHAR(500) NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at DATETIME NULL,
  PRIMARY KEY (discovered_asset_id),
  UNIQUE KEY uq_discovered_asset (discovery_target_id, ip),
  KEY idx_discovered_asset_host (host_id),
  KEY idx_discovered_asset_state (discovery_target_id, state),
  CONSTRAINT fk_discovered_asset_target FOREIGN KEY (discovery_target_id)
    REFERENCES tb_discovery_target(discovery_target_id),
  CONSTRAINT fk_discovered_asset_host FOREIGN KEY (host_id)
    REFERENCES tb_host(host_id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ── 열린 포트 : **open 만** 저장 ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tb_discovered_port (
  discovered_port_id  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  discovered_asset_id BIGINT UNSIGNED NOT NULL,
  discovery_run_id    BIGINT UNSIGNED NOT NULL,
  port                INT NOT NULL,
  proto               VARCHAR(8) NOT NULL DEFAULT 'tcp',
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at DATETIME NULL,
  PRIMARY KEY (discovered_port_id),
  UNIQUE KEY uq_discovered_port (discovered_asset_id, discovery_run_id, port, proto),
  KEY idx_discovered_port_run (discovery_run_id),
  CONSTRAINT fk_discovered_port_asset FOREIGN KEY (discovered_asset_id)
    REFERENCES tb_discovered_asset(discovered_asset_id) ON DELETE CASCADE,
  CONSTRAINT fk_discovered_port_run FOREIGN KEY (discovery_run_id)
    REFERENCES tb_discovery_run(discovery_run_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ── 기존 자산의 IP ──────────────────────────────────────────────────────
--   지금 tb_host 에는 IP 컬럼이 아예 없고 fqdn 으로만 식별한다. 에이전트가 IP 를 수집하긴
--   하지만 tb_scan.raw_json 안에만 있고 어떤 테이블로도 파싱되지 않는다. IP 대조가 안 되면
--   "발견한 IP 가 이미 아는 자산인가"를 판단할 수 없어 탐색 기능 전체가 성립하지 않는다.
CREATE TABLE IF NOT EXISTS tb_host_address (
  host_address_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  host_id         BIGINT UNSIGNED NOT NULL,
  ip              VARCHAR(45) NOT NULL,
  iface           VARCHAR(64) NULL,
  first_seen      DATETIME NOT NULL,
  last_seen       DATETIME NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at DATETIME NULL,
  PRIMARY KEY (host_address_id),
  UNIQUE KEY uq_host_address (host_id, ip),
  KEY idx_host_address_ip (ip),
  CONSTRAINT fk_host_address_host FOREIGN KEY (host_id)
    REFERENCES tb_host(host_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
