-- vuln-agent 매처(2단계) 스키마 : CVE / KEV / 영향패키지 / 판정결과
-- 최초 기동 시 01-schema.sql 다음에 자동 적용된다(파일명 순).
-- 모든 테이블은 tb_ 접두사 + 감사 4컬럼(created_at/updated_at/is_deleted/deleted_at) 통일.
SET NAMES utf8mb4;

-- ── CVE 기본 정보 (NVD/OSV 미러에서 채움. 지금은 시드) ──────────────────
CREATE TABLE IF NOT EXISTS tb_cves (
  cve_id    VARCHAR(32) NOT NULL,
  summary   MEDIUMTEXT NULL,
  cvss      DECIMAL(3,1) NULL,       -- CVSS v3 기본점수
  published DATE NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at DATETIME NULL,
  PRIMARY KEY (cve_id),
  INDEX idx_cves_is_deleted (is_deleted),
  -- cves.php 요약 검색(q)용. 와일드카드 선두 LIKE 는 인덱스를 못 타 풀스캔이었다.
  -- 기존 볼륨은 db/migrations/20260719105602_cves_summary_fulltext.sql.
  FULLTEXT KEY ft_cves_summary (summary)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ── CISA KEV (실제 악용된 취약점 목록) — 우선순위 가중의 핵심 ───────────
CREATE TABLE IF NOT EXISTS tb_kev_catalog (
  cve_id     VARCHAR(32) NOT NULL,
  date_added DATE NULL,
  note       TEXT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at DATETIME NULL,
  PRIMARY KEY (cve_id),
  INDEX idx_kev_catalog_is_deleted (is_deleted)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ── CVE ↔ 영향 패키지 (package_name 은 pkg.name 또는 source_pkg 와 대조) ──
CREATE TABLE IF NOT EXISTS tb_cve_affected_packages (
  id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  cve_id        VARCHAR(32) NOT NULL,
  ecosystem     VARCHAR(32) NOT NULL DEFAULT '',  -- rpm | deb | generic (자연키의 일부)
  package_name  VARCHAR(255) NOT NULL,
  fixed_version VARCHAR(128) NULL,    -- 이 버전 이상이면 패치됨(참고용)
  created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted    TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at    DATETIME NULL,
  PRIMARY KEY (id),
  -- 자연키. 같은 패키지라도 배포판(ecosystem)마다 조치버전이 달라 ecosystem 을 키에 포함한다.
  UNIQUE KEY uq_cap (cve_id, package_name, ecosystem),
  KEY idx_cap_pkg (package_name),
  KEY idx_cap_cve (cve_id),
  INDEX idx_cve_affected_packages_is_deleted (is_deleted),
  -- packages.php 의 (package_name,ecosystem) GROUP BY 집계 지원. is_deleted 로 필터를
  -- 인덱스로 만족하고, 그룹·집계 컬럼(cve_id,fixed_version)까지 담아 커버링 스캔이 되게 한다
  -- (92만 행에서 임시테이블+filesort 로 20초 걸리던 걸 없앤다). 마이그레이션도 같은 인덱스.
  KEY idx_cap_group (is_deleted, package_name, ecosystem, cve_id, fixed_version)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ── packages.php 전용 사전집계 요약 (package×ecosystem 1행) ──────────────
--   원본 tb_cve_affected_packages 는 92만 행이라 매 로드 재집계가 ~8초였다. OSV 실행 때만
--   바뀌므로 그때 vg_rebuild_package_summary()(matcher.php)가 통째로 다시 만든다. 화면은
--   이 40K행만 읽는다(8초→0.3초). 기존 볼륨은 db/migrations/..._package_summary.sql.
CREATE TABLE IF NOT EXISTS tb_package_summary (
  package_name VARCHAR(255) NOT NULL,
  ecosystem    VARCHAR(32)  NOT NULL DEFAULT '',
  cve_cnt      INT UNSIGNED NOT NULL DEFAULT 0,
  max_epss     DOUBLE       NULL,
  fix_cnt      INT UNSIGNED NOT NULL DEFAULT 0,
  max_fixed    VARCHAR(255) NULL,                 -- 조치 버전 최댓값(자연순, vg_pkg_max_fixed)
  updated_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (package_name, ecosystem),
  KEY idx_psum_cve  (cve_cnt),
  KEY idx_psum_epss (max_epss),
  -- 목록 정렬 `ORDER BY <cve_cnt|max_epss> DESC, package_name ASC LIMIT 50` 전용.
  -- 정렬 방향이 섞여 있어 **내림차순 복합**(MySQL 8.0)이어야 하고, 표시 컬럼까지 담아
  -- 커버링으로 만들어야 저선택도 필터(배포판·검색어)에서 행 조회로 역전되지 않는다.
  -- 기존 볼륨은 db/migrations/20260812221820_package_summary_sort_index.sql.
  KEY idx_psum_cve_name  (cve_cnt DESC, package_name ASC, ecosystem, max_epss, fix_cnt, max_fixed),
  KEY idx_psum_epss_name (max_epss DESC, package_name ASC, ecosystem, cve_cnt, fix_cnt, max_fixed)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ── 매처 판정 결과 : 스캔×CVE×패키지 1행. 노출/로드/KEV/등급/근거 ──────
CREATE TABLE IF NOT EXISTS tb_findings (
  id                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  scan_id           BIGINT UNSIGNED NOT NULL,
  -- 이 판정이 어느 컨테이너 것인지. **0 = 호스트 자신**(18-containers.sql 주석 참조).
  --   기존 볼륨은 db/migrations/0014_containers.sql 이 같은 위치(AFTER scan_id)에 추가한다.
  container_id      BIGINT UNSIGNED NOT NULL DEFAULT 0,
  cve_id            VARCHAR(32) NOT NULL,
  package_name      VARCHAR(255) NOT NULL,
  installed_version VARCHAR(255) NULL,
  loaded            TINYINT(1) NOT NULL DEFAULT 0,  -- 프로세스가 로드했나
  exposed           TINYINT(1) NOT NULL DEFAULT 0,  -- 로드 + 외부노출(EXTERNAL)
  exposure_scope    VARCHAR(16) NULL,               -- 가장 위험한 노출 범위
  in_kev            TINYINT(1) NOT NULL DEFAULT 0,
  needs_restart     TINYINT(1) NOT NULL DEFAULT 0,   -- 패치됐지만 프로세스가 옛 .so 사용 중(재시작 필요)
  cvss              DECIMAL(3,1) NULL,
  severity          VARCHAR(12) NOT NULL,           -- CRITICAL|HIGH|MEDIUM|LOW
  rationale         VARCHAR(512) NULL,              -- 왜 이 등급인지(설명가능성)
  created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted        TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at        DATETIME NULL,
  PRIMARY KEY (id),
  -- container_id 를 유니크 키에 포함한다. 빼면 호스트의 openssl 과 컨테이너의 openssl 이
  -- 같은 CVE 로 충돌해 서로 덮어쓴다(18-containers.sql / 0014_containers.sql 주석 참조).
  UNIQUE KEY uq_find (scan_id, container_id, cve_id, package_name),
  KEY idx_find_sev (severity),
  KEY idx_find_cve (cve_id),
  INDEX idx_findings_is_deleted (is_deleted),
  CONSTRAINT fk_find_scan FOREIGN KEY (scan_id) REFERENCES tb_scans(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
