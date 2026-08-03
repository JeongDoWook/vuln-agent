-- tb_package_dependency — 패키지 의존성 그래프(부모→자식 엣지). Phase 1(백엔드)만: 스키마 +
--   SBOM dependencies 파싱 + pom.xml best-effort 직접 의존성. UI(직접/전이 표시)는 다음 단계.
--
--   데이터 원천 두 갈래(source 컬럼으로 구분, 정확도가 다르다):
--     'sbom' — CycloneDX SBOM 의 dependencies 그래프(정확한 트리, agent 의 SBOM_DIR 업로드 경로).
--     'pom'  — 대상 서버 pom.xml 의 최상위 <dependencies> 블록 스캔(best-effort, 완전한 트리
--              아님 — 부모 POM 병합·dependencyManagement·BOM import 는 계산하지 않는다. 에이전트는
--              읽기전용·경량 원칙이라 mvn 을 호출하지 않는다).
--
--   핵심 불변식(다음 Phase UI 가 이 계약에 의존):
--     - source='sbom' 이고 parent_manager/name/version 전부 NULL 인 행
--         = 이 컴포넌트가 SBOM 의 루트(최상위 프로젝트) 자신이다(트리의 뿌리).
--     - source='sbom' 이고 parent 가 채워진 행 = "child 는 parent 의 (전이 또는 직접) 의존성이다."
--         어떤 child 가 **직접 의존성**인지는 "parent 가 루트 자신인 엣지가 있는가"로 판정한다
--         (별도 플래그 없이 그래프만으로 판정 가능 — KISS).
--     - source='pom' 이고 parent 가 NULL 인 행 = "child 가 pom.xml 에 직접 선언돼 있다"는 뜻뿐이다
--         (SBOM 루트와 의미가 다르다 — source 컬럼으로 UI 문구를 구분한다: "직접 선언 확인됨
--         (pom.xml)" vs "SBOM 루트").
--     - 같은 (scan_id, container_id) 에 SBOM 과 pom.xml 데이터가 둘 다 있을 수 있다 — SBOM 이 더
--         정확하므로 UI 는 SBOM 데이터가 있으면 그쪽을 우선한다.
--     - 재스캔 시 기존 그래프는 지우고 다시 넣는다(DELETE-then-INSERT, ingest_store.php 의 다른
--         벌크 INSERT 들과 동일 패턴).
SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS tb_package_dependency (
  package_dependency_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  scan_id       BIGINT UNSIGNED NOT NULL,
  container_id  BIGINT UNSIGNED NOT NULL DEFAULT 0,  -- 0 = 호스트 자신 (tb_package 관례와 동일)
  child_manager  VARCHAR(16)  NOT NULL,
  child_name     VARCHAR(255) NOT NULL,
  child_version  VARCHAR(255) NOT NULL,
  parent_manager VARCHAR(16)  NULL,   -- NULL = 루트 자신(source=sbom) 또는 직접 선언(source=pom)
  parent_name    VARCHAR(255) NULL,
  parent_version VARCHAR(255) NULL,
  source VARCHAR(16) NOT NULL,        -- 'sbom' | 'pom'
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at DATETIME NULL,
  PRIMARY KEY (package_dependency_id),
  KEY idx_pkgdep_scan (scan_id, container_id),
  KEY idx_pkgdep_child (child_name, child_version),
  CONSTRAINT fk_pkgdep_scan FOREIGN KEY (scan_id) REFERENCES tb_scan(scan_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
