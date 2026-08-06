-- 패키지 의존성 그래프(직접/전이) — SBOM CycloneDX dependencies 및 pom.xml 최상위 <dependencies>
--   에서 뽑은 부모→자식 엣지를 저장한다. UI/전이 표시·SPDX relationships·mvn 의존성 해석은
--   Phase 2(이번 스코프 밖). 데이터 모델은 CONTEXT.md/PR 본문 참고.
--
-- source='sbom' + parent 전부 NULL  = 그 SBOM 의 루트(최상위 프로젝트) 자신을 가리키는 표식행.
-- source='sbom' + parent 채워짐     = parent 의 (직접/전이) 의존성. parent 가 루트 자신과
--                                      일치하는 엣지가 있으면 그 child 는 직접 의존성이다.
-- source='pom'  + parent 항상 NULL  = pom.xml 최상위 <dependencies> 의 best-effort 직접 선언.
--                                      SBOM 이 있으면 매칭/그래프 조회 시 SBOM 을 우선한다(애플리케이션 로직).
SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS tb_package_dependency (
  package_dependency_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  scan_id         BIGINT UNSIGNED NOT NULL,
  container_id    BIGINT UNSIGNED NOT NULL DEFAULT 0,   -- 0 = 호스트 자신(tb_package 관례와 동일)
  source          ENUM('sbom','pom') NOT NULL,
  parent_manager  VARCHAR(16)  NULL,
  parent_name     VARCHAR(255) NULL,
  parent_version  VARCHAR(255) NULL,
  child_manager   VARCHAR(16)  NOT NULL,
  child_name      VARCHAR(255) NOT NULL,
  child_version   VARCHAR(255) NOT NULL,
  created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (package_dependency_id),
  UNIQUE KEY uk_pkg_dep_edge (scan_id, container_id, source, parent_manager, parent_name, parent_version,
                               child_manager, child_name, child_version),
  KEY idx_pkg_dep_scan (scan_id, container_id),
  CONSTRAINT fk_pkg_dep_scan FOREIGN KEY (scan_id) REFERENCES tb_scan(scan_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
