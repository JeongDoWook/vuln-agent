-- 패키지 레지스트리 메타데이터 — "부모 패키지의 버전 V 는 자식 C 를 어떤 제약으로 요구하는가"
--   업스트림(Packagist/npm/PyPI/Maven Central) 조회 결과를 저장한다. tb_package_dependency 는
--   *설치된 스냅샷 한 벌*이라 "부모의 어느 버전이 안전한 자식을 끌어오는가"를 알 수 없다
--   (server/src/packagedep.php 의 "버전은 제안하지 않는다" 제약과 같은 이유) — 이 표가 그
--   빈 칸을 채우는 데이터 층이다. 계산(semver 범위 해석·최소 상향 버전 산출)과 화면 반영은
--   이 작업 스코프 밖이다(feeds/pkgregistry.php 는 수집만 한다).
--
-- 자식 제약(child_constraint)은 **원문 그대로** 저장한다(`^2.1`, `~1.4`, `[1.2,2.0)`, `>=3,<4`,
--   PEP 508 marker 가 붙은 pip 원문 등). 파서를 고칠 때마다 재수집하지 않으려는 것이다.
--
-- 유일키를 (manager, parent_name, parent_version, child_name) 복합키로 걸지 않고 해시로 거는 이유는
--   tb_package_dependency 의 edge_hash 와 완전히 같다(20260806141456_package_dependency_graph.sql
--   참고) — utf8mb4 에서 VARCHAR(255) 세 개 + VARCHAR(16) 하나를 합치면 약 3,364바이트로 InnoDB
--   인덱스 상한(3,072바이트)을 넘는다. 해시는 값 전체를 보므로 의미가 복합키와 같고 32바이트로 끝난다.
--
-- idx_pkgregmeta_child 는 "이 자식을 요구하는 부모 버전들"(실제 조회 방향)을 위한 인덱스다.
--   manager 를 함께 두는 이유: 생태계가 다르면 이름이 같아도 다른 패키지다(예: npm string vs
--   composer opis/string) — server/src/distro.php 의 "섞이면 이름만 같은 엉뚱한 CVE 가 붙는다"
--   와 같은 원칙.
SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS tb_package_registry_meta (
  package_registry_meta_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  manager           VARCHAR(16)  NOT NULL,
  parent_name       VARCHAR(255) NOT NULL,
  parent_version    VARCHAR(255) NOT NULL,
  child_name        VARCHAR(255) NOT NULL,
  child_constraint  VARCHAR(500) NOT NULL,
  collected_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  edge_hash         BINARY(32) AS (UNHEX(SHA2(CONCAT_WS('|',
                      manager, parent_name, parent_version, child_name
                    ), 256))) STORED,
  PRIMARY KEY (package_registry_meta_id),
  UNIQUE KEY uk_pkgregmeta_edge (edge_hash),
  KEY idx_pkgregmeta_child (child_name, manager)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
