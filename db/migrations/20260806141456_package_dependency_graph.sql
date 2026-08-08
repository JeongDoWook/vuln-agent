-- 패키지 의존성 그래프(직접/전이) — SBOM CycloneDX dependencies 및 pom.xml 최상위 <dependencies>
--   에서 뽑은 부모→자식 엣지를 저장한다. UI/전이 표시·SPDX relationships·mvn 의존성 해석은
--   Phase 2(이번 스코프 밖). 데이터 모델은 CONTEXT.md/PR 본문 참고.
--
-- source='sbom' + parent 전부 NULL  = 그 SBOM 의 루트(최상위 프로젝트) 자신을 가리키는 표식행.
-- source='sbom' + parent 채워짐     = parent 의 (직접/전이) 의존성. parent 가 루트 자신과
--                                      일치하는 엣지가 있으면 그 child 는 직접 의존성이다.
-- source='pom'  + parent 항상 NULL  = pom.xml 최상위 <dependencies> 의 best-effort 직접 선언.
--                                      SBOM 이 있으면 매칭/그래프 조회 시 SBOM 을 우선한다(애플리케이션 로직).
--
-- ── 엣지 유일성을 9개 컬럼 복합키가 아니라 edge_hash 로 거는 이유 ─────────────────
--   원래 정의는 UNIQUE KEY (scan_id, container_id, source, parent_manager, parent_name,
--   parent_version, child_manager, child_name, child_version) 였다. utf8mb4 는 문자당
--   4바이트라 VARCHAR(255) 하나가 1,020바이트고, 합이 약 4,200바이트로 InnoDB 인덱스 상한
--   3,072바이트를 넘는다 — 운영에서 `ERROR 1071 ... max key length is 3072 bytes` 로 실패했다.
--   (dev 는 이미 옛 정의 테이블이 남아 있어 CREATE TABLE IF NOT EXISTS 가 무동작으로 지나가
--    거짓 양성이 났다. 그래서 상한 초과가 운영에서야 드러났다.)
--
--   대안 두 가지 중 **해시 생성컬럼**을 택했다.
--     · 접두 길이(예 child_name(80))는 접두가 겹치는 **서로 다른 패키지**를 같은 키로 묶어
--       정상 엣지를 중복으로 거부한다(적재가 INSERT IGNORE 라 조용히 유실된다). 채택 불가.
--     · edge_hash 는 값 전체를 보므로 의미가 원래 복합키와 같고, 인덱스는 32바이트로 끝난다.
--
--   NULL 처리: CONCAT_WS 는 NULL 인자를 **건너뛴다**. 그대로 쓰면 ('a',NULL) 과 (NULL,'a') 가
--   같은 문자열이 되고, NULL 인 parent 와 빈 문자열 parent 도 구분되지 않는다. 그래서
--   ① 모든 nullable 컬럼을 IFNULL(col,'') 로 감싸 인자에 NULL 이 오지 않게 하고,
--   ② 맨 끝에 `parent_* IS NULL` 3비트 마스크를 덧붙여 NULL 과 '' 을 구분한다.
--   → parent 가 NULL 인 행(SBOM 루트 표식·pom 직접선언)은 마스크가 '111', 값이 빈 문자열인
--     행은 '000' 이라 서로 충돌하지 않는다.
--
--   scan_id/container_id 를 해시에 넣지 않고 **키 앞에 그대로** 둔 이유: MySQL 은 스토어드
--   생성컬럼의 기반 컬럼에 걸린 FK 가 ON DELETE CASCADE 를 못 쓴다("Cannot add foreign key
--   constraint" 1215 로 실패한다 — 실측). scan_id 는 fk_pkg_dep_scan 의 CASCADE 대상이라
--   해시에 넣을 수 없다. 키를 (scan_id, container_id, edge_hash) 로 두면 8+8+32 = 48바이트로
--   상한과 무관하고, "같은 스캔·컨테이너 안에서 같은 엣지 중복 없음" 이라는 원래 의미도 그대로다.
--   덤으로 scan_id 선두라 스캔 단위 조회에도 쓸 수 있다 — 그래서 원래 있던
--   KEY idx_pkg_dep_scan (scan_id, container_id) 는 이 유니크 키의 좌측 접두와 완전히 겹쳐
--   같이 두지 않는다(중복 인덱스는 벌크 INSERT 비용만 늘린다).
--
--   구분자 '|': manager/name/version 은 적재 전에 vg_pkg_ident_valid()
--   (^[A-Za-z0-9][A-Za-z0-9._\-/:+@]*$) 로 검증되므로 '|' 가 값에 들어올 수 없다 → 필드 경계가
--   모호해지지 않는다.
--
--   부수효과: SHA2 는 바이트 기반이라 이 유일성은 **대소문자를 구분**한다(옛 복합키는
--   utf8mb4_unicode_ci 라 'Foo'/'foo' 를 같게 봤다). 더 엄격해질 뿐이라 정상 엣지가 거부되는
--   방향의 위험은 없다.
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
  edge_hash       BINARY(32) AS (UNHEX(SHA2(CONCAT_WS('|',
                    source,
                    IFNULL(parent_manager, ''), IFNULL(parent_name, ''), IFNULL(parent_version, ''),
                    child_manager, child_name, child_version,
                    CONCAT(parent_manager IS NULL, parent_name IS NULL, parent_version IS NULL)
                  ), 256))) STORED,
  PRIMARY KEY (package_dependency_id),
  UNIQUE KEY uk_pkg_dep_edge (scan_id, container_id, edge_hash),
  CONSTRAINT fk_pkg_dep_scan FOREIGN KEY (scan_id) REFERENCES tb_scan(scan_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
