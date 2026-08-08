-- tb_package_dependency 엣지 유일성 보정 — 이미 옛 정의 테이블을 가진 DB(=공용 dev)를
--   20260806141456_package_dependency_graph.sql 의 최종 형태와 **완전히 같게** 맞춘다.
--
--   왜 이 파일이 따로 필요한가:
--     · 20260803162756_package_dependency_graph.sql(PR#399)이 dev 에 옛 정의 테이블을 이미 만들었고,
--       그 파일은 2026-08-06 재작업(PR#480)에서 저장소에서 삭제됐다(커밋 59ceecf 에만 남음).
--     · 그래서 새 파일의 CREATE TABLE IF NOT EXISTS 가 dev 에서 **무동작**으로 지나가고
--       "적용됨"으로 기록됐다 — 유니크 키 3,072바이트 초과(ERROR 1071)가 운영에서야 드러난 이유다.
--     · 새 파일을 고쳐도 dev 는 이미 적용 기록이 있어 다시 실행되지 않는다. 즉 운영은 새 파일로
--       처음 생성되고, dev 는 이 보정 파일로 같은 형태에 도달한다.
--
--   방식: 컬럼 순서·인덱스명·제약명까지 두 DB 의 SHOW CREATE TABLE 이 **문자 단위로 같아야** 하므로
--   ALTER 를 누적하지 않고 최종 정의로 새 테이블을 만들어 데이터를 옮기고 RENAME 한다.
--   (옛 정의는 컬럼 순서가 다르고 idx_pkgdep_child·updated_at·is_deleted·deleted_at 처럼 새 정의에
--    없는 것들이 있다. ALTER 로 맞추면 순서·이름을 하나씩 되돌려야 해서 오히려 어긋나기 쉽다.)
--
--   멱등성: edge_hash 컬럼이 이미 있으면(=최종 형태) 전부 무동작이다. 빈 DB 에서는 앞선 파일이
--   최종 정의로 만들어 두므로 역시 무동작이다.
--
--   데이터: 기존 행은 전부 옮긴다(소프트삭제 컬럼은 적재 코드가 쓴 적이 없다 — 재스캔은
--   DELETE-then-INSERT 다). source 는 적재 코드가 'sbom'|'pom' 리터럴로만 넣으므로
--   ENUM 변환에서 잘리는 값이 없다(server/src/ingest_store.php). 옛 테이블엔 유니크 키가 아예
--   없었으므로 중복 엣지가 있을 수 있어 INSERT IGNORE 로 접는다.
SET NAMES utf8mb4;

SET @need := (
  SELECT IF(
    (SELECT COUNT(*) FROM information_schema.TABLES
      WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_package_dependency') = 1
    AND
    (SELECT COUNT(*) FROM information_schema.COLUMNS
      WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_package_dependency'
        AND COLUMN_NAME = 'edge_hash') = 0,
    1, 0)
);

-- 중단된 이전 실행이 남긴 작업 테이블이 있으면 치운다(이름이 이 파일 전용이라 안전).
DROP TABLE IF EXISTS tb_package_dependency_new;

-- 1) 최종 정의로 작업 테이블 생성 — 20260806141456 파일의 CREATE 문과 동일해야 한다.
SET @s := IF(@need = 1, '
CREATE TABLE tb_package_dependency_new (
  package_dependency_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  scan_id         BIGINT UNSIGNED NOT NULL,
  container_id    BIGINT UNSIGNED NOT NULL DEFAULT 0,
  source          ENUM(''sbom'',''pom'') NOT NULL,
  parent_manager  VARCHAR(16)  NULL,
  parent_name     VARCHAR(255) NULL,
  parent_version  VARCHAR(255) NULL,
  child_manager   VARCHAR(16)  NOT NULL,
  child_name      VARCHAR(255) NOT NULL,
  child_version   VARCHAR(255) NOT NULL,
  created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  edge_hash       BINARY(32) AS (UNHEX(SHA2(CONCAT_WS(''|'',
                    source,
                    IFNULL(parent_manager, ''''), IFNULL(parent_name, ''''), IFNULL(parent_version, ''''),
                    child_manager, child_name, child_version,
                    CONCAT(parent_manager IS NULL, parent_name IS NULL, parent_version IS NULL)
                  ), 256))) STORED,
  PRIMARY KEY (package_dependency_id),
  UNIQUE KEY uk_pkg_dep_edge (scan_id, container_id, edge_hash),
  CONSTRAINT fk_pkg_dep_scan FOREIGN KEY (scan_id) REFERENCES tb_scan(scan_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- 2) 데이터 이관(생성컬럼 edge_hash 는 제외 — 자동 계산된다).
SET @s := IF(@need = 1, '
INSERT IGNORE INTO tb_package_dependency_new
    (package_dependency_id, scan_id, container_id, source,
     parent_manager, parent_name, parent_version,
     child_manager, child_name, child_version, created_at)
SELECT package_dependency_id, scan_id, container_id, source,
       parent_manager, parent_name, parent_version,
       child_manager, child_name, child_version, created_at
  FROM tb_package_dependency
 WHERE source IN (''sbom'',''pom'')', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- 3) 교체.
SET @s := IF(@need = 1, 'DROP TABLE tb_package_dependency', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @s := IF(@need = 1, 'RENAME TABLE tb_package_dependency_new TO tb_package_dependency', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
