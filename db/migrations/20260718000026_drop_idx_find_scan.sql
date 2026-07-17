-- tb_findings 의 중복 인덱스 idx_find_scan 제거.
--   uq_find = UNIQUE(scan_id, container_id, cve_id, package_name) 와 idx_find_scan = KEY(scan_id)
--   는 선두 컬럼이 같다(scan_id) — B-tree 는 선두 컬럼 조회를 복합 인덱스가 그대로 대신하므로
--   idx_find_scan 은 WHERE scan_id=? 조회에 전혀 쓰이지 않는 순수 중복이다.
--   (idx_find_scan 은 db/02-matcher.sql:95 의 CREATE TABLE 정의 말고 코드 어디서도 참조되지 않는다.)
--   tb_findings 는 rematch 마다 전량 DELETE+INSERT 되므로, 이 중복 인덱스는 매 재매칭마다
--   읽기 이득 없이 쓰기·유지 비용만 물린다.
--
--   빈 볼륨은 db/02-matcher.sql(initdb)에서 이 KEY 정의 자체를 뺐다.
--   멱등: information_schema 로 존재를 확인한 뒤에만 DROP 한다(MySQL 8 은 DROP INDEX IF EXISTS 미지원).
SET NAMES utf8mb4;

SET @k := (SELECT COUNT(*) FROM information_schema.STATISTICS
           WHERE TABLE_SCHEMA = DATABASE()
             AND TABLE_NAME   = 'tb_findings'
             AND INDEX_NAME   = 'idx_find_scan');
SET @s := IF(@k > 0, 'ALTER TABLE tb_findings DROP INDEX idx_find_scan', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
