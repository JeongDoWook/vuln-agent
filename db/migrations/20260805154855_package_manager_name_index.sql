-- language-packages.php 가 tb_package 를 manager+name 으로 직접 필터하는데(사전집계는 KPI 전용,
--   목록 검색·필터는 원본을 스캔한다) 이 조합 인덱스가 없었다. packages.php 40초 사고와 같은
--   무인덱스 재집계 클래스라 재발을 막는다. 멱등: information_schema 가드로 두 번 돌아도 안전하다.
SET NAMES utf8mb4;

SET @c := (SELECT COUNT(*) FROM information_schema.STATISTICS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_package' AND INDEX_NAME = 'idx_package_manager_name');
SET @s := IF(@c = 0, 'CREATE INDEX idx_package_manager_name ON tb_package (manager, name)', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
