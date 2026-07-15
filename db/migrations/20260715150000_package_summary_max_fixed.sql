-- tb_package_summary.max_fixed — packages.php 가 매 로드마다 tb_cve_affected_packages 를
--   package_name IN (...) 으로 최대 12만+ 행 fetchAll 해 PHP 에서 strnatcmp 최댓값을 구하던
--   것(운영 1.3~2.6초, CVE 많은 패키지가 상위 정렬일 때 특히)을 없애기 위해 사전집계에 얹는다.
--   자연순 최댓값(vg_pkg_max_fixed)은 SQL MAX() 로 못 구해(사전순이라 '...9' > '...11') OSV
--   커넥터 실행 뒤 vg_rebuild_package_summary()(matcher.php)가 PHP 에서 계산해 채운다.
--   이 마이그레이션은 컬럼만 추가한다 — 기존 행의 초기값은 다음 OSV 실행 때 자동으로 채워진다
--   (자연순 계산이 SQL로 안 되니 여기서 백필하지 않음, PR 설명 참고).
--   멱등: information_schema 확인 후에만 추가(0020 과 동일 패턴).
SET NAMES utf8mb4;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_package_summary' AND COLUMN_NAME = 'max_fixed');
SET @s := IF(@c = 0,
             'ALTER TABLE tb_package_summary ADD COLUMN max_fixed VARCHAR(255) NULL AFTER fix_cnt',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
