-- tb_packages.source_version — deb 소스패키지의 버전.
--   왜: OSV 의 deb 조치안(fixed_version)은 **소스 버전** 기준이다. 바이너리 버전과 다를 수 있어
--   (binNMU: 1.2.3-4+b1), 소스패키지로 매칭된 CVE 는 소스 버전으로 비교해야 정확하다.
--   에이전트는 이미 보내고 있었는데 ingest 가 버리던 값이다.
--   멱등: information_schema 로 존재 확인 후에만 ADD COLUMN.
SET NAMES utf8mb4;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE()
             AND TABLE_NAME   = 'tb_packages'
             AND COLUMN_NAME  = 'source_version');
SET @s := IF(@c = 0,
             'ALTER TABLE tb_packages ADD COLUMN source_version VARCHAR(255) NULL AFTER source_pkg',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
