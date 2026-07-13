-- tb_processes / tb_exposures 에 container_id — 컨테이너 런타임 증거를 담을 자리.
--   왜: 이 두 테이블은 여태 호스트 전용이었다. 그래서 매처가 컨테이너 패키지에는
--   "실행 중 / 로드됨 / 외부노출" 근거를 하나도 쓰지 못해 **컨테이너 취약점이 전부 LOW** 로
--   깔렸다(KEV 여도 MEDIUM). 인터넷에 노출된 컨테이너의 취약한 openssl 이 LOW 로 묻힌다는
--   뜻이라, 오탐이 아니라 과소평가 = 사실상 미탐이다.
--   호스트 신호를 컨테이너에 물려주면 반대로 오탐이 되므로(호스트 nginx 의 노출이 컨테이너
--   openssl 로 샌다), 컨테이너 것은 컨테이너 안에서 따로 모아 이 컬럼으로 구분한다.
--   container_id = 0 이면 호스트 — tb_packages 와 같은 규약.
--   멱등: information_schema 로 존재 확인 후에만 ADD COLUMN.
--   (MySQL 8.0.29+ 에서 ADD COLUMN 은 INSTANT — 큰 테이블에서도 잠기지 않는다.)
SET NAMES utf8mb4;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE()
             AND TABLE_NAME   = 'tb_processes'
             AND COLUMN_NAME  = 'container_id');
SET @s := IF(@c = 0,
             'ALTER TABLE tb_processes ADD COLUMN container_id BIGINT UNSIGNED NOT NULL DEFAULT 0 AFTER scan_id',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE()
             AND TABLE_NAME   = 'tb_exposures'
             AND COLUMN_NAME  = 'container_id');
SET @s := IF(@c = 0,
             'ALTER TABLE tb_exposures ADD COLUMN container_id BIGINT UNSIGNED NOT NULL DEFAULT 0 AFTER scan_id',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
