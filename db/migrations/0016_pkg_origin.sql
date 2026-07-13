-- tb_packages.origin — 패키지 출처 라벨.
--   dpkg: apt 의 Origin 라벨(Debian / Ubuntu / Docker / LP-PPA-… / LOCAL / UNKNOWN)
--   rpm : VENDOR 문자열(에이전트가 이미 보내고 있다)
--   왜 필요한가: 서드파티 저장소(PPA·Docker·NodeSource) 패키지를 배포판 기준으로 판정하면
--   안 된다. 특히 debsecan/errata 억제는 "배포판 트래커에 없으면 이미 수정됨"으로 보는데,
--   서드파티 패키지는 애초에 트래커에 없다 → 진짜 취약점을 숨기는 미탐이 된다.
--   멱등: information_schema 확인 후에만 ADD COLUMN.
SET NAMES utf8mb4;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_packages' AND COLUMN_NAME = 'origin');
SET @s := IF(@c = 0,
             'ALTER TABLE tb_packages ADD COLUMN origin VARCHAR(128) NULL AFTER vendor',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
