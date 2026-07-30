-- 기본 데이터 소스 이름을 화면에서 빠르게 읽을 수 있게 줄인다.
-- 사용자가 직접 바꾼 이름은 보존한다. 한글 기본값은 타입과 기존 길이를 함께 확인해
-- 배포 셸의 문자셋 차이에도 안전하게 식별한다.
UPDATE tb_feed_connector SET name = 'NVD'
 WHERE connector_type = 'nvd' AND name = 'NVD 2.0';
UPDATE tb_feed_connector SET name = 'KISA 공지'
 WHERE connector_type = 'kisa' AND CHAR_LENGTH(name) = 9;
UPDATE tb_feed_connector SET name = 'EPSS'
 WHERE connector_type = 'epss' AND name = 'FIRST EPSS';
UPDATE tb_feed_connector SET name = 'Debian Tracker'
 WHERE connector_type = 'debtracker' AND CHAR_LENGTH(name) = 10;
UPDATE tb_feed_connector SET name = 'RHEL OVAL'
 WHERE connector_type = 'rhoval' AND CHAR_LENGTH(name) = 19;
UPDATE tb_feed_connector SET name = 'Red Hat 미수정'
 WHERE connector_type = 'rhunfixed' AND CHAR_LENGTH(name) = 22;
UPDATE tb_feed_connector SET name = 'SCAP 기준'
 WHERE connector_type = 'ssg' AND CHAR_LENGTH(name) = 28;
UPDATE tb_feed_connector SET name = '커널 CNA'
 WHERE connector_type = 'kcve' AND CHAR_LENGTH(name) = 22;
UPDATE tb_feed_connector SET name = 'Ubuntu OVAL'
 WHERE connector_type = 'ubuntuoval' AND CHAR_LENGTH(name) = 11;
