-- CVE 상세에 쓸 필드 — 이미 받아오던 피드에 들어있는데 버리고 있던 것들.
--
--   tb_kev_catalog.due_date   : CISA KEV 의 dueDate. 연방기관 패치 기한이다. "언제까지"가
--                               있는 유일한 신호라 우선순위 판단에 CVSS 보다 실용적이다.
--   tb_kev_catalog.ransomware : knownRansomwareCampaignUse. 랜섬웨어에 실제로 쓰인 취약점인지.
--   tb_cves.cvss_vector       : CVSS 벡터 문자열(AV:N/AC:L/...). 점수 하나로는 "원격인지
--                               로컬인지, 인증이 필요한지" 를 알 수 없다. 벡터가 그걸 말한다.
--   tb_cves.cwe               : 취약점 유형(CWE-787 등).
--
-- 넷 다 NULL 허용 — 기존 행은 커넥터가 다음에 돌 때 채워진다. UI 는 NULL 을 감당해야 한다.
-- 멱등: information_schema 로 존재 확인 후에만 ADD COLUMN (0009 와 같은 방식).
SET NAMES utf8mb4;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE()
             AND TABLE_NAME   = 'tb_kev_catalog'
             AND COLUMN_NAME  = 'due_date');
SET @s := IF(@c = 0,
             'ALTER TABLE tb_kev_catalog ADD COLUMN due_date DATE NULL AFTER date_added',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE()
             AND TABLE_NAME   = 'tb_kev_catalog'
             AND COLUMN_NAME  = 'ransomware');
SET @s := IF(@c = 0,
             'ALTER TABLE tb_kev_catalog ADD COLUMN ransomware TINYINT(1) NOT NULL DEFAULT 0 AFTER due_date',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE()
             AND TABLE_NAME   = 'tb_cves'
             AND COLUMN_NAME  = 'cvss_vector');
SET @s := IF(@c = 0,
             'ALTER TABLE tb_cves ADD COLUMN cvss_vector VARCHAR(128) NULL AFTER cvss',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE()
             AND TABLE_NAME   = 'tb_cves'
             AND COLUMN_NAME  = 'cwe');
SET @s := IF(@c = 0,
             'ALTER TABLE tb_cves ADD COLUMN cwe VARCHAR(64) NULL AFTER cvss_vector',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
