-- NVD 가 주는 CVE references(벤더 패치/공지 URL 목록)를 저장한다. tb_cves.ref_urls_json.
--
-- NVD/KEV/KISA 는 구조화된 조치버전(fixed_version)을 안 주는 CVE 가 대부분이라, 그런 경우
-- findings.php/host.php/cve.php 는 "패치 확인" 만 보여주고 사용자가 직접 검색해야 했다.
-- NVD API 응답의 references 배열(벤더 KB·자문 등 여러 URL)을 그대로 저장해 최소한 참고
-- 링크라도 보여준다. TEXT 에 JSON 배열 문자열로 저장(예: [{"url":"...","tags":["Patch"]},...]).
--
-- NULL 허용 — 기존 행은 다음 NVD 수집 때 채워진다. 멱등: information_schema 확인 후 ADD COLUMN
-- (0014 와 같은 방식).
SET NAMES utf8mb4;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE()
             AND TABLE_NAME   = 'tb_cves'
             AND COLUMN_NAME  = 'ref_urls_json');
-- AFTER 절 없음(의도적) — cwe 컬럼 존재에 결합되면, cwe 를 추가한 마이그레이션(0014)이
--   무슨 이유로든 건너뛰어진 환경에서 이 마이그레이션이 1054 로 죽고 원인이 안 보인다.
--   컬럼 위치는 기능상 의미가 없다.
SET @s := IF(@c = 0,
             'ALTER TABLE tb_cves ADD COLUMN ref_urls_json TEXT NULL',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
