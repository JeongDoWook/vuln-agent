-- vuln-agent : tb_advisories.url 정규화 마이그레이션
-- ─────────────────────────────────────────────────────────────────────────
-- 보호나라 공지 URL 은 유입 경로마다 쿼리스트링이 달라진다.
--   RSS   : view.do?searchCnd=&bbsId=B0000133&searchWrd=&menuNo=205020&pageIndex=1&categoryCode=&nttId=72127
--   목록 N쪽: view.do?...&pageIndex=5&...&nttId=72127     ← 같은 공지, 다른 url
-- pageIndex 가 섞이면 uq_adv_url dedup 이 깨져 백필 시 같은 공지가 중복 삽입된다.
-- 실제 식별자는 nttId 뿐이므로 bbsId/menuNo/nttId 만 남긴 형태로 통일한다.
-- 코드 쪽 정규화는 feeds.php 의 vg_kisa_canon_url() 가 담당(신규 수집분).
-- 이 파일은 그 이전에 저장된 기존 행을 1회 보정한다.
--
-- 적용(dev):
--   docker compose -p vulnagent-dev exec -T db sh -c \
--     'mysql -uroot -p$(cat /run/secrets/mysql_root_password) vulnagent' \
--     < db/_migrations/2026-07-advisories-canon-url.sql
-- 적용(프로덕션): -p vulnagent 로 동일 실행.
-- ─────────────────────────────────────────────────────────────────────────
SET NAMES utf8mb4;

-- 1) 정규화 후 서로 충돌하는 행 제거(같은 nttId 가 다른 pageIndex 로 이미 중복 저장된 경우).
--    보존 기준: id 가 가장 작은 행(최초 수집분). uq_adv_url 위반을 사전에 없앤다.
DELETE a FROM tb_advisories a
JOIN tb_advisories b
  ON b.id < a.id
 AND REGEXP_SUBSTR(a.url, '(?<=nttId=)[0-9]+') = REGEXP_SUBSTR(b.url, '(?<=nttId=)[0-9]+')
 AND REGEXP_SUBSTR(a.url, '(?<=bbsId=)[A-Za-z0-9]+') = REGEXP_SUBSTR(b.url, '(?<=bbsId=)[A-Za-z0-9]+')
WHERE a.url LIKE '%boho.or.kr%' AND a.url LIKE '%nttId=%';

-- 2) 남은 행의 url 을 정규 형태로 재작성.
UPDATE tb_advisories
SET url = CONCAT(
      'https://www.boho.or.kr/kr/bbs/view.do?bbsId=', REGEXP_SUBSTR(url, '(?<=bbsId=)[A-Za-z0-9]+'),
      '&menuNo=', REGEXP_SUBSTR(url, '(?<=menuNo=)[0-9]+'),
      '&nttId=',  REGEXP_SUBSTR(url, '(?<=nttId=)[0-9]+')
    )
WHERE url LIKE '%boho.or.kr%'
  AND url LIKE '%nttId=%'
  AND REGEXP_SUBSTR(url, '(?<=bbsId=)[A-Za-z0-9]+') IS NOT NULL
  AND REGEXP_SUBSTR(url, '(?<=menuNo=)[0-9]+') IS NOT NULL;
