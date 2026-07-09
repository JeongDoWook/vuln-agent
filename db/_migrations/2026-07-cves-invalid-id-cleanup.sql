-- vuln-agent : 잘못된 형식의 CVE-ID 정리
-- ─────────────────────────────────────────────────────────────────────────
-- 공지 본문/제목에서 CVE 를 뽑는 정규식이 KISA 원문의 오탈자를 그대로 삼켰다.
--   CVE-0215-8451   연도가 0215
--   CVE-2016-03246  일련번호 5자리인데 선행 0 (4자리면 CVE-2014-0160 처럼 정상)
-- 코드 쪽은 vg_is_cve_id() 가 막는다(feeds.php). 이 파일은 이미 들어간 행을 1회 정리한다.
--
-- 판단 기준: 형식이 잘못되었고 + 메타데이터가 전무한 행만 지운다.
--   형식은 잘못됐는데 요약/점수가 있다면 사람이 확인할 여지가 있으므로 남긴다.
--   형식이 맞는데 NVD 에 없는 행(철회·미공개 CVE)도 남긴다.
--
-- 적용(dev):
--   docker compose -p vulnagent-dev exec -T db sh -c \
--     'mysql -uroot -p$(cat /run/secrets/mysql_root_password) vulnagent' \
--     < db/_migrations/2026-07-cves-invalid-id-cleanup.sql
-- 적용(프로덕션): -p vulnagent 로 동일 실행. 멱등(다시 돌려도 안전).
-- ─────────────────────────────────────────────────────────────────────────
SET NAMES utf8mb4;

-- 1) tb_advisories.cve_ids 문자열에서도 잘못된 ID 를 걷어낸다.
--    쉼표 목록이라 REGEXP 로 항목 단위 제거가 어려우므로, 잘못된 ID 를 가진 행만
--    표시해 둔다(코드가 다음 수집 때 vg_extract_cve_ids 로 재작성한다).
SELECT CONCAT('cve_ids 에 잘못된 ID 를 가진 공지: ', COUNT(*)) AS note
  FROM tb_advisories
 WHERE cve_ids REGEXP 'CVE-[0-9]{4}-[0-9]{4,}'
   AND cve_ids NOT REGEXP '^(CVE-(19|20)[0-9]{2}-([0-9]{4}|[1-9][0-9]{4,6}))(,CVE-(19|20)[0-9]{2}-([0-9]{4}|[1-9][0-9]{4,6}))*$';

-- 2) 삭제 대상 확인
SELECT CONCAT('삭제 대상 tb_cves: ', COUNT(*)) AS note
  FROM tb_cves
 WHERE cve_id NOT REGEXP '^CVE-(19|20)[0-9]{2}-([0-9]{4}|[1-9][0-9]{4,6})$'
   AND cvss IS NULL
   AND (summary IS NULL OR summary = '')
   AND published IS NULL;

-- 3) 삭제
DELETE FROM tb_cves
 WHERE cve_id NOT REGEXP '^CVE-(19|20)[0-9]{2}-([0-9]{4}|[1-9][0-9]{4,6})$'
   AND cvss IS NULL
   AND (summary IS NULL OR summary = '')
   AND published IS NULL;
