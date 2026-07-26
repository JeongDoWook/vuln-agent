-- LibreTranslate 제거(20260719231714_drop_cve_summary_ko.sql)의 후속 정리다.
--   그 마이그레이션은 tb_cves.summary_ko / tb_kev_catalog.note_ko 를 DROP 하기 직전에 키+번역값만
--   *_bak 테이블 2개로 옮겨 두고, 정리를 이렇게 미뤘다:
--     "정리: *_bak 은 이번 마이그레이션이 정리하지 않는다 … 배포 후 한동안 문제 없다고 확인되면
--      배포자가 판단해 별도 마이그레이션으로 DROP TABLE 한다."
--   작성 2026-07-19 → 이후 운영에서 문제가 보고되지 않았고, 배포자가 DROP 을 승인했다.
--   이 파일이 그때 예고한 "별도 마이그레이션"이다.
-- 참조 0건 확인: 스키마의 테이블명을 전수로 server/ agent/ tests/ deploy/ 에 grep 했을 때, 읽기·쓰기
--   경로가 양쪽 다 없는 테이블은 이 두 개뿐이었다. 두 테이블을 언급하는 파일은 위 마이그레이션
--   자신(생성 구문·복원 예시 주석)밖에 없다.
-- 되돌릴 수 없다: 이 시점 이후 summary_ko / note_ko 의 번역값은 복원 경로가 없다(번역 컬럼도,
--   재번역용 translate 컨테이너도 이미 없다). 원문 tb_cves.summary / tb_kev_catalog.note 는 애초에
--   지운 적이 없으므로 이 삭제와 무관하다.
-- 멱등: DROP TABLE 에는 IF EXISTS 가 있으므로 information_schema 게이트+PREPARE 가 필요 없다
--   (20260719231714 가 동적 SQL 을 쓴 건 DROP COLUMN 에 IF EXISTS 가 없어서였다).
SET NAMES utf8mb4;

DROP TABLE IF EXISTS tb_cves_summary_ko_bak;
DROP TABLE IF EXISTS tb_kev_note_ko_bak;
