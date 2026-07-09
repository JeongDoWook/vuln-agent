-- vuln-agent : CVE 목록 페이지(cves.php)용 정렬/필터 인덱스
-- ─────────────────────────────────────────────────────────────────────────
-- tb_cves 는 PK(cve_id)와 is_deleted 인덱스뿐이었다. 목록은 is_deleted=0 으로
-- 거르고 published/cvss/epss 로 정렬하므로, 그대로 두면 전체 정렬(filesort)이 된다.
-- 지금은 3,598행이라 체감이 없지만 NVD 전체 백필(20만+)을 하면 바로 문제가 된다.
--
-- is_deleted 를 선두에 둔 복합 인덱스여야 "필터 후 정렬"이 인덱스만으로 끝난다.
--
-- 적용(dev):
--   docker compose -p vulnagent-dev exec -T db sh -c \
--     'mysql -uroot -p$(cat /run/secrets/mysql_root_password) vulnagent' \
--     < db/_migrations/2026-07-cves-list-index.sql
-- 적용(프로덕션): -p vulnagent 로 동일 실행.
-- ─────────────────────────────────────────────────────────────────────────
SET NAMES utf8mb4;

ALTER TABLE tb_cves
  ADD INDEX idx_cves_pub  (is_deleted, published),
  ADD INDEX idx_cves_cvss (is_deleted, cvss),
  ADD INDEX idx_cves_epss (is_deleted, epss);
