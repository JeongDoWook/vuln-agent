-- vuln-agent : tb_advisories.cve_ids 를 VARCHAR(512) → TEXT 로 확장
-- ─────────────────────────────────────────────────────────────────────────
-- 코드가 implode(',', $merged) 결과를 mb_substr(...,500) 으로 잘라 저장했다.
-- 그 결과 두 가지 손상이 생겼다(운영 실측 2026-07-09):
--   1) 마지막 CVE 가 한가운데서 잘려 "CVE-2", "CV" 같은 조각이 남았다 — 114건.
--      상세 페이지의 CVE 링크가 존재하지 않는 CVE 로 연결된다.
--   2) 마이크로소프트 패치데이 공지처럼 CVE 가 많은 경우 대부분이 버려졌다.
--      본문에 263개가 등장하는 공지도 36개만 저장돼 있었다.
--
-- 512바이트로는 CVE 36개가 한계다(1개 = 최대 18자 + 쉼표). 263개면 약 3.7KB 가 필요하다.
-- TEXT(64KB) 로 넓힌다. 인덱스가 걸린 컬럼이 아니라 확장 비용은 없다.
--
-- 적용 후 반드시 재계산 스크립트를 돌린다(저장된 본문에서 다시 뽑는다. 네트워크 불필요):
--   docker compose -p vulnagent exec -T web php /var/www/html/bin/rebuild_advisory_cveids.php
--
-- 적용(dev):
--   docker compose -p vulnagent-dev exec -T db sh -c \
--     'mysql -uroot -p$(cat /run/secrets/mysql_root_password) vulnagent' \
--     < db/_migrations/2026-07-advisories-cveids-text.sql
-- 적용(프로덕션): -p vulnagent 로 동일 실행.
-- ─────────────────────────────────────────────────────────────────────────
SET NAMES utf8mb4;

ALTER TABLE tb_advisories MODIFY COLUMN cve_ids TEXT NULL;
