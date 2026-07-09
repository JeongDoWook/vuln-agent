-- vuln-agent : tb_advisories 본문(content) 컬럼 추가
-- ─────────────────────────────────────────────────────────────────────────
-- 지금까지 KISA 커넥터는 RSS 목록의 제목·링크·날짜만 저장했다. 그래서 목록에서
-- "원문 →" 으로 보호나라 사이트를 새 창에 띄우는 것 말고는 보여줄 내용이 없었다.
-- 상세 페이지(advisory.php)가 저장된 본문을 직접 보여주도록 컬럼을 추가한다.
--
--   content            : 본문 평문(태그 제거). 외부 HTML 을 그대로 저장하면 XSS 표면이
--                        생기므로 평문만 담고, 출력 시 vg_h + nl2br 로 렌더한다.
--   content_fetched_at : 본문을 언제 긁었는지. NULL = 미수집(백필 대상).
--
-- 적용(dev):
--   docker compose -p vulnagent-dev exec -T db sh -c \
--     'mysql -uroot -p$(cat /run/secrets/mysql_root_password) vulnagent' \
--     < db/_migrations/2026-07-advisories-content.sql
-- 적용(프로덕션): -p vulnagent 로 동일 실행.
--
-- 적용 후 기존 행 채우기:
--   docker compose -p vulnagent exec -T web php /var/www/html/bin/backfill_kisa_content.php
-- ─────────────────────────────────────────────────────────────────────────
SET NAMES utf8mb4;

ALTER TABLE tb_advisories
  ADD COLUMN content            MEDIUMTEXT NULL AFTER cve_ids,
  ADD COLUMN content_fetched_at DATETIME   NULL AFTER content;
