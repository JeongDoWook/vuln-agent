-- vuln-agent 프로덕션 in-place 마이그레이션 : 자산관리(assets) 메뉴 권한 시드
-- ─────────────────────────────────────────────────────────────────────────
-- 이 파일은 db/_migrations/ 하위폴더에 있으므로 MySQL initdb 가 자동 실행하지
-- 않는다(initdb 는 최상위 *.sql 만 실행). 신규 볼륨은 db/11-assets.sql 로 충분.
--
-- 기존 볼륨에 딱 1회 수동 적용. INSERT IGNORE 라 재실행해도 안전하고 기존 값은 보존.
-- 새 테이블은 없다 — 자산관리는 기존 tb_hosts 를 보여줄 뿐이다.
--
-- 프로덕션 수동 적용:
--   docker compose -p vulnagent exec -T db sh -c \
--     'mysql -uroot -p$(cat /run/secrets/mysql_root_password) vulnagent' \
--     < db/_migrations/2026-07-assets-permission.sql
-- ─────────────────────────────────────────────────────────────────────────
SET NAMES utf8mb4;

INSERT IGNORE INTO tb_role_permissions (role, menu_code, allowed) VALUES
  ('operator', 'assets', 1),
  ('user',     'assets', 0);
