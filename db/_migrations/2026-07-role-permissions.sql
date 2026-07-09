-- vuln-agent 프로덕션 in-place 마이그레이션 : 역할별 메뉴 접근권한(tb_role_permissions)
-- ─────────────────────────────────────────────────────────────────────────
-- 이 파일은 db/_migrations/ 하위폴더에 있으므로 MySQL initdb 가 자동 실행하지
-- 않는다(initdb 는 최상위 *.sql 만 실행). 신규 볼륨은 db/10-permissions.sql 로 충분.
--
-- 기존 프로덕션 볼륨에 딱 1회 수동 적용. CREATE TABLE IF NOT EXISTS + INSERT IGNORE
-- 로 멱등하게 작성했으므로 재실행해도 안전하다.
--
-- 프로덕션 수동 적용:
--   docker compose -p vulnagent exec -T db sh -c \
--     'mysql -uroot -p$(cat /run/secrets/mysql_root_password) vulnagent' \
--     < db/_migrations/2026-07-role-permissions.sql
-- ─────────────────────────────────────────────────────────────────────────
SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS tb_role_permissions (
  id         INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  role       VARCHAR(20) NOT NULL,               -- operator | user (admin 은 저장 안 함)
  menu_code  VARCHAR(40) NOT NULL,               -- dashboard/findings/advisories/connectors/users/activity/permissions
  allowed    TINYINT(1) NOT NULL DEFAULT 0,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at DATETIME NULL,
  UNIQUE KEY uq_role_menu (role, menu_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 기본값 시드(기존 하드코딩 매트릭스와 동일). INSERT IGNORE 라 기존 값은 보존.
INSERT IGNORE INTO tb_role_permissions (role, menu_code, allowed) VALUES
  ('operator', 'dashboard',  1),
  ('operator', 'findings',   1),
  ('operator', 'advisories', 1),
  ('operator', 'connectors', 1),
  ('operator', 'users',      0),
  ('operator', 'activity',   0),
  ('user',     'dashboard',  1),
  ('user',     'findings',   1),
  ('user',     'advisories', 1),
  ('user',     'connectors', 0),
  ('user',     'users',      0),
  ('user',     'activity',   0);
