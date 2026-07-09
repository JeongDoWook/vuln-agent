-- vuln-agent 역할별 메뉴 접근권한(설정형 RBAC) — 역할×메뉴 → 허용 여부.
--   관리자(admin)는 저장하지 않는다: 코드에서 항상 전체 허용(잠금방지).
--   operator/user 만 행으로 두고, allowed=1 이면 해당 메뉴 접근 가능.
--   메뉴코드(menu_code): dashboard/findings/advisories/connectors/users/activity/permissions
-- 감사 4컬럼 통일: created_at/updated_at/is_deleted/deleted_at.
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

-- 기본값 시드 = 기존 하드코딩 매트릭스와 동일.
--   operator: dashboard/findings/advisories/connectors 허용, users/activity 불가
--   user    : dashboard/findings/advisories 허용, connectors/users/activity 불가
--   permissions 메뉴는 admin 전용 성격이라 시드하지 않는다(코드에서 admin 만 true).
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
