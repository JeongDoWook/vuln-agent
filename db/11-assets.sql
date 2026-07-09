-- vuln-agent 자산관리(assets) 메뉴 권한 시드.
--   호스트(tb_hosts)는 이미 01-schema.sql 에 있으므로 새 테이블은 없다.
--   operator: 자산관리 허용(호스트 삭제까지 수행 가능) / user: 읽기 메뉴만 — 자산관리 불가.
--   admin 은 코드에서 항상 전체 허용이라 행을 두지 않는다(잠금방지).
SET NAMES utf8mb4;

INSERT IGNORE INTO tb_role_permissions (role, menu_code, allowed) VALUES
  ('operator', 'assets', 1),
  ('user',     'assets', 0);
