-- vuln-agent : 역할(RBAC) 3단계 정규화 마이그레이션
-- ─────────────────────────────────────────────────────────────────────────
-- 역할 3값: admin(관리자) | operator(운영자) | user(사용자).
-- 레거시 'viewer' 는 코드에서 'user' 와 동일 취급하지만, DB 값도 정규화한다.
-- 컬럼 변경 없음(role 은 이미 VARCHAR). 신규 볼륨은 04-auth.sql 기본값이 'user'
-- 이므로 이 파일이 필요 없다. 기존 프로덕션 볼륨에 1회 수동 적용.
--
-- 프로덕션 수동 적용:
--   docker compose -p vulnagent exec -T db sh -c \
--     'mysql -uroot -p$(cat /run/secrets/mysql_root_password) vulnagent' \
--     < db/_migrations/2026-07-role-3tier.sql
-- ─────────────────────────────────────────────────────────────────────────
SET NAMES utf8mb4;

UPDATE tb_users SET role = 'user' WHERE role = 'viewer';
