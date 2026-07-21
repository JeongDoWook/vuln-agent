-- 로그인 보안: 동시 로그인 차단(세션 토큰) + 로그인 실패 제한/계정 잠금.
--   session_token   : 계정당 "현재 유효한 세션 1개"를 나타내는 토큰. 재로그인 시 갱신되어
--                      이전 세션을 자동 무효화한다(vg_current_user() 가 대조).
--   failed_login_count / locked_until : 계정 단위 실패 집계 + 잠금 해제 시각.
-- 멱등: information_schema 확인 후에만 추가(20260720170006 과 동일 패턴).
SET NAMES utf8mb4;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_users' AND COLUMN_NAME = 'session_token');
SET @s := IF(@c = 0,
             'ALTER TABLE tb_users ADD COLUMN session_token VARCHAR(64) NULL AFTER password_hash',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_users' AND COLUMN_NAME = 'failed_login_count');
SET @s := IF(@c = 0,
             'ALTER TABLE tb_users ADD COLUMN failed_login_count INT UNSIGNED NOT NULL DEFAULT 0 AFTER role',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_users' AND COLUMN_NAME = 'locked_until');
SET @s := IF(@c = 0,
             'ALTER TABLE tb_users ADD COLUMN locked_until DATETIME NULL AFTER failed_login_count',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
