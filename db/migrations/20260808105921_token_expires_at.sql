-- API 토큰·에이전트 토큰에 유효기간(expires_at) 추가.
--   NULL = 무기한 — 기존에 발급된 토큰은 그대로 계속 쓰인다(하위호환).
--   값이 있으면 검증 경로(vg_api_token_verify / vg_agent_token_verify)가 지난 토큰을 인증 실패로
--   처리하고 감사로그(api_token_expired / agent_token_expired)를 남긴다.
--   대응 기준: ISMS-P 2.5.1(사용자 식별·인증정보 관리) · N2SF AC-1(4).
--
--   테이블 존재 여부까지 함께 확인한다 — 공용 dev DB 에서 이 마이그레이션만 먼저 도는 상황을
--   대비한 방어(멱등 + 순서 무관).
SET NAMES utf8mb4;

SET @t := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_api_token');
SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_api_token' AND COLUMN_NAME = 'expires_at');
SET @s := IF(@t = 1 AND @c = 0, 'ALTER TABLE tb_api_token ADD COLUMN expires_at DATETIME NULL COMMENT ''만료시각(NULL=무기한)''', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @t := (SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_agent_token');
SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_agent_token' AND COLUMN_NAME = 'expires_at');
SET @s := IF(@t = 1 AND @c = 0, 'ALTER TABLE tb_agent_token ADD COLUMN expires_at DATETIME NULL COMMENT ''만료시각(NULL=무기한)''', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
