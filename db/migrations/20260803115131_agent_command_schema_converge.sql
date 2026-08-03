-- tb_agent_command 스키마 수렴 확정.
--   agent-command-web-ui 워커와 agent-command-queue-api 워커가 각자 독립 워크트리에서
--   CREATE TABLE IF NOT EXISTS 로 같은 테이블을 만들었다(계약은 같지만 세부 타입이 달랐다 —
--   web-ui: host_id BIGINT UNSIGNED / status VARCHAR(16), queue-api: host_id BIGINT / status
--   ENUM('pending','done','failed')). CREATE TABLE IF NOT EXISTS 는 실제로 먼저 실행된 쪽의
--   스키마를 그대로 굳히므로, 신규 설치(마이그레이션 전체를 처음부터 순서대로 적용)에서는
--   파일명 사전순(이 마이그레이션이 queue-api 의 CREATE 뒤에 먼저 온다)대로 실행되어
--   host_id 가 SIGNED 로 굳는다 — tb_host.host_id(BIGINT UNSIGNED)와 타입이 어긋난다.
--   실행 순서에 관계없이 최종 스키마가 하나로 수렴하도록 여기서 명시적으로 확정한다.
SET NAMES utf8mb4;

ALTER TABLE tb_agent_command
  MODIFY COLUMN host_id BIGINT UNSIGNED NOT NULL,
  MODIFY COLUMN status VARCHAR(16) NOT NULL DEFAULT 'pending',
  MODIFY COLUMN created_by BIGINT UNSIGNED NULL;
