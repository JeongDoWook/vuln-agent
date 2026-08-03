-- tb_host 에 최근 수집 접속 IP 를 기록한다.
--   에이전트는 net.interfaces 로 여러 인터페이스를 보내지만, 다중 인터페이스 중 대표값을
--   고르는 건 모호하다(YAGNI) — ingest.php 가 이미 보는 REMOTE_ADDR(수신 접속지) 하나로 충분하다.
--   IPv6 최대 길이(45자) 대비, 첫 수집 전엔 값이 없으므로 NULL 허용.
SET NAMES utf8mb4;

ALTER TABLE tb_host
  ADD COLUMN last_seen_ip VARCHAR(45) NULL AFTER last_seen;
