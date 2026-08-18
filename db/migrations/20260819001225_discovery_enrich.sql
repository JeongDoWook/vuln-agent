-- 자산 탐색 수집 강화 — 발견한 IP 에 "이게 뭔지" 를 채운다.
--
--   첫 스캔 결과가 IP 와 열린 포트뿐이라, 담당자가 "10.3.142.109 가 무엇인가"를 손으로
--   다시 조사해야 했다. 그 조사(역DNS·포트 관례·HTTP Server 헤더·TLS 인증서 CN)는 전부
--   스캐너가 자동으로 할 수 있는 것들이라 수집 단계로 옮긴다.
--
--   ★ MAC 주소는 넣지 않는다. 엔진이 web 컨테이너 안에서 도는데 /proc/net/arp 에는 도커
--     브리지(172.18.0.x)뿐이고, 스캔 대상 대역은 게이트웨이 너머라 컨테이너가 ARP 를 하지
--     않는다(실측). 그래서 같은 MAC 을 공유하는 가상 IP(MetalLB/Traefik VIP)를 자동으로
--     걸러낼 수 없고, 그런 건 사람이 state='ignored' 로 표시한다.
--
--   ★ 자산 탐색 DDL 은 20260818205835_asset_discovery.sql 이 정본이고 여기는 컬럼만 더한다.
--     공용 dev DB 를 여러 워크트리가 함께 쓰므로 같은 테이블을 두 파일이 만들면 스키마가
--     갈라진다(2564719f).
SET NAMES utf8mb4;

-- 발견 IP 의 역DNS 호스트명. NULL = 아직 못 찾음(집행기는 빈 값으로 덮지 않는다 —
--   이번에 DNS 가 안 떴다고 지난번에 얻은 이름을 지우면 정보가 사라진다).
SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_discovered_asset'
             AND COLUMN_NAME = 'hostname');
SET @s := IF(@c = 0,
  "ALTER TABLE tb_discovered_asset
     ADD COLUMN hostname VARCHAR(255) NULL COMMENT '역DNS(PTR) 호스트명. NULL=조회 실패/미조회' AFTER ip",
  'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- 열린 포트의 정체 힌트.
--   service_hint : 포트 번호 관례에서 유추한 서비스 이름. **추측이다**(22 가 항상 SSH 는 아니다).
--   banner       : HTTP 응답의 Server 헤더 또는 TLS 인증서 subject CN. 웹 포트에만 붙는다.
--                  본문은 읽지 않는다 — 헤더 한 줄·인증서 한 필드가 전부다.
SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_discovered_port'
             AND COLUMN_NAME = 'service_hint');
SET @s := IF(@c = 0,
  "ALTER TABLE tb_discovered_port
     ADD COLUMN service_hint VARCHAR(64)  NULL COMMENT '포트 관례에서 유추한 서비스(추측)' AFTER proto,
     ADD COLUMN banner       VARCHAR(255) NULL COMMENT 'HTTP Server 헤더 또는 TLS 인증서 CN' AFTER service_hint",
  'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
