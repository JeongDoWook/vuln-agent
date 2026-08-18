-- 호스트 라우팅 테이블 — 세그먼트 맵(망 구조 화면)의 데이터 원천.
--
--   에이전트는 예전부터 `ip route`(없으면 `route -n`) 원문을 보내 왔지만, 그 값은
--   tb_scan.raw_json 안에만 있고 어떤 테이블로도 파싱되지 않았다. 화면이 "이 호스트가
--   어느 대역에 붙어 있고 게이트웨이가 뭔가"를 그리려면 이 좌변이 필요하다.
--
--   행 모양은 실제 라우팅 테이블 그대로다 — 게이트웨이도 라우팅 행 하나일 뿐이다(기본
--   경로 0.0.0.0/0). 별도 "게이트웨이 컬럼"을 tb_host 에 두지 않는 이유: 호스트 하나가
--   기본 게이트웨이 없이 직결 서브넷만 갖거나(라우터 자신), 서브넷이 여러 개인 경우가
--   흔해 어차피 N행 구조가 필요하다 — tb_host_address 와 같은 모양이다.
--
--     · cidr = '0.0.0.0/0', gateway_ip = 게이트웨이         → 기본 게이트웨이 행
--     · cidr = 직결 서브넷,   gateway_ip = NULL(= scope link) → 직결 서브넷 행
--
--   가상 인터페이스(docker·br-·virbr 등, src/netiface.php)가 물린 라우팅은 **저장하지
--   않는다** — 컨테이너·오버레이가 만든 것이라 실제 망 구조가 아니다.
--
--   라우팅 너머(게이트웨이 건너 도달하는 서브넷)는 다루지 않는다. B단계(트래픽 엣지)와
--   달리 A단계는 "이 호스트가 물리적으로 붙어 있는 대역"만 그린다.
SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS tb_host_route (
  host_route_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  host_id       BIGINT UNSIGNED NOT NULL,
  cidr          VARCHAR(18)  NOT NULL COMMENT '예: 10.3.142.0/24, 기본경로는 0.0.0.0/0',
  gateway_ip    VARCHAR(45)  NULL     COMMENT 'NULL=직결 서브넷(scope link). 값 있으면 기본 게이트웨이 행',
  iface         VARCHAR(64)  NULL,
  first_seen    DATETIME NOT NULL,
  last_seen     DATETIME NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at DATETIME NULL,
  PRIMARY KEY (host_route_id),
  UNIQUE KEY uq_host_route (host_id, cidr),
  KEY idx_host_route_cidr (cidr) COMMENT '세그먼트 맵이 대역별로 호스트를 묶을 때 사용',
  CONSTRAINT fk_host_route_host FOREIGN KEY (host_id)
    REFERENCES tb_host(host_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
