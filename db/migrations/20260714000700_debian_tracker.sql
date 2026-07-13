-- 데비안 보안 트래커 — 릴리스별 "아직 취약한" 패키지×CVE 목록.
--   왜: 데비안은 보안패치를 백포트한다(버전을 안 올리고 고친다). 그래서 버전 비교만으로는
--   "이미 고쳐진 것"과 "진짜 취약한 것"을 구분할 수 없고, 오탐이 대량으로 남는다
--   (실측 raspberrypi5-00: HIGH 160 중 73건이 이 오탐이었다).
--
--   지금까지는 **대상 서버에 debsecan 을 설치**해 그 판정을 받아왔다(tb_debsecan).
--   그건 정석이 아니다 — 에이전트는 사실만 수집하고, 판정에 필요한 지식은 중앙이 갖는 게 맞다.
--   폐쇄망 서버엔 apt 설치조차 못 한다. 그래서 debsecan 이 **받아 쓰는 바로 그 데이터**를
--   중앙이 직접 수집한다(security-tracker.debian.org/tracker/debsecan/release/1/<코드명>,
--   zlib 1.6MB — 전체 JSON 79MB 와 달리 가볍다).
--
--   판정 규칙은 debsecan 원본(/usr/bin/debsecan, Vulnerability.is_vulnerable)과 동일하다:
--     · 바이너리 항목(is_binary=1): 설치 바이너리 버전 < fixed_version 이면 취약
--     · 소스 항목:                  설치 소스 버전 < fixed_version 이고 other_versions 에 없으면 취약
--     · fixed_version 이 비면 아직 수정본이 없다 → 무조건 취약
SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS tb_debian_tracker (
  id               BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  release_codename VARCHAR(32)  NOT NULL,          -- bookworm | trixie …
  pkg_name         VARCHAR(255) NOT NULL,          -- 소스 패키지(기본) 또는 바이너리(is_binary=1)
  is_binary        TINYINT(1)   NOT NULL DEFAULT 0,
  cve_id           VARCHAR(32)  NOT NULL,
  fixed_version    VARCHAR(255) NULL,              -- 이 릴리스에서 고쳐진 버전(비면 미수정)
  other_versions   VARCHAR(512) NULL,              -- 취약하지 않은 예외 버전들(공백 구분)
  urgency          VARCHAR(8)   NULL,              -- low | medium | high | ''
  has_fix          TINYINT(1)   NOT NULL DEFAULT 0,
  created_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted       TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at       DATETIME NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_debtracker (release_codename, pkg_name, is_binary, cve_id),
  KEY idx_debtracker_lookup (release_codename, pkg_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 커넥터 등록 — 하루 1회. 다른 피드와 같은 스케줄러(vg_feed_due)가 돌린다.
--   releases 를 비우면 커넥터가 **수집된 호스트의 데비안 버전에서 자동으로** 코드명을 뽑는다
--   (호스트가 없으면 bookworm·trixie 를 기본으로 받는다).
INSERT INTO tb_feed_connectors (name, connector_type, connection_json, schedule_json, enabled, last_status)
SELECT '데비안 보안 트래커', 'debtracker',
       JSON_OBJECT('releases', JSON_ARRAY()),
       JSON_OBJECT('mode','interval','interval_minutes',1440), 1, 'never'
 WHERE NOT EXISTS (SELECT 1 FROM tb_feed_connectors WHERE connector_type = 'debtracker');
