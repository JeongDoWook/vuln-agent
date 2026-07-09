-- vuln-agent 국내 보안공지(4b) : KISA(보호나라) 등 국내 특화 피드
--   해외 도구가 안 하는 국내 보안공지를 수집해 보여준다.
--   RSS 에 CVE 가 없어 공지 자체를 저장(제목에 CVE 있으면 best-effort 연계).
SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS tb_advisories (
  id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  source     VARCHAR(16)  NOT NULL DEFAULT 'kisa',   -- kisa | ...
  title      VARCHAR(512) NOT NULL,
  url        VARCHAR(768) NOT NULL,
  published  DATE NULL,
  cve_ids    VARCHAR(512) NULL,                       -- 제목에서 추출한 CVE(쉼표)
  fetched_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at DATETIME NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_adv_url (url(500)),
  KEY idx_adv_pub (published),
  INDEX idx_advisories_is_deleted (is_deleted)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- KISA 보안공지 커넥터 (활성, 12시간 주기)
INSERT INTO tb_feed_connectors (name, connector_type, connection_json, schedule_json, enabled, last_status)
VALUES
  ('KISA 보안공지', 'kisa',
   JSON_OBJECT(),  -- url 비움 → 커넥터가 보호나라 다중 카테고리(보안공지·취약점정보·경보단계) 순회 수집
   JSON_OBJECT('mode','interval','interval_minutes',720), 1, 'never')
ON DUPLICATE KEY UPDATE name = name;
