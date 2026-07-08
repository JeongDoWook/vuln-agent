-- vuln-agent EPSS(악용확률) — 차별점 #2 (EPSS + KEV)
--   FIRST.org EPSS: CVE별 향후 30일 내 악용될 확률(0~1) + 백분위.
--   KEV(이미 악용됨)와 함께 "실제 악용 가능성"으로 우선순위/정렬에 반영.
SET NAMES utf8mb4;

-- (MySQL 8 은 ADD COLUMN IF NOT EXISTS 미지원 → 초기화 시 1회 실행 전제)
ALTER TABLE tb_cves
  ADD COLUMN epss            DECIMAL(6,5) NULL AFTER cvss,
  ADD COLUMN epss_percentile DECIMAL(6,5) NULL AFTER epss;

-- EPSS 커넥터 (기본 활성, 매일) — gzip CSV 다운로드해 보유 CVE 의 epss 갱신
INSERT INTO tb_feed_connectors (name, connector_type, connection_json, schedule_json, enabled, last_status)
VALUES
  ('FIRST EPSS', 'epss',
   JSON_OBJECT('url','https://epss.cyentia.com/epss_scores-current.csv.gz'),
   JSON_OBJECT('mode','daily','time','05:00'), 1, 'never')
ON DUPLICATE KEY UPDATE name = name;
