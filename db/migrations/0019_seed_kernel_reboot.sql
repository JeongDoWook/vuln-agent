-- 커널 재부팅 데모 시드 — 기존 볼륨용(빈 볼륨은 db/03-seed-cve.sql).
--   설치 커널 = 조치 버전(5.14.0-503.11.1.el9_5) 이라 "이미 패치됨"으로 억제될 건이지만,
--   실행 중인 커널은 5.14.0-427(옛 것)이다 → 재부팅 전까지 여전히 취약(미탐 방지).
--   멱등: 없을 때만 INSERT.
SET NAMES utf8mb4;

INSERT INTO tb_cves (cve_id, summary, cvss, published)
SELECT 'CVE-2024-26581', 'Linux 커널 netfilter nft_set_rbtree — 권한상승', 7.8, '2024-02-20'
  FROM DUAL WHERE NOT EXISTS (SELECT 1 FROM tb_cves WHERE cve_id = 'CVE-2024-26581');

INSERT INTO tb_cve_affected_packages (cve_id, ecosystem, package_name, fixed_version)
SELECT 'CVE-2024-26581', 'Rocky Linux:9', 'kernel', '5.14.0-503.11.1.el9_5'
  FROM DUAL WHERE NOT EXISTS (
    SELECT 1 FROM tb_cve_affected_packages WHERE cve_id = 'CVE-2024-26581' AND package_name = 'kernel');
