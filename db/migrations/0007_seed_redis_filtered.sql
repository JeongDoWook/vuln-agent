-- 데모 시드에 redis 케이스 추가 — 기존 볼륨용(빈 볼륨은 db/03-seed-cve.sql).
--   redis 는 0.0.0.0:6379 로 떠 있지만 방화벽이 막는다(scope=FILTERED) → 외부노출 아님(MEDIUM).
--   방화벽을 안 보면 EXTERNAL 로 오판해 HIGH 가 되던 케이스다.
--   멱등: 없을 때만 INSERT.
SET NAMES utf8mb4;

INSERT INTO tb_cves (cve_id, summary, cvss, published)
SELECT 'CVE-2023-28425', 'redis MSETNX 명령 처리 중 단언 실패 — DoS', 5.5, '2023-03-20'
  FROM DUAL WHERE NOT EXISTS (SELECT 1 FROM tb_cves WHERE cve_id = 'CVE-2023-28425');

INSERT INTO tb_cve_affected_packages (cve_id, ecosystem, package_name, fixed_version)
SELECT 'CVE-2023-28425', 'Rocky Linux:9', 'redis', '6.2.11-1.el9'
  FROM DUAL WHERE NOT EXISTS (
    SELECT 1 FROM tb_cve_affected_packages WHERE cve_id = 'CVE-2023-28425' AND package_name = 'redis');
