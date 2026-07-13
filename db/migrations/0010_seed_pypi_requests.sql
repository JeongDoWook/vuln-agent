-- 데모 시드에 언어 패키지(PyPI) 케이스 추가 — 기존 볼륨용(빈 볼륨은 db/03-seed-cve.sql).
--   requests 2.19.1 (설치) < 2.31.0 (조치) → 취약. 지금까지 언어 패키지는 ingest 가 버려서
--   이런 CVE 가 전부 미탐이었다.
--   멱등: 없을 때만 INSERT.
SET NAMES utf8mb4;

INSERT INTO tb_cves (cve_id, summary, cvss, published)
SELECT 'CVE-2023-32681', 'python-requests: 리다이렉트 시 Proxy-Authorization 헤더 유출', 6.1, '2023-05-26'
  FROM DUAL WHERE NOT EXISTS (SELECT 1 FROM tb_cves WHERE cve_id = 'CVE-2023-32681');

INSERT INTO tb_cve_affected_packages (cve_id, ecosystem, package_name, fixed_version)
SELECT 'CVE-2023-32681', 'PyPI', 'requests', '2.31.0'
  FROM DUAL WHERE NOT EXISTS (
    SELECT 1 FROM tb_cve_affected_packages WHERE cve_id = 'CVE-2023-32681' AND package_name = 'requests');
