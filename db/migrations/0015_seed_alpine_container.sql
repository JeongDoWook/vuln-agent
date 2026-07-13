-- 컨테이너 데모 시드 — 기존 볼륨용(빈 볼륨은 db/03-seed-cve.sql).
--   알파인 컨테이너(api)의 openssl 3.1.4-r2 < 조치 3.1.4-r5 → 취약.
--   호스트(Rocky)의 openssl 과 생태계가 달라 섞이지 않는다는 것도 함께 보여준다.
--   멱등: 없을 때만 INSERT.
SET NAMES utf8mb4;

INSERT INTO tb_cves (cve_id, summary, cvss, published)
SELECT 'CVE-2024-0727', 'OpenSSL PKCS12 NULL 역참조 — DoS', 5.5, '2024-01-26'
  FROM DUAL WHERE NOT EXISTS (SELECT 1 FROM tb_cves WHERE cve_id = 'CVE-2024-0727');

INSERT INTO tb_cve_affected_packages (cve_id, ecosystem, package_name, fixed_version)
SELECT 'CVE-2024-0727', 'Alpine:v3.19', 'openssl', '3.1.4-r5'
  FROM DUAL WHERE NOT EXISTS (
    SELECT 1 FROM tb_cve_affected_packages
     WHERE cve_id = 'CVE-2024-0727' AND package_name = 'openssl' AND ecosystem = 'Alpine:v3.19');
