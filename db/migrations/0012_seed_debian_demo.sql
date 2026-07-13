-- 데비안 데모 시드(web02) — 기존 볼륨용(빈 볼륨은 db/03-seed-cve.sql).
--   둘 다 설치 버전보다 조치 버전이 높아 "버전만 보면" 취약하다.
--     curl    : debsecan 이 지목 → 진짜 취약(finding 유지)
--     openssl : debsecan 이 지목하지 않음 → 데비안이 백포트로 이미 고침(억제)
--   멱등: 없을 때만 INSERT.
SET NAMES utf8mb4;

INSERT INTO tb_cves (cve_id, summary, cvss, published)
SELECT 'CVE-2024-2004', 'curl: 비활성 프로토콜의 기본 설정이 잘못 적용됨', 5.5, '2024-03-27'
  FROM DUAL WHERE NOT EXISTS (SELECT 1 FROM tb_cves WHERE cve_id = 'CVE-2024-2004');
INSERT INTO tb_cves (cve_id, summary, cvss, published)
SELECT 'CVE-2023-5678', 'OpenSSL DH 키 생성 시 과도한 지연 — DoS', 5.3, '2023-11-06'
  FROM DUAL WHERE NOT EXISTS (SELECT 1 FROM tb_cves WHERE cve_id = 'CVE-2023-5678');

INSERT INTO tb_cve_affected_packages (cve_id, ecosystem, package_name, fixed_version)
SELECT 'CVE-2024-2004', 'Debian:12', 'curl', '7.88.1-10+deb12u7'
  FROM DUAL WHERE NOT EXISTS (
    SELECT 1 FROM tb_cve_affected_packages WHERE cve_id = 'CVE-2024-2004' AND package_name = 'curl');
INSERT INTO tb_cve_affected_packages (cve_id, ecosystem, package_name, fixed_version)
SELECT 'CVE-2023-5678', 'Debian:12', 'openssl', '3.0.11-1~deb12u3'
  FROM DUAL WHERE NOT EXISTS (
    SELECT 1 FROM tb_cve_affected_packages WHERE cve_id = 'CVE-2023-5678' AND package_name = 'openssl');
