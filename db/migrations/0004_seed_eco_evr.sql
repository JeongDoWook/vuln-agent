-- 데모 시드 행(db/03-seed-cve.sql)을 배포판 형식으로 교정 — 기존 볼륨용.
--   왜: ecosystem='rpm' + 업스트림 조치안('1.21.0')이면 매처가 버전 비교를 할 수 없다
--   (배포판 EVR '1:1.20.1-14.el9_2' 와 섞어 비교하면 epoch 때문에 오억제가 난다).
--   'Rocky Linux:9' + 배포판 EVR 로 바꿔야 "이미 패치됨" 판정이 동작한다.
--   멱등: 옛 값일 때만 UPDATE, curl 행은 없을 때만 INSERT.
SET NAMES utf8mb4;

UPDATE tb_cve_affected_packages SET ecosystem = 'Rocky Linux:9', fixed_version = '2.34-83.el9_3.7'
  WHERE cve_id = 'CVE-2023-4911'  AND package_name = 'glibc'   AND ecosystem = 'rpm';
UPDATE tb_cve_affected_packages SET ecosystem = 'Rocky Linux:9', fixed_version = '1:3.0.7-25.el9_3'
  WHERE cve_id = 'CVE-2023-0286'  AND package_name = 'openssl' AND ecosystem = 'rpm';
UPDATE tb_cve_affected_packages SET ecosystem = 'Rocky Linux:9', fixed_version = '1:1.20.1-16.el9_4'
  WHERE cve_id = 'CVE-2021-23017' AND package_name = 'nginx'   AND ecosystem = 'rpm';

INSERT INTO tb_cves (cve_id, summary, cvss, published)
SELECT 'CVE-2023-38545', 'curl SOCKS5 힙 버퍼 오버플로우 — 원격 코드실행 가능', 9.8, '2023-10-11'
  FROM DUAL WHERE NOT EXISTS (SELECT 1 FROM tb_cves WHERE cve_id = 'CVE-2023-38545');

INSERT INTO tb_cve_affected_packages (cve_id, ecosystem, package_name, fixed_version)
SELECT 'CVE-2023-38545', 'Rocky Linux:9', 'curl', '7.76.1-26.el9_3.2'
  FROM DUAL WHERE NOT EXISTS (
    SELECT 1 FROM tb_cve_affected_packages WHERE cve_id = 'CVE-2023-38545' AND package_name = 'curl');
