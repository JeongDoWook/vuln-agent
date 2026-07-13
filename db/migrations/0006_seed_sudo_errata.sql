-- 데모 시드에 sudo 케이스 추가 — 기존 볼륨용(빈 볼륨은 db/03-seed-cve.sql).
--   피드는 조치 버전을 -13 이라 하지만 벤더 권고가 설치된 -10 빌드에서 이미 고친 상황.
--   버전만 보면 취약(오탐) → errata 근거로 억제되는 것을 보여준다.
--   멱등: 없을 때만 INSERT.
SET NAMES utf8mb4;

INSERT INTO tb_cves (cve_id, summary, cvss, published)
SELECT 'CVE-2023-22809', 'sudo sudoedit 임의 파일 편집 — 권한상승', 7.8, '2023-01-18'
  FROM DUAL WHERE NOT EXISTS (SELECT 1 FROM tb_cves WHERE cve_id = 'CVE-2023-22809');

INSERT INTO tb_cve_affected_packages (cve_id, ecosystem, package_name, fixed_version)
SELECT 'CVE-2023-22809', 'Rocky Linux:9', 'sudo', '1.9.5p2-13.el9_4'
  FROM DUAL WHERE NOT EXISTS (
    SELECT 1 FROM tb_cve_affected_packages WHERE cve_id = 'CVE-2023-22809' AND package_name = 'sudo');
