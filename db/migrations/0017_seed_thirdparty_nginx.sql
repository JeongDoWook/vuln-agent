-- 서드파티 저장소 데모(web02) — 기존 볼륨용(빈 볼륨은 db/03-seed-cve.sql).
--   nginx 를 nginx.org 저장소에서 설치한 상황(origin=nginx). 배포판 조치안은 1.22.1-9+deb12u1 인데
--   설치는 1.24.0-2~bookworm 이라, 버전만 비교하면 "이미 패치됨"으로 억제된다(체계가 다른데도).
--   debsecan 목록에도 없으니 "백포트로 수정됨"으로도 억제된다 → 둘 다 미탐이다.
--   출처가 서드파티임을 알면 두 억제 모두 막고 사람이 판단하게 남긴다.
--   멱등: 없을 때만 INSERT.
SET NAMES utf8mb4;

INSERT INTO tb_cve_affected_packages (cve_id, ecosystem, package_name, fixed_version)
SELECT 'CVE-2021-23017', 'Debian:12', 'nginx', '1.22.1-9+deb12u1'
  FROM DUAL WHERE NOT EXISTS (
    SELECT 1 FROM tb_cve_affected_packages
     WHERE cve_id = 'CVE-2021-23017' AND package_name = 'nginx' AND ecosystem = 'Debian:12');
