-- vuln-agent 매처 데모 시드
-- 실제 운영에서는 NVD/OSV/KEV 미러 동기화가 이 데이터를 채운다(4단계).
-- 샘플 호스트(Rocky 9.3)의 패키지에 매칭되는 실제 CVE 소수를 넣어 매처가
-- CRITICAL/HIGH 를 산출하는 것과, **이미 패치된 건은 억제**하는 것을 함께 보여준다.
--
-- ecosystem 은 배포판 형식('Rocky Linux:9')을 쓴다 — OSV 커넥터가 실제로 쓰는 표기이고,
-- 이 형식일 때만 fixed_version 이 배포판 EVR 이라 설치 버전과 직접 비교할 수 있다.
-- (예전엔 'rpm' + 업스트림 버전 '1.21.0' 이 섞여 있어, 배포판 EVR '1:1.20.1-14.el9_2' 와
--  비교하면 epoch 때문에 "설치가 더 최신"이 되는 오억제가 났다.)
SET NAMES utf8mb4;

INSERT INTO tb_cves (cve_id, summary, cvss, published) VALUES
  ('CVE-2023-4911', 'glibc ld.so GLIBC_TUNABLES 스택 버퍼 오버플로우 (Looney Tunables) — 로컬 권한상승', 7.8, '2023-10-03'),
  ('CVE-2023-0286', 'OpenSSL X.400 address type confusion (X.509 GeneralName) — DoS/메모리', 7.4, '2023-02-08'),
  ('CVE-2021-23017', 'nginx resolver off-by-one 힙 쓰기 — 원격 코드실행 가능', 7.7, '2021-05-25'),
  ('CVE-2023-38545', 'curl SOCKS5 힙 버퍼 오버플로우 — 원격 코드실행 가능', 9.8, '2023-10-11')
ON DUPLICATE KEY UPDATE summary=VALUES(summary), cvss=VALUES(cvss), published=VALUES(published);

-- CISA KEV: 실제 악용 목록 (Looney Tunables 는 KEV 등재)
INSERT INTO tb_kev_catalog (cve_id, date_added, note) VALUES
  ('CVE-2023-4911', '2023-11-21', 'CISA KEV 등재 — 실제 악용 확인')
ON DUPLICATE KEY UPDATE date_added=VALUES(date_added), note=VALUES(note);

-- CVE ↔ 영향 패키지 (package_name 은 수집된 pkg.name / source_pkg 와 대조)
--   fixed_version 은 Rocky 9 의 조치 EVR. 샘플 호스트는 glibc/openssl/nginx 가 이보다 낮아
--   취약으로 뜨고, curl 은 조치 버전과 같아 "이미 패치됨"으로 억제된다.
INSERT INTO tb_cve_affected_packages (cve_id, ecosystem, package_name, fixed_version) VALUES
  ('CVE-2023-4911', 'Rocky Linux:9', 'glibc',   '2.34-83.el9_3.7'),
  ('CVE-2023-0286', 'Rocky Linux:9', 'openssl', '1:3.0.7-25.el9_3'),
  ('CVE-2021-23017','Rocky Linux:9', 'nginx',   '1:1.20.1-16.el9_4'),
  ('CVE-2023-38545','Rocky Linux:9', 'curl',    '7.76.1-26.el9_3.2')
ON DUPLICATE KEY UPDATE ecosystem=VALUES(ecosystem), fixed_version=VALUES(fixed_version);
