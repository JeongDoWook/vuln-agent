-- vuln-agent 매처 데모 시드
-- 실제 운영에서는 NVD/OSV/KEV 미러 동기화가 이 데이터를 채운다(4단계).
-- 지금은 샘플 호스트(openssl/glibc/nginx)에 매칭되는 실제 CVE 소수를 넣어
-- 매처가 CRITICAL/HIGH 를 산출하는 것을 보여준다.
SET NAMES utf8mb4;

INSERT INTO cves (cve_id, summary, cvss, published) VALUES
  ('CVE-2023-4911', 'glibc ld.so GLIBC_TUNABLES 스택 버퍼 오버플로우 (Looney Tunables) — 로컬 권한상승', 7.8, '2023-10-03'),
  ('CVE-2023-0286', 'OpenSSL X.400 address type confusion (X.509 GeneralName) — DoS/메모리', 7.4, '2023-02-08'),
  ('CVE-2021-23017', 'nginx resolver off-by-one 힙 쓰기 — 원격 코드실행 가능', 7.7, '2021-05-25')
ON DUPLICATE KEY UPDATE summary=VALUES(summary), cvss=VALUES(cvss), published=VALUES(published);

-- CISA KEV: 실제 악용 목록 (Looney Tunables 는 KEV 등재)
INSERT INTO kev_catalog (cve_id, date_added, note) VALUES
  ('CVE-2023-4911', '2023-11-21', 'CISA KEV 등재 — 실제 악용 확인')
ON DUPLICATE KEY UPDATE date_added=VALUES(date_added), note=VALUES(note);

-- CVE ↔ 영향 패키지 (package_name 은 수집된 pkg.name / source_pkg 와 대조)
INSERT INTO cve_affected_packages (cve_id, ecosystem, package_name, fixed_version) VALUES
  ('CVE-2023-4911', 'rpm', 'glibc',   '2.34-83.el9_3.7'),
  ('CVE-2023-0286', 'rpm', 'openssl', '3.0.7-25.el9_3'),
  ('CVE-2021-23017','rpm', 'nginx',   '1.21.0');
