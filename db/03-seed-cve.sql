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
  ('CVE-2023-38545', 'curl SOCKS5 힙 버퍼 오버플로우 — 원격 코드실행 가능', 9.8, '2023-10-11'),
  ('CVE-2023-22809', 'sudo sudoedit 임의 파일 편집 — 권한상승', 7.8, '2023-01-18'),
  ('CVE-2023-28425', 'redis MSETNX 명령 처리 중 단언 실패 — DoS', 5.5, '2023-03-20'),
  ('CVE-2023-32681', 'python-requests: 리다이렉트 시 Proxy-Authorization 헤더 유출', 6.1, '2023-05-26'),
  -- 데비안 데모(web02): debsecan 이 지목한 CVE 는 남고, 지목하지 않은 CVE 는 백포트로 억제된다.
  ('CVE-2024-2004', 'curl: 비활성 프로토콜의 기본 설정이 잘못 적용됨', 5.5, '2024-03-27'),
  ('CVE-2023-5678', 'OpenSSL DH 키 생성 시 과도한 지연 — DoS', 5.3, '2023-11-06'),
  -- 컨테이너 데모: 알파인 컨테이너(api) 안의 openssl. 호스트가 아니라 컨테이너 배포판 기준으로 매칭된다.
  ('CVE-2024-0727', 'OpenSSL PKCS12 NULL 역참조 — DoS', 5.5, '2024-01-26'),
  -- 커널 데모: 패치는 설치됐지만 재부팅 전이라 옛 커널이 실행 중 → 억제하면 미탐.
  ('CVE-2024-26581', 'Linux 커널 netfilter nft_set_rbtree — 권한상승', 7.8, '2024-02-20')
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
  ('CVE-2023-38545','Rocky Linux:9', 'curl',    '7.76.1-26.el9_3.2'),
  -- sudo 는 피드가 조치 버전을 더 높게(-13) 말하지만, 벤더 권고(RLSA-2023:0136)가 설치된
  -- -10 빌드에서 이미 고쳤다. 버전만 보면 취약(오탐) → errata 근거로 억제되는 케이스.
  ('CVE-2023-22809','Rocky Linux:9', 'sudo',    '1.9.5p2-13.el9_4'),
  -- redis 는 0.0.0.0:6379 로 떠 있지만 방화벽이 막는다(scope=FILTERED) → 외부노출 아님.
  -- 방화벽을 안 보면 EXTERNAL 로 오판해 HIGH 가 된다. 실제로는 MEDIUM.
  ('CVE-2023-28425','Rocky Linux:9', 'redis',   '6.2.11-1.el9'),
  -- 언어 패키지(PyPI). OS 패키지와 생태계가 달라 섞이지 않는다.
  -- 조치안은 semver/PEP440 이라 EVR 비교기가 아니라 version_compare 로 비교한다.
  ('CVE-2023-32681','PyPI',          'requests', '2.31.0'),
  -- 데비안 호스트(web02). 둘 다 설치 버전보다 조치 버전이 높아 "버전만 보면" 취약하다.
  --   curl    : debsecan 이 지목 → 진짜 취약(finding 유지)
  --   openssl : debsecan 이 지목하지 않음 → 데비안이 백포트로 이미 고침(억제)
  ('CVE-2024-2004', 'Debian:12',    'curl',     '7.88.1-10+deb12u7'),
  ('CVE-2023-5678', 'Debian:12',    'openssl',  '3.0.11-1~deb12u3'),
  -- 알파인 컨테이너(api)의 openssl 3.1.4-r2 < 조치 3.1.4-r5 → 취약.
  -- 호스트(Rocky)의 openssl 과는 생태계가 달라 서로 섞이지 않는다.
  ('CVE-2024-0727', 'Alpine:v3.19', 'openssl',  '3.1.4-r5'),
  -- 서드파티 데모(web02): nginx 를 nginx.org 저장소에서 설치(origin=nginx).
  -- 배포판 조치안(1.22.1-9+deb12u1)과 버전 체계가 달라 자동 판정이 불가하다 → 억제하지 않는다.
  ('CVE-2021-23017','Debian:12',    'nginx',    '1.22.1-9+deb12u1'),
  -- 커널: 설치 버전 = 조치 버전이라 "이미 패치됨"으로 억제될 건이다.
  -- 하지만 실행 중인 커널은 5.14.0-427(옛 것) → 재부팅 전까지 여전히 취약하다.
  ('CVE-2024-26581','Rocky Linux:9', 'kernel',  '5.14.0-503.11.1.el9_5')
ON DUPLICATE KEY UPDATE ecosystem=VALUES(ecosystem), fixed_version=VALUES(fixed_version);
