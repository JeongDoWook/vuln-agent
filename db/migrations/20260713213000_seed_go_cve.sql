-- Go 생태계 시드 — "컨테이너의 Go 의존성 취약점" 이 실제로 매칭되는지 스모크가 검증할 근거.
--   왜 필요한가: 패키지 DB 가 없는 이미지(Calico 등)와, DB 는 있어도 알맹이가 Go 인 이미지
--   (kube-apiserver: dpkg 4개 vs Go 의존 248개)의 취약점은 **Go 생태계로만** 잡힌다.
--   이 시드가 없으면 스모크가 "Go 매칭이 죽었다"를 못 잡는다.
--   실제 취약점이다(OSV 확인): golang.org/x/net 은 0.23.0 에서 고쳐졌고 v0.20.0 은 취약하다.
--   멱등: ON DUPLICATE KEY UPDATE.
SET NAMES utf8mb4;

INSERT INTO tb_cves (cve_id, summary, cvss, published) VALUES
  ('CVE-2023-45288', 'golang.org/x/net HTTP/2 — 과도한 헤더로 자원 고갈(DoS)', 5.3, '2024-04-04')
ON DUPLICATE KEY UPDATE summary=VALUES(summary), cvss=VALUES(cvss), published=VALUES(published);

INSERT INTO tb_cve_affected_packages (cve_id, ecosystem, package_name, fixed_version) VALUES
  ('CVE-2023-45288', 'Go', 'golang.org/x/net', '0.23.0')
ON DUPLICATE KEY UPDATE fixed_version=VALUES(fixed_version);
