-- 업스트림 앱(Bitnami 생태계) 시드 — "패키지 DB 도 Go 도 없는 이미지" 의 취약점이 실제로
--   매칭되는지 스모크가 검증할 근거.
--   왜 필요한가: calico 의 whisker 는 nginx(C 바이너리)만 얹은 이미지라 rpm/dpkg DB 도 Go 도
--   없다. 바이너리에서 버전을 뽑아 OSV 의 **Bitnami** 생태계로 매칭한다(BIT-nginx-… 는 CVE 를
--   alias 로 달고 있다). 이 시드가 없으면 스모크가 "업스트림 매칭이 죽었다"를 못 잡는다.
--   실제 취약점이다: HTTP/2 Rapid Reset — nginx 1.25.3 에서 고쳐졌다.
--   멱등: ON DUPLICATE KEY UPDATE.
SET NAMES utf8mb4;

INSERT INTO tb_cves (cve_id, summary, cvss, published) VALUES
  ('CVE-2023-44487', 'HTTP/2 Rapid Reset — 스트림 대량 취소로 자원 고갈(실제 악용)', 7.5, '2023-10-10')
ON DUPLICATE KEY UPDATE summary=VALUES(summary), cvss=VALUES(cvss), published=VALUES(published);

INSERT INTO tb_cve_affected_packages (cve_id, ecosystem, package_name, fixed_version) VALUES
  ('CVE-2023-44487', 'Bitnami', 'nginx', '1.25.3')
ON DUPLICATE KEY UPDATE fixed_version=VALUES(fixed_version);
