-- 우분투에도 **벤더 판정**을 붙인다. 지금까지 우분투만 비어 있었다.
--
--   데비안엔 보안 트래커, RHEL 계열엔 OVAL + 미수정 CVE 피드가 있는데 우분투는 OSV 뿐이었다.
--   우분투도 백포트를 하므로(1.2-3ubuntu0.1) 버전만 보면 오탐이 남고, "벤더가 아직 안 고쳤나"
--   (조치 불가)를 알 방법도 없었다.
--   실측(deskmini-x300, Ubuntu 24.04): 억제 765건. 같은 규모의 데비안 호스트는 4,135건이다.
--
--   Canonical 이 릴리스별 CVE OVAL 을 낸다(security-metadata.canonical.com, noble 7.4MB bz2).
--   한 파일이 두 축을 다 준다:
--     · 테스트에 state 가 있으면  → 그 EVR 미만이 취약(= 조치 버전이 있다)
--     · 테스트에 state 가 없으면  → "패키지가 있으면 취약"(= 아직 수정본 없음 → 조치 불가)
--   그래서 fixed_evr 을 NULL 로 둘 수 있게 만든다 — NULL 이 곧 "조치 불가" 다.
SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS tb_ubuntu_oval (
  id               BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  release_codename VARCHAR(32)  NOT NULL,   -- noble | jammy | focal …
  pkg_name         VARCHAR(255) NOT NULL,   -- **바이너리** 패키지명(perl-base …)
  cve_id           VARCHAR(32)  NOT NULL,
  fixed_evr        VARCHAR(128) NULL,       -- 0:5.38.2-3.2ubuntu0.1 · NULL = 아직 수정본 없음
  severity         VARCHAR(16)  NULL,
  created_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted       TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at       DATETIME NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_ubuntu_oval (release_codename, pkg_name, cve_id),
  KEY idx_ubuntu_oval_lookup (release_codename, pkg_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 커넥터 등록 — 하루 1회. releases 를 비우면 수집된 우분투 호스트·컨테이너에서 자동으로 뽑는다.
INSERT INTO tb_feed_connectors (name, connector_type, connection_json, schedule_json, enabled, last_status)
SELECT '우분투 보안 OVAL', 'ubuntuoval',
       JSON_OBJECT('releases', JSON_ARRAY()),
       JSON_OBJECT('mode','interval','interval_minutes',1440), 1, 'never'
 WHERE NOT EXISTS (SELECT 1 FROM tb_feed_connectors WHERE connector_type = 'ubuntuoval');
