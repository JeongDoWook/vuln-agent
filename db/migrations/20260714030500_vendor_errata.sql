-- 벤더 보안권고(errata) — RHEL 계열의 "이 CVE 는 이 EVR 에서 고쳐졌다" 표.
--   왜: RHEL 계열도 데비안처럼 **백포트**한다(업스트림 버전은 그대로 두고 릴리스만 올린다).
--   버전 비교만으로는 "이미 고쳐짐"과 "진짜 취약"을 구분할 수 없다.
--
--   지금까지 그 판정 근거를 **에이전트가 대상 서버에서** 긁어왔다(dnf updateinfo --with-cve →
--   tb_applied_errata). debsecan 과 똑같은 안티패턴이다 — 에이전트는 사실만 모으고 판정 지식은
--   중앙이 갖는다. 그래서 벤더 OVAL 을 중앙이 직접 받는다(데비안 트래커와 같은 구조).
--
--   소스:
--     redhat    https://security.access.redhat.com/data/oval/v2/RHEL{N}/rhel-{N}.oval.xml.bz2
--     almalinux https://security.almalinux.org/oval/org.almalinux.alsa-{N}.xml
--   Rocky 는 OSV(Rocky Linux:N)가 이미 조치 버전을 주므로 여기 넣지 않는다(중복 수집 회피).
SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS tb_vendor_errata (
  id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  vendor        VARCHAR(16)  NOT NULL,          -- redhat | almalinux
  release_major VARCHAR(8)   NOT NULL,          -- 8 | 9 …
  pkg_name      VARCHAR(255) NOT NULL,          -- 바이너리 rpm 이름
  cve_id        VARCHAR(32)  NOT NULL,
  fixed_evr     VARCHAR(128) NOT NULL,          -- 0:3.0.7-24.el9_2  (epoch:version-release)
  advisory      VARCHAR(64)  NULL,              -- RHSA-2024:1234 / ALSA-2024:1234
  severity      VARCHAR(16)  NULL,
  created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted    TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at    DATETIME NULL,
  PRIMARY KEY (id),
  -- 같은 (패키지, CVE) 가 마이너 릴리스마다 다른 EVR 로 고쳐진다(el9_2 · el9_4 …).
  --   그래서 EVR 까지 키에 넣어 **전부 보관**한다 — 하나만 남기면 다른 스트림에서 오판한다.
  UNIQUE KEY uq_vendor_errata (vendor, release_major, pkg_name, cve_id, fixed_evr),
  KEY idx_vendor_errata_lookup (vendor, release_major, pkg_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 커넥터 등록 — 하루 1회. releases 를 비우면 수집된 RHEL 계열 호스트·컨테이너에서 자동으로 뽑는다.
INSERT INTO tb_feed_connectors (name, connector_type, connection_json, schedule_json, enabled, last_status)
SELECT 'RHEL 계열 벤더 권고(OVAL)', 'rhoval',
       JSON_OBJECT('releases', JSON_ARRAY()),
       JSON_OBJECT('mode','interval','interval_minutes',1440), 1, 'never'
 WHERE NOT EXISTS (SELECT 1 FROM tb_feed_connectors WHERE connector_type = 'rhoval');
