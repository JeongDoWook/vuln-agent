-- Red Hat "아직 안 고친" CVE — 조치 불가 취약점.
--   OVAL(tb_vendor_errata)엔 **수정본이 나온 것(RHSA)만** 있다. 그래서 Red Hat 이
--   "영향받음 / 고치지 않겠다 / 조사 중 / 지원 종료" 로 표시한 CVE 는 우리가 통째로 못 봤다
--   (실측 UBI8: Trivy 523건 중 514건이 이것 — 수정본이 있는 9건은 우리도 정확히 9건 잡았다).
--
--   이건 오탐이 아니라 **미탐**이다. 다만 성격이 다르다 — **패치가 존재하지 않는다.**
--   그래서 findings 에 no_fix 로 표시해 "지금 고칠 수 있는 것" 과 화면에서 분리한다.
--   섞으면 조치 불가 500건이 고칠 수 있는 9건을 덮어버린다.
--
--   소스: access.redhat.com/hydra/rest/securitydata (CVE 상세 3KB — CSAF VEX 는 587KB 라 못 쓴다)
--   판정 단위는 **컴포넌트(소스 패키지)** 다. Red Hat 은 bzip2 로 상태를 매기고, 우리는 그걸
--   설치된 바이너리(bzip2-libs …)에 펼친다. Trivy 도 같은 방식이다.
SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS tb_vendor_unfixed (
  id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  vendor        VARCHAR(16)  NOT NULL,          -- redhat
  release_major VARCHAR(8)   NOT NULL,          -- 8 | 9 …
  component     VARCHAR(255) NOT NULL,          -- 소스 패키지명(bzip2)
  cve_id        VARCHAR(32)  NOT NULL,
  -- Affected | Fix deferred | Will not fix | Under investigation | Out of support scope | Not affected
  --   'Not affected' 도 저장한다 — 다시 조회하지 않기 위한 캐시다(재실행마다 수천 건을 또 받지 않는다).
  fix_state     VARCHAR(32)  NOT NULL,
  severity      VARCHAR(16)  NULL,
  cvss          DECIMAL(3,1) NULL,
  checked_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted    TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at    DATETIME NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_vendor_unfixed (vendor, release_major, component, cve_id),
  KEY idx_vendor_unfixed_lookup (vendor, release_major, component)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- findings 에 "조치 불가" 표시. 등급은 그대로 두고(런타임 노출 기준) 별도 축으로 구분한다 —
--   조치 불가라고 덜 위험한 게 아니라, **지금 할 수 있는 일이 없다**는 뜻이다.
SET @has := (SELECT COUNT(*) FROM information_schema.COLUMNS
              WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_findings' AND COLUMN_NAME = 'no_fix');
SET @sql := IF(@has = 0,
  'ALTER TABLE tb_findings ADD COLUMN no_fix TINYINT(1) NOT NULL DEFAULT 0 AFTER needs_restart',
  'SELECT 1');
PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;

-- 커넥터 등록 — 하루 1회. OVAL(rhoval)이 먼저 돌아야 "이미 고쳐진 CVE" 를 건너뛸 수 있다.
INSERT INTO tb_feed_connectors (name, connector_type, connection_json, schedule_json, enabled, last_status)
SELECT 'Red Hat 미수정 CVE(조치 불가)', 'rhunfixed',
       JSON_OBJECT(),
       JSON_OBJECT('mode','interval','interval_minutes',1440), 1, 'never'
 WHERE NOT EXISTS (SELECT 1 FROM tb_feed_connectors WHERE connector_type = 'rhunfixed');
