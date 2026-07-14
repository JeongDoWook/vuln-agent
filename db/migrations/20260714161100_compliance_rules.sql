-- 보안설정 점검(CCE) 룰을 **검증된 룰셋에 묶는다** — SCAP Security Guide(SSG).
--
--   지금까지 점검 룰은 우리가 코드에 직접 써 넣었다(server/src/cce.php 385줄). 이유는 있었다 —
--   MITRE CCE 사전은 2013년경 갱신이 끊겼고, KISA 가이드는 PDF/HWP 로만 나온다(API 없음).
--   하지만 그러면 "이 항목이 왜 중요한가 / 어느 기준에 근거하나" 를 우리가 지어내는 셈이다.
--
--   SSG(ComplianceAsCode)는 오픈소스 룰셋이고, 룰마다 **CIS·NIST 800-53·STIG·PCI-DSS 참조**와
--   제목·근거(rationale)를 갖고 있다. 그걸 카탈로그로 받아, 우리 점검을 그 룰 ID 에 묶는다.
--   → 룰의 정체·근거·기준 매핑은 **검증된 소스**가 갖고, 우리는 수집값으로 판정만 한다.
--
--   솔직한 한계: 판정 로직(OVAL)까지 중앙에서 돌리진 못한다. OVAL 은 살아 있는 파일시스템을
--   프로브하는데, 우리는 에이전트가 보낸 사실만 갖고 있고 대상 서버엔 아무것도 설치하지 않는다.
--   그래서 **우리가 판정할 수 있는 룰만** 묶고, 나머지는 "수집 항목 없음(판정 불가)" 으로 드러낸다.
SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS tb_compliance_rules (
  id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  rule_id     VARCHAR(191) NOT NULL,          -- SSG 룰 ID(디렉터리명): sshd_disable_empty_passwords
  title       VARCHAR(255) NOT NULL,
  severity    VARCHAR(16)  NOT NULL,          -- high | medium | low | unknown (SSG 표기)
  rationale   TEXT NULL,                      -- 왜 필요한가(SSG 원문)
  refs_json   JSON NULL,                      -- {"cis@rhel9":"5.2.11","nist":"AC-17(a)","stig":"..."}
  ssg_version VARCHAR(16) NULL,               -- 어느 릴리스에서 받았나(v0.1.81)
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted  TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at  DATETIME NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_compliance_rule (rule_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 우리 점검 결과를 SSG 룰에 묶는다. 비어 있으면 아직 매핑되지 않은(=우리만의) 점검이다.
SET @has := (SELECT COUNT(*) FROM information_schema.COLUMNS
              WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_cce_findings' AND COLUMN_NAME = 'ssg_rule_id');
SET @sql := IF(@has = 0,
  'ALTER TABLE tb_cce_findings ADD COLUMN ssg_rule_id VARCHAR(191) NULL AFTER code',
  'SELECT 1');
PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;

-- 커넥터 등록 — 룰셋은 자주 안 바뀐다(릴리스 단위). 주 1회면 충분하다.
INSERT INTO tb_feed_connectors (name, connector_type, connection_json, schedule_json, enabled, last_status)
SELECT 'SCAP Security Guide(보안설정 룰셋)', 'ssg',
       JSON_OBJECT(),
       JSON_OBJECT('mode','interval','interval_minutes',10080), 1, 'never'
 WHERE NOT EXISTS (SELECT 1 FROM tb_feed_connectors WHERE connector_type = 'ssg');
