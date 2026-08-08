-- 자산 중요도·보안등급(N2SF) 필드 — ISMS-P 1.2.1 "중요도를 산정한 후 목록을 최신으로 관리".
--
--   지금까지 자산은 있지만 **등급이 없어서** 자산식별 통제가 "필드 누락 여부"만 보는 얕은 판정에
--   머물렀다. 여기서 호스트에 중요도(criticality)와 N2SF 등급(C/S/O)을 붙인다.
--
--   ※ 핵심 경계 — "판정은 사람이, 초안은 시스템이".
--     등급 판정 기준은 「정보공개법」 제9조 비공개 대상정보의 호 매핑이고, **업무정보 등급 확정은
--     기관의 법적 처분**이라 시스템이 대신할 수 없다. 그래서 컬럼을 둘로 나눈다.
--       · grade / grade_reason / approved_by / approved_at  ← **사람이 확정한 값**
--       · grade_suggested / grade_suggested_reason          ← **시스템이 만든 초안 제안**
--     같은 칸에 쓰면 "시스템이 등급을 정했다"가 되어 이 경계가 무너진다. 화면도 제안값에는
--     '제안' 표기를 붙여 확정값과 섞이지 않게 한다.
--
--   멱등성: MySQL 8 은 ADD COLUMN ... IF NOT EXISTS 가 없다. 같은 저장소의
--   20260726115611_pk_naming_unification.sql·20260806115810_agent_speed_tier.sql 이 쓰는
--   information_schema 가드 패턴을 그대로 따른다 — 두 번 돌아도 안전하다.
SET NAMES utf8mb4;

-- ── 중요도(자산 자체의 업무 중요도) ────────────────────────────────────────
--   값 3종은 바뀔 일이 없는 고정 어휘라 ENUM 으로 못 박는다(고정 5종 피드 매핑과 같은 원칙).
--   라벨(상/중/하)은 PHP 상수 VG_ASSET_CRITICALITY 가 소유한다.
SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_host' AND COLUMN_NAME = 'criticality');
SET @s := IF(@c = 0,
  "ALTER TABLE tb_host ADD COLUMN criticality ENUM('HIGH','MEDIUM','LOW') NULL AFTER os_version",
  'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- ── 확정 등급(사람) ────────────────────────────────────────────────────────
SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_host' AND COLUMN_NAME = 'grade');
SET @s := IF(@c = 0,
  "ALTER TABLE tb_host ADD COLUMN grade CHAR(1) NULL COMMENT 'N2SF 등급 C(기밀)/S(민감)/O(공개) — 사람이 확정' AFTER criticality",
  'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_host' AND COLUMN_NAME = 'grade_reason');
SET @s := IF(@c = 0,
  "ALTER TABLE tb_host ADD COLUMN grade_reason VARCHAR(255) NULL COMMENT '확정 근거(정보공개법 제9조 호 등)' AFTER grade",
  'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- ── 승인 이력 — 누가 언제 확정했나 ────────────────────────────────────────
SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_host' AND COLUMN_NAME = 'approved_by');
SET @s := IF(@c = 0,
  "ALTER TABLE tb_host ADD COLUMN approved_by BIGINT UNSIGNED NULL COMMENT '확정한 사용자(tb_user.user_id)' AFTER grade_reason",
  'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_host' AND COLUMN_NAME = 'approved_at');
SET @s := IF(@c = 0,
  "ALTER TABLE tb_host ADD COLUMN approved_at DATETIME NULL COMMENT '확정 시각' AFTER approved_by",
  'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- 확정자 FK. 사용자를 지우면(소프트삭제라 실제로는 드물다) 이력만 끊고 등급은 남긴다 → SET NULL.
SET @c := (SELECT COUNT(*) FROM information_schema.TABLE_CONSTRAINTS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_host'
             AND CONSTRAINT_NAME = 'fk_host_grade_approver');
SET @s := IF(@c = 0,
  'ALTER TABLE tb_host ADD CONSTRAINT fk_host_grade_approver
     FOREIGN KEY (approved_by) REFERENCES tb_user(user_id) ON DELETE SET NULL',
  'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- ── 시스템 초안 제안(사람 확정과 분리 보관) ────────────────────────────────
SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_host' AND COLUMN_NAME = 'grade_suggested');
SET @s := IF(@c = 0,
  "ALTER TABLE tb_host ADD COLUMN grade_suggested CHAR(1) NULL COMMENT '시스템 초안 제안 — 확정값 아님' AFTER approved_at",
  'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_host' AND COLUMN_NAME = 'grade_suggested_reason');
SET @s := IF(@c = 0,
  "ALTER TABLE tb_host ADD COLUMN grade_suggested_reason VARCHAR(255) NULL COMMENT '제안 근거(수집 데이터 인용)' AFTER grade_suggested",
  'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- ── 목록 등급 필터용 인덱스 ────────────────────────────────────────────────
--   assets.php 는 늘 is_deleted = 0 을 함께 걸므로 그 순서로 복합 인덱스를 만든다.
SET @c := (SELECT COUNT(*) FROM information_schema.STATISTICS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_host' AND INDEX_NAME = 'idx_host_grade');
SET @s := IF(@c = 0, 'ALTER TABLE tb_host ADD INDEX idx_host_grade (is_deleted, grade)', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
