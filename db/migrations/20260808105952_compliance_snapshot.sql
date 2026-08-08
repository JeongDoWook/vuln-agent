-- 컴플라이언스 판정 스냅샷 — compliance.php 는 지금까지 "그때그때 판정만" 하고 저장이 없어서
--   "작년 심사 시점엔 어땠나"에 답할 수 없었다. 심사 증적의 본질은 시점이 아니라 시계열이라
--   스케줄러가 하루 1건씩 통제별 판정 결과를 여기 남긴다.
--
-- 하루 1건(snapshot_date UNIQUE) — 같은 날 두 번 돌아도 UPSERT 로 덮어쓴다.
-- evidence 는 "무엇이 위반이었나"를 되짚을 최소 식별자 목록이고 상한이 있다
--   (server/src/compliance.php 의 VG_COMPLIANCE_EVIDENCE_MAX = 500, 넘으면 truncated=true).
--   무제한 JSON 은 위반이 수천 건인 환경에서 스냅샷 행이 본 데이터보다 커진다.
--
-- unjudged_count 는 **판정 불가** 건수다. 위반 건수만 저장하면 "근거가 모자라 판정을 못 했다"는
--   사실이 증적에서 사라지고, 나중에 그 스냅샷을 "위반 0건 = 준수"로 되읽게 된다(허위 안심).
--   화면(vg_compliance_status)이 위반 0건 + 판정 불가 존재를 "판정 불가"로 내는 것과 짝이다.
SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS tb_compliance_snapshot (
  compliance_snapshot_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  snapshot_date DATE     NOT NULL,                 -- 판정 기준일(하루 1건)
  taken_at      DATETIME NOT NULL,                 -- 실제 판정을 돌린 시각
  created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted    TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at    DATETIME NULL,
  PRIMARY KEY (compliance_snapshot_id),
  UNIQUE KEY uk_compliance_snapshot_date (snapshot_date),
  KEY idx_compliance_snapshot_live (is_deleted, snapshot_date)   -- 추이 조회(최근 N일) 전용
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS tb_compliance_snapshot_control (
  compliance_snapshot_control_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  compliance_snapshot_id BIGINT UNSIGNED NOT NULL,
  control_key     VARCHAR(32)  NOT NULL,           -- patch / asset / secops (VG_COMPLIANCE_CONTROLS 키)
  framework_ids   VARCHAR(128) NOT NULL,           -- 예: 'ISMS-P 2.10.8 / ISO 27001 A.8.8'
  status_label    VARCHAR(16)  NOT NULL,           -- 준수 / 판정 불가 / 부분준수 / 미준수 (vg_compliance_status SSOT)
  violation_count INT UNSIGNED NOT NULL DEFAULT 0,
  unjudged_count  INT UNSIGNED NOT NULL DEFAULT 0, -- 판정 불가 건수(위반도 준수도 아닌 것)
  evidence        JSON NULL,                       -- {total, truncated, items[], unjudged{…}}
  created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted      TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at      DATETIME NULL,
  PRIMARY KEY (compliance_snapshot_control_id),
  UNIQUE KEY uk_compliance_snapshot_control (compliance_snapshot_id, control_key),
  KEY idx_compliance_snapshot_control_key (control_key, compliance_snapshot_id),
  CONSTRAINT fk_compliance_snapshot_control_snap FOREIGN KEY (compliance_snapshot_id)
      REFERENCES tb_compliance_snapshot(compliance_snapshot_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 이 파일의 이전 판(unjudged_count 가 없던 버전)을 이미 적용한 DB 를 위한 보강.
--   러너는 파일명 기준이라 내용이 바뀌어도 재실행하지 않는다 — 그래도 멱등하게 두면
--   재실행/신규 생성 어느 경로로 와도 스키마가 같아진다.
SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE()
             AND TABLE_NAME   = 'tb_compliance_snapshot_control'
             AND COLUMN_NAME  = 'unjudged_count');
SET @s := IF(@c = 0,
             'ALTER TABLE tb_compliance_snapshot_control
                ADD COLUMN unjudged_count INT UNSIGNED NOT NULL DEFAULT 0 AFTER violation_count',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
