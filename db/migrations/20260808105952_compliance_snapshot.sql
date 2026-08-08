-- 컴플라이언스 판정 스냅샷 — compliance.php 는 지금까지 "그때그때 판정만" 하고 저장이 없어서
--   "작년 심사 시점엔 어땠나"에 답할 수 없었다. 심사 증적의 본질은 시점이 아니라 시계열이라
--   스케줄러가 하루 1건씩 통제별 판정 결과를 여기 남긴다.
--
-- 하루 1건(snapshot_date UNIQUE) — 같은 날 두 번 돌아도 UPSERT 로 덮어쓴다.
-- evidence 는 "무엇이 위반이었나"를 되짚을 최소 식별자 목록이고 상한이 있다
--   (server/src/compliance.php 의 VG_COMPLIANCE_EVIDENCE_MAX = 500, 넘으면 truncated=true).
--   무제한 JSON 은 위반이 수천 건인 환경에서 스냅샷 행이 본 데이터보다 커진다.
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
  status_label    VARCHAR(16)  NOT NULL,           -- 준수 / 부분준수 / 미준수 (vg_compliance_status SSOT)
  violation_count INT UNSIGNED NOT NULL DEFAULT 0,
  evidence        JSON NULL,                       -- {total, truncated, items[]}
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
