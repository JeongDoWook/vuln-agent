-- 전역 운영 설정 테이블(tb_setting) — 조직마다 달라지는 판정 기준값을 코드에서 뺀다.
--   배경: compliance.php 의 SLA 기준일(KEV 15 / CRITICAL 30 / HIGH 60)과 부분준수 컷라인은
--   "업계 관행값이라 바뀔 일이 없다"는 전제로 상수였다. 그러나 SLA 는 조직 내부 규정이라
--   심사 기준이 조직마다 다르다 — 코드를 고쳐야 바꿀 수 있으면 제품으로 쓸 수 없다.
--   (CLAUDE.md 보안·운영 준수 원칙 1 "하드코딩 금지 / 설정으로 관리")
--
--   전역 값 하나씩만 둔다(YAGNI). 조직별·호스트별 다단계 설정은 만들지 않는다.
--   코드의 상수는 지우지 않고 "설정 행이 없을 때의 폴백"으로 남는다 — 이 마이그레이션이
--   아직 안 든 DB 에서도 지금과 똑같이 동작해야 하기 때문.
SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS tb_setting (
  setting_id    BIGINT AUTO_INCREMENT PRIMARY KEY,
  setting_key   VARCHAR(100) NOT NULL,
  setting_value VARCHAR(255) NOT NULL,
  value_type    ENUM('int','string') NOT NULL DEFAULT 'int',
  description   VARCHAR(255) NULL,
  created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted    TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at    DATETIME NULL,
  UNIQUE KEY uq_setting_key (setting_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 기본값 시드. ON DUPLICATE KEY 로 멱등하되 **setting_value 는 덮어쓰지 않는다** —
--   재실행 시 관리자가 화면에서 바꿔 둔 값이 기본값으로 되돌아가면 안 된다.
--   설명문만 최신으로 맞춘다(문구를 고쳐도 값은 보존).
INSERT INTO tb_setting (setting_key, setting_value, value_type, description) VALUES
  ('compliance.sla_kev_days',  '15', 'int', 'KEV 등재 취약점 조치 기한(일). 패치관리 통제 판정 기준.'),
  ('compliance.sla_crit_days', '30', 'int', 'CRITICAL 취약점 조치 기한(일).'),
  ('compliance.sla_high_days', '60', 'int', 'HIGH 취약점 조치 기한(일).'),
  ('compliance.partial_max',   '5',  'int', '부분준수 상한(건). 1~이 값이면 부분준수, 초과면 미준수.'),
  -- 최초 발견 시각 역산 구간 = 가장 긴 SLA + 이 여유일. 절대 일수가 아니라 "여유"인 이유:
  --   SLA 를 올려 놓고 역산 구간이 그대로면 경과일이 구간 길이에서 잘려 위반이 검출되지 않는다
  --   (= §7-1 허위 안심이 설정 실수로 재현된다). SLA 를 따라 자동으로 늘어나게 묶어 둔다.
  ('compliance.history_lookback_margin_days', '14', 'int', '최초 발견 시각 역산 구간의 여유일(가장 긴 SLA + 이 값).')
ON DUPLICATE KEY UPDATE
  value_type  = VALUES(value_type),
  description = VALUES(description),
  is_deleted  = 0,
  deleted_at  = NULL;
