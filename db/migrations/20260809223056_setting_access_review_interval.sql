-- 접근권한 검토 주기 설정 시드 — 컴플라이언스 통제 'access_review'(ISMS-P 2.5.3) 판정 기준.
--   검토 주기는 조직 내부 규정이라 분기(90일)·반기(180일)로 갈린다. 코드 상수
--   VG_COMPLIANCE_ACCESS_REVIEW_DAYS 는 이 행이 없을 때의 폴백으로 남는다
--   (마이그레이션이 아직 안 든 DB 에서도 같은 값으로 동작해야 한다).
--
--   컬럼은 setting_key/setting_value/description 셋뿐이다 — value_type 은
--   20260809162209_drop_unused_columns.sql 이 걷어냈다(타입 정본은 vg_setting_defs()).
--   멱등: 20260808110238_setting.sql 과 같은 형식 — 재실행해도 setting_value 는 덮지 않는다
--   (관리자가 화면에서 바꿔 둔 값이 기본값으로 되돌아가면 안 된다).
SET NAMES utf8mb4;

INSERT INTO tb_setting (setting_key, setting_value, description) VALUES
  ('compliance.access_review_interval_days', '90',
   '접근권한·접속기록 검토 주기(일). 이 주기 안에 검토 기록이 없으면 위반으로 판정.')
ON DUPLICATE KEY UPDATE
  description = VALUES(description),
  is_deleted  = 0,
  deleted_at  = NULL;
