-- 소스코드 저장소 주소 설정(app.source_url) — AGPL-3.0 제13조 실효화.
--   AGPL 은 "네트워크로 이 소프트웨어를 이용한 사람에게도 소스를 제공하라"고 요구한다.
--   화면 하단의 "소스코드 (AGPL-3.0)" 링크가 그 통로인데, 포크해 배포하는 쪽은 자기
--   저장소를 가리켜야 하므로 주소를 코드에 박을 수 없다(CLAUDE.md 원칙 1 하드코딩 금지).
--
--   컬럼은 setting_key/setting_value/description 셋뿐이다 — value_type 은
--   20260809162209_drop_unused_columns.sql 이 걷어냈다(타입 정본은 vg_setting_defs()).
--   멱등: 기존 시드와 같은 형식 — 재실행해도 setting_value 는 덮지 않는다(관리자가
--   설정 화면에서 바꿔 둔 주소가 기본값으로 되돌아가면 안 된다).
--   이 행이 없어도 화면은 죽지 않는다 — server/src/view/layout.php 의 VG_SOURCE_URL 이 폴백이다.
SET NAMES utf8mb4;

INSERT INTO tb_setting (setting_key, setting_value, description) VALUES
  ('app.source_url', 'https://github.com/JeongDoWook/vuln-agent',
   '화면 하단 "소스코드 (AGPL-3.0)" 링크가 가리키는 저장소 주소(AGPL 제13조).')
ON DUPLICATE KEY UPDATE
  description = VALUES(description),
  is_deleted  = 0,
  deleted_at  = NULL;
