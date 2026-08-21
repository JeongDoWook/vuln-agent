-- AI 보고서 외부 연동을 "기본 꺼짐"으로 내리면서, **이미 쓰고 있던 곳만** 그대로 켜 둔다.
--
--   배경: server/src/report_job.php 의 VG_REPORT_API_BASE_URL 은 'http://172.17.0.1:8000'
--   이었고, 설정(tb_setting.report.api_base_url) 행이 없으면 이 상수가 폴백으로 쓰였다.
--   즉 설정 행이 없는 운영 환경도 지금 이 주소로 동작한다. 상수를 빈 문자열(= 연동 꺼짐)로
--   바꾸는 순간 그 환경이 조용히 꺼지므로, 쓰던 주소를 설정 행으로 한 번 옮겨 담는다.
--
--   왜 무조건 넣지 않고 EXISTS 로 거르나: 이 마이그레이션은 **빈 DB 에도 전부 적용된다**
--   (initdb 후 migrate.sh 가 미적용분을 처음부터 다 돌린다). 무조건 넣으면 저장소를 클론해
--   처음 띄운 사람에게까지 외부 주소가 심겨 "닿지 않는 서버를 가리키는 버튼"이 화면에 뜬다 —
--   기본 꺼짐으로 내리는 이 작업의 목적이 정확히 그것을 없애는 것이다. 그래서 **이미 보고서
--   작업을 만들어 본 설치**(tb_report_job 에 행이 있다 = 연동을 실제로 쓰고 있었다)에만 넣는다.
--   그 밖의 설치는 꺼진 채로 시작하고, 필요하면 설정 화면에서 주소를 넣어 켠다.
--
--   멱등: 같은 키의 행이 이미 있으면 **setting_value 를 덮지 않는다**(관리자가 화면에서
--   바꿔 둔 주소가 옛 기본값으로 되돌아가면 안 된다 — 20260808110238_setting.sql 과 같은 판단).
--   is_deleted 는 건드리지 않는다: 이 키에서 "안 쓴다"는 상태를 사람이 만들어 뒀을 수 있는데
--   재적용이 그걸 되살리면 꺼 둔 연동이 혼자 켜진다.
SET NAMES utf8mb4;

INSERT INTO tb_setting (setting_key, setting_value, description)
SELECT 'report.api_base_url', 'http://172.17.0.1:8000',
       '보고서 작업큐 API 의 base URL. 비우면 AI 보고서 연동을 사용하지 않습니다(기본).'
  FROM DUAL
 WHERE EXISTS (SELECT 1 FROM tb_report_job)
ON DUPLICATE KEY UPDATE description = VALUES(description);
