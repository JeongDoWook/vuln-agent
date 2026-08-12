-- 접속기록 "월 1회 점검" 기능 제거 — 그 기능만 쓰던 테이블·설정을 걷어낸다.
--   화면(activity.php 의 점검 폼·이력·미점검 배너)과 컴플라이언스 자동판정 통제
--   'access_review'(ISMS-P 2.5.3)가 함께 제거됐다. 그 통제는 증적이 제품 밖(검토 승인이력)에
--   있는 항목이라 VG_COMPLIANCE_MANUAL_CHECKLIST(수동 심사)로 내려갔다.
--   과거 감사로그 행의 'activity_review_save' 코드는 그대로 남는다(라벨도 nav.php 에 남긴다).
--   멱등: DROP TABLE IF EXISTS · DELETE 는 없으면 0행.

DROP TABLE IF EXISTS tb_activity_review;

-- 이 설정은 위 통제의 판정 기준(검토 주기)에만 쓰였다 — 읽는 코드가 남지 않았다.
DELETE FROM tb_setting WHERE setting_key = 'compliance.access_review_interval_days';
