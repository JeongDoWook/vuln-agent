-- "저장된 보기"(사용자별 저장 필터) 기능 전면 제거 — 테이블도 함께 DROP.
-- 쓰이지 않는 기능이라 사용자 확인을 받고 걷어냈다(YAGNI). 저장 UI·삭제 UI 가 없어
--   실제로 쌓인 데이터도 없다시피 했고, 화면에선 필터가 하나 더 있는 것처럼 보였다.
-- 되돌릴 수 없다: DROP 이므로 남아 있던 행은 복구되지 않는다(백업에서만 복원 가능).
-- 옛 이름 tb_saved_views 도 함께 정리한다 — 20260726115611_pk_naming_unification.sql 이
--   단수형으로 rename 하기 전 이름이라, 환경에 따라 둘 중 어느 쪽이 남아 있을 수 있다.

DROP TABLE IF EXISTS tb_saved_view;
DROP TABLE IF EXISTS tb_saved_views;
