-- Rollback for 20260809184905_asset_grade_suggestion_history.sql.
-- 이력 전체가 삭제되므로 적용 전 필요한 감사 증적을 내보낸 뒤 실행한다.
DROP TABLE IF EXISTS tb_asset_grade_suggestion_history;
