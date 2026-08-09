-- 코드가 읽지도 쓰지도 않는 컬럼 3개 제거(YAGNI).
--   dev DB 51개 테이블 594개 컬럼을 코드 토큰과 대조해 확인한 결과다.
--
--   1) tb_finding.matched_at / tb_suppressed_finding.matched_at
--      INSERT 에 명시된 적도, SELECT 된 적도 없다. 판정 시각은 부모 스캔(tb_scan)의 시각으로
--      이미 정해지고(매처가 스캔마다 DELETE+INSERT 로 재작성), 화면·API 어디도 이 컬럼을 안 본다.
--   2) tb_setting.value_type
--      settings.php 의 INSERT 에만 등장하는 **쓰기 전용** 컬럼이다. 읽는 곳이 한 군데도 없고,
--      타입 구분은 vg_setting_defs() 의 'type' 이 정본이라 DB 에 중복으로 둘 이유가 없다.
--      (같은 커밋에서 settings.php 의 INSERT 컬럼 목록·바인딩에서도 뺐다.)
--
--   되돌리기는 docs/dev/drop-unused-columns-rollback.sql 에 남겼다(migrate.sh 는 up 만 적용한다).
--   멱등성: information_schema 로 존재할 때만 DROP 한다 — 두 번 돌아도 안전하다.
SET NAMES utf8mb4;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='tb_finding' AND COLUMN_NAME='matched_at');
SET @s := IF(@c=1, 'ALTER TABLE tb_finding DROP COLUMN matched_at', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='tb_suppressed_finding' AND COLUMN_NAME='matched_at');
SET @s := IF(@c=1, 'ALTER TABLE tb_suppressed_finding DROP COLUMN matched_at', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='tb_setting' AND COLUMN_NAME='value_type');
SET @s := IF(@c=1, 'ALTER TABLE tb_setting DROP COLUMN value_type', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
