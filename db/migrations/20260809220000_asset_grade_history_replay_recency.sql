-- #542 후속: 동일 결과 replay 의 "마지막 관찰 시각"을 행을 늘리지 않고 보존한다.
--
-- 왜 컬럼이 둘로 갈리나
--   source_collected_at / observed_at 은 **그 결과를 처음 본 시각**이다(변하지 않는 사실).
--   last_source_collected_at / last_observed_at 은 **같은 결과를 마지막으로 다시 본 시각**이다.
--   유일키(host_id, scan_id, result_fingerprint) 로 replay 는 행이 늘지 않으므로, 마지막 관찰을
--   따로 두지 않으면 "아직도 같은 상태다"라는 정보가 통째로 사라진다.
--
-- 왜 7일 클램프인가 (effective_at)
--   source_collected_at 은 에이전트가 보고한 값이라 **신뢰 경계 밖**이다. 노드 시계가 어긋나
--   과거로 크게 밀린 값이 들어오면 effective_at 정렬이 뒤집혀, 오래된 관찰이 최신 제안을
--   덮어쓴다. 그렇다고 서버 시각만 쓰면 오프라인 노드가 밀린 보고를 올렸을 때 실제 수집
--   순서를 잃는다.
--   그래서 "서버가 본 시각 기준 7일 이전"을 하한으로 둔다. 7 은 에이전트가 지원하는 가장 긴
--   수집 주기(install-agent.sh 의 daily = 86400초)의 7배다 — 한 주 내내 끊겼던 노드의 정직한
--   지연 보고까지는 실제 수집 시각대로 정렬하고, 그보다 더 과거인 값은 시계 오류·리플레이로
--   보아 서버 관찰 시각 쪽으로 끌어올린다.
--   이 값은 STORED 생성컬럼 식에 박히므로 설정으로 뺄 수 없다(바꾸려면 테이블 재구축).
--   PHP 쪽 동일 기준은 server/src/assetgrade_history.php 의 VG_ASSET_GRADE_RECENCY_CLAMP_DAYS
--   이며, tests/assetgrade_history_test.php 가 두 값이 어긋나면 실패시킨다.
--
-- 멱등성: 컬럼·인덱스는 information_schema 로 존재 검사하고, effective_at 재정의는 생성식이
--   이미 last_observed_at 을 참조하면 통째로 건너뛴다(재실행이 테이블을 재구축하지 않는다).
SET NAMES utf8mb4;

-- (1) 마지막 관찰 컬럼 추가.
SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='tb_asset_grade_suggestion_history'
    AND COLUMN_NAME='last_source_collected_at');
SET @s := IF(@c=0,
  'ALTER TABLE tb_asset_grade_suggestion_history
     ADD COLUMN last_source_collected_at DATETIME NULL
       COMMENT ''같은 결과를 마지막으로 다시 본 에이전트 수집 시각'' AFTER observed_at',
  'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='tb_asset_grade_suggestion_history'
    AND COLUMN_NAME='last_observed_at');
SET @s := IF(@c=0,
  'ALTER TABLE tb_asset_grade_suggestion_history
     ADD COLUMN last_observed_at DATETIME NULL
       COMMENT ''같은 결과를 마지막으로 다시 본 서버 관찰 시각'' AFTER last_source_collected_at',
  'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- (2) 기존 행 백필 — 최초 관찰이 곧 마지막 관찰이다. NOT NULL 로 조이기 전에 채워야 한다.
--     이미 채워진 재실행에서는 0행이 걸린다.
UPDATE tb_asset_grade_suggestion_history
   SET last_source_collected_at = COALESCE(last_source_collected_at, source_collected_at),
       last_observed_at         = COALESCE(last_observed_at, observed_at)
 WHERE last_observed_at IS NULL;

-- (3) effective_at 재정의 + 인덱스 갱신. 이미 새 식이면 (3) 전체가 무동작.
SET @done := (SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='tb_asset_grade_suggestion_history'
    AND COLUMN_NAME='effective_at' AND GENERATION_EXPRESSION LIKE '%last_observed_at%');

-- 생성컬럼을 참조하는 인덱스가 남아 있으면 DROP COLUMN 이 거부된다 — 인덱스를 먼저 지운다.
SET @c := (SELECT COUNT(*) FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='tb_asset_grade_suggestion_history'
    AND INDEX_NAME='idx_asset_grade_suggestion_host_time');
SET @s := IF(@done=0 AND @c>0,
  'ALTER TABLE tb_asset_grade_suggestion_history DROP INDEX idx_asset_grade_suggestion_host_time',
  'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='tb_asset_grade_suggestion_history'
    AND COLUMN_NAME='effective_at');
SET @s := IF(@done=0 AND @c>0,
  'ALTER TABLE tb_asset_grade_suggestion_history DROP COLUMN effective_at',
  'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @s := IF(@done=0,
  'ALTER TABLE tb_asset_grade_suggestion_history
     MODIFY last_observed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
       COMMENT ''같은 결과를 마지막으로 다시 본 서버 관찰 시각'',
     ADD COLUMN effective_at DATETIME GENERATED ALWAYS AS
       (LEAST(GREATEST(COALESCE(last_source_collected_at, last_observed_at),
                       DATE_SUB(last_observed_at, INTERVAL 7 DAY)), last_observed_at)) STORED
       AFTER last_observed_at,
     ADD INDEX idx_asset_grade_suggestion_host_time
       (host_id, effective_at, last_observed_at, suggestion_history_id)',
  'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
