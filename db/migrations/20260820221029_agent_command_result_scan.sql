-- 명령 → 그 명령이 만들어 낸 스캔 연결.
--
--   왜 필요한가: 중앙이 `verify_files=1` 로 명령을 걸었는데 **그 명령으로 생성된 스캔의
--   `integrity_checked` 가 0** 이면, 그 노드의 에이전트는 무결성 검사를 지원하지 않는다는
--   뜻이다(옛 run.sh 가 `--verify-files` 를 안 붙였다). 지금까지는 명령과 스캔을 잇는 키가
--   없어 그 사실을 판정할 수 없었고, 명령은 done 으로 닫히고 화면은 "미수행" 이라 **조용한
--   실패**가 됐다. 시각으로 어림잡지 않고 ingest.php 가 이미 아는 값을 그대로 저장한다.
--
--   FK 는 걸지 않는다 — 이 컬럼은 "그때 무엇이 만들어졌나"를 남기는 감사 성격이라
--   (created_by 와 같은 관례) 스캔 정리·삭제와 수명을 묶지 않는다. 스캔이 사라지면 조인이
--   비고, 화면은 "판정 근거 없음" 으로 조용히 떨어진다(잘못된 단정보다 낫다).
SET NAMES utf8mb4;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='tb_agent_command' AND COLUMN_NAME='result_scan_id');
SET @s := IF(@c=0, "ALTER TABLE tb_agent_command ADD COLUMN result_scan_id BIGINT UNSIGNED NULL COMMENT '이 명령의 결과로 저장된 tb_scan.scan_id (ingest 가 채운다, FK 없음)' AFTER executed_at", 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
