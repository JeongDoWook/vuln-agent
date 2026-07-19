-- cves.php 검색(q) 성능 개선 — tb_cves.summary FULLTEXT 인덱스.
--   왜: 기존 `summary LIKE '%q%'` 는 와일드카드 선두라 인덱스를 못 타 전체 스캔이었다
--   (summary 는 MEDIUMTEXT). 샘플 확인 결과(2026-07-19, 25772행) summary 는 NVD/OSV 원문 그대로라
--   영문 위주다(예: "Execute commands as root via buffer overflow ...") — 한글/짧은 토큰용
--   ngram 파서는 과설계라 기본(영문) 파서로 충분하다. 최근 추가된 summary_ko(번역본,
--   20260718113107_cve_summary_ko.sql)는 이번 검색 범위에 포함하지 않는다 — 이번 작업 스코프 아님.
--   멱등: information_schema 확인 후에만 추가(기존 마이그레이션 관례와 동일).
SET NAMES utf8mb4;

-- 이 테이블의 '첫' FULLTEXT 인덱스라 InnoDB 가 숨은 FTS_DOC_ID 컬럼을 위해 테이블을 재구축한다.
--   ALGORITHM=INPLACE 라도 동시 DML 은 못 받는다(사실상 쓰기 잠금) — LOCK=SHARED 로 의도를
--   드러내고, 수집 잡이 쓰기 중이면 조용히 기다리는 대신 즉시 실패하게 한다. 지금(2.5만행)은
--   짧게 끝나지만 운영 볼륨이 커지면 점검창 배포를 고려할 것.
SET @c := (SELECT COUNT(*) FROM information_schema.STATISTICS
           WHERE TABLE_SCHEMA = DATABASE()
             AND TABLE_NAME   = 'tb_cves'
             AND INDEX_NAME   = 'ft_cves_summary'
             AND INDEX_TYPE   = 'FULLTEXT');
SET @s := IF(@c = 0,
             'ALTER TABLE tb_cves ADD FULLTEXT KEY ft_cves_summary (summary), ALGORITHM=INPLACE, LOCK=SHARED',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
