-- tb_finding 의 통계 샘플 페이지를 20(기본) → 200 으로 올린다.
--
-- 왜: 대시보드가 1.92초였고 그 중 74.1%(1,554ms)가 index.php:218 의 추세 High 집계 하나였다.
--   느린 이유는 인덱스가 없어서가 아니라 **옵티마이저가 인덱스를 잘못 골라서**다 —
--   idx_find_scan_sev(scan_id, severity) 라는 딱 맞는 커버링 인덱스를 두고 uq_find 를 타서
--   32,114행이 필요한데 1,180,214행을 읽고 97%를 버렸다.
--
--   뿌리는 통계였다. InnoDB 기본값은 테이블 크기와 무관하게 20페이지만 샘플링하는데,
--   운영 tb_finding 은 143만행이라 표본이 너무 얕아 uq_find 의 scan_id distinct 를
--   6,962 로 봤다(실제 456 — 15배 과대). 그러면 "scan_id 하나당 206행" 으로 계산돼
--   틀린 계획이 싸 보인다. ANALYZE TABLE 은 이미 자동으로 돌고 있었다(auto_recalc=1) —
--   재계산을 안 해서가 아니라 **표본이 작아서** 틀린 것이라 ANALYZE 만으로는 안 고쳐졌다
--   (운영에서 실제로 돌려 확인: 1,574ms → 1,567ms, 계획 그대로).
--
-- 효과 (운영 실측 2026-08-16, MySQL 8.0.46 · tb_finding 1,434,104행):
--   uq_find 의 scan_id distinct 추정  6,959 → 451 (실제 456)
--   index.php:218 추세 High 집계      1,574.85ms → 75.05ms   (21배)
--   index.php:93  KEV 행               56.15ms →  1.48ms      (38배)
--   index.php:260 호스트별 현황       132.52ms → 90.15ms
--   대시보드 SQL 합계                2,097ms → 504ms         (4.2배)
--   결과값은 바뀌지 않는다(인덱스 선택만 달라진다 — 294행 값·합계 32,114 완전 일치 확인).
--
-- 왜 200 인가: 200 에서 추정이 이미 실측과 거의 일치했다(451 vs 456). 더 올릴 이유가 없고,
--   ALTER+ANALYZE 전체가 0.35초로 끝났다(143만행 기준). 되돌리려면 STATS_SAMPLE_PAGES=DEFAULT.
--
-- 왜 ALGORITHM=INPLACE, LOCK=NONE 을 명시하나: STATS_* 변경은 테이블 재구축 없이 되는데,
--   명시하지 않으면 MySQL 이 조용히 COPY 로 떨어질 여지를 남긴다 — 143만행을 운영에서
--   복사하는 사고를 막으려고 "안 되면 실패" 하게 못박는다.
--   (ALGORITHM=INSTANT 는 이 연산에 지원되지 않는다 — 운영에서 1845 오류로 확인.)
--
-- 남은 것: 최적 인덱스(idx_find_scan_sev, 26ms)까지 가려면 eq_range_index_dive_limit 이
--   레인지 수보다 커야 한다(IN 294개 × severity 2개 = 588 > 기본값 200). 지금은 서버 전역
--   설정이라 이 마이그레이션 범위 밖이고, 남은 이득도 49ms(전체의 10%)라 넣지 않았다.
--   자세한 것은 docs/dev/dashboard-index-profiling.md §11.
--
-- 멱등: 같은 값을 다시 넣어도 무해하고, ANALYZE 는 몇 번 돌려도 된다.

ALTER TABLE tb_finding STATS_SAMPLE_PAGES=200, ALGORITHM=INPLACE, LOCK=NONE;

ANALYZE TABLE tb_finding;
