-- tb_package_summary — packages.php OS 탭 목록 정렬을 filesort 없이 인덱스로 푼다.
--
-- 무엇이 문제였나
--   목록 쿼리는 `ORDER BY <cve_cnt|max_epss> DESC, package_name ASC LIMIT 50` 이다.
--   `idx_psum_cve (cve_cnt)` 가 이미 있는데도 옵티마이저가 안 썼다 — 단일 컬럼 인덱스로는
--   2차 정렬(package_name)을 줄 수 없어 21,370행을 통째로 읽고 정렬한다(Table scan + Sort).
--   FORCE INDEX 로도 안 바뀐다. 타이브레이크를 빼면 0.35ms 로 떨어지지만, 동점이 흔한
--   데이터라(상위 8종이 전부 CVE 3,246건) 타이브레이크 없이는 페이지를 넘길 때 행이
--   중복·누락된다 — 그래서 쿼리가 아니라 인덱스를 고친다.
--
-- 왜 **내림차순** 복합인가
--   정렬 방향이 섞여 있다(cve_cnt DESC + package_name ASC). 오름차순 복합
--   `(cve_cnt, package_name)` 은 역방향 스캔해도 package_name 까지 DESC 가 돼 못 쓴다 —
--   실측에서 계획이 Table scan + Sort 그대로였다. MySQL 8.0 의 내림차순 인덱스가 필요하다.
--   (운영·dev 모두 MySQL 8.0.x 다. 5.7 이면 이 파일이 실패하므로 버전 전제를 여기 남긴다.)
--
-- 왜 **커버링**(뒤에 ecosystem·나머지 표시 컬럼까지)인가
--   키 두 개짜리 `(cve_cnt DESC, package_name)` 만 붙이면 무필터 목록은 8.2ms→0.17ms 로
--   빨라지지만, **선택도가 낮은 필터에서 역전된다** — 옵티마이저가 "LIMIT 50 이니 인덱스
--   앞부분만 읽으면 되겠지" 하고 인덱스 스캔을 고르는데, 실제로는 조건에 맞는 50행을
--   못 채워 인덱스 전체를 훑으며 행 조회를 반복한다:
--     eco=Debian:12(29행)  6.94ms → 24.85ms      검색어 미존재  7.04ms → 26.85ms
--   표시 컬럼을 전부 인덱스에 넣어 커버링으로 만들면 그 행 조회가 사라져 같은 경우가
--   5.9~6.3ms 로 **베이스라인보다도 빨라진다**. 그래서 키 폭보다 커버링을 택했다.
--
-- 비용
--   인덱스 두 개가 사실상 테이블 사본이라 저장·쓰기 비용이 는다. 이 표는 OSV 커넥터 직후
--   vg_rebuild_package_summary() 가 통째로 다시 만드는데(웹 요청 밖 배치), 그 시간이
--   dev 21,370행 기준 늘어난다. 수치는 PR 본문에 before/after 로 적었다.
--
-- 기존 idx_psum_cve / idx_psum_epss 는 **남긴다**. 새 복합이 그 조회를 덮지만, 인덱스
--   삭제는 되돌리는 데 재구축이 필요해 이번 범위 밖으로 미룬다(PR 본문에 근거 기록).
--
-- 멱등: information_schema.STATISTICS 로 존재 검사 후에만 ALTER. 온라인(INPLACE·LOCK=NONE).
SET NAMES utf8mb4;

SET @c := (SELECT COUNT(*) FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='tb_package_summary'
    AND INDEX_NAME='idx_psum_cve_name');
SET @s := IF(@c=0,
  'ALTER TABLE tb_package_summary
     ADD INDEX idx_psum_cve_name
       (cve_cnt DESC, package_name ASC, ecosystem, max_epss, fix_cnt, max_fixed),
     ALGORITHM=INPLACE, LOCK=NONE',
  'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='tb_package_summary'
    AND INDEX_NAME='idx_psum_epss_name');
SET @s := IF(@c=0,
  'ALTER TABLE tb_package_summary
     ADD INDEX idx_psum_epss_name
       (max_epss DESC, package_name ASC, ecosystem, cve_cnt, fix_cnt, max_fixed),
     ALGORITHM=INPLACE, LOCK=NONE',
  'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
