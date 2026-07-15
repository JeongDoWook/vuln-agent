-- tb_package_summary — packages.php(영향 패키지 목록) 전용 사전집계 요약 테이블.
--   원본 tb_cve_affected_packages 는 92만 행이라, packages.php 가 매 로드마다 (package_name,
--   ecosystem) 로 GROUP BY 하며 총개수·정렬·배포판목록을 전부 재집계해 운영에서 ~8초 걸렸다.
--   페이지네이션은 "표시"만 10건으로 줄일 뿐 "계산"은 전체를 훑는다. 집계 결과는 OSV 커넥터가
--   돌 때만 바뀌므로(affected_packages 는 OSV 만 쓴다), 그때 한 번 요약해 두고 화면은 이 40K행
--   테이블만 읽게 한다 → 8초→0.3초. 갱신은 vg_rebuild_package_summary()(matcher.php)가 OSV
--   실행 직후 트랜잭션으로 통째 다시 만든다(읽는 쪽은 MVCC 로 옛 값을 보다 커밋 때 전환).
--   멱등: CREATE IF NOT EXISTS + 초기 채움은 ON DUPLICATE KEY UPDATE. 빈 볼륨은 db/02-matcher.sql.
SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS tb_package_summary (
  package_name VARCHAR(255) NOT NULL,
  ecosystem    VARCHAR(32)  NOT NULL DEFAULT '',
  cve_cnt      INT UNSIGNED NOT NULL DEFAULT 0,   -- COUNT(DISTINCT cve_id)
  max_epss     DOUBLE       NULL,                 -- MAX(tb_cves.epss)
  fix_cnt      INT UNSIGNED NOT NULL DEFAULT 0,   -- 조치버전 있는 행 수
  updated_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (package_name, ecosystem),
  KEY idx_psum_cve  (cve_cnt),
  KEY idx_psum_epss (max_epss)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 초기 1회 채움. 이후 갱신은 vg_rebuild_package_summary(). 멱등(재실행 시 값만 갱신).
INSERT INTO tb_package_summary (package_name, ecosystem, cve_cnt, max_epss, fix_cnt)
SELECT a.package_name, a.ecosystem,
       COUNT(DISTINCT a.cve_id), MAX(c.epss), SUM(a.fixed_version IS NOT NULL)
  FROM tb_cve_affected_packages a
  LEFT JOIN tb_cves c ON c.cve_id = a.cve_id AND c.is_deleted = 0
 WHERE a.is_deleted = 0
 GROUP BY a.package_name, a.ecosystem
ON DUPLICATE KEY UPDATE
  cve_cnt = VALUES(cve_cnt), max_epss = VALUES(max_epss), fix_cnt = VALUES(fix_cnt);
