-- 패키지 무결성 검증(rpm -Va / dpkg --verify) 결과 — "설치 이후 파일이 바뀌었나"(N2SF IN 구성요소 무결성).
--
--   행 = 패키지 원본과 다른 파일 하나. flags 는 rpm/dpkg 의 **원본 플래그 문자열을 그대로** 둔다
--   (5=digest 불일치, M=권한, U/G=소유자, missing=파일 없음). 해석은 화면이 한다.
--   `c`(설정파일) 줄은 에이전트가 이미 버리고 보낸다 — 관리자가 고치는 게 정상이라 전부 노이즈다.
--
--   ★ "검사 여부 · 부분 결과 · 전체 건수" 는 행이 아니라 **스캔 단위 사실**이라 tb_scan 에 둔다.
--     행이 0개인 것만으로는 "검사했는데 깨끗함"과 "아예 검사 안 함(기본 꺼짐·구버전 에이전트)"을
--     구분할 수 없고, 둘을 합치면 "검사도 안 했는데 깨끗하다"로 읽힌다 — 이 제품이 반복해서
--     경계해 온 실수다(tb_collection_stage·assetgrade_history 와 같은 취지).
--     integrity_total 은 상한(에이전트 VERIFY_MAX_LINES)에 잘리기 **전** 전체 건수다.
SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS tb_package_integrity (
  package_integrity_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  scan_id      BIGINT UNSIGNED NOT NULL,
  package_name VARCHAR(255) NULL,             -- 소유 패키지(조회 실패 시 NULL)
  flags        VARCHAR(32)  NOT NULL,         -- rpm/dpkg 원본 플래그 (예: S.5....T. / ??5?????? / missing)
  file_path    VARCHAR(512) NOT NULL,
  created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (package_integrity_id),
  KEY idx_pkg_integrity_scan (scan_id, package_name),
  CONSTRAINT fk_pkg_integrity_scan FOREIGN KEY (scan_id) REFERENCES tb_scan(scan_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_scan' AND COLUMN_NAME = 'integrity_checked');
SET @s := IF(@c = 0,
  "ALTER TABLE tb_scan
     ADD COLUMN integrity_checked TINYINT(1) NOT NULL DEFAULT 0 COMMENT '무결성 검사 수행 여부(0=미수행: 기본 꺼짐·구버전 에이전트)',
     ADD COLUMN integrity_partial TINYINT(1) NOT NULL DEFAULT 0 COMMENT '1=타임아웃/상한으로 잘린 부분 결과',
     ADD COLUMN integrity_total   INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '상한에 잘리기 전 전체 위반 건수'",
  'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
