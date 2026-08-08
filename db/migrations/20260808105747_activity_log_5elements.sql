-- 접속기록 5요소 정렬 + 월 1회 점검 기록 (ISMS-P 2.9.4 접속기록 보관·점검 / 2.9.5 로그 및 접속기록 점검).
--   5요소: 식별자(user_id/user_name) · 접속일시(created_at) · 접속지 IP(ip_address) ·
--          처리한 정보주체(subject) · 수행업무(action).
--   앞의 세 요소는 tb_activity_log 에 이미 독립 컬럼으로 있고, 뒤의 두 요소만 여기서 추가한다
--   (일부가 data JSON 안에 묻혀 있어 정렬·조회가 안 됐다).
--   멱등: information_schema 가드 — 두 번 돌아도 안전하다(pk_naming_unification.sql 과 같은 패턴).
SET NAMES utf8mb4;

-- subject — ISMS-P 가 말하는 "처리한 정보주체" 자리.
--   이 제품은 개인정보를 처리하지 않는다. 그래서 실제로 담는 값은 그 행위가 다룬 **대상 자원**
--   (호스트 FQDN · CVE ID · 패키지명 · 계정 아이디 등)이다. 억지로 "정보주체"라고 부르지 않고
--   컬럼 주석에 이 사실을 남긴다 — 감사 때 이 컬럼이 무엇인지 코드를 안 열어도 알 수 있어야 한다.
SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_activity_log' AND COLUMN_NAME = 'subject');
SET @s := IF(@c = 0,
  "ALTER TABLE tb_activity_log ADD COLUMN subject VARCHAR(255) NULL
     COMMENT '처리 대상 자원(호스트 FQDN·CVE·패키지·계정 등). 이 제품은 개인정보를 처리하지 않아 ISMS-P 의 [처리한 정보주체] 자리를 대상 자원으로 채운다.'
     AFTER message",
  'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- action — 수행업무. activity_type(세부 이벤트 코드, 기존 54개 호출지점이 쓴다) 위의 정규화 계층.
--   READ/CREATE/UPDATE/DELETE/EXPORT/LOGIN/EXECUTE/OTHER — 어휘는 vg_activity_action() 이 소유한다.
SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_activity_log' AND COLUMN_NAME = 'action');
SET @s := IF(@c = 0,
  "ALTER TABLE tb_activity_log ADD COLUMN action VARCHAR(20) NULL
     COMMENT '수행업무 정규화 동사(READ/CREATE/UPDATE/DELETE/EXPORT/LOGIN/EXECUTE/OTHER). activity_type 위의 정규화 계층.'
     AFTER subject",
  'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- 조회 화면의 '수행업무' 필터가 등호로 거는 유일한 새 컬럼 → 인덱스는 action 만 만든다.
--   subject 는 부분일치(LIKE '%…%') 검색이라 인덱스가 안 먹으므로 만들지 않는다(YAGNI).
SET @c := (SELECT COUNT(*) FROM information_schema.STATISTICS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_activity_log' AND INDEX_NAME = 'idx_activity_action');
SET @s := IF(@c = 0, 'ALTER TABLE tb_activity_log ADD INDEX idx_activity_action (action)', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- 월 1회 접속기록 점검 이력(ISMS-P 2.9.5). 점검 대상 기간·수행자·결과를 남긴다.
--   UNIQUE (period_start, period_end) — 같은 기간을 두 번 기록하지 못하게 막는다.
--   reviewed_by 는 tb_user.user_id (FK 미설정 — 이 저장소 감사 관련 테이블 관례. 계정이 지워져도
--   점검 이력은 남아야 한다).
CREATE TABLE IF NOT EXISTS tb_activity_review (
  activity_review_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  period_start DATE NOT NULL,                    -- 점검 대상 기간 시작(월 1회면 그 달 1일)
  period_end   DATE NOT NULL,                    -- 점검 대상 기간 종료(그 달 말일)
  reviewed_by  BIGINT UNSIGNED NULL,             -- 점검 수행자 tb_user.user_id
  reviewer_name VARCHAR(100) NULL,               -- 수행자 아이디 스냅샷(계정 삭제 후에도 남게)
  reviewed_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  result       VARCHAR(20) NOT NULL DEFAULT 'OK',-- OK(이상없음) | FINDING(이상징후) | NA(대상없음)
  note         TEXT NULL,
  created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted   TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at   DATETIME NULL,
  UNIQUE KEY uq_activity_review_period (period_start, period_end),
  KEY idx_activity_review_period (period_start)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
