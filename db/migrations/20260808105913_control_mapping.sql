-- 다중 기준 매핑 테이블 — 한 CCE 점검 결과를 U-코드·ISMS-P·N2SF 세 체계의 증적으로 함께 본다.
--   지금까지 이 매핑은 server/src/cce.php 의 주석(U-XX)과 compliance.php 의 문자열
--   ("ISMS-P 2.10.8 · ISO 27001 A.8.8")에 흩어져 있어, 한 점검 결과를 다른 기준으로 볼 수 없었다.
--   여기 한 곳에 모아 화면이 기준을 골라 그룹핑할 수 있게 한다.
--
--   근거 원칙: 억지 매핑을 넣지 않는다. U-코드는 cce.php 주석에 명시된 항목만,
--   ISMS-P·N2SF 는 컴플라이언스 감사 리포트(2026-08-07)가 명시한 매핑과 그 규칙을
--   같은 성격의 룰에 그대로 적용한 것만 넣는다. 근거가 없으면 행 자체를 만들지 않는다
--   (예: CCE-SSH-PWAUTH·CCE-SEC-MODULE 등은 U-코드 행이 없다).
--
--   멱등: CREATE TABLE IF NOT EXISTS + UNIQUE(rule_code, framework, control_id) 에
--   INSERT ... ON DUPLICATE KEY UPDATE 라 두 번 적용해도 행이 늘지 않는다.
SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS tb_control_mapping (
  control_mapping_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  rule_code    VARCHAR(64)  NOT NULL,        -- tb_cce_finding.code (CCE-SSH-ROOT 등)
  framework    VARCHAR(32)  NOT NULL,        -- KISA_U | ISMS_P | N2SF
  control_id   VARCHAR(64)  NOT NULL,        -- U-01 / 2.5.4 / AP 등 기준별 통제 식별자
  control_name VARCHAR(255) NOT NULL,        -- 통제의 정식 명칭
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at DATETIME NULL,
  PRIMARY KEY (control_mapping_id),
  UNIQUE KEY uq_control_mapping (rule_code, framework, control_id),
  KEY idx_control_mapping_framework (framework, control_id),
  KEY idx_control_mapping_rule (rule_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ── 시드 ──────────────────────────────────────────────────────────────────
-- 소프트삭제된 행이 있으면 시드 재적용 시 되살린다(멱등하게 "선언한 상태"로 수렴).

-- 1) KISA 「주요정보통신기반시설 기술적 취약점 분석·평가 가이드」 U-코드.
--    근거는 server/src/cce.php 의 각 점검 주석에 달린 U-코드다. 주석에 없는 점검은 넣지 않는다.
--    예외 1건 — CCE-ACC-UID0: cce.php 주석과 감사 리포트는 U-02 로 적고 있으나, U-02 는
--      "패스워드 복잡성 설정"이라 UID 0 점검과 의미가 맞지 않는다. 같은 가이드의
--      U-44 "root 이외의 UID가 '0' 금지"가 정확한 대응이라 그쪽으로 넣는다
--      (틀린 명칭을 화면에 증적으로 띄우는 것이 더 큰 신뢰 손실).
INSERT INTO tb_control_mapping (rule_code, framework, control_id, control_name) VALUES
  ('CCE-SSH-ROOT',      'KISA_U', 'U-01', 'root 계정 원격접속 제한'),
  ('CCE-PW-QUALITY',    'KISA_U', 'U-02', '패스워드 복잡성 설정'),
  ('CCE-PW-LOCKOUT',    'KISA_U', 'U-03', '계정 잠금 임계값 설정'),
  ('CCE-ACC-SHADOW',    'KISA_U', 'U-04', '패스워드 파일 보호'),
  ('CCE-ROOT-PATH',     'KISA_U', 'U-05', 'root 홈·PATH 디렉터리 권한 및 PATH 설정'),
  ('CCE-FILE-PASSWD',   'KISA_U', 'U-07', '/etc/passwd 파일 소유자 및 권한 설정'),
  ('CCE-FILE-SHADOW',   'KISA_U', 'U-08', '/etc/shadow 파일 소유자 및 권한 설정'),
  ('CCE-FILE-HOSTS',    'KISA_U', 'U-09', '/etc/hosts 파일 소유자 및 권한 설정'),
  ('CCE-FILE-XINETD',   'KISA_U', 'U-10', '/etc/(x)inetd.conf 파일 소유자 및 권한 설정'),
  ('CCE-FILE-SYSLOG',   'KISA_U', 'U-11', '/etc/syslog.conf 파일 소유자 및 권한 설정'),
  ('CCE-FILE-SERVICES', 'KISA_U', 'U-12', '/etc/services 파일 소유자 및 권한 설정'),
  ('CCE-RHOSTS',        'KISA_U', 'U-17', '$HOME/.rhosts, hosts.equiv 사용 금지'),
  -- cce.php 는 CCE-SVC-LEGACY 를 "U-19~U-25 계열"로 적는다. 그 범위 중 이 점검이 실제로
  --   탐지하는 서비스에 정확히 대응하는 두 항목만 넣는다(finger, r 계열).
  ('CCE-SVC-LEGACY',    'KISA_U', 'U-19', 'Finger 서비스 비활성화'),
  ('CCE-SVC-LEGACY',    'KISA_U', 'U-21', 'r 계열 서비스 비활성화'),
  ('CCE-ACC-UID0',      'KISA_U', 'U-44', 'root 이외의 UID가 ''0'' 금지'),
  ('CCE-PW-MINLEN',     'KISA_U', 'U-46', '패스워드 최소 길이 설정'),
  ('CCE-PW-MAXDAYS',    'KISA_U', 'U-47', '패스워드 최대 사용기간 설정'),
  ('CCE-PW-MINDAYS',    'KISA_U', 'U-48', '패스워드 최소 사용기간 설정'),
  ('CCE-ACC-DUPUID',    'KISA_U', 'U-52', '동일한 UID 금지'),
  ('CCE-SESSION-TMOUT', 'KISA_U', 'U-54', '세션 종료 없는 방치 시간 설정'),
  ('CCE-SSH-IDLE',      'KISA_U', 'U-54', '세션 종료 없는 방치 시간 설정'),
  ('CCE-UMASK',         'KISA_U', 'U-56', 'UMASK 설정 관리')
ON DUPLICATE KEY UPDATE control_name = VALUES(control_name), is_deleted = 0, deleted_at = NULL;

-- 2) ISMS-P 인증기준. 리포트가 명시한 매핑(2.5.3/2.5.4/2.5.5/2.6.1/2.6.3/2.6.6/2.10.1)과
--    같은 성격의 점검을 같은 통제로 확장한 것만 넣는다(SSH 접근통제 → 2.6.6, 파일권한 → 2.10.1).
INSERT INTO tb_control_mapping (rule_code, framework, control_id, control_name) VALUES
  ('CCE-PW-LOCKOUT',    'ISMS_P', '2.5.3',  '사용자 인증'),
  ('CCE-PW-QUALITY',    'ISMS_P', '2.5.4',  '비밀번호 관리'),
  ('CCE-PW-MINLEN',     'ISMS_P', '2.5.4',  '비밀번호 관리'),
  ('CCE-PW-MAXDAYS',    'ISMS_P', '2.5.4',  '비밀번호 관리'),
  ('CCE-PW-MINDAYS',    'ISMS_P', '2.5.4',  '비밀번호 관리'),
  ('CCE-ACC-SHADOW',    'ISMS_P', '2.5.4',  '비밀번호 관리'),
  ('CCE-ACC-EMPTYPW',   'ISMS_P', '2.5.4',  '비밀번호 관리'),
  ('CCE-SSH-EMPTYPW',   'ISMS_P', '2.5.4',  '비밀번호 관리'),
  ('CCE-SSH-ROOT',      'ISMS_P', '2.5.5',  '특수 계정 및 권한 관리'),
  ('CCE-ACC-UID0',      'ISMS_P', '2.5.5',  '특수 계정 및 권한 관리'),
  ('CCE-ACC-DUPUID',    'ISMS_P', '2.5.5',  '특수 계정 및 권한 관리'),
  ('CCE-SEC-FW',        'ISMS_P', '2.6.1',  '네트워크 접근'),
  ('CCE-SESSION-TMOUT', 'ISMS_P', '2.6.3',  '응용프로그램 접근'),
  ('CCE-SSH-IDLE',      'ISMS_P', '2.6.3',  '응용프로그램 접근'),
  ('CCE-SSH-ROOT',      'ISMS_P', '2.6.6',  '원격접근 통제'),
  ('CCE-SSH-PWAUTH',    'ISMS_P', '2.6.6',  '원격접근 통제'),
  ('CCE-SSH-MAXAUTH',   'ISMS_P', '2.6.6',  '원격접근 통제'),
  ('CCE-SSH-X11',       'ISMS_P', '2.6.6',  '원격접근 통제'),
  ('CCE-SSH-GRACE',     'ISMS_P', '2.6.6',  '원격접근 통제'),
  ('CCE-RHOSTS',        'ISMS_P', '2.6.6',  '원격접근 통제'),
  ('CCE-FILE-PASSWD',   'ISMS_P', '2.10.1', '보안시스템 운영'),
  ('CCE-FILE-SHADOW',   'ISMS_P', '2.10.1', '보안시스템 운영'),
  ('CCE-FILE-GSHADOW',  'ISMS_P', '2.10.1', '보안시스템 운영'),
  ('CCE-FILE-GROUP',    'ISMS_P', '2.10.1', '보안시스템 운영'),
  ('CCE-FILE-HOSTS',    'ISMS_P', '2.10.1', '보안시스템 운영'),
  ('CCE-FILE-SYSLOG',   'ISMS_P', '2.10.1', '보안시스템 운영'),
  ('CCE-FILE-SERVICES', 'ISMS_P', '2.10.1', '보안시스템 운영'),
  ('CCE-FILE-XINETD',   'ISMS_P', '2.10.1', '보안시스템 운영'),
  ('CCE-FILE-CRONTAB',  'ISMS_P', '2.10.1', '보안시스템 운영'),
  ('CCE-UMASK',         'ISMS_P', '2.10.1', '보안시스템 운영'),
  ('CCE-ROOT-PATH',     'ISMS_P', '2.10.1', '보안시스템 운영'),
  ('CCE-SEC-MODULE',    'ISMS_P', '2.10.1', '보안시스템 운영'),
  ('CCE-SVC-LEGACY',    'ISMS_P', '2.10.1', '보안시스템 운영')
ON DUPLICATE KEY UPDATE control_name = VALUES(control_name), is_deleted = 0, deleted_at = NULL;

-- 3) N2SF(국가 망 보안체계). 리포트가 명시한 매핑만 넣고, 파일권한 계열만 같은 영역(제6장 IN)으로
--    확장한다. 그 밖의 룰은 확신 있는 근거가 없어 행을 만들지 않는다.
--    control_name 은 리포트 표기를 그대로 쓴다(영역 약어의 정식 명칭을 지어내지 않는다).
INSERT INTO tb_control_mapping (rule_code, framework, control_id, control_name) VALUES
  ('CCE-PW-QUALITY',    'N2SF', 'AP',   '제2장 인증정책'),
  ('CCE-PW-MAXDAYS',    'N2SF', 'AP',   '제2장 인증정책'),
  ('CCE-PW-MINDAYS',    'N2SF', 'AP',   '제2장 인증정책'),
  ('CCE-PW-MINLEN',     'N2SF', 'AP',   '제2장 인증정책'),
  ('CCE-ACC-SHADOW',    'N2SF', 'AP',   '제2장 인증정책'),
  ('CCE-PW-LOCKOUT',    'N2SF', 'LI',   '제2장 로그인'),
  ('CCE-ACC-UID0',      'N2SF', 'LP',   '제1장 최소권한'),
  ('CCE-ACC-DUPUID',    'N2SF', 'LP',   '제1장 최소권한'),
  ('CCE-ACC-UID0',      'N2SF', 'AC',   '제1장 계정관리'),
  ('CCE-ACC-DUPUID',    'N2SF', 'AC',   '제1장 계정관리'),
  ('CCE-SSH-ROOT',      'N2SF', 'LP-4', '제1장 관리자 권한 제한'),
  ('CCE-SESSION-TMOUT', 'N2SF', 'SN',   '제4장 세션'),
  ('CCE-SSH-IDLE',      'N2SF', 'SN',   '제4장 세션'),
  ('CCE-SEC-FW',        'N2SF', 'EB',   '제4장 외부경계'),
  ('CCE-FILE-PASSWD',   'N2SF', 'IN',   '제6장 IN'),
  ('CCE-FILE-SHADOW',   'N2SF', 'IN',   '제6장 IN'),
  ('CCE-FILE-GSHADOW',  'N2SF', 'IN',   '제6장 IN'),
  ('CCE-FILE-GROUP',    'N2SF', 'IN',   '제6장 IN'),
  ('CCE-FILE-HOSTS',    'N2SF', 'IN',   '제6장 IN'),
  ('CCE-FILE-SYSLOG',   'N2SF', 'IN',   '제6장 IN'),
  ('CCE-FILE-SERVICES', 'N2SF', 'IN',   '제6장 IN'),
  ('CCE-FILE-XINETD',   'N2SF', 'IN',   '제6장 IN'),
  ('CCE-FILE-CRONTAB',  'N2SF', 'IN',   '제6장 IN'),
  ('CCE-UMASK',         'N2SF', 'IN',   '제6장 IN')
ON DUPLICATE KEY UPDATE control_name = VALUES(control_name), is_deleted = 0, deleted_at = NULL;
