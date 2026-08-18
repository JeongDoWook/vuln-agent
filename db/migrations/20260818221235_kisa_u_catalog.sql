-- KISA 「주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드」서버(UNIX) 부문 항목 카탈로그.
--   왜 필요한가: tb_control_mapping 은 rule_code(우리 CCE 코드)가 NOT NULL 이라 **우리가 점검하지
--   않는 U-코드는 행이 아예 없다.** 그래서 "기반시설 기준으로 몇 %를 덮나" 를 답할 수 없었다.
--   이 표가 분모(전체 항목)를 세우고, tb_control_mapping 이 분자(덮는 항목)로 남는다.
--   두 표는 역할이 다르므로 tb_control_mapping 은 건드리지 않는다.
--
--   ── 출처(서로 독립적인 2곳이 일치할 때만 명칭을 넣는다) ──────────────────────
--   판: 과학기술정보통신부·한국인터넷진흥원 「주요정보통신기반시설 기술적 취약점 분석·평가
--       방법 상세가이드」(2021.03) — UNIX 서버 부문. 총 72개 항목(U-01~U-72).
--   (1) AllThatLinux 위키 '보안 취약점 점검 가이드(KISA 기준)'
--       https://atl.kr/dokuwiki/doku.php/보안_취약점_점검_가이드_kisa기준
--       -> U-01~U-72 전 항목의 코드·명칭·위험도 표.
--   (2) catember/vulnerability-check (위 상세가이드 기반 점검 스크립트, GitHub)
--       https://github.com/catember/vulnerability-check  LINUX/Ubuntu/Ubuntu_Script.sh
--       -> 각 점검 머리글이 'U-NN(위험도) | N. 분류 > N.N 항목명' 형식으로 전 72항목을 적는다.
--   두 출처는 72개 코드·명칭·위험도가 전부 일치했고, 분류(계정관리/파일및디렉토리관리/
--   서비스관리/패치관리/로그관리)는 (2)의 장·절 표기를 정본으로 삼았다 — (1)은 서비스 계열까지
--   '파일및디렉터리'로 뭉뚱그려 적어 분류 열만은 신뢰할 수 없다.
--   보조 확인 (3) verdantjuly/exploit_checker 의 파일명(u_04_password_protect·u_45_su_root 등)이
--   같은 번호 체계임을 확인했다 — 2026년 개정판은 번호 체계가 다르므로(예: 개정판 U-06 = su 제한)
--   섞으면 안 된다. 이 카탈로그는 2021.03 판 하나로만 채운다.
--
--   기존 tb_control_mapping 의 U-코드 21종 명칭은 이미 검증된 것으로 보고 **그대로 재사용**한다.
--   위 출처와 뜻이 어긋난 항목은 없었다(표기 차이만 있다 — 예: U-54 '세션 종료 없는 방치 시간
--   설정' vs 가이드 'Session Timeout 설정'). 기존 판정과 얽혀 있어 고치지 않는다.
--
--   멱등: CREATE TABLE IF NOT EXISTS + UNIQUE(framework, control_id) 에
--   INSERT ... ON DUPLICATE KEY UPDATE 라 두 번 적용해도 행이 늘지 않는다.
SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS tb_control_catalog (
  control_catalog_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  framework    VARCHAR(32)  NOT NULL,        -- 'KISA_U' (다른 기준은 실제 요구가 생길 때)
  control_id   VARCHAR(64)  NOT NULL,        -- 'U-01'
  control_name VARCHAR(255) NULL,            -- 출처로 확인 못 한 항목은 NULL(지어내지 않는다)
  category     VARCHAR(64)  NULL,            -- 계정관리 / 파일및디렉토리관리 / 서비스관리 / 패치관리 / 로그관리
  severity     VARCHAR(16)  NULL,            -- 가이드의 위험도(상/중/하)
  sort_order   INT NOT NULL DEFAULT 0,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at DATETIME NULL,
  PRIMARY KEY (control_catalog_id),
  UNIQUE KEY uq_control_catalog (framework, control_id),
  KEY idx_control_catalog_framework (framework, sort_order)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 시드 — 소프트삭제된 행이 있으면 재적용 시 되살린다(선언한 상태로 수렴).
INSERT INTO tb_control_catalog (framework, control_id, control_name, category, severity, sort_order) VALUES
  ('KISA_U', 'U-01', 'root 계정 원격접속 제한',                                 '계정관리',           '상',  1),
  ('KISA_U', 'U-02', '패스워드 복잡성 설정',                                    '계정관리',           '상',  2),
  ('KISA_U', 'U-03', '계정 잠금 임계값 설정',                                   '계정관리',           '상',  3),
  ('KISA_U', 'U-04', '패스워드 파일 보호',                                      '계정관리',           '상',  4),
  ('KISA_U', 'U-05', 'root 홈·PATH 디렉터리 권한 및 PATH 설정',                 '파일및디렉토리관리', '상',  5),
  ('KISA_U', 'U-06', '파일 및 디렉터리 소유자 설정',                            '파일및디렉토리관리', '상',  6),
  ('KISA_U', 'U-07', '/etc/passwd 파일 소유자 및 권한 설정',                    '파일및디렉토리관리', '상',  7),
  ('KISA_U', 'U-08', '/etc/shadow 파일 소유자 및 권한 설정',                    '파일및디렉토리관리', '상',  8),
  ('KISA_U', 'U-09', '/etc/hosts 파일 소유자 및 권한 설정',                     '파일및디렉토리관리', '상',  9),
  ('KISA_U', 'U-10', '/etc/(x)inetd.conf 파일 소유자 및 권한 설정',             '파일및디렉토리관리', '상', 10),
  ('KISA_U', 'U-11', '/etc/syslog.conf 파일 소유자 및 권한 설정',               '파일및디렉토리관리', '상', 11),
  ('KISA_U', 'U-12', '/etc/services 파일 소유자 및 권한 설정',                  '파일및디렉토리관리', '상', 12),
  ('KISA_U', 'U-13', 'SUID, SGID, Sticky bit 설정 파일 점검',                   '파일및디렉토리관리', '상', 13),
  ('KISA_U', 'U-14', '사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정', '파일및디렉토리관리', '상', 14),
  ('KISA_U', 'U-15', 'world writable 파일 점검',                                '파일및디렉토리관리', '상', 15),
  ('KISA_U', 'U-16', '/dev 에 존재하지 않는 device 파일 점검',                  '파일및디렉토리관리', '상', 16),
  ('KISA_U', 'U-17', '$HOME/.rhosts, hosts.equiv 사용 금지',                    '파일및디렉토리관리', '상', 17),
  ('KISA_U', 'U-18', '접속 IP 및 포트 제한',                                    '파일및디렉토리관리', '상', 18),
  ('KISA_U', 'U-19', 'Finger 서비스 비활성화',                                  '서비스관리',         '상', 19),
  ('KISA_U', 'U-20', 'Anonymous FTP 비활성화',                                  '서비스관리',         '상', 20),
  ('KISA_U', 'U-21', 'r 계열 서비스 비활성화',                                  '서비스관리',         '상', 21),
  ('KISA_U', 'U-22', 'crond 파일 소유자 및 권한 설정',                          '서비스관리',         '상', 22),
  ('KISA_U', 'U-23', 'DoS 공격에 취약한 서비스 비활성화',                       '서비스관리',         '상', 23),
  ('KISA_U', 'U-24', 'NFS 서비스 비활성화',                                     '서비스관리',         '상', 24),
  ('KISA_U', 'U-25', 'NFS 접근 통제',                                           '서비스관리',         '상', 25),
  ('KISA_U', 'U-26', 'automountd 제거',                                         '서비스관리',         '상', 26),
  ('KISA_U', 'U-27', 'RPC 서비스 확인',                                         '서비스관리',         '상', 27),
  ('KISA_U', 'U-28', 'NIS, NIS+ 점검',                                          '서비스관리',         '상', 28),
  ('KISA_U', 'U-29', 'tftp, talk 서비스 비활성화',                              '서비스관리',         '상', 29),
  ('KISA_U', 'U-30', 'Sendmail 버전 점검',                                      '서비스관리',         '상', 30),
  ('KISA_U', 'U-31', '스팸 메일 릴레이 제한',                                   '서비스관리',         '상', 31),
  ('KISA_U', 'U-32', '일반사용자의 Sendmail 실행 방지',                         '서비스관리',         '상', 32),
  ('KISA_U', 'U-33', 'DNS 보안 버전 패치',                                      '서비스관리',         '상', 33),
  ('KISA_U', 'U-34', 'DNS Zone Transfer 설정',                                  '서비스관리',         '상', 34),
  ('KISA_U', 'U-35', '웹서비스 디렉토리 리스팅 제거',                           '서비스관리',         '상', 35),
  ('KISA_U', 'U-36', '웹서비스 웹 프로세스 권한 제한',                          '서비스관리',         '상', 36),
  ('KISA_U', 'U-37', '웹서비스 상위 디렉토리 접근 금지',                        '서비스관리',         '상', 37),
  ('KISA_U', 'U-38', '웹서비스 불필요한 파일 제거',                             '서비스관리',         '상', 38),
  ('KISA_U', 'U-39', '웹서비스 링크 사용금지',                                  '서비스관리',         '상', 39),
  ('KISA_U', 'U-40', '웹서비스 파일 업로드 및 다운로드 제한',                   '서비스관리',         '상', 40),
  ('KISA_U', 'U-41', '웹서비스 영역의 분리',                                    '서비스관리',         '상', 41),
  ('KISA_U', 'U-42', '최신 보안패치 및 벤더 권고사항 적용',                     '패치관리',           '상', 42),
  ('KISA_U', 'U-43', '로그의 정기적 검토 및 보고',                              '로그관리',           '상', 43),
  ('KISA_U', 'U-44', 'root 이외의 UID가 ''0'' 금지',                            '계정관리',           '중', 44),
  ('KISA_U', 'U-45', 'root 계정 su 제한',                                       '계정관리',           '하', 45),
  ('KISA_U', 'U-46', '패스워드 최소 길이 설정',                                 '계정관리',           '중', 46),
  ('KISA_U', 'U-47', '패스워드 최대 사용기간 설정',                             '계정관리',           '중', 47),
  ('KISA_U', 'U-48', '패스워드 최소 사용기간 설정',                             '계정관리',           '중', 48),
  ('KISA_U', 'U-49', '불필요한 계정 제거',                                      '계정관리',           '하', 49),
  ('KISA_U', 'U-50', '관리자 그룹에 최소한의 계정 포함',                        '계정관리',           '하', 50),
  ('KISA_U', 'U-51', '계정이 존재하지 않는 GID 금지',                           '계정관리',           '하', 51),
  ('KISA_U', 'U-52', '동일한 UID 금지',                                         '계정관리',           '중', 52),
  ('KISA_U', 'U-53', '사용자 shell 점검',                                       '계정관리',           '하', 53),
  ('KISA_U', 'U-54', '세션 종료 없는 방치 시간 설정',                           '계정관리',           '하', 54),
  ('KISA_U', 'U-55', 'hosts.lpd 파일 소유자 및 권한 설정',                      '파일및디렉토리관리', '하', 55),
  ('KISA_U', 'U-56', 'UMASK 설정 관리',                                         '파일및디렉토리관리', '중', 56),
  ('KISA_U', 'U-57', '홈디렉토리 소유자 및 권한 설정',                          '파일및디렉토리관리', '중', 57),
  ('KISA_U', 'U-58', '홈디렉토리로 지정한 디렉토리의 존재 관리',                '파일및디렉토리관리', '중', 58),
  ('KISA_U', 'U-59', '숨겨진 파일 및 디렉토리 검색 및 제거',                    '파일및디렉토리관리', '하', 59),
  ('KISA_U', 'U-60', 'ssh 원격접속 허용',                                       '서비스관리',         '중', 60),
  ('KISA_U', 'U-61', 'ftp 서비스 확인',                                         '서비스관리',         '하', 61),
  ('KISA_U', 'U-62', 'ftp 계정 shell 제한',                                     '서비스관리',         '중', 62),
  ('KISA_U', 'U-63', 'ftpusers 파일 소유자 및 권한 설정',                       '서비스관리',         '하', 63),
  ('KISA_U', 'U-64', 'ftpusers 파일 설정(FTP 서비스 root 계정 접근제한)',       '서비스관리',         '중', 64),
  ('KISA_U', 'U-65', 'at 서비스 권한 설정',                                     '서비스관리',         '중', 65),
  ('KISA_U', 'U-66', 'SNMP 서비스 구동 점검',                                   '서비스관리',         '중', 66),
  ('KISA_U', 'U-67', 'SNMP 서비스 Community String 의 복잡성 설정',             '서비스관리',         '중', 67),
  ('KISA_U', 'U-68', '로그온 시 경고 메시지 제공',                              '서비스관리',         '하', 68),
  ('KISA_U', 'U-69', 'NFS 설정파일 접근권한',                                   '서비스관리',         '중', 69),
  ('KISA_U', 'U-70', 'expn, vrfy 명령어 제한',                                  '서비스관리',         '중', 70),
  ('KISA_U', 'U-71', 'Apache 웹 서비스 정보 숨김',                              '서비스관리',         '중', 71),
  ('KISA_U', 'U-72', '정책에 따른 시스템 로깅 설정',                            '로그관리',           '하', 72)
ON DUPLICATE KEY UPDATE
  control_name = VALUES(control_name), category = VALUES(category),
  severity = VALUES(severity), sort_order = VALUES(sort_order),
  is_deleted = 0, deleted_at = NULL;
