-- 통제 상세 화면(/control.php)이 읽는 설명·조치 데이터.
--   지금까지 DB 어디에도 "이 통제가 무엇을 요구하는가"와 "이 점검을 어떻게 고치는가"가 없었다.
--   tb_control_mapping 은 "어느 룰이 어느 통제인가"만 갖는다(20260808105913). 그래서 통제를 눌러도
--   결과 표만 보이고, 사용자는 무엇을 해야 하는지 알 수 없었다. 그 두 가지를 여기 둔다.
--
--   테이블을 둘로 나눈 이유: 설명은 통제 단위(기준마다 다름)이고, 조치는 룰 단위(기준과 무관하게
--   같은 설정 파일을 고친다)다. 합치면 한 룰의 조치를 기준 수만큼 복제하게 된다.
--
--   근거 원칙(20260808105913 과 동일): 지어내지 않는다.
--     · 룰 조치(tb_cce_rule_guide)는 server/src/cce.php 의 **실제 판정 로직**에서만 끌어냈다 —
--       무슨 파일의 무슨 지시어를 보는지, 임계값이 얼마인지가 코드와 일치한다
--       (예: PASS_MAX_DAYS 90 / MaxAuthTries 5 / UMASK 022 / 로그보존 90일 / 시각오차 1.0초).
--     · 통제 설명(tb_control_guide)은 tb_control_mapping 의 control_name 이 말하는 범위와,
--       그 통제에 실제로 걸린 점검이 보는 대상 안에서만 쓴다. 조문 번호·원문을 새로 짓지 않는다.
--     · 근거가 모자란 통제·룰은 행을 만들지 않는다. 화면은 가이드가 없으면 "설명 준비 중"으로 비운다.
--
--   멱등: CREATE TABLE IF NOT EXISTS + UNIQUE 에 INSERT ... ON DUPLICATE KEY UPDATE.
SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS tb_control_guide (
  control_guide_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  framework   VARCHAR(32) NOT NULL,        -- KISA_U | ISMS_P | N2SF (vg_control_frameworks SSOT)
  control_id  VARCHAR(64) NOT NULL,        -- tb_control_mapping.control_id 와 같은 식별자
  description TEXT        NOT NULL,        -- 이 통제가 무엇을 요구하는가(2~4문장)
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at DATETIME NULL,
  PRIMARY KEY (control_guide_id),
  UNIQUE KEY uq_control_guide (framework, control_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS tb_cce_rule_guide (
  cce_rule_guide_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  rule_code   VARCHAR(64)  NOT NULL,       -- tb_cce_finding.code / tb_control_mapping.rule_code
  summary     VARCHAR(255) NOT NULL,       -- 이 점검이 무엇을 보는가(한 줄)
  remediation TEXT         NOT NULL,       -- 어떻게 고치는가(파일·지시어·명령 수준)
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at DATETIME NULL,
  PRIMARY KEY (cce_rule_guide_id),
  UNIQUE KEY uq_cce_rule_guide (rule_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ── 1) 통제 설명 ────────────────────────────────────────────────────────────
-- KISA 「주요정보통신기반시설 기술적 취약점 분석·평가 가이드」 U-코드.
INSERT INTO tb_control_guide (framework, control_id, description) VALUES
  ('KISA_U', 'U-01', 'root 계정으로 원격에서 직접 로그인하지 못하게 한다. root 는 어느 서버에나 있는 이름이라 무차별 대입의 첫 표적이 되고, 직접 로그인이 열려 있으면 "누가 작업했는가"가 로그에 남지 않는다. 일반 계정으로 접속한 뒤 권한을 올리는 경로만 남긴다.'),
  ('KISA_U', 'U-02', '패스워드가 짧거나 사전에 있는 단어만으로 만들어지지 않도록 복잡성 규칙을 시스템이 강제한다. 사용자 교육이나 규정만으로는 지켜지지 않으므로, 인증 모듈 수준에서 거부하도록 설정한다.'),
  ('KISA_U', 'U-03', '로그인 실패가 일정 횟수 이상 반복되면 계정을 잠근다. 임계값이 없으면 공격자가 시간 제한 없이 패스워드를 계속 시도할 수 있다. 잠금은 인증 모듈에서 처리해 모든 로그인 경로에 함께 적용되게 한다.'),
  ('KISA_U', 'U-04', '패스워드 해시를 누구나 읽는 /etc/passwd 가 아니라 /etc/shadow 로 분리해 보관한다. passwd 는 계정 정보 조회를 위해 전체 읽기 권한이 필요하므로, 해시가 거기 남아 있으면 일반 사용자도 오프라인 크래킹 재료를 가져갈 수 있다.'),
  ('KISA_U', 'U-05', 'root 의 홈 디렉터리와 PATH 를 안전하게 유지한다. PATH 에 현재 디렉터리(.)가 들어 있으면 공격자가 작업 디렉터리에 심어 둔 동명의 실행 파일이 정상 명령보다 먼저 실행된다.'),
  ('KISA_U', 'U-07', '/etc/passwd 의 소유자를 root 로 두고 쓰기 권한을 제한한다. 계정 목록과 셸·UID 가 담긴 파일이라 쓰기가 열리면 임의 계정 추가와 UID 변조가 가능하다.'),
  ('KISA_U', 'U-08', '/etc/shadow 는 패스워드 해시 원본이므로 root 만 읽을 수 있어야 한다. 읽기 권한이 조금이라도 넓으면 해시가 유출돼 오프라인에서 무제한으로 크래킹된다.'),
  ('KISA_U', 'U-09', '/etc/hosts 의 소유자·권한을 제한한다. 이 파일은 DNS 보다 먼저 조회되므로 쓰기가 열리면 이름을 공격자 서버로 돌려 놓아 정상 통신을 가로챌 수 있다.'),
  ('KISA_U', 'U-10', '(x)inetd 설정 파일의 소유자·권한을 제한한다. 이 파일이 수정되면 임의 서비스를 슈퍼데몬에 등록해 원격 실행 경로를 만들 수 있다. 서비스를 쓰지 않는 서버에는 파일 자체가 없는 것이 정상이다.'),
  ('KISA_U', 'U-11', 'syslog(rsyslog) 설정 파일의 소유자·권한을 제한한다. 로그 설정이 수정되면 기록 대상·전송 경로가 바뀌어 침해 흔적이 애초에 남지 않게 만들 수 있다.'),
  ('KISA_U', 'U-12', '/etc/services 의 소유자·권한을 제한한다. 포트와 서비스 이름의 대응표라 변조되면 운영자와 점검 도구가 실제와 다른 서비스를 보게 된다.'),
  ('KISA_U', 'U-17', 'hosts.equiv 와 $HOME/.rhosts 를 쓰지 않는다. 이 파일들은 "이 호스트·계정은 믿는다"는 선언이라, 남아 있으면 패스워드 없이 원격 접속이 성립한다.'),
  ('KISA_U', 'U-19', 'Finger 서비스를 비활성화한다. 사용자 계정·로그인 이력을 인증 없이 외부에 알려 주어 공격 대상 계정을 고르는 데 그대로 쓰인다.'),
  ('KISA_U', 'U-21', 'rsh·rlogin·rexec 등 r 계열 서비스를 비활성화한다. 인증과 데이터를 평문으로 주고받고 신뢰 파일 기반 접속을 허용하므로 SSH 로 대체한다.'),
  ('KISA_U', 'U-44', 'root 외의 계정이 UID 0 을 갖지 않게 한다. UID 0 이면 이름이 무엇이든 커널은 root 로 취급하므로, 계정 하나만 추가하면 root 권한을 우회 취득할 수 있고 감사 추적도 흐려진다.'),
  ('KISA_U', 'U-46', '패스워드 최소 길이를 시스템이 강제한다. 길이는 무차별 대입에 필요한 시간을 직접 결정하는 값이라, 짧으면 복잡성 규칙이 있어도 방어가 되지 않는다.'),
  ('KISA_U', 'U-47', '패스워드 최대 사용기간을 정해 주기적으로 바꾸게 한다. 만료가 없으면 유출된 패스워드가 발견될 때까지 무기한 유효하다.'),
  ('KISA_U', 'U-48', '패스워드 최소 사용기간을 둔다. 최소 기간이 없으면 사용자가 변경 직후 곧바로 예전 패스워드로 되돌려 이력 검사와 주기 변경을 무력화할 수 있다.'),
  ('KISA_U', 'U-52', '동일한 UID 를 여러 계정이 나눠 쓰지 않게 한다. UID 가 겹치면 파일 소유권과 로그가 계정을 구분하지 못해 "누가 했는가"를 사후에 특정할 수 없다.'),
  ('KISA_U', 'U-54', '로그인한 채 방치된 세션을 일정 시간 뒤 자동 종료한다. 자리를 비운 터미널과 끊긴 원격 세션은 그대로 인증된 통로로 남는다.'),
  ('KISA_U', 'U-56', '새로 만들어지는 파일의 기본 권한(UMASK)을 제한한다. UMASK 가 느슨하면 이후 생성되는 모든 파일이 그룹·타인에게 열린 채로 만들어져, 파일별로 권한을 고쳐도 계속 새 구멍이 생긴다.')
ON DUPLICATE KEY UPDATE description = VALUES(description), is_deleted = 0, deleted_at = NULL;

-- ISMS-P 인증기준. 통제명(tb_control_mapping.control_name)이 말하는 범위 안에서,
--   이 통제에 실제로 매핑된 점검이 보는 대상만 설명한다.
INSERT INTO tb_control_guide (framework, control_id, description) VALUES
  ('ISMS_P', '2.5.3', '사용자 인증 수단이 추측·자동화 공격에 견디도록 운영되어야 한다. 반복되는 로그인 실패를 그대로 허용하면 인증 자체가 시간을 들이면 뚫리는 관문이 된다. 이 화면에서는 로그인 실패 임계값과 계정 잠금 설정 여부로 증적을 본다.'),
  ('ISMS_P', '2.5.4', '비밀번호의 생성·변경·보관 규칙을 정하고 시스템이 강제해야 한다. 길이·복잡도·사용기간이 설정으로 강제되지 않으면 규정 문서만 남고 실제 계정은 규칙 밖에 있게 된다. 해시는 일반 사용자가 읽을 수 없는 곳에 보관해야 한다.'),
  ('ISMS_P', '2.5.5', '관리자 권한 계정과 특수 권한은 최소한으로 부여하고 식별 가능해야 한다. root 와 같은 권한을 가진 계정이 이름만 다르게 존재하거나 UID 가 겹치면, 권한 현황을 파악할 수도 행위를 추적할 수도 없다.'),
  ('ISMS_P', '2.6.1', '네트워크 접근은 필요한 경로만 허용하고 나머지는 차단해야 한다. 호스트에 방화벽 정책이 없으면 서버가 열어 둔 모든 포트가 그대로 접근 경로가 된다.'),
  ('ISMS_P', '2.6.3', '응용프로그램·시스템 세션은 일정 시간 사용이 없으면 종료되어야 한다. 유휴 세션이 남아 있으면 인증 절차를 거치지 않은 사람이 이미 인증된 화면을 그대로 쓸 수 있다.'),
  ('ISMS_P', '2.6.6', '원격에서의 접근은 안전한 방식으로 제한해야 한다. 원격 관리 통로는 인터넷에 직접 노출되는 경우가 많아, 특권 계정 직접 로그인·약한 인증 수단·불필요한 기능이 열려 있으면 그대로 침입 경로가 된다.'),
  ('ISMS_P', '2.10.1', '보안 관련 시스템 파일과 설정은 인가된 사용자만 변경할 수 있어야 한다. 계정·인증·로그·스케줄 관련 파일의 소유자와 권한이 느슨하면, 권한 상승과 흔적 제거가 별도의 취약점 없이도 가능해진다.')
ON DUPLICATE KEY UPDATE description = VALUES(description), is_deleted = 0, deleted_at = NULL;

-- N2SF(국가 망 보안체계). control_name 은 20260808105913 시드가 리포트 표기를 그대로 쓴다 —
--   여기서도 영역이 다루는 성격만 적고 정식 명칭·조문을 새로 짓지 않는다.
INSERT INTO tb_control_guide (framework, control_id, description) VALUES
  ('N2SF', 'AP', '인증에 쓰는 자격증명의 강도와 수명을 정책으로 강제하는 영역이다. 패스워드 복잡도·최소 길이·사용기간과 해시 보관 위치가 이 영역의 증적이 된다.'),
  ('N2SF', 'LI', '로그인 시도 자체를 통제하는 영역이다. 실패 횟수 제한 없이 시도를 무한히 허용하면 다른 인증 정책이 아무리 강해도 시간 문제로 뚫린다.'),
  ('N2SF', 'LP', '권한을 필요한 만큼만 주는 최소권한 영역이다. root 와 동일한 UID 를 가진 계정이나 여러 사람이 공유하는 UID 는 최소권한 원칙과 정면으로 어긋난다.'),
  ('N2SF', 'LP-4', '관리자 권한의 사용 경로를 제한하는 영역이다. 특권 계정으로 원격에서 직접 접속하는 통로가 열려 있으면 권한 제한과 행위 추적이 함께 무너진다.'),
  ('N2SF', 'AC', '계정의 생성·식별·정리를 다루는 영역이다. 계정마다 유일한 식별자가 보장되어야 접근 이력과 파일 소유권이 사람과 이어진다.'),
  ('N2SF', 'SN', '세션의 유지와 종료를 다루는 영역이다. 사용하지 않는 세션은 정해진 시간 뒤 끊어 인증된 통로가 방치되지 않게 한다.'),
  ('N2SF', 'EB', '외부와의 경계에서 트래픽을 통제하는 영역이다. 호스트 방화벽 정책은 경계 장비가 놓치는 내부·측면 이동 경로를 막는 마지막 층이다.'),
  ('N2SF', 'IN', '시스템 내부의 무결성을 다루는 영역이다. 계정·인증·로그·스케줄 관련 설정 파일의 소유자와 권한이 지켜져야 시스템이 스스로 보고하는 상태를 신뢰할 수 있다.')
ON DUPLICATE KEY UPDATE description = VALUES(description), is_deleted = 0, deleted_at = NULL;

-- ── 2) 점검 항목별 조치 방법 ────────────────────────────────────────────────
-- 전부 server/src/cce.php 의 판정 로직에서 끌어냈다. 판정이 보는 파일·지시어·임계값과
--   조치가 말하는 것이 어긋나면 사용자는 고쳐도 FAIL 이 안 사라지는 안내를 따르게 된다.
--   sshd 항목의 판정 근거는 `sshd -T` 실효값이므로, 조치 후 확인도 같은 명령으로 한다.
INSERT INTO tb_cce_rule_guide (rule_code, summary, remediation) VALUES
  ('CCE-SSH-ROOT', 'sshd 의 PermitRootLogin 실효값이 yes 이면 위반이다.',
   '/etc/ssh/sshd_config 에 PermitRootLogin no 를 명시한다(키 기반 root 작업이 꼭 필요하면 prohibit-password). sshd_config.d/*.conf 에 같은 지시어가 뒤에서 덮어쓰지 않는지 함께 확인한다. 적용은 sshd 재시작(systemctl restart sshd) 후 sshd -T | grep permitrootlogin 으로 실효값을 확인한다. 끊기지 않도록 일반 계정의 sudo 권한을 먼저 확보한 뒤 바꾼다.'),
  ('CCE-SSH-PWAUTH', 'sshd 의 PasswordAuthentication 실효값이 yes 이면 위반이다.',
   '접속 계정에 공개키를 먼저 등록(~/.ssh/authorized_keys, 권한 600)한 뒤 /etc/ssh/sshd_config 에 PasswordAuthentication no 를 설정한다. KbdInteractiveAuthentication(구 ChallengeResponseAuthentication)도 no 인지 확인한다 — 이쪽이 열려 있으면 패스워드 인증이 사실상 남는다. 재시작 후 sshd -T | grep passwordauthentication 으로 확인한다.'),
  ('CCE-SSH-EMPTYPW', 'sshd 의 PermitEmptyPasswords 실효값이 yes 이면 위반이다.',
   '/etc/ssh/sshd_config 에 PermitEmptyPasswords no 를 설정하고 sshd 를 재시작한다. 빈 패스워드 계정이 실제로 있는지는 CCE-ACC-EMPTYPW 점검과 함께 확인해 계정 쪽도 함께 정리한다.'),
  ('CCE-SSH-MAXAUTH', 'sshd 의 MaxAuthTries 가 5 를 넘으면 위반이다.',
   '/etc/ssh/sshd_config 에 MaxAuthTries 5 이하(예: MaxAuthTries 4)를 설정하고 sshd 를 재시작한다. 값이 클수록 한 연결에서 시도할 수 있는 인증 횟수가 늘어난다. sshd -T | grep maxauthtries 로 실효값을 확인한다.'),
  ('CCE-SSH-X11', 'sshd 의 X11Forwarding 실효값이 yes 이면 위반이다.',
   'GUI 전달이 필요 없는 서버라면 /etc/ssh/sshd_config 에 X11Forwarding no 를 설정하고 sshd 를 재시작한다. 특정 사용자·그룹만 필요하면 Match 블록으로 범위를 좁힌다.'),
  ('CCE-SSH-GRACE', 'sshd 의 LoginGraceTime 이 60(초)을 넘으면 위반이다.',
   '/etc/ssh/sshd_config 에 LoginGraceTime 60 이하를 설정하고 sshd 를 재시작한다. 인증을 마치지 않은 연결이 오래 열려 있을수록 연결 슬롯 고갈 공격에 노출된다.'),
  ('CCE-SSH-IDLE', 'sshd 의 ClientAliveInterval 이 0(무제한)이거나 300(초)을 넘으면 위반이다.',
   '/etc/ssh/sshd_config 에 ClientAliveInterval 300 이하와 ClientAliveCountMax 를 함께 설정한다(예: 300 / 2 → 무응답 약 10분 뒤 종료). 0 은 "끊지 않음"이라 설정되어 있어도 위반이다. 재시작 후 sshd -T | grep clientaliveinterval 로 확인한다.'),
  ('CCE-ACC-UID0', 'root 외에 UID 가 0 인 계정이 있으면 위반이다.',
   'awk -F: ''$3==0 {print $1}'' /etc/passwd 로 UID 0 계정을 확인하고, root 외의 계정은 usermod -u <새 UID> 로 일반 UID 를 주거나 필요 없으면 삭제한다. 관리 목적이라면 별도 계정 + sudo 로 대체한다 — UID 0 은 이름과 무관하게 커널이 root 로 취급한다.'),
  ('CCE-ACC-DUPUID', '서로 다른 계정이 같은 UID 를 쓰면 위반이다.',
   'cut -d: -f3 /etc/passwd | sort | uniq -d 로 겹친 UID 를 찾는다. 남길 계정을 정한 뒤 나머지는 usermod -u 로 UID 를 바꾸고, 그 계정이 소유하던 파일은 find / -uid <옛 UID> -exec chown 으로 함께 옮긴다.'),
  ('CCE-ACC-SHADOW', '/etc/passwd 의 패스워드 칸에 해시가 남아 있으면 위반이다.',
   'pwconv 를 실행해 패스워드를 /etc/shadow 로 이전한다(passwd 의 두 번째 칸이 x 가 된다). 그룹 쪽도 grpconv 로 함께 정리하고, 이전 뒤 /etc/shadow 의 소유자·권한을 CCE-FILE-SHADOW 기준으로 확인한다.'),
  ('CCE-ACC-EMPTYPW', '패스워드가 비어 있어 인증 없이 로그인되는 계정이 있으면 위반이다.',
   'awk -F: ''$2==""'' /etc/shadow 로 대상 계정을 확인한다. 사용하는 계정이면 passwd <계정> 으로 즉시 설정하고, 쓰지 않는 계정이면 passwd -l <계정> 으로 잠그거나 usermod -s /usr/sbin/nologin 으로 로그인을 막는다.'),
  ('CCE-SEC-MODULE', 'SELinux 가 Enforcing 도 아니고 AppArmor 프로파일도 적재돼 있지 않으면 위반이다.',
   'RHEL 계열: /etc/selinux/config 에 SELINUX=enforcing 을 설정하고 setenforce 1 로 즉시 적용한다(오래 Disabled 였다면 재라벨링이 필요할 수 있다 — touch /.autorelabel 후 재부팅). 데비안/우분투 계열: apparmor 를 활성화(systemctl enable --now apparmor)하고 aa-status 로 프로파일 적재를 확인한다.'),
  ('CCE-SEC-FW', 'ufw·firewalld·nftables·iptables 어디에도 활성 정책이 없으면 위반이다.',
   '배포판이 쓰는 방화벽 하나를 골라 기본 차단 + 필요한 포트만 허용으로 구성한다. ufw: ufw default deny incoming → ufw allow <포트> → ufw enable. firewalld: systemctl enable --now firewalld 후 firewall-cmd --permanent --add-service=ssh --reload. nftables/iptables 직접 운용이면 정책을 저장해 재부팅 후에도 남게 한다. 원격 접속 포트를 먼저 허용한 뒤 활성화한다.'),
  ('CCE-FILE-PASSWD', '/etc/passwd 의 소유자가 root 가 아니거나 권한이 644 보다 느슨하면 위반이다.',
   'chown root:root /etc/passwd && chmod 644 /etc/passwd 로 되돌린다. 644 보다 넓힐 이유는 없다 — 읽기는 계정 조회를 위해 필요하지만 쓰기는 root 만이면 된다.'),
  ('CCE-FILE-SHADOW', '/etc/shadow 의 소유자가 root 가 아니거나 권한이 400 보다 느슨하면 위반이다.',
   'chown root:root /etc/shadow && chmod 400 /etc/shadow 로 되돌린다(배포판에 따라 그룹이 shadow 인 0640 관례가 있으나 이 점검은 400 이하를 기준으로 본다). 권한을 좁힌 뒤 passwd 변경이 정상 동작하는지 확인한다.'),
  ('CCE-FILE-GROUP', '/etc/group 의 소유자가 root 가 아니거나 권한이 644 보다 느슨하면 위반이다.',
   'chown root:root /etc/group && chmod 644 /etc/group 로 되돌린다. 쓰기가 열려 있으면 임의 계정을 wheel·sudo 같은 특권 그룹에 넣을 수 있다.'),
  ('CCE-FILE-GSHADOW', '/etc/gshadow 의 소유자가 root 가 아니거나 권한이 400 보다 느슨하면 위반이다.',
   'chown root:root /etc/gshadow && chmod 400 /etc/gshadow 로 되돌린다. 그룹 패스워드 해시가 담기므로 shadow 와 같은 수준으로 보호한다.'),
  ('CCE-FILE-HOSTS', '/etc/hosts 의 소유자가 root 가 아니거나 권한이 600 보다 느슨하면 위반이다.',
   'chown root:root /etc/hosts && chmod 600 /etc/hosts 로 되돌린다. 배포판 기본값이 644 라 손대지 않은 서버도 위반으로 잡히는데, 이는 오탐이 아니라 점검 기준(600)과 배포판 기본값이 다른 것이다 — 기준을 완화하지 않고 그대로 표시한다. 600 으로 좁히면 root 아닌 프로세스가 이름 해석에 이 파일을 읽지 못할 수 있으므로 서비스 영향을 먼저 확인한다.'),
  ('CCE-FILE-SERVICES', '/etc/services 의 소유자가 root 가 아니거나 권한이 644 보다 느슨하면 위반이다.',
   'chown root:root /etc/services && chmod 644 /etc/services 로 되돌린다.'),
  ('CCE-FILE-CRONTAB', '/etc/crontab 의 소유자가 root 가 아니거나 권한이 640 보다 느슨하면 위반이다.',
   'chown root:root /etc/crontab && chmod 640 /etc/crontab 로 되돌린다. 쓰기가 열리면 root 권한으로 도는 작업을 심을 수 있다. /etc/cron.d/ 와 /etc/cron.*/ 아래 파일 권한도 함께 확인한다. 파일이 아예 없는 환경(일부 컨테이너)에서는 판정 불가(NA)로 남는다.'),
  ('CCE-FILE-XINETD', '/etc/xinetd.conf 의 소유자가 root 가 아니거나 권한이 600 보다 느슨하면 위반이다.',
   'xinetd 를 쓰지 않는다면 패키지를 제거해 파일 자체를 없애는 것이 가장 확실하다(그 경우 이 점검은 판정 불가로 남는다). 계속 쓴다면 chown root:root /etc/xinetd.conf && chmod 600 /etc/xinetd.conf 로 되돌리고 /etc/xinetd.d/ 아래 항목도 함께 확인한다.'),
  ('CCE-FILE-SYSLOG', '/etc/rsyslog.conf 의 소유자가 root 가 아니거나 권한이 640 보다 느슨하면 위반이다.',
   'chown root:root /etc/rsyslog.conf && chmod 640 /etc/rsyslog.conf 로 되돌리고, /etc/rsyslog.d/ 아래 설정 파일에도 같은 권한을 적용한다. 로그 설정이 바뀌면 침해 흔적이 애초에 기록되지 않을 수 있다.'),
  ('CCE-PW-MAXDAYS', '/etc/login.defs 의 PASS_MAX_DAYS 가 90 을 넘거나 0 이하(무제한)이면 위반이다.',
   '/etc/login.defs 에 PASS_MAX_DAYS 90 (이하)를 설정한다. login.defs 는 이후 만들어지는 계정에만 적용되므로, 기존 계정은 chage -M 90 <계정> 으로 함께 조정하고 chage -l <계정> 으로 확인한다.'),
  ('CCE-PW-MINDAYS', '/etc/login.defs 의 PASS_MIN_DAYS 가 1 미만이면 위반이다.',
   '/etc/login.defs 에 PASS_MIN_DAYS 1 (이상)을 설정하고, 기존 계정은 chage -m 1 <계정> 으로 적용한다. 최소 기간이 없으면 변경 직후 원래 패스워드로 되돌릴 수 있어 주기 정책이 무력화된다.'),
  ('CCE-PW-MINLEN', '/etc/login.defs 의 PASS_MIN_LEN 이 8 미만이면 위반이다.',
   '/etc/login.defs 에 PASS_MIN_LEN 8 (이상)을 설정한다. 실제 강제는 PAM 이 하는 배포판이 많으므로 /etc/security/pwquality.conf 의 minlen 도 같은 값 이상으로 맞춰 둔다(CCE-PW-QUALITY 와 함께 적용).'),
  ('CCE-UMASK', '/etc/login.defs 의 UMASK 가 022 보다 느슨하면 위반이다.',
   '/etc/login.defs 에 UMASK 022 (이상, 즉 더 엄격하게)를 설정한다. 셸 초기화 파일(/etc/profile, /etc/bashrc 등)에서 더 느슨한 umask 를 다시 지정하고 있지 않은지 함께 확인한다 — 나중에 실행되는 쪽이 최종값이 된다.'),
  ('CCE-PW-QUALITY', 'PAM 설정에 pam_pwquality 또는 pam_cracklib 이 없으면 위반이다.',
   'pwquality 모듈을 설치하고(libpam-pwquality / libpwquality) 패스워드 스택에 pam_pwquality.so 를 넣는다(데비안 계열 /etc/pam.d/common-password, RHEL 계열은 authselect 로 관리). 규칙은 /etc/security/pwquality.conf 에서 minlen·minclass 등으로 정한다. 직접 편집보다 배포판의 설정 도구를 쓰는 편이 업데이트 때 덮이지 않는다.'),
  ('CCE-PW-LOCKOUT', 'PAM 설정에 pam_faillock 또는 pam_tally2 가 없으면 위반이다.',
   'pam_faillock 을 auth 스택에 넣고 /etc/security/faillock.conf 에서 deny(실패 허용 횟수)·unlock_time 을 정한다(RHEL 계열은 authselect enable-feature with-faillock). 설정 후 일부러 실패시켜 faillock --user <계정> 으로 카운트가 오르는지 확인한다 — 모듈만 넣고 스택 순서가 틀리면 잠기지 않는다.'),
  ('CCE-RHOSTS', '/etc/hosts.equiv 또는 사용자 홈의 .rhosts 가 있으면 위반이다.',
   '파일을 제거한다(rm -f /etc/hosts.equiv; find /home /root -maxdepth 2 -name .rhosts -delete). 두 파일은 패스워드 없는 신뢰 접속을 선언하므로 남겨 둘 이유가 없다. 함께 r 계열 서비스가 남아 있지 않은지 CCE-SVC-LEGACY 로 확인한다.'),
  ('CCE-ROOT-PATH', 'root 의 PATH 에 현재 디렉터리(.)가 독립 경로로 들어 있으면 위반이다.',
   '/root/.bash_profile·/root/.bashrc·/etc/profile 등에서 PATH 정의를 찾아 "." 과 빈 항목(연속된 콜론, 맨 앞·맨 뒤 콜론)을 제거한다. 빈 항목도 현재 디렉터리로 해석되므로 눈에 보이는 점만 지우면 남는다.'),
  ('CCE-SVC-LEGACY', 'telnet·rsh·rlogin·rexec·vsftpd·proftpd·tftp·finger·talk 중 활성인 것이 있으면 위반이다.',
   '해당 서비스를 중지·비활성화하고(systemctl disable --now <유닛>) 가능하면 패키지째 제거한다. xinetd 로 뜨는 항목이면 /etc/xinetd.d/ 의 해당 파일에서 disable = yes 로 바꾼 뒤 xinetd 를 재시작한다. 원격 셸은 SSH, 파일 전송은 SFTP/SCP 로 대체한다.'),
  ('CCE-SESSION-TMOUT', '셸의 TMOUT 이 설정되지 않았거나 600(초)을 넘으면 위반이다.',
   '/etc/profile 또는 /etc/profile.d/tmout.sh 에 TMOUT=600 과 export TMOUT(변경을 막으려면 readonly TMOUT)를 넣는다. 600 이하 값을 쓰고, 미설정도 위반이다. 로그아웃 후 다시 접속해 echo $TMOUT 으로 확인한다. SSH 세션 쪽 유휴 종료는 CCE-SSH-IDLE 이 따로 본다.'),
  ('CCE-TIME-SYNC', 'NTP 동기화 상태가 확인되지 않으면 위반이다.',
   'chrony(또는 systemd-timesyncd)를 설치·활성화한다: systemctl enable --now chronyd. /etc/chrony.conf 에 조직이 쓰는 NTP 서버를 지정하고, timedatectl 의 "System clock synchronized: yes" 와 chronyc tracking 의 Leap status: Normal 로 확인한다. 폐쇄망이면 내부 시간 서버를 두고 방화벽에서 123/udp 를 열어 둔다.'),
  ('CCE-TIME-OFFSET', 'NTP 기준 시각 오차가 1.0초를 넘으면 위반이다.',
   '먼저 동기화 자체가 살아 있는지 확인하고(chronyc sources -v 로 선택된 소스 유무), 오차가 크면 chronyc makestep 으로 즉시 보정한다. 지속적으로 벌어지면 상위 NTP 서버 도달성·네트워크 지연·가상화 호스트의 시계 설정을 점검한다. 오차가 크면 여러 서버의 로그를 시간순으로 맞춰 볼 수 없어 사고 분석이 무너진다.'),
  ('CCE-LOG-RETENTION', '저널·logrotate 어느 쪽으로도 계산한 로그 보존기간이 90일 미만이면 위반이다.',
   '둘 중 긴 쪽이 기준을 넘으면 통과다. journald: /etc/systemd/journald.conf 에 Storage=persistent 와 MaxRetentionSec=90d 를 설정하고 systemctl restart systemd-journald. logrotate: /etc/logrotate.conf 의 주기와 rotate 값을 곱해 90일 이상이 되게 한다(예: weekly + rotate 13) 또는 maxage 90 을 명시한다. 보존기간을 늘리기 전에 /var/log 여유 공간을 먼저 확인한다.'),
  ('CCE-LOG-REMOTE', 'rsyslog 에 원격 전송 설정이 없으면 위반이다.',
   '/etc/rsyslog.d/ 에 전송 규칙을 추가한다(예: *.* @@로그서버:514 — @@ 는 TCP, @ 는 UDP). 전송 중 유실을 줄이려면 action(type="omfwd" …) 형식으로 큐·재시도를 함께 지정한다. 설정 후 rsyslogd -N1 로 문법을 확인하고 재시작한 뒤 수집 서버에 실제로 도착하는지 확인한다.'),
  ('CCE-CRYPTO-SSH-CIPHER', 'sshd 의 Ciphers·MACs·KexAlgorithms 에 CBC·MD5·SHA1·64비트 UMAC 계열이 남아 있으면 위반이다.',
   '/etc/ssh/sshd_config 에 허용 목록을 명시한다. 예: Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes128-ctr / MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com / KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512. OpenSSH 기본 MACs 에 hmac-sha1·umac-64 가 들어 있어 설정을 손대지 않은 서버는 대부분 위반으로 잡힌다 — 명시 설정이 곧 조치다. 오래된 클라이언트의 접속 가능 여부를 먼저 확인하고, 재시작 후 sshd -T | grep -E ''^(ciphers|macs|kexalgorithms)'' 로 실효값을 확인한다.'),
  ('CCE-CRYPTO-DISK', 'LUKS 암호화 볼륨이 있으면 통과로 보고, 없으면 정보성(판정 불가)으로 남긴다.',
   '위반으로 판정하지 않는 항목이다 — 디스크 암호화는 모든 서버의 필수 요건이 아니다. 다만 개인정보·기밀을 저장하는 서버라면 저장 데이터 암호화 적용 여부를 별도로 검토한다(신규 구축 시 설치 단계에서 LUKS 를 적용하는 편이 이후 전환보다 훨씬 간단하다).'),
  ('CCE-CRYPTO-KCMVP', 'SSH 알고리즘 목록에 ARIA/SEED 계열이 있는지만 정보로 남긴다 — 판정하지 않는다.',
   '이 도구로는 조치 여부를 확인할 수 없다. 검증필 암호모듈 요건은 "어떤 알고리즘을 쓰는가"가 아니라 "쓰는 모듈이 검증을 받았는가"를 묻기 때문에, 사용 중인 암호모듈의 검증 여부를 별도 문서로 확인해야 한다.')
ON DUPLICATE KEY UPDATE summary = VALUES(summary), remediation = VALUES(remediation), is_deleted = 0, deleted_at = NULL;
