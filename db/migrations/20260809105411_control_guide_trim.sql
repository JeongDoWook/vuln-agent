-- 통제 상세 화면(/control.php)의 문구 축약.
--   20260809093626 이 넣은 설명·조치 원문이 화면에서 너무 길었다 — remediation 은 평균 179자,
--   최대 464자라 표 한 칸에 긴 문단이 통째로 들어갔고, 통제 하나만 열어도 세로로 길게 늘어졌다.
--   내용에는 근거가 있으므로 버리지 않는다: **원문 전문은 docs/dev/보안설정-조치가이드.md 로
--   옮겼고**, 화면에는 한 줄 요약만 남긴다. 화면 = 무엇이 문제인가, 문서 = 어떻게 고치는가.
--
--   길이 기준(화면 표에서 한 줄로 읽히는 폭):
--     · tb_control_guide.description  ≤ 60자
--     · tb_cce_rule_guide.summary     ≤ 40자
--     · tb_cce_rule_guide.remediation ≤ 80자
--
--   축약해도 사실관계는 원문과 같아야 한다. 파일명·지시어·임계값은 server/src/cce.php 의 판정
--   로직과 계속 일치한다(PASS_MAX_DAYS 90 / MaxAuthTries 5 / UMASK 022 / 로그보존 90일 …) —
--   고쳐도 FAIL 이 안 사라지는 안내가 되면 안 되기 때문이다.
--
--   20260809093626 은 이미 적용·병합됐으므로 수정하지 않는다. 여기서 UPDATE 로 덮는다.
--   멱등: rule_code / (framework, control_id) 단위 선언적 UPDATE — 몇 번 돌려도 같은 값이 된다.
SET NAMES utf8mb4;

-- ── 1) 통제 설명 ────────────────────────────────────────────────────────────
UPDATE tb_control_guide SET description = CASE control_id
  WHEN 'U-01' THEN 'root 계정의 원격 직접 로그인을 막는다.'
  WHEN 'U-02' THEN '패스워드 복잡성 규칙을 인증 모듈에서 강제한다.'
  WHEN 'U-03' THEN '로그인 실패가 임계값을 넘으면 계정을 잠근다.'
  WHEN 'U-04' THEN '패스워드 해시를 /etc/shadow 로 분리해 보관한다.'
  WHEN 'U-05' THEN 'root 의 홈과 PATH 를 안전하게 유지한다(현재 디렉터리 제외).'
  WHEN 'U-07' THEN '/etc/passwd 의 소유자를 root 로 두고 쓰기를 제한한다.'
  WHEN 'U-08' THEN '/etc/shadow 는 root 만 읽을 수 있어야 한다.'
  WHEN 'U-09' THEN '/etc/hosts 의 소유자·권한을 제한한다.'
  WHEN 'U-10' THEN '(x)inetd 설정 파일의 소유자·권한을 제한한다.'
  WHEN 'U-11' THEN 'syslog(rsyslog) 설정 파일의 소유자·권한을 제한한다.'
  WHEN 'U-12' THEN '/etc/services 의 소유자·권한을 제한한다.'
  WHEN 'U-17' THEN 'hosts.equiv 와 .rhosts 를 쓰지 않는다.'
  WHEN 'U-19' THEN 'Finger 서비스를 비활성화한다.'
  WHEN 'U-21' THEN 'rsh·rlogin·rexec 등 r 계열 서비스를 비활성화한다.'
  WHEN 'U-44' THEN 'root 외의 계정이 UID 0 을 갖지 않게 한다.'
  WHEN 'U-46' THEN '패스워드 최소 길이를 시스템이 강제한다.'
  WHEN 'U-47' THEN '패스워드 최대 사용기간을 정해 주기적으로 바꾸게 한다.'
  WHEN 'U-48' THEN '패스워드 최소 사용기간을 두어 즉시 되돌리기를 막는다.'
  WHEN 'U-52' THEN '동일한 UID 를 여러 계정이 나눠 쓰지 않게 한다.'
  WHEN 'U-54' THEN '방치된 로그인 세션을 일정 시간 뒤 자동 종료한다.'
  WHEN 'U-56' THEN '새로 만들어지는 파일의 기본 권한(UMASK)을 제한한다.'
  ELSE description END
WHERE framework = 'KISA_U';

UPDATE tb_control_guide SET description = CASE control_id
  WHEN '2.5.3'  THEN '인증 수단이 추측·자동화 공격에 견디도록 운영한다.'
  WHEN '2.5.4'  THEN '비밀번호 생성·변경·보관 규칙을 시스템이 강제한다.'
  WHEN '2.5.5'  THEN '관리자·특수 권한은 최소로 주고 식별 가능해야 한다.'
  WHEN '2.6.1'  THEN '네트워크 접근은 필요한 경로만 허용하고 나머지는 차단한다.'
  WHEN '2.6.3'  THEN '세션은 일정 시간 사용이 없으면 종료되어야 한다.'
  WHEN '2.6.6'  THEN '원격에서의 접근은 안전한 방식으로 제한한다.'
  WHEN '2.10.1' THEN '보안 관련 파일·설정은 인가된 사용자만 변경할 수 있다.'
  ELSE description END
WHERE framework = 'ISMS_P';

UPDATE tb_control_guide SET description = CASE control_id
  WHEN 'AP'   THEN '인증 자격증명의 강도와 수명을 정책으로 강제하는 영역.'
  WHEN 'LI'   THEN '로그인 시도 횟수 자체를 제한하는 영역.'
  WHEN 'LP'   THEN '권한을 필요한 만큼만 주는 최소권한 영역.'
  WHEN 'LP-4' THEN '관리자 권한의 사용 경로를 제한하는 영역.'
  WHEN 'AC'   THEN '계정의 생성·식별·정리를 다루는 영역(유일한 식별자).'
  WHEN 'SN'   THEN '세션의 유지와 종료를 다루는 영역.'
  WHEN 'EB'   THEN '외부 경계에서 트래픽을 통제하는 영역.'
  WHEN 'IN'   THEN '시스템 내부 설정의 무결성을 다루는 영역.'
  ELSE description END
WHERE framework = 'N2SF';

-- ── 2) 점검 항목별 요약·조치 ────────────────────────────────────────────────
-- 상세 절차(예시 나열·주의사항·검증 명령)는 docs/dev/보안설정-조치가이드.md 에 있다.
UPDATE tb_cce_rule_guide SET
  summary = CASE rule_code
    WHEN 'CCE-SSH-ROOT'          THEN 'PermitRootLogin 실효값이 yes 인지'
    WHEN 'CCE-SSH-PWAUTH'        THEN 'PasswordAuthentication 이 yes 인지'
    WHEN 'CCE-SSH-EMPTYPW'       THEN 'PermitEmptyPasswords 가 yes 인지'
    WHEN 'CCE-SSH-MAXAUTH'       THEN 'MaxAuthTries 가 5 를 넘는지'
    WHEN 'CCE-SSH-X11'           THEN 'X11Forwarding 이 yes 인지'
    WHEN 'CCE-SSH-GRACE'         THEN 'LoginGraceTime 이 60초를 넘는지'
    WHEN 'CCE-SSH-IDLE'          THEN 'ClientAliveInterval 이 0 이거나 300초 초과인지'
    WHEN 'CCE-ACC-UID0'          THEN 'root 외에 UID 0 인 계정이 있는지'
    WHEN 'CCE-ACC-DUPUID'        THEN '여러 계정이 같은 UID 를 쓰는지'
    WHEN 'CCE-ACC-SHADOW'        THEN '/etc/passwd 에 해시가 남아 있는지'
    WHEN 'CCE-ACC-EMPTYPW'       THEN '패스워드가 비어 있는 계정이 있는지'
    WHEN 'CCE-SEC-MODULE'        THEN 'SELinux Enforcing 또는 AppArmor 적재 여부'
    WHEN 'CCE-SEC-FW'            THEN '호스트 방화벽 활성 정책이 있는지'
    WHEN 'CCE-FILE-PASSWD'       THEN '/etc/passwd 소유자 root · 권한 644 이하인지'
    WHEN 'CCE-FILE-SHADOW'       THEN '/etc/shadow 소유자 root · 권한 400 이하인지'
    WHEN 'CCE-FILE-GROUP'        THEN '/etc/group 소유자 root · 권한 644 이하인지'
    WHEN 'CCE-FILE-GSHADOW'      THEN '/etc/gshadow 소유자 root · 권한 400 이하인지'
    WHEN 'CCE-FILE-HOSTS'        THEN '/etc/hosts 소유자 root · 권한 600 이하인지'
    WHEN 'CCE-FILE-SERVICES'     THEN '/etc/services 소유자 root · 644 이하인지'
    WHEN 'CCE-FILE-CRONTAB'      THEN '/etc/crontab 소유자 root · 640 이하인지'
    WHEN 'CCE-FILE-XINETD'       THEN '/etc/xinetd.conf 소유자 root · 600 이하인지'
    WHEN 'CCE-FILE-SYSLOG'       THEN '/etc/rsyslog.conf 소유자 root · 640 이하인지'
    WHEN 'CCE-PW-MAXDAYS'        THEN 'PASS_MAX_DAYS 가 90 초과이거나 0 이하인지'
    WHEN 'CCE-PW-MINDAYS'        THEN 'PASS_MIN_DAYS 가 1 미만인지'
    WHEN 'CCE-PW-MINLEN'         THEN 'PASS_MIN_LEN 이 8 미만인지'
    WHEN 'CCE-UMASK'             THEN 'login.defs 의 UMASK 가 022 보다 느슨한지'
    WHEN 'CCE-PW-QUALITY'        THEN 'PAM 에 pam_pwquality/cracklib 이 있는지'
    WHEN 'CCE-PW-LOCKOUT'        THEN 'PAM 에 pam_faillock/tally2 가 있는지'
    WHEN 'CCE-RHOSTS'            THEN 'hosts.equiv 나 .rhosts 가 있는지'
    WHEN 'CCE-ROOT-PATH'         THEN 'root PATH 에 현재 디렉터리(.)가 있는지'
    WHEN 'CCE-SVC-LEGACY'        THEN 'telnet·rsh·ftp·finger 등 구식 서비스 활성 여부'
    WHEN 'CCE-SESSION-TMOUT'     THEN '셸 TMOUT 미설정이거나 600초 초과인지'
    WHEN 'CCE-TIME-SYNC'         THEN 'NTP 동기화 상태가 확인되는지'
    WHEN 'CCE-TIME-OFFSET'       THEN 'NTP 기준 시각 오차가 1.0초를 넘는지'
    WHEN 'CCE-LOG-RETENTION'     THEN '로그 보존기간이 90일 미만인지'
    WHEN 'CCE-LOG-REMOTE'        THEN 'rsyslog 원격 전송 설정이 있는지'
    WHEN 'CCE-CRYPTO-SSH-CIPHER' THEN 'SSH 에 CBC·MD5·SHA1 계열이 남아 있는지'
    WHEN 'CCE-CRYPTO-DISK'       THEN 'LUKS 암호화 볼륨 유무(정보성)'
    WHEN 'CCE-CRYPTO-KCMVP'      THEN 'SSH 에 ARIA/SEED 유무(정보성, 판정 안 함)'
    ELSE summary END,
  remediation = CASE rule_code
    WHEN 'CCE-SSH-ROOT'          THEN '/etc/ssh/sshd_config 에 PermitRootLogin no 설정 후 sshd 재시작'
    WHEN 'CCE-SSH-PWAUTH'        THEN '공개키 등록 후 sshd_config 에 PasswordAuthentication no 설정'
    WHEN 'CCE-SSH-EMPTYPW'       THEN 'sshd_config 에 PermitEmptyPasswords no 설정 후 sshd 재시작'
    WHEN 'CCE-SSH-MAXAUTH'       THEN 'sshd_config 의 MaxAuthTries 를 5 이하로 설정 후 sshd 재시작'
    WHEN 'CCE-SSH-X11'           THEN 'GUI 가 필요 없으면 sshd_config 에 X11Forwarding no 설정'
    WHEN 'CCE-SSH-GRACE'         THEN 'sshd_config 의 LoginGraceTime 을 60 이하로 설정'
    WHEN 'CCE-SSH-IDLE'          THEN 'sshd_config 에 ClientAliveInterval 300 이하와 CountMax 설정'
    WHEN 'CCE-ACC-UID0'          THEN 'root 외 UID 0 계정은 usermod -u 로 일반 UID 부여 또는 삭제'
    WHEN 'CCE-ACC-DUPUID'        THEN 'usermod -u 로 중복 UID 를 바꾸고 소유 파일을 chown 으로 이전'
    WHEN 'CCE-ACC-SHADOW'        THEN 'pwconv 로 해시를 /etc/shadow 로 옮긴다(그룹은 grpconv)'
    WHEN 'CCE-ACC-EMPTYPW'       THEN 'passwd <계정> 으로 설정하거나 passwd -l 로 잠근다'
    WHEN 'CCE-SEC-MODULE'        THEN 'SELINUX=enforcing + setenforce 1, 또는 apparmor 활성화'
    WHEN 'CCE-SEC-FW'            THEN '방화벽 하나를 기본 차단으로 구성(ufw enable / firewalld)'
    WHEN 'CCE-FILE-PASSWD'       THEN 'chown root:root /etc/passwd && chmod 644 /etc/passwd'
    WHEN 'CCE-FILE-SHADOW'       THEN 'chown root:root /etc/shadow && chmod 400 /etc/shadow'
    WHEN 'CCE-FILE-GROUP'        THEN 'chown root:root /etc/group && chmod 644 /etc/group'
    WHEN 'CCE-FILE-GSHADOW'      THEN 'chown root:root /etc/gshadow && chmod 400 /etc/gshadow'
    WHEN 'CCE-FILE-HOSTS'        THEN 'chown root:root /etc/hosts && chmod 600 /etc/hosts'
    WHEN 'CCE-FILE-SERVICES'     THEN 'chown root:root /etc/services && chmod 644 /etc/services'
    WHEN 'CCE-FILE-CRONTAB'      THEN 'chown root:root /etc/crontab && chmod 640 /etc/crontab'
    WHEN 'CCE-FILE-XINETD'       THEN 'xinetd 를 안 쓰면 제거, 쓰면 chmod 600 /etc/xinetd.conf'
    WHEN 'CCE-FILE-SYSLOG'       THEN 'chown root:root /etc/rsyslog.conf && chmod 640 로 되돌린다'
    WHEN 'CCE-PW-MAXDAYS'        THEN '/etc/login.defs 의 PASS_MAX_DAYS 를 90 이하로(chage -M 90)'
    WHEN 'CCE-PW-MINDAYS'        THEN '/etc/login.defs 의 PASS_MIN_DAYS 를 1 이상으로(chage -m 1)'
    WHEN 'CCE-PW-MINLEN'         THEN '/etc/login.defs 의 PASS_MIN_LEN 을 8 이상으로 설정'
    WHEN 'CCE-UMASK'             THEN '/etc/login.defs 의 UMASK 를 022 이상(더 엄격)으로 설정'
    WHEN 'CCE-PW-QUALITY'        THEN 'PAM 패스워드 스택에 pam_pwquality.so 를 넣고 규칙 지정'
    WHEN 'CCE-PW-LOCKOUT'        THEN 'PAM auth 스택에 pam_faillock 추가 후 deny·unlock_time 지정'
    WHEN 'CCE-RHOSTS'            THEN '/etc/hosts.equiv 와 사용자 홈의 .rhosts 파일을 제거한다'
    WHEN 'CCE-ROOT-PATH'         THEN 'root 의 PATH 정의에서 . 과 빈 항목(연속 콜론)을 제거'
    WHEN 'CCE-SVC-LEGACY'        THEN 'systemctl disable --now <유닛> 후 가능하면 패키지째 제거'
    WHEN 'CCE-SESSION-TMOUT'     THEN '/etc/profile.d/tmout.sh 에 TMOUT=600 과 export TMOUT 추가'
    WHEN 'CCE-TIME-SYNC'         THEN 'systemctl enable --now chronyd 후 NTP 서버 지정'
    WHEN 'CCE-TIME-OFFSET'       THEN 'chronyc makestep 으로 보정하고 chronyc sources -v 로 점검'
    WHEN 'CCE-LOG-RETENTION'     THEN 'journald MaxRetentionSec=90d 또는 logrotate 로 90일 확보'
    WHEN 'CCE-LOG-REMOTE'        THEN '/etc/rsyslog.d/ 에 전송 규칙 추가(예: *.* @@로그서버:514)'
    WHEN 'CCE-CRYPTO-SSH-CIPHER' THEN 'sshd_config 에 Ciphers·MACs·KexAlgorithms 를 명시해 구식 제외'
    WHEN 'CCE-CRYPTO-DISK'       THEN '위반으로 판정하지 않는다. 기밀 저장 서버면 LUKS 를 검토'
    WHEN 'CCE-CRYPTO-KCMVP'      THEN '알고리즘이 아니라 암호모듈의 검증필 여부를 문서로 확인'
    ELSE remediation END;
