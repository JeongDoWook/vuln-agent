<?php
declare(strict_types=1);

/**
 * cce.php — 보안설정 점검(CCE). 에이전트가 이미 수집한 security/users 섹션을
 *   서버에서 판정해 tb_cce_finding 에 저장한다. (CVE=취약한 버전, CCE=잘못된 설정)
 *
 *   신규 수집 없음 — vuln-inventory-agent.sh 의 12)보안자세 · 13)사용자/인증 섹션을 재활용.
 *   각 점검은 [코드, 제목, 결과(PASS/FAIL/NA), 위험도, 근거값, 판정사유] 를 남긴다(설명가능성).
 *   수집값이 없으면(비-root 실행 등) NA — 통과로 위장하지 않고 "미점검"을 드러낸다.
 */

require_once __DIR__ . '/db.php';

if (!function_exists('vg_sshd_val')) {
    // 판정 임계값 — 코드에 숫자를 박지 않는다(하드코딩 금지). 근거는 각 상수 주석 참고.
    define('VG_CCE_TIME_OFFSET_MAX_SEC', 1.0);   // 로그 상관분석이 흔들리기 시작하는 경계(초)
    define('VG_CCE_LOG_RETENTION_DAYS', 90);     // ISMS-P 2.9.4 통상 요구 보존기간(일)

    /**
     * systemd 시간 표기 → 초. "90d" · "2592000" · "1month" · "1h30m" 를 받는다.
     *   해석할 수 없으면 null — 모르면 NA 로 가야지 0 으로 읽어 FAIL 을 만들면 안 된다.
     */
    function vg_cce_timespan_sec(string $v): ?float {
        $v = trim($v);
        if ($v === '' || !preg_match_all('/(\d+(?:\.\d+)?)\s*([A-Za-z]*)/', $v, $ms, PREG_SET_ORDER)) {
            return null;
        }
        // systemd 는 대문자 M 만 "달"이고 소문자 m 은 "분"이다 → 소문자화 전에 가른다.
        $unit = [
            ''    => 1.0,       'us'  => 0.000001, 'ms'  => 0.001,
            's'   => 1.0,       'sec' => 1.0,      'secs' => 1.0, 'second' => 1.0, 'seconds' => 1.0,
            'm'   => 60.0,      'min' => 60.0,     'mins' => 60.0, 'minute' => 60.0, 'minutes' => 60.0,
            'h'   => 3600.0,    'hr'  => 3600.0,   'hour' => 3600.0, 'hours' => 3600.0,
            'd'   => 86400.0,   'day' => 86400.0,  'days' => 86400.0,
            'w'   => 604800.0,  'week' => 604800.0, 'weeks' => 604800.0,
            'month' => 2629800.0, 'months' => 2629800.0,
            'y'   => 31557600.0, 'year' => 31557600.0, 'years' => 31557600.0,
        ];
        $total = 0.0;
        foreach ($ms as $m) {
            $u = ($m[2] === 'M') ? 'month' : strtolower($m[2]);
            if (!isset($unit[$u])) { return null; }
            $total += (float) $m[1] * $unit[$u];
        }
        return $total;
    }

    /**
     * chronyc tracking / ntpq -pn 출력에서 현재 시간 오차(초, 절대값)를 뽑는다.
     *   못 뽑으면 null(→ NA). 값을 지어내지 않는다.
     */
    function vg_cce_time_offset(string $tracking): ?float {
        // chronyc: "System time : 0.000000123 seconds fast of NTP time"
        if (preg_match('/System time\s*:\s*([0-9.]+(?:e-?\d+)?)\s*seconds/i', $tracking, $m)) {
            return abs((float) $m[1]);
        }
        // chronyc: "Last offset : +0.000000123 seconds"
        if (preg_match('/Last offset\s*:\s*([+-]?[0-9.]+(?:e-?\d+)?)\s*seconds/i', $tracking, $m)) {
            return abs((float) $m[1]);
        }
        // ntpq -pn: 선택된 피어(*) 행의 9번째 칼럼이 offset(ms).
        foreach (preg_split('/\r?\n/', $tracking) as $line) {
            $line = trim($line);
            if ($line === '' || $line[0] !== '*') { continue; }
            $f = preg_split('/\s+/', $line);
            if (count($f) >= 10 && is_numeric($f[8])) { return abs((float) $f[8]) / 1000.0; }
        }
        return null;
    }

    // sshd 설정값 조회: sshd -T(권위, 소문자키) 우선, 없으면 sshd_config grep 폴백.
    //   반환: 소문자 값 문자열, 못 찾으면 null.
    function vg_sshd_val(string $eff, string $cfg, string $key): ?string {
        $key = strtolower($key);
        foreach ([$eff, $cfg] as $src) {
            foreach (preg_split('/\r?\n/', $src) as $line) {
                $line = trim($line);
                if ($line === '' || $line[0] === '#') { continue; }
                $p = preg_split('/\s+/', $line, 2);
                if (isset($p[0]) && strtolower($p[0]) === $key) {
                    return strtolower(trim($p[1] ?? ''));
                }
            }
        }
        return null;
    }

    // 수집 JSON → 점검 결과 배열. 각 원소: [code,title,result,severity,evidence,rationale].
    function vg_cce_checks(array $data): array {
        $sec  = $data['security'] ?? [];
        $usr  = $data['users']    ?? [];
        $meta = $data['meta']     ?? [];
        $isRoot = strtolower(trim((string) ($meta['running_as'] ?? ''))) === 'root';

        $sshEff = (string) ($usr['sshd_effective'] ?? '');
        $sshCfg = (string) ($usr['sshd_config']    ?? '');

        $out = [];

        // ── CCE-SSH-ROOT : SSH root 원격 로그인 차단 (KISA U-01 계열) ──
        $v = vg_sshd_val($sshEff, $sshCfg, 'permitrootlogin');
        if ($v === null) {
            $out[] = ['CCE-SSH-ROOT', 'SSH root 원격 로그인 차단', 'NA', 'HIGH',
                null, 'sshd 설정을 수집하지 못함(비-root 실행 시 제한적).'];
        } else {
            $fail = ($v === 'yes');
            $out[] = ['CCE-SSH-ROOT', 'SSH root 원격 로그인 차단', $fail ? 'FAIL' : 'PASS', 'HIGH',
                'PermitRootLogin ' . $v,
                $fail ? 'root 로 직접 SSH 로그인이 허용됨 → no 또는 prohibit-password 권고.'
                      : 'PermitRootLogin=' . $v . ' 로 직접 root 로그인이 제한됨.'];
        }

        // ── CCE-SSH-PWAUTH : SSH 패스워드 인증 제한(키 기반 권고) ──
        $v = vg_sshd_val($sshEff, $sshCfg, 'passwordauthentication');
        if ($v === null) {
            $out[] = ['CCE-SSH-PWAUTH', 'SSH 패스워드 인증 제한', 'NA', 'MEDIUM',
                null, 'sshd 설정을 수집하지 못함.'];
        } else {
            $fail = ($v === 'yes');
            $out[] = ['CCE-SSH-PWAUTH', 'SSH 패스워드 인증 제한', $fail ? 'FAIL' : 'PASS', 'MEDIUM',
                'PasswordAuthentication ' . $v,
                $fail ? '패스워드 인증 허용 → 무차별 대입에 노출. 공개키 인증 권고.'
                      : '패스워드 인증이 비활성(공개키 기반).'];
        }

        // ── CCE-ACC-UID0 : root 외 UID 0 계정 금지 (KISA U-02 계열) ──
        $acc = (string) ($usr['accounts'] ?? '');
        if ($acc === '') {
            $out[] = ['CCE-ACC-UID0', 'root 외 UID 0 계정 금지', 'NA', 'HIGH',
                null, '계정 목록을 수집하지 못함.'];
        } else {
            $dups = [];
            foreach (preg_split('/\r?\n/', $acc) as $line) {
                if ($line === '') { continue; }
                $f = explode("\t", $line);          // name \t uid \t shell
                $name = trim($f[0] ?? '');
                $uid  = trim($f[1] ?? '');
                if ($uid !== '' && ctype_digit($uid) && (int) $uid === 0 && $name !== 'root') {
                    $dups[] = $name;
                }
            }
            if ($dups) {
                $out[] = ['CCE-ACC-UID0', 'root 외 UID 0 계정 금지', 'FAIL', 'HIGH',
                    'UID0: ' . implode(', ', $dups),
                    'root 와 동일한 UID 0 을 가진 계정이 존재 → root 권한 우회 가능.'];
            } else {
                $out[] = ['CCE-ACC-UID0', 'root 외 UID 0 계정 금지', 'PASS', 'HIGH',
                    'UID0: root', 'UID 0 은 root 뿐.'];
            }
        }

        // ── CCE-SEC-MODULE : 강제접근제어(SELinux/AppArmor) 활성 ──
        $se = (string) ($sec['selinux']  ?? '');
        $aa = (string) ($sec['apparmor'] ?? '');
        $seEnforcing = (bool) preg_match('/Enforcing/i', $se);
        $sePermDis   = (bool) preg_match('/Permissive|Disabled/i', $se);
        $aaActive    = $aa !== '' && (bool) preg_match('/profiles are loaded|in enforce mode|module is loaded/i', $aa);
        if ($seEnforcing || $aaActive) {
            $out[] = ['CCE-SEC-MODULE', '강제접근제어(SELinux/AppArmor) 활성', 'PASS', 'MEDIUM',
                $seEnforcing ? 'SELinux Enforcing' : 'AppArmor 적용',
                '커널 강제접근제어가 동작 중.'];
        } elseif ($sePermDis) {
            $mode = preg_match('/Permissive/i', $se) ? 'Permissive' : 'Disabled';
            $out[] = ['CCE-SEC-MODULE', '강제접근제어(SELinux/AppArmor) 활성', 'FAIL', 'MEDIUM',
                'SELinux ' . $mode, 'SELinux 가 ' . $mode . ' → 강제접근제어 미적용. Enforcing 권고.'];
        } elseif ($aa !== '') {
            $out[] = ['CCE-SEC-MODULE', '강제접근제어(SELinux/AppArmor) 활성', 'FAIL', 'MEDIUM',
                'AppArmor 프로파일 미적재', 'AppArmor 프로파일이 로드되지 않음.'];
        } else {
            $out[] = ['CCE-SEC-MODULE', '강제접근제어(SELinux/AppArmor) 활성', 'NA', 'MEDIUM',
                null, 'SELinux/AppArmor 상태를 수집하지 못함.'];
        }

        // ── CCE-SEC-FW : 호스트 방화벽 정책 존재 ──
        //   방화벽 섹션은 root 실행 시에만 수집됨. 탐지는 휴리스틱(활성 신호 존재 여부).
        $ufw = (string) ($sec['ufw']       ?? '');
        $fwd = (string) ($sec['firewalld'] ?? '');
        $nft = (string) ($sec['nftables']  ?? '');
        $ipt = (string) ($sec['iptables']  ?? '');
        $active = false; $ev = '';
        if ($ufw !== '' && preg_match('/Status:\s*active/i', $ufw))      { $active = true; $ev = 'ufw active'; }
        elseif ($fwd !== '')                                             { $active = true; $ev = 'firewalld 활성'; }
        elseif ($nft !== '' && preg_match('/\btable\b/i', $nft))         { $active = true; $ev = 'nftables 룰 존재'; }
        elseif ($ipt !== '' && preg_match('/^-A /m', $ipt))              { $active = true; $ev = 'iptables 룰 존재'; }
        $anyCollected = ($ufw !== '' || $fwd !== '' || $nft !== '' || $ipt !== '');
        if ($active) {
            $out[] = ['CCE-SEC-FW', '호스트 방화벽 정책 존재', 'PASS', 'MEDIUM',
                $ev, '방화벽 정책이 활성.'];
        } elseif ($isRoot || $anyCollected) {
            $out[] = ['CCE-SEC-FW', '호스트 방화벽 정책 존재', 'FAIL', 'MEDIUM',
                '활성 룰 없음', '활성 방화벽 정책(ufw/firewalld/nft/iptables)을 찾지 못함.'];
        } else {
            $out[] = ['CCE-SEC-FW', '호스트 방화벽 정책 존재', 'NA', 'MEDIUM',
                null, '방화벽 상태를 수집하지 못함(root 실행 필요).'];
        }

        // ══════════════════════════════════════════════════════════════════
        // KISA 「주요정보통신기반시설 기술적 취약점 분석·평가 가이드」(U-XX) 항목
        //   CCE 는 CVE 처럼 받아올 피드가 없다 — MITRE/NIST CCE 사전은 2013년경 갱신이
        //   끊겼고, KISA·금융보안원 가이드는 PDF/HWP 문서로만 배포된다(API 없음).
        //   그래서 가이드 항목을 코드로 옮긴다. 각 판정은 근거값과 사유를 남긴다.
        // ══════════════════════════════════════════════════════════════════

        // ── SSH 세부 (U-01 계열 확장) ──
        //   sshd -T 는 "실제 적용값"이라 config 파일보다 권위 있다.
        $sshChecks = [
            // [코드, 제목, 키, 판정 콜백(값 → [실패여부, 권고]), 위험도]
            ['CCE-SSH-EMPTYPW', 'SSH 빈 패스워드 로그인 차단', 'permitemptypasswords',
             fn(string $v) => [$v === 'yes', 'PermitEmptyPasswords=no 권고.'], 'HIGH'],
            ['CCE-SSH-MAXAUTH', 'SSH 인증 시도 횟수 제한', 'maxauthtries',
             fn(string $v) => [(int) $v > 5, '무차별 대입 방어 — MaxAuthTries 5 이하 권고.'], 'MEDIUM'],
            ['CCE-SSH-X11', 'SSH X11 포워딩 차단', 'x11forwarding',
             fn(string $v) => [$v === 'yes', '불필요하면 X11Forwarding=no 권고.'], 'LOW'],
            ['CCE-SSH-GRACE', 'SSH 로그인 유예시간 제한', 'logingracetime',
             fn(string $v) => [(int) $v > 60, 'LoginGraceTime 60초 이하 권고.'], 'LOW'],
            ['CCE-SSH-IDLE', 'SSH 유휴 세션 종료', 'clientaliveinterval',
             fn(string $v) => [(int) $v === 0 || (int) $v > 300, 'ClientAliveInterval 300초 이하 권고(0=무제한).'], 'MEDIUM'],
        ];
        foreach ($sshChecks as [$code, $title, $key, $judge, $sev]) {
            $v = vg_sshd_val($sshEff, $sshCfg, $key);
            if ($v === null) {
                $out[] = [$code, $title, 'NA', $sev, null, 'sshd 설정을 수집하지 못함(비-root 실행 시 제한적).'];
                continue;
            }
            [$fail, $advice] = $judge($v);
            $out[] = [$code, $title, $fail ? 'FAIL' : 'PASS', $sev, $key . ' ' . $v,
                $fail ? $advice : '권고 기준을 만족.'];
        }

        // ── 파일 권한 (U-07~U-12) ──
        //   stat 출력: "644 root root /etc/passwd"
        //   모드는 **8진수 문자열**이다("644"). (int) 로 읽으면 10진수 644 가 되어 표시가 깨진다
        //   (sprintf('%o', 644) → "1204"). 원문은 그대로 보여주고, 비교만 octdec() 로 한다.
        $perms = [];
        foreach (preg_split('/\r?\n/', (string) ($sec['file_perms'] ?? '')) as $line) {
            $f = preg_split('/\s+/', trim($line), 4);
            if (count($f) === 4 && ctype_digit($f[0])) {
                $perms[$f[3]] = ['mode' => $f[0], 'user' => $f[1], 'group' => $f[2]];
            }
        }
        // [경로, 코드, 제목, 최대 허용 모드, 위험도] — 모드는 "이 값 이하"여야 통과
        //   [경로, 코드, 제목, 최대 허용 모드(8진수 문자열), 위험도]
        $fileRules = [
            ['/etc/passwd',   'CCE-FILE-PASSWD',   '/etc/passwd 소유자·권한 (U-07)',   '644', 'MEDIUM'],
            ['/etc/shadow',   'CCE-FILE-SHADOW',   '/etc/shadow 소유자·권한 (U-08)',   '400', 'HIGH'],
            // U-09 기준은 600 이다. 배포판 기본이 644 라 대부분 FAIL 로 뜨는데, 기준을 임의로
            // 완화하면 감사에서 지적될 항목을 "통과"로 표시하게 된다 → 기준 그대로 둔다.
            ['/etc/hosts',    'CCE-FILE-HOSTS',    '/etc/hosts 소유자·권한 (U-09)',    '600', 'LOW'],
            ['/etc/services', 'CCE-FILE-SERVICES', '/etc/services 소유자·권한 (U-12)', '644', 'LOW'],
            ['/etc/crontab',  'CCE-FILE-CRONTAB',  '/etc/crontab 소유자·권한',         '640', 'MEDIUM'],
            ['/etc/group',    'CCE-FILE-GROUP',    '/etc/group 소유자·권한',           '644', 'MEDIUM'],
            ['/etc/gshadow',  'CCE-FILE-GSHADOW',  '/etc/gshadow 소유자·권한',         '400', 'HIGH'],
            // 아래 둘은 없는 서버가 많다(xinetd 미사용, syslog→rsyslog). 없으면 NA 로 남는다.
            ['/etc/xinetd.conf', 'CCE-FILE-XINETD', '/etc/xinetd.conf 소유자·권한 (U-10)', '600', 'MEDIUM'],
            ['/etc/rsyslog.conf','CCE-FILE-SYSLOG', '/etc/rsyslog.conf 소유자·권한 (U-11)', '640', 'LOW'],
        ];
        foreach ($fileRules as [$path, $code, $title, $maxMode, $sev]) {
            if (!isset($perms[$path])) {
                // 파일이 없을 수도 있다(예: 컨테이너의 /etc/crontab) → 판정 불가로 남긴다.
                $out[] = [$code, $title, 'NA', $sev, null, $path . ' 권한을 수집하지 못함(파일 없음 또는 권한 부족).'];
                continue;
            }
            $p = $perms[$path];
            $badOwner = ($p['user'] !== 'root');
            $badMode  = (octdec($p['mode']) > octdec($maxMode));   // 8진수로 비교
            $fail = $badOwner || $badMode;
            $out[] = [$code, $title, $fail ? 'FAIL' : 'PASS', $sev,
                sprintf('%s %s:%s %s', $p['mode'], $p['user'], $p['group'], $path),
                $fail
                    ? sprintf('소유자 root, 권한 %s 이하 권고 (현재 %s, %s).', $maxMode, $p['user'], $p['mode'])
                    : sprintf('소유자 root, 권한 %s — 기준 만족.', $p['mode'])];
        }

        // ── 패스워드 정책 (U-46~U-48) ──
        $defs = [];
        foreach (preg_split('/\r?\n/', (string) ($sec['login_defs'] ?? '')) as $line) {
            $f = preg_split('/\s+/', trim($line), 2);
            if (count($f) === 2) { $defs[strtoupper($f[0])] = trim($f[1]); }
        }
        $pwRules = [
            ['CCE-PW-MAXDAYS', '패스워드 최대 사용기간 (U-47)', 'PASS_MAX_DAYS',
             fn(int $v) => $v <= 0 || $v > 90, '90일 이하 권고(0/미설정 = 무제한).', 'MEDIUM'],
            ['CCE-PW-MINDAYS', '패스워드 최소 사용기간 (U-48)', 'PASS_MIN_DAYS',
             fn(int $v) => $v < 1, '1일 이상 권고(즉시 재변경으로 이력 우회 방지).', 'LOW'],
            ['CCE-PW-MINLEN',  '패스워드 최소 길이 (U-46)',    'PASS_MIN_LEN',
             fn(int $v) => $v < 8, '8자 이상 권고.', 'MEDIUM'],
        ];
        foreach ($pwRules as [$code, $title, $key, $isFail, $advice, $sev]) {
            if (!isset($defs[$key])) {
                $out[] = [$code, $title, 'NA', $sev, null, '/etc/login.defs 에서 ' . $key . ' 를 찾지 못함.'];
                continue;
            }
            $v = (int) $defs[$key];
            $fail = $isFail($v);
            $out[] = [$code, $title, $fail ? 'FAIL' : 'PASS', $sev, $key . ' ' . $v,
                $fail ? $advice : '권고 기준을 만족.'];
        }

        // ── UMASK (U-56) ──
        //   022 보다 느슨하면(예: 002, 000) 새로 만든 파일이 그룹/타인에게 쓰기 허용된다.
        if (!isset($defs['UMASK'])) {
            $out[] = ['CCE-UMASK', '기본 UMASK 설정 (U-56)', 'NA', 'MEDIUM', null,
                '/etc/login.defs 에서 UMASK 를 찾지 못함.'];
        } else {
            $um = $defs['UMASK'];
            // 8진수 문자열. 022 보다 작은 값(=더 느슨)이면 FAIL.
            $fail = octdec($um) < octdec('022');
            $out[] = ['CCE-UMASK', '기본 UMASK 설정 (U-56)', $fail ? 'FAIL' : 'PASS', 'MEDIUM',
                'UMASK ' . $um,
                $fail ? 'UMASK 가 느슨해 새 파일이 그룹/타인에게 열린다 → 022 이상 권고.'
                      : 'UMASK 022 이상 — 기준 만족.'];
        }

        // ── 판정하지 않는 수집값(이유를 남긴다) ──
        //   tcp_wrapper(hosts.allow/deny): 요즘 배포판은 sshd 등에서 libwrap 을 뺐다. 접근 제한은
        //     방화벽이 담당하고 그건 CCE-SEC-FW 로 이미 점검한다. 여기서 또 FAIL 을 내면
        //     방화벽을 제대로 쓰는 서버까지 전부 지적돼 노이즈만 는다 → 증거로만 보관한다.
        //   fips: KISA U-XX 항목이 아니다(암호모듈 검증 필요 환경에서만 의미). 정보로만 보관.

        // ── 패스워드 복잡도·계정 잠금 (U-02, U-03) ──
        $pam = (string) ($sec['pam_rules'] ?? '');
        if ($pam === '') {
            $out[] = ['CCE-PW-QUALITY', '패스워드 복잡도 정책 (U-02)', 'NA', 'MEDIUM', null, 'PAM 설정을 수집하지 못함.'];
            $out[] = ['CCE-PW-LOCKOUT', '계정 잠금 임계값 (U-03)',    'NA', 'MEDIUM', null, 'PAM 설정을 수집하지 못함.'];
        } else {
            $hasQuality = (bool) preg_match('/pam_(pwquality|cracklib)/i', $pam);
            $out[] = ['CCE-PW-QUALITY', '패스워드 복잡도 정책 (U-02)', $hasQuality ? 'PASS' : 'FAIL', 'MEDIUM',
                $hasQuality ? 'pam_pwquality/cracklib 적용' : '복잡도 모듈 없음',
                $hasQuality ? '패스워드 복잡도 모듈이 적용됨.' : 'pam_pwquality(또는 cracklib)로 복잡도 강제 권고.'];
            $hasLock = (bool) preg_match('/pam_(faillock|tally2)/i', $pam);
            $out[] = ['CCE-PW-LOCKOUT', '계정 잠금 임계값 (U-03)', $hasLock ? 'PASS' : 'FAIL', 'MEDIUM',
                $hasLock ? 'pam_faillock/tally2 적용' : '잠금 모듈 없음',
                $hasLock ? '로그인 실패 시 계정 잠금이 설정됨.' : 'pam_faillock 으로 실패 횟수 제한 권고.'];
        }

        // ── "위반 목록" 형태의 항목들 (U-04, U-52, 빈 패스워드, U-17) ──
        //   에이전트는 위반이 없으면 "NONE" 을 찍는다. 수집 자체가 실패하면 키가 아예 없다.
        //   이 둘을 구분해야 한다 — 없는 걸 "정상"으로 읽으면 위험을 숨기고,
        //   정상을 "판정 불가"로 읽으면 매번 NA 가 뜬다.
        $listChecks = [
            ['CCE-ACC-SHADOW', '패스워드를 /etc/passwd 에 저장하지 않음 (U-04)', 'passwd_shadowed', 'HIGH',
             '패스워드 해시가 /etc/passwd 에 노출됨 → shadow 로 이전 권고.', '패스워드가 /etc/shadow 로 분리됨.',
             '/etc/passwd 를 읽지 못함.'],
            ['CCE-ACC-DUPUID', '동일 UID 계정 금지 (U-52)', 'duplicate_uid', 'MEDIUM',
             '같은 UID 를 쓰는 계정이 있어 감사 추적이 불가능하다 → UID 를 유일하게.', 'UID 가 계정마다 유일함.',
             '계정 목록을 읽지 못함.'],
            ['CCE-ACC-EMPTYPW', '빈 패스워드 계정 금지', 'empty_passwords', 'HIGH',
             '패스워드 없이 로그인 가능한 계정이 있다 → 즉시 잠금/설정.', '빈 패스워드 계정이 없음.',
             '/etc/shadow 를 읽지 못함(root 실행 필요).'],
            ['CCE-RHOSTS', 'hosts.equiv / .rhosts 미사용 (U-17)', 'rhosts', 'HIGH',
             'r 계열 신뢰 파일이 있으면 패스워드 없이 원격 접속이 가능하다 → 제거 권고.', 'hosts.equiv/.rhosts 가 없음.',
             '수집하지 못함.'],
        ];
        foreach ($listChecks as [$code, $title, $key, $sev, $failWhy, $passWhy, $naWhy]) {
            if (!isset($sec[$key])) {
                $out[] = [$code, $title, 'NA', $sev, null, $naWhy];
                continue;
            }
            $val  = trim((string) $sec[$key]);
            $fail = ($val !== '' && strtoupper($val) !== 'NONE');
            $out[] = [$code, $title, $fail ? 'FAIL' : 'PASS', $sev,
                $fail ? mb_strimwidth(str_replace("\n", ' | ', $val), 0, 120, '…') : '위반 없음',
                $fail ? $failWhy : $passWhy];
        }

        // ── root PATH 에 "." 포함 금지 (U-05) ──
        $rootPath = (string) ($sec['root_path'] ?? '');
        if ($rootPath === '') {
            $out[] = ['CCE-ROOT-PATH', 'root PATH 에 현재 디렉토리(.) 미포함 (U-05)', 'NA', 'MEDIUM', null, 'PATH 설정을 수집하지 못함.'];
        } else {
            // PATH="/usr/bin:.:/bin" 처럼 "." 이 독립 경로로 들어간 경우만 위험(상대경로 실행 유도).
            $fail = (bool) preg_match('/PATH=[^\n]*(^|[:="])\.(:|"|$)/m', $rootPath);
            $out[] = ['CCE-ROOT-PATH', 'root PATH 에 현재 디렉토리(.) 미포함 (U-05)', $fail ? 'FAIL' : 'PASS', 'MEDIUM',
                mb_strimwidth(trim(str_replace("\n", ' / ', $rootPath)), 0, 120, '…'),
                $fail ? 'PATH 에 "." 이 있어 공격자가 심어둔 동명 실행파일이 먼저 실행될 수 있다.'
                      : 'PATH 에 "." 이 없음.'];
        }

        // ── 취약한 레거시 서비스 비활성 (U-19~U-25 계열) ──
        $svc = (string) ($sec['legacy_services'] ?? '');
        if ($svc === '') {
            $out[] = ['CCE-SVC-LEGACY', '취약한 레거시 서비스 비활성 (telnet/rsh/ftp 등)', 'NA', 'HIGH', null, '서비스 목록을 수집하지 못함.'];
        } else {
            // 평문 전송·인증이 약한 서비스들. 이름이 포함된 유닛/xinetd 항목을 찾는다.
            $bad = [];
            foreach (['telnet', 'rsh', 'rlogin', 'rexec', 'vsftpd', 'proftpd', 'tftp', 'finger', 'talk'] as $name) {
                if (preg_match('/\b' . preg_quote($name, '/') . '\b/i', $svc)) { $bad[] = $name; }
            }
            $fail = $bad !== [];
            $out[] = ['CCE-SVC-LEGACY', '취약한 레거시 서비스 비활성 (telnet/rsh/ftp 등)', $fail ? 'FAIL' : 'PASS', 'HIGH',
                $fail ? '활성: ' . implode(', ', $bad) : '없음',
                $fail ? '평문 전송·약한 인증 서비스가 활성 → SSH/SFTP 로 대체 권고.'
                      : '레거시 취약 서비스가 활성화돼 있지 않음.'];
        }

        // ── 세션 타임아웃 (U-54) ──
        $tmout = (string) ($sec['tmout'] ?? '');
        if ($tmout === '') {
            $out[] = ['CCE-SESSION-TMOUT', '셸 세션 타임아웃 설정 (U-54)', 'FAIL', 'LOW',
                'TMOUT 미설정', '유휴 세션이 무제한 유지된다 → TMOUT=600 이하 권고.'];
        } else {
            $sec600 = preg_match('/TMOUT\s*=\s*(\d+)/', $tmout, $m) ? (int) $m[1] : 0;
            $fail = ($sec600 === 0 || $sec600 > 600);
            $out[] = ['CCE-SESSION-TMOUT', '셸 세션 타임아웃 설정 (U-54)', $fail ? 'FAIL' : 'PASS', 'LOW',
                'TMOUT ' . ($sec600 ?: '미설정'),
                $fail ? 'TMOUT 600초 이하 권고.' : '유휴 세션이 자동 종료됨.'];
        }

        // ══════════════════════════════════════════════════════════════════
        // 시간 동기화 · 로그 설정 · 암호화 (ISMS-P 2.9.6 / 2.9.4 / 2.7.1, N2SF 제5장 DT·EA-1)
        //   앞의 KISA U-XX 항목과 마찬가지로 판정 근거는 에이전트가 모은 원자료뿐이다.
        //   수집이 안 됐으면 PASS 가 아니라 NA — "못 봤다"를 "괜찮다"로 바꾸지 않는다.
        //   대응 기준은 주석으로만 남긴다(코드↔기준 매핑 테이블은 별도 작업 소관).
        // ══════════════════════════════════════════════════════════════════

        // ── CCE-TIME-SYNC : 시간 동기화 (ISMS-P 2.9.6) ──
        //   타임스탬프가 틀어지면 아래 모든 로그 증적의 증거력이 함께 무너진다.
        $tSync  = (string) ($sec['time_sync']     ?? '');
        $tTrack = (string) ($sec['time_tracking'] ?? '');
        $tSvc   = (string) ($sec['time_services'] ?? '');
        $activeSvc = [];
        foreach (preg_split('/\r?\n/', $tSvc) as $line) {
            if (preg_match('/^(\S+)=active$/', trim($line), $m)) { $activeSvc[] = $m[1]; }
        }
        $synced = null;   // true=동기화됨 / false=아님 / null=모름
        if (preg_match('/NTPSynchronized=(yes|no)/i', $tSync, $m)) {
            $synced = strtolower($m[1]) === 'yes';
        } elseif (preg_match('/System clock synchronized:\s*(yes|no)/i', $tSync, $m)) {
            $synced = strtolower($m[1]) === 'yes';
        } elseif (preg_match('/Leap status\s*:\s*(\S+)/i', $tTrack, $m)) {
            $synced = strcasecmp(trim($m[1]), 'Normal') === 0;
        }
        $svcEv = $activeSvc ? '활성 서비스: ' . implode(', ', $activeSvc) : '활성 서비스 없음';
        if ($synced === null) {
            $out[] = ['CCE-TIME-SYNC', '시간 동기화 상태 (ISMS-P 2.9.6)', 'NA', 'MEDIUM',
                $tSvc !== '' ? $svcEv : null,
                '시간 동기화 여부를 수집하지 못함(timedatectl·chronyc 없음).'];
        } else {
            $out[] = ['CCE-TIME-SYNC', '시간 동기화 상태 (ISMS-P 2.9.6)', $synced ? 'PASS' : 'FAIL', 'MEDIUM',
                'synchronized=' . ($synced ? 'yes' : 'no') . ' / ' . $svcEv,
                $synced ? '시스템 시각이 NTP 와 동기화된 상태 — 로그 타임스탬프의 전제가 충족됨.'
                        : 'NTP 동기화가 되어 있지 않다 → 로그 타임스탬프를 신뢰할 수 없다. '
                          . 'chrony/systemd-timesyncd 등 동기화 서비스 활성 권고.'];
        }

        // ── CCE-TIME-OFFSET : 시각 오차 임계 (ISMS-P 2.9.6) ──
        $offset = vg_cce_time_offset($tTrack);
        if ($offset === null) {
            $out[] = ['CCE-TIME-OFFSET', '시각 오차 허용범위 (ISMS-P 2.9.6)', 'NA', 'MEDIUM', null,
                '시각 오차(offset)를 수집하지 못함(chronyc/ntpq 없음).'];
        } else {
            $fail = $offset > VG_CCE_TIME_OFFSET_MAX_SEC;
            $out[] = ['CCE-TIME-OFFSET', '시각 오차 허용범위 (ISMS-P 2.9.6)', $fail ? 'FAIL' : 'PASS', 'MEDIUM',
                sprintf('offset %.6f초', $offset),
                $fail ? sprintf('NTP 기준 시각 오차가 %.3f초로 임계(%.1f초)를 초과 → 로그 상관분석·감사 증적이 어긋난다.',
                                $offset, VG_CCE_TIME_OFFSET_MAX_SEC)
                      : sprintf('시각 오차가 임계(%.1f초) 이내.', VG_CCE_TIME_OFFSET_MAX_SEC)];
        }

        // ── CCE-LOG-RETENTION : 로그 보존기간 설정 (ISMS-P 2.9.4) ──
        //   결함 사례 "중요 로그의 최대 크기를 불충분하게 설정해 보존기간 미충족" 대응.
        //   journald(MaxRetentionSec) 와 logrotate(전역 rotate×주기 / maxage) 중 **긴 쪽**을 본다 —
        //   둘은 대상이 다르고(저널 vs /var/log 파일), 하나라도 기준을 채우면 원문이 남는다.
        $jd = (string) ($sec['journald_conf']  ?? '');
        $lr = (string) ($sec['logrotate_conf'] ?? '');
        $retDays = null; $retSrc = [];
        if (preg_match('/MaxRetentionSec\s*=\s*(\S+)/i', $jd, $m)) {
            $s = vg_cce_timespan_sec($m[1]);
            if ($s !== null && $s > 0) { $retDays = $s / 86400.0; $retSrc[] = 'journald MaxRetentionSec=' . $m[1]; }
        }
        if ($lr !== '' && strcasecmp(trim($lr), 'NONE') !== 0) {
            $lrDays = null; $lrSrc = '';
            if (preg_match('/^maxage\s+(\d+)/mi', $lr, $m)) {
                $lrDays = (float) $m[1]; $lrSrc = 'logrotate maxage ' . $m[1];
            } elseif (preg_match('/^(daily|weekly|monthly|yearly)/mi', $lr, $mf)
                   && preg_match('/^rotate\s+(\d+)/mi', $lr, $mr)) {
                $per = ['daily' => 1, 'weekly' => 7, 'monthly' => 30, 'yearly' => 365][strtolower($mf[1])];
                $lrDays = (float) ((int) $mr[1] * $per);
                $lrSrc  = sprintf('logrotate %s×rotate %d', strtolower($mf[1]), (int) $mr[1]);
            }
            if ($lrDays !== null && ($retDays === null || $lrDays > $retDays)) { $retDays = $lrDays; }
            if ($lrSrc !== '') { $retSrc[] = $lrSrc; }
        }
        if ($retDays === null) {
            $out[] = ['CCE-LOG-RETENTION', '로그 보존기간 설정 (ISMS-P 2.9.4)', 'NA', 'MEDIUM', null,
                'journald MaxRetentionSec 도 logrotate 전역 보존 설정도 확인되지 않아 보존기간을 계산할 수 없음'
                . '(설정 미기재이거나 파일을 읽지 못함).'];
        } else {
            $fail = $retDays < VG_CCE_LOG_RETENTION_DAYS;
            $out[] = ['CCE-LOG-RETENTION', '로그 보존기간 설정 (ISMS-P 2.9.4)', $fail ? 'FAIL' : 'PASS', 'MEDIUM',
                sprintf('%.0f일 (%s)', $retDays, implode(' / ', $retSrc)),
                $fail ? sprintf('보존기간이 약 %.0f일로 기준(%d일) 미만 → 사후 추적 시점에 로그가 이미 삭제된다.',
                                $retDays, VG_CCE_LOG_RETENTION_DAYS)
                      : sprintf('보존기간 약 %.0f일로 기준(%d일) 이상.', $retDays, VG_CCE_LOG_RETENTION_DAYS)];
        }

        // ── CCE-LOG-REMOTE : 원격 로그 전송 (ISMS-P 2.9.4) ──
        //   결함 사례 "서버 로그를 백업하지 않아 임의 삭제 가능" 대응. 침해 시 로컬 로그는 지워진다.
        $rsr = $sec['rsyslog_remote'] ?? null;
        $rsr = $rsr === null ? '' : trim((string) $rsr);
        if ($rsr === '') {
            $out[] = ['CCE-LOG-REMOTE', '원격 로그 전송 설정 (ISMS-P 2.9.4)', 'NA', 'MEDIUM', null,
                'rsyslog 설정을 읽지 못함(미설치이거나 권한 부족).'];
        } elseif (strcasecmp($rsr, 'NONE') === 0) {
            $out[] = ['CCE-LOG-REMOTE', '원격 로그 전송 설정 (ISMS-P 2.9.4)', 'FAIL', 'MEDIUM',
                '전송 설정 없음',
                '로그가 이 서버에만 남는다 → 침해 시 삭제·위변조를 막을 수 없다. 원격 로그 서버 전송(@/@@/omfwd) 권고.'];
        } else {
            $out[] = ['CCE-LOG-REMOTE', '원격 로그 전송 설정 (ISMS-P 2.9.4)', 'PASS', 'MEDIUM',
                mb_strimwidth(str_replace("\n", ' | ', $rsr), 0, 200, '…'),
                '원격 로그 서버로 전송하도록 설정됨 — 로컬 삭제만으로는 증적이 사라지지 않는다.'];
        }

        // ── SSH 암호 알고리즘 (ISMS-P 2.7.1 / N2SF 제5장 DT) ──
        //   sshd -T 의 실효값에 취약 알고리즘이 남아 있는지. 근거값에 **실제로 걸린 이름**을 남긴다.
        //   주의: OpenSSH 기본 MACs 에는 hmac-sha1·umac-64 가 들어 있어 **설정을 손대지 않은 서버는
        //   대부분 FAIL 로 뜬다**(Debian 12 실측). 이건 오탐이 아니라 실제로 그 알고리즘을 제안한다는
        //   뜻이고, CIS·KISA 가 제거를 요구하는 항목이다 — U-09(/etc/hosts 600)와 같은 이유로
        //   기준을 임의로 완화하지 않는다. 조치는 sshd_config 에 MACs 를 명시하는 것이다.
        $algoKeys = ['ciphers' => 'Ciphers', 'macs' => 'MACs', 'kexalgorithms' => 'KexAlgorithms'];
        $weakPat = [
            // CBC 모드(패딩오라클)·arcfour·3DES·blowfish 계열
            'ciphers' => ['/-cbc$/', '/^arcfour/', '/^3des/', '/^des$/', '/^blowfish/', '/^cast128/'],
            // MD5·SHA1 기반 MAC, 64비트 UMAC
            'macs' => ['/^hmac-md5/', '/^hmac-sha1(-96)?(-etm)?$/', '/^umac-64/', '/^hmac-ripemd160/'],
            // SHA1 기반 키교환(group1/group14/group-exchange 포함)
            'kexalgorithms' => ['/sha1$/', '/^gss-group1/'],
        ];
        $algoVals = []; $weakFound = [];
        foreach ($algoKeys as $key => $label) {
            $v = vg_sshd_val($sshEff, $sshCfg, $key);
            if ($v === null || $v === '') { continue; }
            $algoVals[$label] = $v;
            foreach (explode(',', $v) as $algo) {
                $algo = trim($algo);
                if ($algo === '') { continue; }
                $bare = preg_replace('/@.*$/', '', $algo);   // hmac-sha1-etm@openssh.com → hmac-sha1-etm
                foreach ($weakPat[$key] as $p) {
                    if (preg_match($p, $bare)) { $weakFound[] = $label . ':' . $algo; break; }
                }
            }
        }
        if (!$algoVals) {
            $out[] = ['CCE-CRYPTO-SSH-CIPHER', 'SSH 취약 암호 알고리즘 사용 금지 (ISMS-P 2.7.1)', 'NA', 'MEDIUM',
                null, 'sshd 의 Ciphers/MACs/KexAlgorithms 실효값을 수집하지 못함(root 실행 필요).'];
        } else {
            $fail = $weakFound !== [];
            $out[] = ['CCE-CRYPTO-SSH-CIPHER', 'SSH 취약 암호 알고리즘 사용 금지 (ISMS-P 2.7.1)',
                $fail ? 'FAIL' : 'PASS', 'MEDIUM',
                $fail ? mb_strimwidth(implode(', ', $weakFound), 0, 200, '…')
                      : '취약 알고리즘 없음 (' . implode('/', array_keys($algoVals)) . ' 점검)',
                $fail ? 'CBC·MD5·SHA1 등 취약 알고리즘이 허용 목록에 남아 있다 → sshd_config 에 '
                        . 'Ciphers/MACs/KexAlgorithms 를 명시해 AES-GCM·hmac-sha2·curve25519 계열만 남기도록 권고'
                        . '(OpenSSH 기본값에도 hmac-sha1·umac-64 가 포함돼 있어 명시 설정이 필요하다).'
                      : '허용 목록에 알려진 취약 알고리즘이 없음.'];
        }

        // ── CCE-CRYPTO-DISK : 디스크 암호화(LUKS) 적용 여부 (N2SF 제5장 DT) ──
        //   디스크 암호화가 모든 서버의 필수 요건은 아니다 → 미적용을 FAIL 로 몰지 않는다(억지 판정 금지).
        //   적용돼 있으면 PASS, 없으면 정보성(NA)으로 남기고 사유에 검토 기준을 적는다.
        $disk = $sec['disk_encryption'] ?? null;
        $disk = $disk === null ? '' : trim((string) $disk);
        if ($disk === '') {
            $out[] = ['CCE-CRYPTO-DISK', '디스크 암호화(LUKS) 적용 (N2SF DT)', 'NA', 'LOW', null,
                '블록 장치 정보를 수집하지 못함(lsblk/blkid 없음).'];
        } elseif (strcasecmp($disk, 'NONE') === 0) {
            $out[] = ['CCE-CRYPTO-DISK', '디스크 암호화(LUKS) 적용 (N2SF DT)', 'NA', 'LOW',
                'LUKS 볼륨 없음',
                '정보성 — LUKS 암호화 볼륨이 없다. 디스크 암호화는 모든 서버의 필수 요건이 아니므로 '
                . '위반으로 판정하지 않는다. 개인정보·기밀을 저장하는 서버라면 별도 검토가 필요하다.'];
        } else {
            $out[] = ['CCE-CRYPTO-DISK', '디스크 암호화(LUKS) 적용 (N2SF DT)', 'PASS', 'LOW',
                mb_strimwidth(preg_replace('/\s+/', ' ', str_replace("\n", ' | ', $disk)), 0, 200, '…'),
                'LUKS 암호화 볼륨이 존재 — 저장 데이터 암호화가 적용돼 있다.'];
        }

        // ── CCE-CRYPTO-KCMVP : 국내 검증필 암호알고리즘(ARIA/SEED) 사용 여부 (N2SF EA-1 부분대응) ──
        //   EA-1(검증필 암호모듈)은 "모듈이 KCMVP 검증을 받았는가"를 묻는다. 우리가 볼 수 있는 건
        //   SSH 알고리즘 목록뿐이라 **완전 판정이 불가능**하다 → PASS/FAIL 을 내지 않고 정보성으로만 남긴다.
        if (!$algoVals) {
            $out[] = ['CCE-CRYPTO-KCMVP', '국내 검증필 암호알고리즘 사용 (N2SF EA-1)', 'NA', 'LOW', null,
                '정보성 — SSH 알고리즘 목록을 수집하지 못해 확인할 수 없다. EA-1(검증필 암호모듈)은 '
                . '모듈 검증 여부까지 필요해 이 도구만으로는 완전 판정이 불가능하다.'];
        } else {
            $kcmvp = [];
            foreach ($algoVals as $label => $v) {
                if (preg_match('/\b(aria|seed)\b/i', $v)) { $kcmvp[] = $label; }
            }
            $out[] = ['CCE-CRYPTO-KCMVP', '국내 검증필 암호알고리즘 사용 (N2SF EA-1)', 'NA', 'LOW',
                $kcmvp ? 'ARIA/SEED 포함: ' . implode(', ', $kcmvp) : 'ARIA/SEED 미포함',
                '정보성 — ' . ($kcmvp
                    ? 'SSH 알고리즘 목록에 국내 검증필 계열(ARIA/SEED)이 포함돼 있다. '
                    : 'SSH 알고리즘 목록에 국내 검증필 계열(ARIA/SEED)이 없다. ')
                . 'EA-1 은 사용 알고리즘이 아니라 암호모듈의 KCMVP 검증 여부를 요구하므로, 이 결과만으로는 '
                . '준수·미준수를 판정하지 않는다(별도 모듈 검증 확인 필요).'];
        }

        return $out;
    }

    /**
     * 우리 점검 코드 → **SCAP Security Guide(SSG) 룰 ID**.
     *
     * 왜 필요한가: 점검 항목의 "왜 중요한가 / 어느 기준에 근거하나" 를 우리가 지어내면 안 된다.
     *   SSG 는 오픈소스 룰셋이고 룰마다 CIS·NIST 800-53·STIG·PCI-DSS 참조와 근거를 갖는다.
     *   여기서 묶어 두면 화면이 그 기준을 그대로 인용할 수 있다(tb_compliance_rule).
     *
     * 매핑은 **추측하지 않았다** — SSG 룰 2,493개의 ID 를 실제로 검색해 대응하는 것만 적었다.
     *   대응하는 SSG 룰이 없는 항목(KISA 가이드 고유 등)은 여기 없다 → 화면에서 "자체 기준" 으로 뜬다.
     *
     *   #519 에서 나머지 12개를 `tb_compliance_rule` 전수 대조했다(v0.1.81, 2,493룰).
     *   4개만 대응 룰이 있었고 8개는 **정말로 없어서** 자체 기준으로 남는다:
     *     · CCE-TIME-OFFSET  — SSG 는 maxpoll·RootDistanceMaxSec 같은 *설정값*만 본다.
     *                          실측 오차(chronyc offset)를 판정하는 룰은 없다.
     *     · CCE-LOG-RETENTION — 보존기간 룰은 auditd 전용(num_logs·max_log_file)뿐이고,
     *                          journald MaxRetentionSec/logrotate 보존일수 룰은 없다.
     *     · CCE-CRYPTO-KCMVP — SSG 의 검증 개념은 FIPS 140 이다. 국내 KCMVP 는 다른 제도라
     *                          FIPS 룰에 묶으면 없는 근거를 인용하게 된다.
     *     · CCE-SSH-PWAUTH   — PasswordAuthentication 을 다루는 룰이 없다.
     *                          sshd_enable_pubkey_auth 는 *다른 설정*이라 대체할 수 없다.
     *     · CCE-FILE-HOSTS/SERVICES/SYSLOG/XINETD — file_permissions_* 에 /etc/hosts·
     *                          /etc/services·/etc/rsyslog.conf·/etc/xinetd.conf 가 없다
     *                          (hosts.allow/deny 는 다른 파일, xinetd 는 제거·비활성 룰만 있다).
     */
    function vg_cce_ssg_map(): array { return [
        // SSH (sshd -T 실효값으로 판정)
        'CCE-SSH-ROOT'      => 'sshd_disable_root_login',
        'CCE-SSH-EMPTYPW'   => 'sshd_disable_empty_passwords',
        'CCE-SSH-MAXAUTH'   => 'sshd_set_max_auth_tries',
        'CCE-SSH-X11'       => 'sshd_disable_x11_forwarding',
        'CCE-SSH-GRACE'     => 'sshd_set_login_grace_time',
        'CCE-SSH-IDLE'      => 'sshd_set_idle_timeout',
        // 계정
        'CCE-ACC-EMPTYPW'   => 'no_empty_passwords',
        'CCE-ACC-UID0'      => 'accounts_no_uid_except_zero',
        'CCE-ACC-DUPUID'    => 'no_duplicate_uids',
        'CCE-ACC-SHADOW'    => 'accounts_password_all_shadowed',
        // 패스워드 정책
        'CCE-PW-MINLEN'     => 'accounts_password_minlen_login_defs',
        'CCE-PW-MAXDAYS'    => 'accounts_maximum_age_login_defs',
        'CCE-PW-MINDAYS'    => 'accounts_minimum_age_login_defs',
        'CCE-PW-QUALITY'    => 'accounts_password_pam_pwquality_enabled',
        'CCE-PW-LOCKOUT'    => 'accounts_passwords_pam_faillock_deny',
        // 파일 권한
        'CCE-FILE-PASSWD'   => 'file_permissions_etc_passwd',
        'CCE-FILE-SHADOW'   => 'file_permissions_etc_shadow',
        'CCE-FILE-GROUP'    => 'file_permissions_etc_group',
        'CCE-FILE-GSHADOW'  => 'file_permissions_etc_gshadow',
        'CCE-FILE-CRONTAB'  => 'file_permissions_crontab',
        // 시스템
        'CCE-UMASK'         => 'accounts_umask_etc_login_defs',
        'CCE-SESSION-TMOUT' => 'accounts_tmout',
        'CCE-ROOT-PATH'     => 'root_path_default',
        'CCE-RHOSTS'        => 'no_rsh_trust_files',
        'CCE-SVC-LEGACY'    => 'service_telnetd_disabled',
        'CCE-SEC-MODULE'    => 'selinux_state',
        'CCE-SEC-FW'        => 'service_firewalld_enabled',
        // 시간 동기화 — 룰 ID 는 chrony 네임스페이스지만 제목·근거가 서비스 중립이다
        //   ("Synchronize internal information system clocks" / 로그 상관분석 근거).
        //   우리 점검도 chrony·ntpd·timesyncd 를 가리지 않고 동기화 여부만 본다.
        'CCE-TIME-SYNC'         => 'chronyd_sync_clock',
        // 로그·암호화
        'CCE-LOG-REMOTE'        => 'rsyslog_remote_loghost',
        'CCE-CRYPTO-DISK'       => 'encrypt_partitions',
        // Ciphers/MACs/Kex 를 한 항목에서 함께 보지만, 대표 룰은 CBC 취약성을 다루는 이것이다
        //   (sshd_use_strong_macs·sshd_use_strong_kex 도 있으나 매핑은 코드당 1개다).
        'CCE-CRYPTO-SSH-CIPHER' => 'sshd_use_strong_ciphers',
    ]; }

    /**
     * 점검 룰 카탈로그 — [코드 => ['title'=>…, 'severity'=>…, 'ssg_rule_id'=>…|null]].
     *   cce-rules.php(CCE 카탈로그)가 "우리가 무엇을 점검하는가" 를 목록으로 보여줄 때 쓴다.
     *
     * 왜 목록을 따로 안 적나: 코드·제목·심각도를 화면이나 새 테이블에 복사하면 판정 로직과
     *   반드시 어긋난다(항목을 하나 고치면 두 곳을 고쳐야 한다). 그래서 판정 함수를
     *   **빈 수집값**으로 한 번 돌려 그 결과에서 메타만 뽑는다 — 이 파일이 SSOT 로 남는다.
     *   수집값이 없으면 결과는 NA(설정 부재를 위반으로 보는 항목은 FAIL)로 떨어지지만,
     *   코드·제목·심각도는 어느 분기로 가든 항목마다 하나로 고정돼 있어 그대로 쓸 수 있다.
     *   판정 결과(3번째 값)는 여기서 버린다 — 카탈로그는 실제 판정을 말하지 않는다.
     *
     * @return array<string, array{title: string, severity: string, ssg_rule_id: ?string}>
     */
    function vg_cce_rules(): array {
        static $rules = null;
        if ($rules !== null) { return $rules; }

        $ssg = vg_cce_ssg_map();
        $out = [];
        foreach (vg_cce_checks([]) as [$code, $title, , $severity]) {
            $out[$code] = [
                'title'       => $title,
                'severity'    => $severity,
                'ssg_rule_id' => $ssg[$code] ?? null,
            ];
        }
        return $rules = $out;
    }

    /**
     * 한 스캔에 대해 CCE 점검 수행 → tb_cce_finding 재계산. 반환: 결과별 카운트.
     *   matcher 와 동일하게 스캔별 DELETE 후 재삽입, 자체 트랜잭션으로 원자성 보장.
     */
    function vg_evaluate_cce(PDO $pdo, int $scanId, array $data): array {
        $rows = vg_cce_checks($data);

        return vg_with_tx($pdo, function () use ($pdo, $scanId, $rows) {
            $pdo->prepare('DELETE FROM tb_cce_finding WHERE scan_id = ?')->execute([$scanId]);
            $ins = $pdo->prepare(
                'INSERT INTO tb_cce_finding (scan_id, code, ssg_rule_id, title, result, severity, evidence, rationale)
                 VALUES (?,?,?,?,?,?,?,?)'
            );
            $counts = ['PASS' => 0, 'FAIL' => 0, 'NA' => 0];
            foreach ($rows as $r) {
                [$code, $title, $result, $sev, $ev, $why] = $r;
                // 검증된 룰셋에 묶는다 — 없으면 null(자체 기준 항목).
                $ssg = vg_cce_ssg_map()[$code] ?? null;
                $ins->execute([$scanId, $code, $ssg, $title, $result, $sev, $ev, $why]);
                $counts[$result] = ($counts[$result] ?? 0) + 1;
            }
            return $counts;
        });
    }
}
