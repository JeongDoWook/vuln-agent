<?php
declare(strict_types=1);

/**
 * cce/checks/system.php — 커널 강제접근제어·방화벽·파일 권한·셸 환경 점검
 *   (KISA U-05, U-07~U-12, U-19~U-25, U-54 계열).
 *   수집이 안 됐으면 PASS 가 아니라 NA — "못 봤다"를 "괜찮다"로 바꾸지 않는다.
 *
 *   ※ cce/checks.php 가 로드하고 호출한다. 각 함수는 [코드,제목,결과,위험도,근거값,사유] 행 배열을
 *     돌려주고, 그 순서가 곧 vg_cce_checks() 결과의 순서다(순서를 바꾸지 않는다).
 */

/** CCE-SEC-MODULE · CCE-SEC-FW — 커널 강제접근제어와 호스트 방화벽. */
function vg_cce_check_mac_firewall(array $sec, bool $isRoot): array {
    $out = [];

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

    return $out;
}

/**
 * 파일 권한 (U-07~U-12).
 *   stat 출력: "644 root root /etc/passwd"
 *   모드는 **8진수 문자열**이다("644"). (int) 로 읽으면 10진수 644 가 되어 표시가 깨진다
 *   (sprintf('%o', 644) → "1204"). 원문은 그대로 보여주고, 비교만 octdec() 로 한다.
 */
function vg_cce_check_file_perms(array $sec): array {
    $perms = [];
    foreach (preg_split('/\r?\n/', (string) ($sec['file_perms'] ?? '')) as $line) {
        $f = preg_split('/\s+/', trim($line), 4);
        if (count($f) === 4 && ctype_digit($f[0])) {
            $perms[$f[3]] = ['mode' => $f[0], 'user' => $f[1], 'group' => $f[2]];
        }
    }
    // [경로, 코드, 제목, 최대 허용 모드(8진수 문자열), 위험도] — 모드는 "이 값 이하"여야 통과
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
    $out = [];
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
    return $out;
}

/**
 * 셸 환경·레거시 서비스 (U-05, U-19~U-25 계열, U-54).
 *   전부 "로그인 셸이 놓인 환경"을 보는 항목이라 한 함수가 소유한다.
 */
function vg_cce_check_shell_env(array $sec): array {
    $out = [];

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

    return $out;
}
