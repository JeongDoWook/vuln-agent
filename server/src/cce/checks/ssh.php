<?php
declare(strict_types=1);

/**
 * cce/checks/ssh.php — SSH 접근 통제 점검(KISA U-01 계열).
 *   판정 근거는 sshd -T 실효값 우선, 없으면 sshd_config 폴백(vg_sshd_val).
 *   수집이 안 됐으면 PASS 가 아니라 NA — "못 봤다"를 "괜찮다"로 바꾸지 않는다.
 *
 *   ※ cce/checks.php 가 로드하고 호출한다. 각 함수는 [코드,제목,결과,위험도,근거값,사유] 행 배열을
 *     돌려주고, 그 순서가 곧 vg_cce_checks() 결과의 순서다(순서를 바꾸지 않는다).
 */

require_once __DIR__ . '/../parse.php';   // vg_sshd_val

/** CCE-SSH-ROOT · CCE-SSH-PWAUTH — 원격 로그인 경로 자체를 좁히는 두 항목. */
function vg_cce_check_ssh_login(string $sshEff, string $sshCfg): array {
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

    return $out;
}

/**
 * SSH 세부 (U-01 계열 확장) — sshd -T 는 "실제 적용값"이라 config 파일보다 권위 있다.
 */
function vg_cce_check_ssh_hardening(string $sshEff, string $sshCfg): array {
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
    $out = [];
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
    return $out;
}
