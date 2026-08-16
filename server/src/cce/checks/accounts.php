<?php
declare(strict_types=1);

/**
 * cce/checks/accounts.php — 계정·패스워드 정책 점검(KISA U-02~U-04, U-46~U-48, U-52, U-56 계열).
 *   수집이 안 됐으면 PASS 가 아니라 NA — "못 봤다"를 "괜찮다"로 바꾸지 않는다.
 *
 *   ※ cce/checks.php 가 로드하고 호출한다. 각 함수는 [코드,제목,결과,위험도,근거값,사유] 행 배열을
 *     돌려주고, 그 순서가 곧 vg_cce_checks() 결과의 순서다(순서를 바꾸지 않는다).
 */

/** CCE-ACC-UID0 : root 외 UID 0 계정 금지 (KISA U-02 계열). */
function vg_cce_check_uid0(array $usr): array {
    $acc = (string) ($usr['accounts'] ?? '');
    if ($acc === '') {
        return [['CCE-ACC-UID0', 'root 외 UID 0 계정 금지', 'NA', 'HIGH',
            null, '계정 목록을 수집하지 못함.']];
    }
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
        return [['CCE-ACC-UID0', 'root 외 UID 0 계정 금지', 'FAIL', 'HIGH',
            'UID0: ' . implode(', ', $dups),
            'root 와 동일한 UID 0 을 가진 계정이 존재 → root 권한 우회 가능.']];
    }
    return [['CCE-ACC-UID0', 'root 외 UID 0 계정 금지', 'PASS', 'HIGH',
        'UID0: root', 'UID 0 은 root 뿐.']];
}

/**
 * 패스워드 정책 (U-46~U-48) + 기본 UMASK (U-56).
 *   둘 다 /etc/login.defs 한 원자료를 파싱해 읽으므로 같은 함수가 소유한다 —
 *   가르면 같은 파싱을 두 번 하게 되고 키 대소문자 규칙이 갈라진다.
 */
function vg_cce_check_password_policy(array $sec): array {
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
    $out = [];
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
    return $out;
}

/**
 * 패스워드 복잡도·계정 잠금 (U-02, U-03).
 *
 * 판정하지 않는 수집값(이유를 남긴다):
 *   tcp_wrapper(hosts.allow/deny): 요즘 배포판은 sshd 등에서 libwrap 을 뺐다. 접근 제한은
 *     방화벽이 담당하고 그건 CCE-SEC-FW 로 이미 점검한다. 여기서 또 FAIL 을 내면
 *     방화벽을 제대로 쓰는 서버까지 전부 지적돼 노이즈만 는다 → 증거로만 보관한다.
 *   fips: KISA U-XX 항목이 아니다(암호모듈 검증 필요 환경에서만 의미). 정보로만 보관.
 */
function vg_cce_check_pam(array $sec): array {
    $pam = (string) ($sec['pam_rules'] ?? '');
    if ($pam === '') {
        return [
            ['CCE-PW-QUALITY', '패스워드 복잡도 정책 (U-02)', 'NA', 'MEDIUM', null, 'PAM 설정을 수집하지 못함.'],
            ['CCE-PW-LOCKOUT', '계정 잠금 임계값 (U-03)',    'NA', 'MEDIUM', null, 'PAM 설정을 수집하지 못함.'],
        ];
    }
    $out = [];
    $hasQuality = (bool) preg_match('/pam_(pwquality|cracklib)/i', $pam);
    $out[] = ['CCE-PW-QUALITY', '패스워드 복잡도 정책 (U-02)', $hasQuality ? 'PASS' : 'FAIL', 'MEDIUM',
        $hasQuality ? 'pam_pwquality/cracklib 적용' : '복잡도 모듈 없음',
        $hasQuality ? '패스워드 복잡도 모듈이 적용됨.' : 'pam_pwquality(또는 cracklib)로 복잡도 강제 권고.'];
    $hasLock = (bool) preg_match('/pam_(faillock|tally2)/i', $pam);
    $out[] = ['CCE-PW-LOCKOUT', '계정 잠금 임계값 (U-03)', $hasLock ? 'PASS' : 'FAIL', 'MEDIUM',
        $hasLock ? 'pam_faillock/tally2 적용' : '잠금 모듈 없음',
        $hasLock ? '로그인 실패 시 계정 잠금이 설정됨.' : 'pam_faillock 으로 실패 횟수 제한 권고.'];
    return $out;
}

/**
 * "위반 목록" 형태의 항목들 (U-04, U-52, 빈 패스워드, U-17).
 *   에이전트는 위반이 없으면 "NONE" 을 찍는다. 수집 자체가 실패하면 키가 아예 없다.
 *   이 둘을 구분해야 한다 — 없는 걸 "정상"으로 읽으면 위험을 숨기고,
 *   정상을 "판정 불가"로 읽으면 매번 NA 가 뜬다.
 */
function vg_cce_check_account_lists(array $sec): array {
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
    $out = [];
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
    return $out;
}
