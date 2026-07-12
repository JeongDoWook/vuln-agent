<?php
declare(strict_types=1);

/**
 * cce.php — 보안설정 점검(CCE). 에이전트가 이미 수집한 security/users 섹션을
 *   서버에서 판정해 tb_cce_findings 에 저장한다. (CVE=취약한 버전, CCE=잘못된 설정)
 *
 *   신규 수집 없음 — vuln-inventory-agent.sh 의 12)보안자세 · 13)사용자/인증 섹션을 재활용.
 *   각 점검은 [코드, 제목, 결과(PASS/FAIL/NA), 위험도, 근거값, 판정사유] 를 남긴다(설명가능성).
 *   수집값이 없으면(비-root 실행 등) NA — 통과로 위장하지 않고 "미점검"을 드러낸다.
 */

require_once __DIR__ . '/db.php';

if (!function_exists('vg_sshd_val')) {
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

        return $out;
    }

    /**
     * 한 스캔에 대해 CCE 점검 수행 → tb_cce_findings 재계산. 반환: 결과별 카운트.
     *   matcher 와 동일하게 스캔별 DELETE 후 재삽입, 자체 트랜잭션으로 원자성 보장.
     */
    function vg_evaluate_cce(PDO $pdo, int $scanId, array $data): array {
        $rows = vg_cce_checks($data);

        $ownTx = !$pdo->inTransaction();
        if ($ownTx) { $pdo->beginTransaction(); }
        try {
            $pdo->prepare('DELETE FROM tb_cce_findings WHERE scan_id = ?')->execute([$scanId]);
            $ins = $pdo->prepare(
                'INSERT INTO tb_cce_findings (scan_id, code, title, result, severity, evidence, rationale)
                 VALUES (?,?,?,?,?,?,?)'
            );
            $counts = ['PASS' => 0, 'FAIL' => 0, 'NA' => 0];
            foreach ($rows as $r) {
                [$code, $title, $result, $sev, $ev, $why] = $r;
                $ins->execute([$scanId, $code, $title, $result, $sev, $ev, $why]);
                $counts[$result] = ($counts[$result] ?? 0) + 1;
            }
            if ($ownTx) { $pdo->commit(); }
            return $counts;
        } catch (Throwable $e) {
            if ($ownTx && $pdo->inTransaction()) { $pdo->rollBack(); }
            throw $e;
        }
    }
}
