<?php
declare(strict_types=1);

/**
 * cce/checks/crypto.php — 암호화 점검(ISMS-P 2.7.1, N2SF 제5장 DT·EA-1).
 *   세 항목이 한 함수인 이유: SSH 알고리즘 실효값($algoVals)을 CIPHER 와 KCMVP 가 함께 본다 —
 *   가르면 같은 sshd -T 파싱이 두 벌이 되고 두 판정이 갈라진다.
 *   수집이 안 됐으면 PASS 가 아니라 NA — "못 봤다"를 "괜찮다"로 바꾸지 않는다.
 *
 *   ※ cce/checks.php 가 로드하고 호출한다. 반환 순서(CIPHER → DISK → KCMVP)를 바꾸지 않는다.
 */

require_once __DIR__ . '/../parse.php';   // vg_sshd_val

/** CCE-CRYPTO-SSH-CIPHER · CCE-CRYPTO-DISK · CCE-CRYPTO-KCMVP. */
function vg_cce_check_crypto(array $sec, string $sshEff, string $sshCfg): array {
    $out = [];

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
