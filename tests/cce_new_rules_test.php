<?php
declare(strict_types=1);
/**
 * cce_new_rules_test.php — 시간동기화·로그설정·암호화 룰의 판정 단위 검증.
 *   서버 없이 돈다: php tests/cce_new_rules_test.php (호스트 php 는 7.2 라 8.3 컨테이너로 실행).
 *   가장 중요한 케이스는 **수집값이 없을 때 FAIL 이 아니라 NA** 라는 것 — 비-root 실행 시나리오다.
 */
require_once __DIR__ . '/../server/src/cce.php';

$pass = 0; $fail = 0;

function res(array $rows, string $code): array {
    foreach ($rows as $r) { if ($r[0] === $code) { return $r; } }
    return ['', '', 'MISSING', '', null, ''];
}
function chk(string $what, string $got, string $want): void {
    global $pass, $fail;
    if ($got === $want) { $pass++; return; }
    $fail++;
    printf("FAIL %s: got=%s want=%s\n", $what, $got, $want);
}

// ── 1) 비-root: 새 수집 키가 하나도 없음 → 전부 NA ──
$rows = vg_cce_checks(['security' => [], 'users' => [], 'meta' => ['running_as' => 'vulnagent']]);
foreach (['CCE-TIME-SYNC', 'CCE-TIME-OFFSET', 'CCE-LOG-RETENTION', 'CCE-LOG-REMOTE',
          'CCE-CRYPTO-SSH-CIPHER', 'CCE-CRYPTO-DISK', 'CCE-CRYPTO-KCMVP'] as $code) {
    chk('비-root ' . $code, res($rows, $code)[2], 'NA');
}

// ── 2) 시간 동기화 ──
$rows = vg_cce_checks(['security' => [
    'time_sync'     => "NTP=yes\nNTPSynchronized=yes\n",
    'time_services' => "chrony=active\nntpd=inactive\n",
    'time_tracking' => "Reference ID    : C0248F97\nSystem time     : 0.000012345 seconds fast of NTP time\nLeap status     : Normal\n",
]]);
chk('동기화됨', res($rows, 'CCE-TIME-SYNC')[2], 'PASS');
chk('오차 정상', res($rows, 'CCE-TIME-OFFSET')[2], 'PASS');

$rows = vg_cce_checks(['security' => [
    'time_sync'     => "NTPSynchronized=no\n",
    'time_services' => "chrony=inactive\n",
    'time_tracking' => "System time     : 12.500000000 seconds slow of NTP time\n",
]]);
chk('미동기화', res($rows, 'CCE-TIME-SYNC')[2], 'FAIL');
chk('오차 초과', res($rows, 'CCE-TIME-OFFSET')[2], 'FAIL');

// 서비스 상태만 있고 동기화 여부를 모르면 NA (활성만 보고 PASS 로 위장하지 않는다)
$rows = vg_cce_checks(['security' => ['time_services' => "chrony=active\n"]]);
chk('상태 불명 NA', res($rows, 'CCE-TIME-SYNC')[2], 'NA');

// ntpq 폴백(offset 은 ms 칼럼)
$rows = vg_cce_checks(['security' => ['time_tracking' =>
    "     remote           refid      st t when poll reach   delay   offset  jitter\n"
    . "*192.168.0.1     10.0.0.1         2 u   64  128  377    0.512   -3.250   0.081\n"]]);
chk('ntpq offset', res($rows, 'CCE-TIME-OFFSET')[2], 'PASS');

// ── 3) 로그 보존기간 ──
$rows = vg_cce_checks(['security' => ['journald_conf' => "SystemMaxUse=500M\nMaxRetentionSec=90d\n"]]);
chk('journald 90일', res($rows, 'CCE-LOG-RETENTION')[2], 'PASS');
$rows = vg_cce_checks(['security' => ['logrotate_conf' => "weekly\nrotate 4\n"]]);
chk('logrotate 28일', res($rows, 'CCE-LOG-RETENTION')[2], 'FAIL');
$rows = vg_cce_checks(['security' => ['logrotate_conf' => "daily\nrotate 180\n"]]);
chk('logrotate 180일', res($rows, 'CCE-LOG-RETENTION')[2], 'PASS');
// 크기만 있고 기간이 없으면 계산 불가 → NA
$rows = vg_cce_checks(['security' => ['journald_conf' => "SystemMaxUse=500M\n", 'logrotate_conf' => "NONE\n"]]);
chk('기간 없음 NA', res($rows, 'CCE-LOG-RETENTION')[2], 'NA');

// ── 4) 원격 로그 전송 ──
$rows = vg_cce_checks(['security' => ['rsyslog_remote' => "*.* @@log.example.com:514\n"]]);
chk('원격 전송 설정', res($rows, 'CCE-LOG-REMOTE')[2], 'PASS');
$rows = vg_cce_checks(['security' => ['rsyslog_remote' => "NONE\n"]]);
chk('원격 전송 없음', res($rows, 'CCE-LOG-REMOTE')[2], 'FAIL');

// ── 5) SSH 암호 알고리즘 ──
$strong = "ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr\n"
        . "macs hmac-sha2-512-etm@openssh.com,hmac-sha2-256\n"
        . "kexalgorithms curve25519-sha256,diffie-hellman-group16-sha512\n";
$rows = vg_cce_checks(['users' => ['sshd_effective' => $strong]]);
chk('강한 알고리즘', res($rows, 'CCE-CRYPTO-SSH-CIPHER')[2], 'PASS');

$weak = "ciphers aes256-ctr,aes128-cbc,3des-cbc\n"
      . "macs hmac-sha2-256,hmac-sha1,hmac-md5\n"
      . "kexalgorithms curve25519-sha256,diffie-hellman-group-exchange-sha1\n";
$rows = vg_cce_checks(['users' => ['sshd_effective' => $weak]]);
$r = res($rows, 'CCE-CRYPTO-SSH-CIPHER');
chk('취약 알고리즘', $r[2], 'FAIL');
foreach (['aes128-cbc', '3des-cbc', 'hmac-sha1', 'hmac-md5', 'diffie-hellman-group-exchange-sha1'] as $bad) {
    chk('근거값에 ' . $bad, str_contains((string) $r[4], $bad) ? 'yes' : 'no', 'yes');
}
// -etm 접미사가 붙은 sha2 계열을 오탐하지 않는다
chk('sha2-etm 오탐 없음', str_contains((string) $r[4], 'hmac-sha2-256') ? 'yes' : 'no', 'no');

// OpenSSH 기본 MACs(Debian 12 실측)에는 hmac-sha1·umac-64 가 들어 있다 → 설정을 안 건드린
//   서버는 FAIL 이 정상이다. "기본값이니 봐준다"로 기준을 완화하지 않았음을 여기에 고정한다.
$stock = "macs umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,"
       . "hmac-sha1-etm@openssh.com,umac-64@openssh.com,hmac-sha2-256,hmac-sha1\n";
$rows = vg_cce_checks(['users' => ['sshd_effective' => $stock]]);
chk('OpenSSH 기본 MACs', res($rows, 'CCE-CRYPTO-SSH-CIPHER')[2], 'FAIL');

// ── 6) 디스크 암호화 · KCMVP (정보성) ──
$rows = vg_cce_checks(['security' => ['disk_encryption' => "sda3 crypto_LUKS\n"]]);
chk('LUKS 있음', res($rows, 'CCE-CRYPTO-DISK')[2], 'PASS');
$rows = vg_cce_checks(['security' => ['disk_encryption' => "NONE\n"]]);
chk('LUKS 없음은 FAIL 아님', res($rows, 'CCE-CRYPTO-DISK')[2], 'NA');
$rows = vg_cce_checks(['users' => ['sshd_effective' => $strong]]);
chk('KCMVP 정보성', res($rows, 'CCE-CRYPTO-KCMVP')[2], 'NA');

printf("\n%d passed, %d failed\n", $pass, $fail);
exit($fail === 0 ? 0 : 1);
