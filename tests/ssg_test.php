<?php
declare(strict_types=1);

/**
 * ssg 단위 테스트 — SCAP Security Guide 룰 파서 + 우리 점검과의 매핑.
 *
 * 왜 파서를 직접 짰나: rule.yml 의 **3분의 1에 Jinja 블록**({{% if %}})이 섞여 있어 표준 YAML
 *   파서가 깨진다(실측: 표본 400개 중 130개). 우리가 쓰는 필드는 제목·심각도·근거·참조뿐이라
 *   그 필드만 정규식으로 뽑는다. 그래서 **형식이 조금 달라도 안 깨지는지**를 여기서 고정한다.
 *
 * 실행: docker run --rm -v "$PWD:/w" -w /w php:8.3-cli php tests/ssg_test.php
 */

require_once __DIR__ . '/../server/src/cce.php';

// 커넥터 파일은 VgFeedConnector 를 구현하므로 계약을 먼저 정의한다(파서만 쓰려고 feeds.php 를
//   통째로 로드하면 DB 커넥션까지 딸려온다).
if (!interface_exists('VgFeedConnector')) {
    interface VgFeedConnector {
        public function run(PDO $pdo, array $conn): array;
        public function preview(PDO $pdo, array $conn): array;
    }
}
require_once __DIR__ . '/../server/src/feeds/ssg.php';

$fail = 0;
$eq = static function (string $label, $got, $want) use (&$fail): void {
    if ($got !== $want) {
        printf("  ✗ [%s] 기대 %s, 실제 %s\n", $label, var_export($want, true), var_export($got, true));
        $fail++;
    }
};

// ── 실제 SSG rule.yml 형식(발췌) ───────────────────────────────────────────
$yaml = <<<'YML'
documentation_complete: true

title: 'Disable SSH Access via Empty Passwords'

description: |-
    Disallow SSH login with empty passwords.
    {{{ sshd_config_file() }}}

rationale: |-
    Configuring this setting for the SSH daemon provides additional assurance
    that remote login via SSH will require a password.

severity: high

references:
    cis@rhel9: 5.2.11
    cis-csc: 11,12,13
    nist: AC-17(a),CM-6(a)
    stigid@rhel9: RHEL-09-255025

{{% if 'rhel' in product %}}
platform: machine
{{% endif %}}
YML;

$r = vg_ssg_parse_rule($yaml);
$eq('제목',        $r['title'],    'Disable SSH Access via Empty Passwords');
$eq('심각도',      $r['severity'], 'high');
$eq('CIS 참조',    $r['refs']['cis@rhel9'] ?? null, '5.2.11');
$eq('NIST 참조',   $r['refs']['nist'] ?? null,      'AC-17(a),CM-6(a)');
$eq('STIG 참조',   $r['refs']['stigid@rhel9'] ?? null, 'RHEL-09-255025');
// Jinja 블록이 섞여 있어도 앞의 필드는 정상적으로 읽혀야 한다(YAML 파서라면 여기서 죽는다).
$eq('근거(rationale) 추출', str_contains($r['rationale'], 'require a password'), true);

// 제목이 없는 파일은 룰이 아니다 → null (템플릿 조각·부분 파일이 섞여 있다)
$eq('제목 없으면 null', vg_ssg_parse_rule("severity: medium\n"), null);

// ── 우리 점검 ↔ SSG 룰 매핑 ────────────────────────────────────────────────
//   매핑은 추측이 아니라 SSG 룰 ID 를 실제로 검색해 붙였다. 오타가 나면 조용히 "자체 기준" 이
//   되어 근거가 사라지므로, 대표 항목을 여기서 고정한다.
$map = vg_cce_ssg_map();
$eq('SSH 루트 로그인',   $map['CCE-SSH-ROOT']    ?? null, 'sshd_disable_root_login');
$eq('SSH 빈 패스워드',   $map['CCE-SSH-EMPTYPW'] ?? null, 'sshd_disable_empty_passwords');
$eq('passwd 파일 권한',  $map['CCE-FILE-PASSWD'] ?? null, 'file_permissions_etc_passwd');
$eq('UID 0 중복',        $map['CCE-ACC-UID0']    ?? null, 'accounts_no_uid_except_zero');
$eq('SELinux 상태',      $map['CCE-SEC-MODULE']  ?? null, 'selinux_state');
// #519 에서 전수 대조로 추가한 4개.
$eq('시간 동기화',       $map['CCE-TIME-SYNC']         ?? null, 'chronyd_sync_clock');
$eq('원격 로그 전송',    $map['CCE-LOG-REMOTE']        ?? null, 'rsyslog_remote_loghost');
$eq('디스크 암호화',     $map['CCE-CRYPTO-DISK']       ?? null, 'encrypt_partitions');
$eq('SSH 취약 알고리즘', $map['CCE-CRYPTO-SSH-CIPHER'] ?? null, 'sshd_use_strong_ciphers');
// 대응 룰이 **없어서** 자체 기준으로 남기기로 한 항목들. 나중에 "비슷해 보인다"는 이유로
//   끼워 넣는 것을 막는다 — 근거는 cce.php 의 vg_cce_ssg_map() 주석에 남겼다.
foreach (['CCE-TIME-OFFSET', 'CCE-LOG-RETENTION', 'CCE-CRYPTO-KCMVP', 'CCE-SSH-PWAUTH',
          'CCE-FILE-HOSTS', 'CCE-FILE-SERVICES', 'CCE-FILE-SYSLOG', 'CCE-FILE-XINETD'] as $c) {
    $eq('자체 기준 유지: ' . $c, isset($map[$c]), false);
}
$eq('매핑 개수(31개)',   count($map), 31);

if ($fail === 0) {
    echo "ssg: 모든 검사 통과\n";
    exit(0);
}
printf("ssg: %d 개 실패\n", $fail);
exit(1);
