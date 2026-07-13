<?php
declare(strict_types=1);

/**
 * ingest_parse 단위 테스트 — ingest.php 에서 뽑아낸 순수 변환 함수(server/src/ingest_parse.php).
 * DB·인증·감사로그는 건드리지 않는다(그건 ingest.php 에 남아 tests/smoke.sh 의 e2e 로 검증됨).
 *
 * 실행:
 *   docker run --rm -v "$PWD:/w" -w /w php:8.3-cli php tests/ingest_parse_test.php
 */

require_once __DIR__ . '/../server/src/ingest_parse.php';

date_default_timezone_set('UTC');   // collected_at 변환이 TZ 에 의존하므로 환경과 무관하게 고정

$fail = 0;
$eq = static function (string $label, $got, $want) use (&$fail): void {
    if ($got !== $want) {
        printf("  ✗ [%s] 기대 %s, 실제 %s\n", $label, var_export($want, true), var_export($got, true));
        $fail++;
    }
};

// ── collected_at ──────────────────────────────────────────────────────────
$eq('collected_at 정상(UTC 환산)', vg_ingest_parse_collected_at('2026-07-07T10:15:30+09:00'), '2026-07-07 01:15:30');
$eq('collected_at 빈값', vg_ingest_parse_collected_at(''), null);
$eq('collected_at null', vg_ingest_parse_collected_at(null), null);
$eq('collected_at 파싱불가', vg_ingest_parse_collected_at('not-a-date'), null);

// ── 패키지 목록 ────────────────────────────────────────────────────────────
$rpmRows = vg_ingest_parse_packages('rpm', "openssl\t1:3.0.7-24.el9\tx86_64\topenssl-3.0.7-24.el9.src.rpm\tRocky Enterprise Software Foundation");
$eq('rpm 패키지 1건', count($rpmRows), 1);
$eq('rpm 패키지 name', $rpmRows[0][0], 'openssl');
$eq('rpm 패키지 version', $rpmRows[0][1], '1:3.0.7-24.el9');
$eq('rpm 패키지 vendor', $rpmRows[0][5], 'Rocky Enterprise Software Foundation');

$dpkgList = "curl\t7.88.1-10\tamd64\tcurl\t7.88.1-10\tii\n"
          . "oldpkg\t1.0-1\tamd64\toldpkg\t1.0-1\trc\n"   // rc = 제거됨, 설정만 남음 → 버려야 함
          . "\t1.0\tamd64\t\t\tii";                         // name 없음 → 버려야 함
$dpkgRows = vg_ingest_parse_packages('dpkg', $dpkgList);
$eq('dpkg ii 만 유지', count($dpkgRows), 1);
$eq('dpkg name', $dpkgRows[0][0], 'curl');
$eq('dpkg 빈 목록', count(vg_ingest_parse_packages('dpkg', '')), 0);

// ── 패키지 출처(Origin) ────────────────────────────────────────────────────
$origins = vg_ingest_parse_origins("docker-ce-cli\tDocker\ncurl\tDebian\nbad-line-no-tab\nfoo\t");
$eq('origin 2건', count($origins), 2);
$eq('origin docker', $origins['docker-ce-cli'], 'Docker');

// ── 언어 패키지 ────────────────────────────────────────────────────────────
$lang = vg_ingest_parse_langpkgs([
    'pip'        => "requests==2.19.1\nurllib3==2.0.7\nnot-a-valid-line",
    'npm_global' => "/usr/local/lib\n+-- corepack@0.34.6\n`-- npm@10.8.2",
    'gem'        => "rails (7.0.4, 6.1.7)\nabbrev (default: 0.1.1)",
    'composer'   => "psr/log 3.0.2 어떤 설명",
]);
$eq('langpkg 총 7건(pip2+npm2+gem2+composer1)', count($lang), 7);
$byKey = [];
foreach ($lang as $r) { $byKey[$r[0] . '|' . $r[1]] = $r[2]; }
$eq('pip requests 버전', $byKey['pip|requests'] ?? null, '2.19.1');
$eq('npm corepack 버전', $byKey['npm|corepack'] ?? null, '0.34.6');
$eq('gem rails 첫 버전만', $byKey['gem|rails'] ?? null, '7.0.4');
$eq('gem abbrev default 제거', $byKey['gem|abbrev'] ?? null, '0.1.1');
$eq('composer psr/log 버전', $byKey['composer|psr/log'] ?? null, '3.0.2');

// ── 노출 상관 ──────────────────────────────────────────────────────────────
$exp = vg_ingest_parse_exposures(
    "pid|proc|proto|bind|port|scope|exe_pkg|loaded_pkgs\n"
    . "1201|nginx|tcp|0.0.0.0|443|EXTERNAL|nginx|openssl,glibc\n"
    . "short|line"   // 필드 부족 → 버려야 함
);
$eq('노출 헤더 스킵 + 1건', count($exp), 1);
$eq('노출 scope', $exp[0][5], 'EXTERNAL');

// ── 실행 프로세스 ──────────────────────────────────────────────────────────
$proc = vg_ingest_parse_processes(
    "pid|comm|user|exe_pkg|loaded_pkgs\n980|sshd|root|openssh-server|openssl,glibc\nbad"
);
$eq('프로세스 1건', count($proc), 1);
$eq('프로세스 comm', $proc[0][1], 'sshd');

// ── stale libs ─────────────────────────────────────────────────────────────
$stale = vg_ingest_parse_stale(
    "pid|comm|pkg|lib\n1201|nginx|curl|/usr/lib64/libcurl.so.4.7.0\n1202|foo||/no/pkg\n"
);
$eq('stale pkg 없는 행 제외 → 1건', count($stale), 1);
$eq('stale pkg명', $stale[0][2], 'curl');

// ── changelog CVE ──────────────────────────────────────────────────────────
$clog = vg_ingest_parse_changelog([
    'nginx' => "fix CVE-2024-1234 buffer overflow\nfix CVE-2024-1234 again (같은 CVE 중복)\nunrelated line",
    ''      => "CVE-2024-9999",   // 패키지명 없음 → 버려야 함
    'empty' => '',                // 빈 텍스트 → 버려야 함
]);
$eq('changelog CVE 1건(중복 제거)', count($clog), 1);
$eq('changelog CVE ID', $clog[0][1], 'CVE-2024-1234');

// ── errata CVE ─────────────────────────────────────────────────────────────
$errata = vg_ingest_parse_errata(
    "CVE-2023-22809 Important/Sec. sudo-1.9.5p2-10.el9_3.x86_64\n"
    . "RLSA-2023:0136 Important/Sec. sudo-1.9.5p2-10.el9_3.x86_64\n"   // 권고ID 줄 → 버려야 함
);
$eq('errata CVE 1건', count($errata), 1);
$eq('errata pkgName(NEVRA→name)', $errata[0][0], 'sudo');
$eq('errata CVE ID', $errata[0][1], 'CVE-2023-22809');

// ── debsecan ───────────────────────────────────────────────────────────────
$debsecan = vg_ingest_parse_debsecan("CVE-2026-13595 bsdutils\nmalformed line\nCVE-2026-13595 bsdutils");
$eq('debsecan 중복 제거 → 1건', count($debsecan), 1);
$eq('debsecan package', $debsecan[0][1], 'bsdutils');

// ── 컨테이너 ───────────────────────────────────────────────────────────────
$ctrList = vg_ingest_parse_container_list(
    "cid|name|image|os_id|os_version|manager|pkg_count\napi|api|myco/api:1.4|alpine|3.19.1|apk|2"
);
$eq('컨테이너 목록 1건', count($ctrList), 1);
$eq('컨테이너 cid 키', isset($ctrList['api']), true);

$ctrPkg = vg_ingest_parse_container_packages(
    "cid|manager|name|version|source\napi|apk|openssl|3.1.4-r2|openssl\nbad|apk||1.0|src"
);
$eq('컨테이너 패키지 1건(name 없는 행 제외)', count($ctrPkg), 1);

$ctrProc = vg_ingest_parse_container_processes(
    "cid|pid|comm|user|exe_pkg|loaded_pkgs\napi|2100|nginx|root|nginx|openssl,busybox"
);
$eq('컨테이너 프로세스 1건', count($ctrProc), 1);

$ctrExp = vg_ingest_parse_container_exposures(
    "cid|pid|proc|proto|bind|port|scope|exe_pkg|loaded_pkgs\napi|2100|nginx|tcp|0.0.0.0|8443|EXTERNAL|nginx|openssl,busybox"
);
$eq('컨테이너 노출 1건', count($ctrExp), 1);
$eq('컨테이너 노출 scope', $ctrExp[0][6], 'EXTERNAL');

// ── 커널 ───────────────────────────────────────────────────────────────────
$kernelRpm = vg_ingest_parse_kernel('rpm', '5.14.0-427.13.1.el9_4.x86_64', 'kernel-core-5.14.0-503.11.1.el9_5.x86_64');
$eq('rpm 커널 재부팅 필요', $kernelRpm['reboot_needed'], 1);
$eq('rpm 커널 latest', $kernelRpm['latest'], '5.14.0-503.11.1.el9_5.x86_64');

$kernelDpkgSame = vg_ingest_parse_kernel('dpkg', '6.1.0-18-amd64', "linux-image-6.1.0-18-amd64\t6.1.76-1");
$eq('dpkg 커널 재부팅 불필요(동일)', $kernelDpkgSame['reboot_needed'], 0);

$kernelNone = vg_ingest_parse_kernel('rpm', '', '');
$eq('설치 커널 후보 없음 → latest 빈값', $kernelNone['latest'], '');
$eq('설치 커널 후보 없음 → 재부팅 판정 안 함', $kernelNone['reboot_needed'], 0);

// ── 내용 해시 ──────────────────────────────────────────────────────────────
$commonArgs = static fn(array $pkgRows, array $expRows) => vg_ingest_content_hash(
    $pkgRows, 'rpm', [], $expRows, [], [], [], [],
    '5.14.0', '5.14.0', 0, ['distro_id' => 'rocky'], ['kernel_release' => '5.14.0']
);
$hashA = $commonArgs([['openssl', '1.0']], [['1201', 'nginx', 'tcp', '0.0.0.0', '443', 'EXTERNAL', 'nginx', 'openssl']]);
$hashB = $commonArgs([['openssl', '1.0']], [['9999', 'nginx', 'tcp', '0.0.0.0', '443', 'EXTERNAL', 'nginx', 'openssl']]);
$eq('해시: PID 만 다르면 동일해야 함', $hashA, $hashB);
$hashC = $commonArgs([['openssl', '2.0']], [['1201', 'nginx', 'tcp', '0.0.0.0', '443', 'EXTERNAL', 'nginx', 'openssl']]);
if ($hashA === $hashC) {
    printf("  ✗ [해시: 패키지 버전이 다르면 달라야 함] 두 해시가 같음\n");
    $fail++;
}

// ── 패키지 맵 + 변경 diff ───────────────────────────────────────────────────
$pkgMap = vg_ingest_build_pkg_map('rpm', [['openssl', '1.0'], ['glibc', '2.0']], [['pip', 'requests', '2.19.1']]);
$eq('패키지 맵 3건', count($pkgMap), 3);
$eq('패키지 맵 rpm 키', $pkgMap['rpm|openssl'], '1.0');
$eq('패키지 맵 언어 키', $pkgMap['pip|requests'], '2.19.1');

$verCmp = static function (string $a, string $b, string $mgr): int {
    // 테스트용 단순 비교 — 실제 vg_ver_cmp 는 vercmp_test.php 가 이미 검증한다.
    return $a <=> $b;
};
$changes = vg_ingest_diff_packages(
    ['rpm|openssl' => '1.0', 'rpm|removed-pkg' => '9.9'],
    ['rpm|openssl' => '1.1', 'rpm|new-pkg' => '1.0'],
    $verCmp
);
$byType = [];
foreach ($changes as [$key, $type, $old, $new]) { $byType[$type][] = [$key, $old, $new]; }
$eq('설치 1건', count($byType['installed'] ?? []), 1);
$eq('설치 키', $byType['installed'][0][0] ?? null, 'rpm|new-pkg');
$eq('업그레이드 1건', count($byType['upgraded'] ?? []), 1);
$eq('제거 1건', count($byType['removed'] ?? []), 1);
$eq('제거 키', $byType['removed'][0][0] ?? null, 'rpm|removed-pkg');

if ($fail === 0) {
    echo "ingest_parse: 전체 통과\n";
    exit(0);
}
printf("ingest_parse: %d건 실패\n", $fail);
exit(1);
