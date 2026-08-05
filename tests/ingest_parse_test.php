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
require_once __DIR__ . '/../server/src/license_risk.php';

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
    'maven'      => "org.apache.logging.log4j:log4j-core 2.14.1",
    'nuget'      => "Newtonsoft.Json 13.0.3",
    'cargo'      => "ripgrep v14.1.1:",
    'inventory'  => "maven|org.example:demo|1.2.3\nnuget|Serilog|3.1.0",
]);
$eq('langpkg 총 12건(기존10+프로젝트2)', count($lang), 12);
$byKey = [];
foreach ($lang as $r) { $byKey[$r[0] . '|' . $r[1]] = $r[2]; }
$eq('pip requests 버전', $byKey['pip|requests'] ?? null, '2.19.1');
$eq('npm corepack 버전', $byKey['npm|corepack'] ?? null, '0.34.6');
$eq('gem rails 첫 버전만', $byKey['gem|rails'] ?? null, '7.0.4');
$eq('gem abbrev default 제거', $byKey['gem|abbrev'] ?? null, '0.1.1');
$eq('composer psr/log 버전', $byKey['composer|psr/log'] ?? null, '3.0.2');
$eq('maven 좌표', $byKey['maven|org.apache.logging.log4j:log4j-core'] ?? null, '2.14.1');
$eq('nuget 패키지', $byKey['nuget|Newtonsoft.Json'] ?? null, '13.0.3');
$eq('cargo crate', $byKey['cargo|ripgrep'] ?? null, '14.1.1');

// ── 언어 패키지: inventory 신뢰도(weak) 우선순위 ────────────────────────────
//   weak = 선언 파일(go.mod/requirements.txt/pom.xml) 유래. 이미 잡힌 값을 덮지 못한다.
//   그 외(설치본 조회)는 예전 그대로 나중 값이 이긴다.
$prio = vg_ingest_parse_langpkgs([
    'pip'       => "requests==2.19.1\nurllib3==1.26.5",
    'inventory' => "pip|requests|99.0.0|weak\n"          // weak → 설치본 2.19.1 유지
                 . "pip|urllib3|1.26.18\n"               // non-weak → 덮어쓴다(기존 동작)
                 . "go|example.com/x|v1.2.3|weak\n"      // 경쟁 없음 → 채택
                 . "maven|bad:coord|1.0|garbage\n"       // 4번째 필드가 weak 아님 → 오염 줄로 폐기
                 . "maven|inj|ect|1.0|weak\n"            // name 에 '|' → 자리 밀림 → 폐기
                 . "unknownmgr|foo|1.0",                 // 미지원 매니저 → 폐기
]);
$prioKey = [];
foreach ($prio as $r) { $prioKey[$r[0] . '|' . $r[1]] = $r[2]; }
$eq('weak 는 설치본을 덮지 않음', $prioKey['pip|requests'] ?? null, '2.19.1');
$eq('non-weak 는 예전대로 덮어씀', $prioKey['pip|urllib3'] ?? null, '1.26.18');
$eq('weak 라도 경쟁 없으면 채택', $prioKey['go|example.com/x'] ?? null, 'v1.2.3');
$eq('4번째 필드 오염 줄 폐기', $prioKey['maven|bad:coord'] ?? null, null);
$eq('파이프 인젝션 줄 폐기', count($prio), 3);

// ── CycloneDX/SPDX SBOM ──────────────────────────────────────────────────
$cdx = json_encode(['bomFormat'=>'CycloneDX','components'=>[
    ['name'=>'log4j-core','version'=>'2.14.1','purl'=>'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1'],
    ['name'=>'requests','version'=>'2.19.1','purl'=>'pkg:pypi/requests@2.19.1'],
]]);
$sbom = vg_ingest_parse_sbom('ctr-a|cyclonedx|' . base64_encode($cdx));
$eq('SBOM 패키지 2건', count($sbom['packages']), 2);
$eq('SBOM 형식', $sbom['meta']['ctr-a'][0] ?? null, 'cyclonedx');
$eq('SBOM 해시', $sbom['meta']['ctr-a'][1] ?? null, hash('sha256', $cdx));

// ── SBOM 라이선스 파싱(CycloneDX licenses[] / SPDX licenseConcluded) ────────
$cdxLic = json_encode(['bomFormat'=>'CycloneDX','components'=>[
    ['name'=>'log4j-core','version'=>'2.14.1','purl'=>'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
     'licenses'=>[['license'=>['id'=>'Apache-2.0']]]],
    // 같은 이름, 다른 버전 — dedup 키에 버전이 없으면 서로 덮어써 하나를 잃는다.
    ['name'=>'log4j-core','version'=>'2.17.0','purl'=>'pkg:maven/org.apache.logging.log4j/log4j-core@2.17.0',
     'licenses'=>[['expression'=>'MIT OR Apache-2.0']]],
]]);
$sbomLic = vg_ingest_parse_sbom('ctr-b|cyclonedx|' . base64_encode($cdxLic));
$eq('SBOM 라이선스: 버전 다르면 dedup 안 됨(2건 유지)', count($sbomLic['packages']), 2);
$byVer = [];
foreach ($sbomLic['packages'] as $p) { $byVer[$p[3]] = $p[5] ?? null; }
$eq('SBOM 라이선스: license.id', $byVer['2.14.1'] ?? null, 'Apache-2.0');
$eq('SBOM 라이선스: expression', $byVer['2.17.0'] ?? null, 'MIT OR Apache-2.0');

$spdxDoc = json_encode(['spdxVersion'=>'SPDX-2.3','packages'=>[
    ['name'=>'requests','versionInfo'=>'2.19.1','externalRefs'=>[
        ['referenceType'=>'purl','referenceLocator'=>'pkg:pypi/requests@2.19.1'],
    ],'licenseConcluded'=>'Apache-2.0'],
    ['name'=>'noassert','versionInfo'=>'1.0','externalRefs'=>[
        ['referenceType'=>'purl','referenceLocator'=>'pkg:pypi/noassert@1.0'],
    ],'licenseConcluded'=>'NOASSERTION'],
]]);
$sbomSpdx = vg_ingest_parse_sbom('ctr-c|spdx|' . base64_encode($spdxDoc));
$byName = [];
foreach ($sbomSpdx['packages'] as $p) { $byName[$p[2]] = $p[5] ?? null; }
$eq('SBOM 라이선스: SPDX licenseConcluded', $byName['requests'] ?? null, 'Apache-2.0');
$eq('SBOM 라이선스: NOASSERTION 은 빈값', $byName['noassert'] ?? null, '');

// ── 언어 패키지 라이선스 스트림(pkg_license, 4필드) ─────────────────────────
$lic = vg_ingest_parse_pkg_license(
    "pip|requests|2.19.1|Apache-2.0\n"
    . "composer|psr/log|3.0.2|MIT\n"
    . "bad-mgr|foo|1.0|MIT\n"          // 미지원 매니저 → 폐기
    . "pip|onlythree|1.0"              // 필드 3개(라이선스 없음) → 폐기
);
$eq('pkg_license 2건(미지원 매니저·필드부족 제외)', count($lic), 2);
$licByKey = [];
foreach ($lic as $r) { $licByKey["{$r[0]}|{$r[1]}|{$r[2]}"] = $r[3]; }
$eq('pkg_license pip requests', $licByKey['pip|requests|2.19.1'] ?? null, 'Apache-2.0');

$attached = vg_ingest_attach_pkg_license(
    [['pip', 'requests', '2.19.1'], ['npm', 'lodash', '4.17.21']],
    $lic
);
$eq('attach: 매칭된 라이선스 부여', $attached[0][3] ?? null, 'Apache-2.0');
$eq('attach: 미매칭은 빈 문자열', $attached[1][3] ?? null, '');

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

// 커널 flavor — 한 호스트에 기종이 다른 커널이 여러 개 깔린다(라즈베리파이 실측).
//   전부를 한 줄로 세우면 **안 쓰는 기종(v8)의 커널이 최신으로 뽑혀** 재부팅 필요가 잘못 붙었다.
//   비교는 실행 중인 커널과 **같은 flavor** 안에서만 해야 한다.
$rpiInstalled = "linux-image-6.12.75+rpt-rpi-2712\t1:6.12.75-1+rpt1\n"
              . "linux-image-6.12.75+rpt-rpi-v8\t1:6.12.75-1+rpt1\n"
              . "linux-image-6.18.34+rpt-rpi-2712\t1:6.18.34-1+rpt1\n"
              . "linux-image-6.18.34+rpt-rpi-v8\t1:6.18.34-1+rpt1";
$rpiCur = vg_ingest_parse_kernel('dpkg', '6.18.34+rpt-rpi-2712', $rpiInstalled);
$eq('라즈베리: 같은 flavor 최신이 곧 실행 커널 → 재부팅 불필요', $rpiCur['reboot_needed'], 0);
$eq('라즈베리: latest 는 같은 flavor(2712) 에서 고른다',           $rpiCur['latest'], '6.18.34+rpt-rpi-2712');

$rpiOld = vg_ingest_parse_kernel('dpkg', '6.12.75+rpt-rpi-2712', $rpiInstalled);
$eq('라즈베리: 같은 flavor 에 더 새 커널이 있으면 재부팅 필요', $rpiOld['reboot_needed'], 1);
$eq('라즈베리: 그때의 latest 도 같은 flavor',                    $rpiOld['latest'], '6.18.34+rpt-rpi-2712');

// 실행 중 커널의 flavor 가 설치 목록에 아예 없으면(그 커널만 제거된 경우) 전체를 본다 —
//   여기서 비교를 포기하면 진짜 재부팅 필요를 놓친다(미탐).
$rpiGone = vg_ingest_parse_kernel('dpkg', '6.1.0-18-amd64', $rpiInstalled);
$eq('실행 flavor 가 설치 목록에 없으면 전체 비교로 폴백', $rpiGone['reboot_needed'], 1);

$eq('flavor(dpkg) — 마지막 - 뒤', vg_kernel_flavor('6.18.34+rpt-rpi-2712', 'dpkg'), '2712');
$eq('flavor(dpkg) — 데비안 표준', vg_kernel_flavor('6.1.0-18-amd64', 'dpkg'), 'amd64');
$eq('flavor(rpm) — 아키만',       vg_kernel_flavor('5.14.0-503.11.1.el9_5.x86_64', 'rpm'), 'x86_64');

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

// **출처(origin)가 바뀌면 해시도 바뀌어야 한다.** 안 그러면 "변경 없음" 으로 스캔을 재사용하고
//   tb_package 를 다시 쓰지 않아, 에이전트가 고쳐 보낸 출처가 DB 에 영원히 안 들어간다
//   (실측: 에이전트 2.2 가 curl→Debian 으로 고쳤는데 DB 엔 LOCAL 이 그대로였다).
$withOrigin = static fn(array $originMap) => vg_ingest_content_hash(
    [['openssl', '1.0']], 'rpm', [], [], [], [], [], [],
    '5.14.0', '5.14.0', 0, ['distro_id' => 'rocky'], ['kernel_release' => '5.14.0'], $originMap
);
if ($withOrigin(['openssl' => 'LOCAL']) === $withOrigin(['openssl' => 'Debian'])) {
    printf("  ✗ [해시: 출처가 다르면 달라야 함] 두 해시가 같음\n");
    $fail++;
}

// **라이선스가 바뀌면 해시도 바뀌어야 한다.** 안 그러면 라이선스만 바뀐 재스캔이 "변경 없음"으로
//   스킵돼 스캔 재사용 시 라이선스 변경이 구조적으로 누락된다(출처 필드와 동일 유형의 사고).
$withLangLicense = static fn(string $lic) => vg_ingest_content_hash(
    [], 'rpm', [['pip', 'requests', '2.19.1', $lic]], [], [], [], [], [],
    '5.14.0', '5.14.0', 0, ['distro_id' => 'rocky'], ['kernel_release' => '5.14.0']
);
if ($withLangLicense('MIT') === $withLangLicense('Apache-2.0')) {
    printf("  ✗ [해시: 언어 패키지 라이선스가 다르면 달라야 함] 두 해시가 같음\n");
    $fail++;
}
$withCtrPkgLicense = static fn(string $lic) => vg_ingest_content_hash(
    [], 'rpm', [], [], [], [['ctr-a', 'maven', 'log4j-core', '2.14.1', '', $lic]], [], [],
    '5.14.0', '5.14.0', 0, ['distro_id' => 'rocky'], ['kernel_release' => '5.14.0']
);
if ($withCtrPkgLicense('MIT') === $withCtrPkgLicense('Apache-2.0')) {
    printf("  ✗ [해시: 컨테이너(SBOM) 패키지 라이선스가 다르면 달라야 함] 두 해시가 같음\n");
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

// ── 라이선스 위험도 분류(license_risk.php) ──────────────────────────────────
$eq('permissive 단일', vg_license_classify('MIT'), 'permissive');
$eq('copyleft 단일', vg_license_classify('GPL-3.0-only'), 'copyleft');
$eq('빈 값은 unknown', vg_license_classify(''), 'unknown');
$eq('생소한 식별자는 unknown', vg_license_classify('Some-Custom-License'), 'unknown');
$eq('복합 표현식: copyleft 가 섞이면 copyleft(보수적 판정)', vg_license_classify('MIT OR GPL-3.0-only'), 'copyleft');
$eq('복합 표현식: 전부 permissive 면 permissive', vg_license_classify('MIT OR Apache-2.0'), 'permissive');
$eq('WITH 예외조항도 토큰 분리', vg_license_classify('GPL-2.0-only WITH Classpath-exception-2.0'), 'copyleft');

if ($fail === 0) {
    echo "ingest_parse: 전체 통과\n";
    exit(0);
}
printf("ingest_parse: %d건 실패\n", $fail);
exit(1);
