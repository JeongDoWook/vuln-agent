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
require_once __DIR__ . '/../server/src/assetgrade.php';
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
]]);
$sbomLic = vg_ingest_parse_sbom('ctr-b|cyclonedx|' . base64_encode($cdxLic));
$eq('SBOM 라이선스: license.id', $sbomLic['packages'][0][5] ?? null, 'Apache-2.0');

$cdxExpr = json_encode(['bomFormat'=>'CycloneDX','components'=>[
    ['name'=>'expr-pkg','version'=>'1.0','purl'=>'pkg:maven/org.example/expr-pkg@1.0',
     'licenses'=>[['expression'=>'MIT OR Apache-2.0']]],
]]);
$sbomExpr = vg_ingest_parse_sbom('ctr-g|cyclonedx|' . base64_encode($cdxExpr));
$eq('SBOM 라이선스: expression', $sbomExpr['packages'][0][5] ?? null, 'MIT OR Apache-2.0');

$spdxDoc = json_encode(['spdxVersion'=>'SPDX-2.3','packages'=>[
    ['name'=>'requests','versionInfo'=>'2.19.1','externalRefs'=>[
        ['referenceType'=>'purl','referenceLocator'=>'pkg:pypi/requests@2.19.1'],
    ],'licenseConcluded'=>'Apache-2.0'],
    ['name'=>'noassert','versionInfo'=>'1.0','externalRefs'=>[
        ['referenceType'=>'purl','referenceLocator'=>'pkg:pypi/noassert@1.0'],
    ],'licenseConcluded'=>'NOASSERTION'],
    // syft/trivy 는 보통 concluded=NOASSERTION 이고 declared 에 실값을 담는다 — fallback 검증.
    ['name'=>'declared-only','versionInfo'=>'1.0','externalRefs'=>[
        ['referenceType'=>'purl','referenceLocator'=>'pkg:pypi/declared-only@1.0'],
    ],'licenseConcluded'=>'NOASSERTION','licenseDeclared'=>'MIT'],
]]);
$sbomSpdx = vg_ingest_parse_sbom('ctr-c|spdx|' . base64_encode($spdxDoc));
$byName = [];
foreach ($sbomSpdx['packages'] as $p) { $byName[$p[2]] = $p[5] ?? null; }
$eq('SBOM 라이선스: SPDX licenseConcluded', $byName['requests'] ?? null, 'Apache-2.0');
$eq('SBOM 라이선스: NOASSERTION 은 빈값', $byName['noassert'] ?? null, '');
$eq('SBOM 라이선스: concluded 없으면 declared 로 폴백', $byName['declared-only'] ?? null, 'MIT');

// ── SBOM dedup 범위 축소(cid|mgr|name, 버전 제외) + 라이선스 병합 ───────────
//   design-review 승인이었던 "dedup 키에 버전 포함"이 다중 버전(중첩 jar 등)을 전부 별도
//   행으로 만들어 tb_container.pkg_count·finding 건수를 부풀렸다 — 이름까지만 dedup 하고
//   라이선스가 비어 있을 때만 채우는 병합으로 좁힌다.
$cdxMerge = json_encode(['bomFormat'=>'CycloneDX','components'=>[
    ['name'=>'log4j-core','version'=>'2.14.1','purl'=>'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
     'licenses'=>[['license'=>['id'=>'Apache-2.0']]]],
    // 같은 이름, 다른 버전 — 이제는 첫 항목으로 병합돼야 한다(라이선스는 이미 채워졌으니 유지).
    ['name'=>'log4j-core','version'=>'2.17.0','purl'=>'pkg:maven/org.apache.logging.log4j/log4j-core@2.17.0',
     'licenses'=>[['expression'=>'MIT']]],
]]);
$sbomMerge = vg_ingest_parse_sbom('ctr-d|cyclonedx|' . base64_encode($cdxMerge));
$eq('SBOM dedup: 같은 이름 다른 버전은 1건으로 병합', count($sbomMerge['packages']), 1);
$eq('SBOM dedup: 버전은 첫 항목 유지', $sbomMerge['packages'][0][3] ?? null, '2.14.1');
$eq('SBOM dedup: 라이선스가 이미 있으면 나중 값으로 안 덮음', $sbomMerge['packages'][0][5] ?? null, 'Apache-2.0');

$cdxFill = json_encode(['bomFormat'=>'CycloneDX','components'=>[
    ['name'=>'foo','version'=>'1.0','purl'=>'pkg:maven/org.example/foo@1.0'],   // 라이선스 없음
    ['name'=>'foo','version'=>'2.0','purl'=>'pkg:maven/org.example/foo@2.0',
     'licenses'=>[['license'=>['id'=>'MIT']]]],
]]);
$sbomFill = vg_ingest_parse_sbom('ctr-e|cyclonedx|' . base64_encode($cdxFill));
$eq('SBOM dedup: 먼저 잡힌 라이선스 빈 항목은 나중 값으로 채움', $sbomFill['packages'][0][5] ?? null, 'MIT');

// CycloneDX 복수 licenses[] 는 스펙상 동시적용(AND) 의미다 — OR 로 이으면 뜻이 뒤집힌다.
$cdxMulti = json_encode(['bomFormat'=>'CycloneDX','components'=>[
    ['name'=>'multi-lic','version'=>'1.0','purl'=>'pkg:maven/org.example/multi-lic@1.0',
     'licenses'=>[['license'=>['id'=>'MIT']], ['license'=>['id'=>'Apache-2.0']]]],
]]);
$sbomMulti = vg_ingest_parse_sbom('ctr-f|cyclonedx|' . base64_encode($cdxMulti));
$eq('SBOM 라이선스: 복수 licenses[] 는 AND 로 결합', $sbomMulti['packages'][0][5] ?? null, 'MIT AND Apache-2.0');

// ── 언어 패키지 라이선스 스트림(pkg_license, 4필드) ─────────────────────────
$lic = vg_ingest_parse_pkg_license(
    "pip|requests|2.19.1|Apache-2.0\n"
    . "composer|psr/log|3.0.2|MIT\n"
    . "bad-mgr|foo|1.0|MIT\n"          // 미지원 매니저 → 폐기
    . "pip|onlythree|1.0\n"            // 필드 3개(라이선스 없음) → 폐기
    // 파이프 인젝션: name 에 '|' 가 섞여 필드가 5개로 밀린 오염 줄 → limit 없는 explode 로
    //   정확히 4필드가 아니면 거부돼야 한다(예전엔 explode(...,4) 라 조용히 통과했다).
    . "pip|evil|name|1.0|MIT\n"
    // 자유서술 라이선스 — 정규화(별칭 매핑)를 거쳐 SPDX 로 저장돼야 한다.
    . "pip|urllib3|2.0.7|BSD License\n"
    // 화이트리스트를 통과 못 하는 오염값(저작권 문구 등, ':' 포함) → 거부.
    . "pip|tainted|1.0|Copyright (c) 2024: all rights reserved"
);
$eq('pkg_license 3건(미지원 매니저·필드부족·인젝션·화이트리스트 위반 제외)', count($lic), 3);
$licByKey = [];
foreach ($lic as $r) { $licByKey["{$r[0]}|{$r[1]}|{$r[2]}"] = $r[3]; }
$eq('pkg_license pip requests', $licByKey['pip|requests|2.19.1'] ?? null, 'Apache-2.0');
$eq('pkg_license 파이프 인젝션 줄 거부', $licByKey['pip|evil|name'] ?? null, null);
$eq('pkg_license 자유서술 표기 정규화(BSD License→BSD-3-Clause)', $licByKey['pip|urllib3|2.0.7'] ?? null, 'BSD-3-Clause');
$eq('pkg_license 화이트리스트 위반 거부', $licByKey['pip|tainted|1.0'] ?? null, null);

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

// ── 패키지 무결성 (rpm -Va / dpkg --verify) ────────────────────────────────
$integ = vg_ingest_parse_integrity(
    "package|flags|path\n"
    . "gzip-1.12-1.el9.x86_64|S.5......|/usr/bin/gzip\n"   // rpm
    . "coreutils|??5??????|/bin/ls\n"                      // dpkg
    . "filesystem|missing|/boot\n"
    . "foo|.M.......|상대경로아님\n"                        // 절대경로 아님 → 버림
    . "bar||/usr/bin/baz\n"                                // 플래그 없음 → 버림
    . "필드부족\n"
);
$eq('무결성 정상 행만 3건', count($integ), 3);
$eq('무결성 패키지명', $integ[0][0], 'gzip-1.12-1.el9.x86_64');
$eq('무결성 원본 플래그 보존', $integ[1][1], '??5??????');
$eq('무결성 경로', $integ[2][2], '/boot');
// 경로에 '|' 가 섞여도 앞 필드를 밀지 않는다(limit=3 고정).
$integPipe = vg_ingest_parse_integrity("package|flags|path\npkg|S.5......|/tmp/a|b");
$eq('무결성 경로 안의 | 는 경로에 남는다', $integPipe[0][2], '/tmp/a|b');
$eq('무결성 플래그는 오염 안 됨', $integPipe[0][1], 'S.5......');

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
    "cid|manager|name|version|source\napi|apk|openssl|3.1.4-r2|openssl\nbad|apk||1.0|src\n"
    // source 필드에 '|' 가 섞인 오염 줄(파이프 인젝션 시도) — limit(5) 없으면 6번째 칸이
    //   생겨 ingest_store.php 가 그 자리를 SBOM 전용 license 필드로 오인해 승격시킨다.
    . 'api2|apk|curl|8.0.0|src|FAKE-LICENSE-INJECTED'
);
$eq('컨테이너 패키지 2건(name 없는 행 제외)', count($ctrPkg), 2);
$byCid = [];
foreach ($ctrPkg as $r) { $byCid[$r[0]] = $r; }
$eq('컨테이너 패키지 파이프 인젝션: 필드가 5개로 고정됨', count($byCid['api2']), 5);
$eq('컨테이너 패키지 파이프 인젝션: 6번째 칸(license) 미생성', $byCid['api2'][5] ?? null, null);

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
    $pkgRows, 'rpm', [], $expRows, [], [], [], [], [],
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
$withProcesses = static fn(array $procRows) => vg_ingest_content_hash(
    [], 'rpm', [], [], vg_asset_grade_relevant_process_rows($procRows), [], [], [], [],
    '5.14.0', '5.14.0', 0, ['distro_id' => 'rocky'], ['kernel_release' => '5.14.0']
);
$procA = $withProcesses([['101', 'restic', 'root', '/usr/bin/restic', 'restic']]);
$procPidOnly = $withProcesses([['999', 'restic', 'root', '/usr/bin/restic', 'restic']]);
$eq('해시: 프로세스 PID 만 다르면 동일해야 함', $procA, $procPidOnly);
$eq('해시: 저장하지 않는 프로세스 잉여 필드는 무시', $procA,
    $withProcesses([['101', 'restic', 'root', '/usr/bin/restic', 'restic', 'attacker-nonce']]));
if ($procA === $withProcesses([])) {
    printf("  ✗ [해시: 역할 프로세스 시작·종료가 다르면 달라야 함] 두 해시가 같음\n");
    $fail++;
}
$eq('등급 무관 일시 프로세스는 스냅샷을 늘리지 않음',
    vg_asset_grade_relevant_process_rows([['1', 'cron', 'root', '', '']]), []);

// **출처(origin)가 바뀌면 해시도 바뀌어야 한다.** 안 그러면 "변경 없음" 으로 스캔을 재사용하고
//   tb_package 를 다시 쓰지 않아, 에이전트가 고쳐 보낸 출처가 DB 에 영원히 안 들어간다
//   (실측: 에이전트 2.2 가 curl→Debian 으로 고쳤는데 DB 엔 LOCAL 이 그대로였다).
$withOrigin = static fn(array $originMap) => vg_ingest_content_hash(
    [['openssl', '1.0']], 'rpm', [], [], [], [], [], [], [],
    '5.14.0', '5.14.0', 0, ['distro_id' => 'rocky'], ['kernel_release' => '5.14.0'], $originMap
);
if ($withOrigin(['openssl' => 'LOCAL']) === $withOrigin(['openssl' => 'Debian'])) {
    printf("  ✗ [해시: 출처가 다르면 달라야 함] 두 해시가 같음\n");
    $fail++;
}

// **라이선스가 바뀌면 해시도 바뀌어야 한다.** 안 그러면 라이선스만 바뀐 재스캔이 "변경 없음"으로
//   스킵돼 스캔 재사용 시 라이선스 변경이 구조적으로 누락된다(출처 필드와 동일 유형의 사고).
$withLangLicense = static fn(string $lic) => vg_ingest_content_hash(
    [], 'rpm', [['pip', 'requests', '2.19.1', $lic]], [], [], [], [], [], [],
    '5.14.0', '5.14.0', 0, ['distro_id' => 'rocky'], ['kernel_release' => '5.14.0']
);
if ($withLangLicense('MIT') === $withLangLicense('Apache-2.0')) {
    printf("  ✗ [해시: 언어 패키지 라이선스가 다르면 달라야 함] 두 해시가 같음\n");
    $fail++;
}
$withCtrPkgLicense = static fn(string $lic) => vg_ingest_content_hash(
    [], 'rpm', [], [], [], [], [['ctr-a', 'maven', 'log4j-core', '2.14.1', '', $lic]], [], [],
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

// ── 라이선스 정규화(자유서술 별칭·괄호 표현식·'+' 접미사) ──────────────────
$eq('별칭: BSD License → permissive', vg_license_classify('BSD License'), 'permissive');
$eq('별칭: 대소문자 무관', vg_license_classify('bsd license'), 'permissive');
$eq('별칭: Apache Software License → permissive', vg_license_classify('Apache Software License'), 'permissive');
$eq('별칭: GNU General Public License v3 → copyleft', vg_license_classify('GNU General Public License v3'), 'copyleft');
$eq("'+' 접미사: GPL-3.0+ → copyleft", vg_license_classify('GPL-3.0+'), 'copyleft');
$eq('괄호 표현식: (MIT OR Apache-2.0) → permissive', vg_license_classify('(MIT OR Apache-2.0)'), 'permissive');
$eq('괄호+copyleft 혼합: (MIT OR GPL-3.0-only) → copyleft(보수적)', vg_license_classify('(MIT OR GPL-3.0-only)'), 'copyleft');

// ── 패키지 의존성 그래프: pom.xml 최상위 <dependencies> (PR#399 재작업) ─────
$pomOk = <<<'XML'
<project>
  <dependencies>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>demo-a</artifactId>
      <version>1.2.3</version>
    </dependency>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>demo-b</artifactId>
      <version>4.5.6</version>
      <scope>compile</scope>
    </dependency>
  </dependencies>
</project>
XML;
$pom = vg_ingest_parse_pom_deps('pom.xml|' . base64_encode($pomOk));
$eq('pom 정상: 2건', count($pom['rows']), 2);
$eq('pom 정상: name', $pom['rows'][0][1], 'org.example:demo-a');
$eq('pom 정상: version', $pom['rows'][0][2], '1.2.3');
$eq('pom 정상: manager', $pom['rows'][0][0], 'maven');

// <exclusions> 안의(비표준이지만 오탐 사례로 실제 목격된) <dependency> 는 최상위 직접선언이 아니다.
$pomExcl = <<<'XML'
<project>
  <dependencies>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>demo-a</artifactId>
      <version>1.0.0</version>
      <exclusions>
        <dependency>
          <groupId>org.excluded</groupId>
          <artifactId>should-not-appear</artifactId>
          <version>9.9.9</version>
        </dependency>
      </exclusions>
    </dependency>
  </dependencies>
</project>
XML;
$pomE = vg_ingest_parse_pom_deps('pom.xml|' . base64_encode($pomExcl));
$eq('pom exclusions: 1건만(부모)', count($pomE['rows']), 1);
$eq('pom exclusions: excluded 좌표는 없음', $pomE['rows'][0][1], 'org.example:demo-a');

// 한 줄 <parent>groupId:artifactId:version</parent> — 최상위 <dependencies> 로 오인하면 안 된다.
$pomParentOneLine = <<<'XML'
<project>
  <parent>org.example:parent-pom:2.0.0</parent>
  <dependencies>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>demo-c</artifactId>
      <version>1.0.0</version>
    </dependency>
  </dependencies>
</project>
XML;
$pomP1 = vg_ingest_parse_pom_deps('pom.xml|' . base64_encode($pomParentOneLine));
$eq('pom 한줄 parent: 부모 좌표 안 섞임(1건)', count($pomP1['rows']), 1);
$eq('pom 한줄 parent: 실제 dependency 만', $pomP1['rows'][0][1], 'org.example:demo-c');

// 여러 줄 <parent><groupId>…</groupId>…</parent> — 역시 dependencies 로 오인하면 안 된다.
$pomParentMultiLine = <<<'XML'
<project>
  <parent>
    <groupId>org.example</groupId>
    <artifactId>parent-pom</artifactId>
    <version>2.0.0</version>
  </parent>
  <dependencies>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>demo-d</artifactId>
      <version>1.0.0</version>
    </dependency>
  </dependencies>
</project>
XML;
$pomP2 = vg_ingest_parse_pom_deps('pom.xml|' . base64_encode($pomParentMultiLine));
$eq('pom 여러줄 parent: 부모 좌표 안 섞임(1건)', count($pomP2['rows']), 1);
$eq('pom 여러줄 parent: 실제 dependency 만', $pomP2['rows'][0][1], 'org.example:demo-d');

// dependencyManagement 는 버전 선언일 뿐 실제 의존이 아니다.
$pomDepMgmt = <<<'XML'
<project>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.managed</groupId>
        <artifactId>bom-only</artifactId>
        <version>1.0.0</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>demo-e</artifactId>
      <version>1.0.0</version>
    </dependency>
  </dependencies>
</project>
XML;
$pomDM = vg_ingest_parse_pom_deps('pom.xml|' . base64_encode($pomDepMgmt));
$eq('pom dependencyManagement 제외: 1건만', count($pomDM['rows']), 1);
$eq('pom dependencyManagement 제외: 실제 dependency 만', $pomDM['rows'][0][1], 'org.example:demo-e');

// test/provided 스코프는 런타임 의존이 아니다. 프로퍼티(${...}) 미해석 버전도 버린다.
$pomSkip = <<<'XML'
<project>
  <dependencies>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>test-only</artifactId>
      <version>1.0.0</version>
      <scope>test</scope>
    </dependency>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>provided-only</artifactId>
      <version>1.0.0</version>
      <scope>provided</scope>
    </dependency>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>unresolved-prop</artifactId>
      <version>${some.version}</version>
    </dependency>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>keep-me</artifactId>
      <version>1.0.0</version>
    </dependency>
  </dependencies>
</project>
XML;
$pomSk = vg_ingest_parse_pom_deps('pom.xml|' . base64_encode($pomSkip));
$eq('pom test/provided/미해석 프로퍼티 제외: 1건만', count($pomSk['rows']), 1);
$eq('pom test/provided/미해석 프로퍼티 제외: 남는 것', $pomSk['rows'][0][1], 'org.example:keep-me');

// 문자셋 위반(공백 등) 좌표는 저장 전 거부한다.
$pomBadChars = <<<'XML'
<project>
  <dependencies>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>bad name; rm -rf</artifactId>
      <version>1.0.0</version>
    </dependency>
  </dependencies>
</project>
XML;
$pomBad = vg_ingest_parse_pom_deps('pom.xml|' . base64_encode($pomBadChars));
$eq('pom 문자셋 위반 거부', count($pomBad['rows']), 0);

// 상한 초과 — 나머지는 버리고 dropped 로 알린다(조용히 자르지 않는다).
$manyDeps = "<project>\n<dependencies>\n";
for ($i = 0; $i < VG_POM_DEP_EDGE_MAX + 50; $i++) {
    $manyDeps .= "<dependency><groupId>org.example</groupId><artifactId>gen-$i</artifactId><version>1.0.$i</version></dependency>\n";
}
$manyDeps .= "</dependencies>\n</project>";
$pomMany = vg_ingest_parse_pom_deps('pom.xml|' . base64_encode($manyDeps));
$eq('pom 상한: rows 는 상한까지만', count($pomMany['rows']), VG_POM_DEP_EDGE_MAX);
$eq('pom 상한: 초과분은 dropped 로 집계', $pomMany['dropped'], 50);

// 여러 pom.xml 라인을 합쳐도 동작(경로 다르지만 동일 좌표는 dedup)
$multiFilePom = 'pom.xml|' . base64_encode($pomOk) . "\n" . 'sub/pom.xml|' . base64_encode($pomOk);
$pomMulti = vg_ingest_parse_pom_deps($multiFilePom);
$eq('pom 여러 파일 dedup: 동일 좌표는 1건', count($pomMulti['rows']), 2);

// 깨진 XML은 예외 없이 그냥 건너뛴다.
$pomBrokenXml = vg_ingest_parse_pom_deps('pom.xml|' . base64_encode('<project><dependencies><dependency>'));
$eq('pom 깨진 XML 은 조용히 스킵', count($pomBrokenXml['rows']), 0);

// ── 패키지 의존성 그래프: SBOM CycloneDX dependencies[] ─────────────────────
$cdxDeps = json_encode([
    'bomFormat' => 'CycloneDX',
    'metadata' => ['component' => ['name' => 'my-app', 'version' => '1.0.0', 'bom-ref' => 'root-ref', 'purl' => 'pkg:npm/my-app@1.0.0']],
    'components' => [
        ['name' => 'compA', 'version' => '1.0.0', 'purl' => 'pkg:npm/compA@1.0.0', 'bom-ref' => 'a-ref'],
        ['name' => 'compB', 'version' => '2.0.0', 'purl' => 'pkg:npm/compB@2.0.0', 'bom-ref' => 'b-ref'],
    ],
    'dependencies' => [
        ['ref' => 'root-ref', 'dependsOn' => ['a-ref']],
        ['ref' => 'a-ref', 'dependsOn' => ['b-ref']],
    ],
]);
$sbomDeps = vg_ingest_parse_sbom('ctr-dep|cyclonedx|' . base64_encode($cdxDeps));
$eq('SBOM deps: 루트 표식 + 직접1 + 전이1 = 3건', count($sbomDeps['deps']), 3);
$byChild = [];
foreach ($sbomDeps['deps'] as $d) { $byChild[$d[5]] = $d; }
$eq('SBOM deps: 루트 표식 행(parent NULL)', array_key_exists('my-app', $byChild) ? $byChild['my-app'][1] : 'MISSING', null);
$eq('SBOM deps: 루트→compA 직접(parent=root)', $byChild['compA'][1] ?? null, 'npm');
$eq('SBOM deps: compA→compB 전이(parent=compA)', $byChild['compB'][2] ?? null, 'compA');

// ref 를 못 찾으면(components 목록에 없는 컴포넌트) 그 엣지는 버린다 — 정체불명 부모/자식을 안 남긴다.
$cdxDangling = json_encode(['bomFormat' => 'CycloneDX', 'components' => [
    ['name' => 'compA', 'version' => '1.0.0', 'purl' => 'pkg:npm/compA@1.0.0', 'bom-ref' => 'a-ref'],
], 'dependencies' => [
    ['ref' => 'a-ref', 'dependsOn' => ['unknown-ref']],
]]);
$sbomDangling = vg_ingest_parse_sbom('ctr-dangling|cyclonedx|' . base64_encode($cdxDangling));
$eq('SBOM deps: 알 수 없는 ref 는 버림', count($sbomDangling['deps']), 0);

// 같은 엣지 중복은 dedup, 상한 초과는 dropped 로 집계.
$manyComponents = []; $manyEdges = [];
for ($i = 0; $i < VG_SBOM_DEP_EDGE_MAX + 20; $i++) {
    $manyComponents[] = ['name' => "gen$i", 'version' => '1.0.0', 'purl' => "pkg:npm/gen$i@1.0.0", 'bom-ref' => "g$i-ref"];
    if ($i > 0) { $manyEdges[] = ['ref' => 'g0-ref', 'dependsOn' => ["g$i-ref"]]; }
}
// dependsOn 을 한 엣지 안에 몰아 넣으면 g0-ref 항목 하나로 표현할 수 있다 — 실제 배열 형태로 재구성.
$manyDependsOn = array_map(static fn($e) => $e['dependsOn'][0], $manyEdges);
$cdxManyDeps = json_encode(['bomFormat' => 'CycloneDX', 'components' => $manyComponents,
    'dependencies' => [['ref' => 'g0-ref', 'dependsOn' => $manyDependsOn]]]);
$sbomMany = vg_ingest_parse_sbom('ctr-many|cyclonedx|' . base64_encode($cdxManyDeps));
$eq('SBOM deps 상한: 상한까지만 저장', count($sbomMany['deps']), VG_SBOM_DEP_EDGE_MAX);
$eq('SBOM deps 상한: 초과분은 dropped 로 집계', $sbomMany['deps_dropped'], 19);

// ── SPDX relationships → 의존 엣지 (이슈 #516) ─────────────────────────────
//   CycloneDX 와 **같은 규약**을 내야 한다: 루트 표식행은 parent 3필드 전부 NULL,
//   루트를 parent 로 갖는 엣지의 child 가 직접 의존, 그 아래가 전이.
$spdxPkg = static fn(string $id, string $name, string $ver, string $type = 'npm') => [
    'SPDXID' => $id, 'name' => $name, 'versionInfo' => $ver,
    'externalRefs' => [['referenceType' => 'purl', 'referenceLocator' => "pkg:$type/$name@$ver"]],
];
$spdxRel = static fn(string $from, string $type, string $to) => [
    'spdxElementId' => $from, 'relationshipType' => $type, 'relatedSpdxElement' => $to,
];

$spdxDeps = json_encode(['spdxVersion' => 'SPDX-2.3', 'SPDXID' => 'SPDXRef-DOCUMENT',
    'packages' => [
        $spdxPkg('SPDXRef-Pkg-root', 'my-app', '1.0.0'),
        $spdxPkg('SPDXRef-Pkg-a', 'compA', '1.0.0'),
        $spdxPkg('SPDXRef-Pkg-b', 'compB', '2.0.0'),
        $spdxPkg('SPDXRef-Pkg-c', 'compC', '3.0.0'),
        $spdxPkg('SPDXRef-Pkg-t', 'compTest', '4.0.0'),
    ],
    'relationships' => [
        $spdxRel('SPDXRef-DOCUMENT', 'DESCRIBES', 'SPDXRef-Pkg-root'),   // 루트 표식(엣지 아님)
        $spdxRel('SPDXRef-Pkg-root', 'DEPENDS_ON', 'SPDXRef-Pkg-a'),     // 직접
        $spdxRel('SPDXRef-Pkg-a', 'DEPENDS_ON', 'SPDXRef-Pkg-b'),        // 전이
        $spdxRel('SPDXRef-Pkg-c', 'DEPENDENCY_OF', 'SPDXRef-Pkg-a'),     // 역방향 → parent=compA
        $spdxRel('SPDXRef-Pkg-root', 'CONTAINS', 'SPDXRef-Pkg-t'),       // 채택 안 함
        $spdxRel('SPDXRef-Pkg-t', 'TEST_DEPENDENCY_OF', 'SPDXRef-Pkg-root'), // 채택 안 함
    ],
]);
$sd = vg_ingest_parse_sbom('ctr-spdx|spdx|' . base64_encode($spdxDeps));
$eq('SPDX deps: 루트 표식 + 직접1 + 전이2 = 4건', count($sd['deps']), 4);
$sdByChild = [];
foreach ($sd['deps'] as $d) { $sdByChild[$d[5]] = $d; }
$eq('SPDX deps: 루트 표식 행(parent NULL)', array_key_exists('my-app', $sdByChild) ? $sdByChild['my-app'][1] : 'MISSING', null);
$eq('SPDX deps: 루트→compA 직접(parent=루트)', $sdByChild['compA'][2] ?? null, 'my-app');
$eq('SPDX deps: compA→compB 전이(parent=compA)', $sdByChild['compB'][2] ?? null, 'compA');
$eq('SPDX deps: DEPENDENCY_OF 는 부모/자식을 뒤집는다', $sdByChild['compC'][2] ?? null, 'compA');
$eq('SPDX deps: CONTAINS/TEST_DEPENDENCY_OF 는 엣지가 아니다', isset($sdByChild['compTest']) ? 'EDGE' : 'none', 'none');
$eq('SPDX deps: 되짚을 수 있는 관계뿐이면 unresolved 0', $sd['deps_unresolved'], 0);

// documentDescribes[] 만으로도 루트 표식행이 나와야 한다(DESCRIBES 관계를 안 쓰는 도구 대응).
$spdxDescribes = json_encode(['spdxVersion' => 'SPDX-2.3',
    'documentDescribes' => ['SPDXRef-Pkg-root'],
    'packages' => [$spdxPkg('SPDXRef-Pkg-root', 'my-app', '1.0.0')],
    'relationships' => [],
]);
$sdDesc = vg_ingest_parse_sbom('ctr-spdx-desc|spdx|' . base64_encode($spdxDescribes));
$eq('SPDX deps: documentDescribes 로도 루트 표식 1건', count($sdDesc['deps']), 1);
$eq('SPDX deps: documentDescribes 루트는 parent NULL', isset($sdDesc['deps'][0]) ? $sdDesc['deps'][0][1] : 'MISSING', null);

// relationships 가 아예 없는 문서 — 패키지는 그대로 뽑되 엣지는 0건이어야 한다(에러 아님).
$spdxNoRel = json_encode(['spdxVersion' => 'SPDX-2.3',
    'packages' => [$spdxPkg('SPDXRef-Pkg-a', 'compA', '1.0.0')]]);
$sdNoRel = vg_ingest_parse_sbom('ctr-spdx-norel|spdx|' . base64_encode($spdxNoRel));
$eq('SPDX deps: relationships 없으면 엣지 0건', count($sdNoRel['deps']), 0);
$eq('SPDX deps: relationships 없어도 패키지는 뽑는다', count($sdNoRel['packages']), 1);

// 알 수 없는 SPDXRef(packages[] 에 없음·외부문서 참조·문서 자신)는 엣지를 버리고 **집계**한다.
$spdxDangling = json_encode(['spdxVersion' => 'SPDX-2.3',
    'packages' => [$spdxPkg('SPDXRef-Pkg-a', 'compA', '1.0.0')],
    'relationships' => [
        $spdxRel('SPDXRef-Pkg-a', 'DEPENDS_ON', 'SPDXRef-Pkg-없음'),
        $spdxRel('DocumentRef-ext:SPDXRef-Pkg-x', 'DEPENDS_ON', 'SPDXRef-Pkg-a'),
        $spdxRel('SPDXRef-Pkg-a', 'DEPENDS_ON', 'NOASSERTION'),
    ],
]);
$sdDangling = vg_ingest_parse_sbom('ctr-spdx-dangling|spdx|' . base64_encode($spdxDangling));
$eq('SPDX deps: 알 수 없는 SPDXRef 는 버림', count($sdDangling['deps']), 0);
$eq('SPDX deps: 버린 건수를 조용히 삼키지 않고 집계', $sdDangling['deps_unresolved'], 3);

// 순환 참조 — 엣지 저장은 그래프 순회가 아니므로 양방향 2건이 그대로 남고 멈춰야 한다(무한루프 없음).
$spdxCycle = json_encode(['spdxVersion' => 'SPDX-2.3',
    'packages' => [$spdxPkg('SPDXRef-Pkg-a', 'compA', '1.0.0'), $spdxPkg('SPDXRef-Pkg-b', 'compB', '2.0.0')],
    'relationships' => [
        $spdxRel('SPDXRef-Pkg-a', 'DEPENDS_ON', 'SPDXRef-Pkg-b'),
        $spdxRel('SPDXRef-Pkg-b', 'DEPENDS_ON', 'SPDXRef-Pkg-a'),
        $spdxRel('SPDXRef-Pkg-b', 'DEPENDENCY_OF', 'SPDXRef-Pkg-a'),   // 첫 엣지와 같은 사실 → dedup
    ],
]);
$sdCycle = vg_ingest_parse_sbom('ctr-spdx-cycle|spdx|' . base64_encode($spdxCycle));
$eq('SPDX deps: 순환 참조는 양방향 2건(중복 표기는 dedup)', count($sdCycle['deps']), 2);

// npm 스코프 패키지(@scope/pkg) — 이름을 **잘라먹지 않는다**. 지금은 양쪽 경로 모두
//   vg_pkg_ident_valid('@…') 에서 걸려 엣지가 통째로 버려진다(미해결 이슈 #481, 이번 스코프 밖).
//   여기서 못박는 것은 "SPDX 가 CycloneDX 와 **같게** 동작하고, 잘린 이름이 저장되지 않는다" 다 —
//   #481 을 고치면 두 경로가 함께 바뀌므로 이 비교는 그때도 유효하다.
$scopedCdx = json_encode(['bomFormat' => 'CycloneDX',
    'metadata' => ['component' => ['name' => 'my-app', 'version' => '1.0.0', 'bom-ref' => 'root-ref', 'purl' => 'pkg:npm/my-app@1.0.0']],
    'components' => [['name' => 'pkg', 'version' => '1.0.0', 'bom-ref' => 's-ref', 'purl' => 'pkg:npm/%40scope/pkg@1.0.0']],
    'dependencies' => [['ref' => 'root-ref', 'dependsOn' => ['s-ref']]],
]);
$scopedSpdx = json_encode(['spdxVersion' => 'SPDX-2.3',
    'documentDescribes' => ['SPDXRef-Pkg-root'],
    'packages' => [
        $spdxPkg('SPDXRef-Pkg-root', 'my-app', '1.0.0'),
        ['SPDXID' => 'SPDXRef-Pkg-s', 'name' => 'pkg', 'versionInfo' => '1.0.0',
         'externalRefs' => [['referenceType' => 'purl', 'referenceLocator' => 'pkg:npm/%40scope/pkg@1.0.0']]],
    ],
    'relationships' => [$spdxRel('SPDXRef-Pkg-root', 'DEPENDS_ON', 'SPDXRef-Pkg-s')],
]);
$stripCid = static fn(array $deps) => array_map(static fn($d) => array_slice($d, 1), $deps);
$scopedC = vg_ingest_parse_sbom('ctr-scope-c|cyclonedx|' . base64_encode($scopedCdx));
$scopedS = vg_ingest_parse_sbom('ctr-scope-s|spdx|' . base64_encode($scopedSpdx));
$eq('SPDX 스코프 이름: CycloneDX 경로와 같은 엣지를 낸다', $stripCid($scopedS['deps']), $stripCid($scopedC['deps']));
$mangled = array_values(array_filter($scopedS['deps'], static fn($d) => in_array($d[5], ['pkg', 'scope/pkg'], true)));
$eq('SPDX 스코프 이름: 잘린 이름(pkg·scope/pkg)으로 저장하지 않는다', count($mangled), 0);

// ── 호스트 IPv4 (net.interfaces) ───────────────────────────────────────────
//   정규식 파싱은 조용히 틀리기 쉽고, 틀리면 기존 자산이 전부 "섀도우 IT" 로 뜬다.
$ipo = "1: lo    inet 127.0.0.1/8 scope host lo
"
     . "2: eth0    inet 10.3.142.200/24 brd 10.3.142.255 scope global eth0
"
     . "2: eth0    inet6 fe80::1/64 scope link 
"
     . "3: wlan0    inet 192.168.0.5/24 brd 192.168.0.255 scope global dynamic wlan0
"
     . "4: veth9    inet 169.254.10.2/16 scope link veth9";
$ipoRows = vg_ingest_parse_host_addresses($ipo);
$eq('ip -o addr: 전역 IPv4 2건만', count($ipoRows), 2);
$eq('ip -o addr: 인터페이스명', $ipoRows[0][0], 'eth0');
$eq('ip -o addr: IP', $ipoRows[0][1], '10.3.142.200');
$eq('ip -o addr: 두번째 IP', $ipoRows[1][1], '192.168.0.5');

$ifc = "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
"
     . "        inet 10.3.142.200  netmask 255.255.255.0  broadcast 10.3.142.255
"
     . "        inet6 fe80::42:acff:fe11:2  prefixlen 64  scopeid 0x20<link>
"
     . "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
"
     . "        inet 127.0.0.1  netmask 255.0.0.0
"
     . "docker0: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
"
     . "        inet 172.17.0.1  netmask 255.255.0.0  broadcast 172.17.255.255";
$ifcRows = vg_ingest_parse_host_addresses($ifc);
$eq('ifconfig: 루프백 제외 2건', count($ifcRows), 2);
$eq('ifconfig: 인터페이스명', $ifcRows[0][0], 'eth0');
$eq('ifconfig: IP', $ifcRows[0][1], '10.3.142.200');
$eq('ifconfig: docker0', $ifcRows[1][0], 'docker0');
$eq('ifconfig: docker0 IP', $ifcRows[1][1], '172.17.0.1');

// net-tools 1.x (inet addr:) 형식도 같은 결과를 내야 한다.
$ifcOld = "eth0      Link encap:Ethernet  HWaddr 00:11:22:33:44:55
"
        . "          inet addr:10.0.0.7  Bcast:10.0.0.255  Mask:255.255.255.0
"
        . "lo        Link encap:Local Loopback
"
        . "          inet addr:127.0.0.1  Mask:255.0.0.0";
$oldRows = vg_ingest_parse_host_addresses($ifcOld);
$eq('ifconfig 구형: 1건', count($oldRows), 1);
$eq('ifconfig 구형: iface', $oldRows[0][0], 'eth0');
$eq('ifconfig 구형: IP', $oldRows[0][1], '10.0.0.7');

// 같은 IP 가 두 번 나와도 행은 하나 — 유니크 키가 (host_id, ip) 다.
$dup = "2: eth0    inet 10.1.1.1/24 scope global eth0
"
     . "3: eth0:1    inet 10.1.1.1/24 scope global secondary eth0:1";
$eq('중복 IP 는 1건', count(vg_ingest_parse_host_addresses($dup)), 1);

// 값 없음/형식 모름 → 빈 배열. 추측해서 채우지 않는다.
$eq('빈 입력', vg_ingest_parse_host_addresses(''), []);
$eq('알 수 없는 형식', vg_ingest_parse_host_addresses("command not found
<html>nope</html>"), []);
$eq('IPv6 전용', vg_ingest_parse_host_addresses("2: eth0    inet6 2001:db8::1/64 scope global eth0"), []);
$eq('형식만 그럴듯한 값', vg_ingest_parse_host_addresses("2: eth0    inet 10.3.142.300/24 scope global eth0"), []);

// ── content_hash: 의존성 그래프가 바뀌면 해시도 바뀌어야 한다 ───────────────
//   안 넣으면 그래프만 바뀐 재전송이 "변경 없음"으로 스킵돼 tb_package_dependency 가
//   영구히 비게 된다(PR#399 리뷰 지적 — 이번 재작업의 핵심 반영사항 중 하나).
$withPomDeps = static fn(array $pomDepRows) => vg_ingest_content_hash(
    [], 'rpm', [], [], [], [], [], [], [],
    '5.14.0', '5.14.0', 0, ['distro_id' => 'rocky'], ['kernel_release' => '5.14.0'], [], $pomDepRows
);
if ($withPomDeps([]) === $withPomDeps([['maven', 'org.example:demo', '1.0.0']])) {
    printf("  ✗ [해시: pom 의존성 그래프가 다르면 달라야 함] 두 해시가 같음\n");
    $fail++;
}
$withSbomDeps = static fn(array $sbomDepRows) => vg_ingest_content_hash(
    [], 'rpm', [], [], [], [], [], [], [],
    '5.14.0', '5.14.0', 0, ['distro_id' => 'rocky'], ['kernel_release' => '5.14.0'], [], [], $sbomDepRows
);
if ($withSbomDeps([]) === $withSbomDeps([['ctr-a', 'npm', 'root', '1.0.0', 'npm', 'child', '2.0.0']])) {
    printf("  ✗ [해시: SBOM 의존성 그래프가 다르면 달라야 함] 두 해시가 같음\n");
    $fail++;
}

if ($fail === 0) {
    echo "ingest_parse: 전체 통과\n";
    exit(0);
}
printf("ingest_parse: %d건 실패\n", $fail);
exit(1);
