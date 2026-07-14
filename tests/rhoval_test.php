<?php
declare(strict_types=1);

/**
 * rhoval 단위 테스트 — RHEL 계열 OVAL 파서(feeds/rhoval.php)와 백포트 판정(src/vendorerrata.php).
 *   네트워크·DB 없이 픽스처(tests/fixtures/rhel-oval/sample.oval.xml)로 돈다.
 *
 * 왜 이 검사가 중요한가: 이 판정이 **억제**를 만든다. 느슨하면 이미 고친 CVE 가 남고(오탐),
 *   빡빡하면 진짜 취약점을 "고쳐졌다"고 지운다(미탐 — 훨씬 나쁘다).
 *   특히 RHEL 은 같은 (패키지, CVE) 가 마이너 스트림마다 다른 EVR 로 고쳐진다(el9_2 · el9_4).
 *
 * 실행: docker run --rm -v "$PWD:/w" -w /w php:8.3-cli php tests/rhoval_test.php
 */

require_once __DIR__ . '/../server/src/feeds.php';       // VgFeedConnector 계약 + rhoval 로드

$fail = 0;
$eq = static function (string $label, $got, $want) use (&$fail): void {
    if ($got !== $want) {
        printf("  ✗ [%s] 기대 %s, 실제 %s\n", $label, var_export($want, true), var_export($got, true));
        $fail++;
    }
};

// ── OVAL 파싱 ──────────────────────────────────────────────────────────────
$rows = vg_rhoval_parse(__DIR__ . '/fixtures/rhel-oval/sample.oval.xml');

// RHSA-2024:0001 → CVE 2개 × openssl 1개 = 2행, RHSA-2024:0002 → 1행. 플랫폼 검사는 버려진다.
$eq('행 3개(플랫폼 검사는 버림)', count($rows), 3);

$byCve = [];
foreach ($rows as $r) { $byCve[$r['cve']][] = $r; }

$eq('CVE-2024-1111 은 두 스트림에서 고쳐졌다', count($byCve['CVE-2024-1111'] ?? []), 2);
$eq('CVE-2024-2222 는 한 번',                  count($byCve['CVE-2024-2222'] ?? []), 1);
$eq('패키지명은 object 에서 온다',             $rows[0]['pkg'], 'openssl');
$eq('조치 EVR 은 state 에서 온다',             $rows[0]['evr'], '0:3.0.7-24.el9_2');
$eq('권고 ID',                                 $rows[0]['advisory'], 'RHSA-2024:0001');
$eq('심각도',                                  $rows[0]['severity'], 'Important');

// redhat-release(플랫폼 검사)는 조치안이 아니므로 어떤 행에도 없어야 한다 — 있으면 오탐 폭탄이다.
$pkgs = array_unique(array_column($rows, 'pkg'));
$eq('플랫폼 패키지는 안 들어온다', in_array('redhat-release', $pkgs, true), false);

// ── 스트림 판정 ────────────────────────────────────────────────────────────
$fixes = [
    ['evr' => '0:3.0.7-24.el9_2', 'advisory' => 'RHSA-2024:0001'],
    ['evr' => '0:3.0.7-27.el9_4', 'advisory' => 'RHSA-2024:0002'],
];

// 9.2 스트림 서버: 자기 스트림의 조치본(24.el9_2)을 깔았으면 고쳐진 것이다.
//   여기서 9.4 의 EVR(27.el9_4)과 비교하면 "아직 취약"으로 오판한다 → 오탐.
$eq('같은 스트림 조치본 → 고쳐짐',
    vg_errata_is_fixed('0:3.0.7-24.el9_2', $fixes) !== null, true);
$eq('같은 스트림 미조치 → 아직 취약',
    vg_errata_is_fixed('0:3.0.7-23.el9_2', $fixes), null);

// 9.4 스트림 서버.
$eq('9.4 조치본 → 고쳐짐',   vg_errata_is_fixed('0:3.0.7-27.el9_4', $fixes) !== null, true);
$eq('9.4 미조치 → 취약',     vg_errata_is_fixed('0:3.0.7-25.el9_4', $fixes), null);

// 스트림이 없는 설치본(el9) — 같은 스트림 후보가 없으니 **가장 높은 조치안**과 비교한다(보수적).
$eq('스트림 불명 + 낮은 버전 → 취약', vg_errata_is_fixed('0:3.0.7-20.el9', $fixes), null);
$eq('스트림 불명 + 높은 버전 → 고쳐짐',
    vg_errata_is_fixed('0:3.0.8-1.el9', $fixes) !== null, true);

$eq('스트림 추출: el9_2', vg_errata_stream('0:3.0.7-24.el9_2'), 'el9_2');
$eq('스트림 추출: el8',   vg_errata_stream('0:1.1.1k-9.el8'),   'el8');
$eq('스트림 없음',        vg_errata_stream('1.2.3'),            '');

// ── 벤더 매핑 — UBI·CentOS 도 RHEL 패키지다 ────────────────────────────────
$eq('rhel → redhat',      vg_errata_vendor('rhel'),      'redhat');
$eq('centos → redhat',    vg_errata_vendor('centos'),    'redhat');
$eq('almalinux',          vg_errata_vendor('almalinux'), 'almalinux');
$eq('ol → oracle',        vg_errata_vendor('ol'),        'oracle');
$eq('rocky 는 OSV 담당',  vg_errata_vendor('rocky'),     null);
$eq('debian 은 대상 아님', vg_errata_vendor('debian'),    null);

// ── Oracle: 전 릴리스가 한 파일이라 <platform> 으로 갈라야 한다 ─────────────
// 안 가르면 OL8 의 조치 EVR(el8_10)로 OL9 를 판정한다 — 억제가 틀어지고 곧 미탐이다.
// 필터 없이 파싱하면 그 파일의 조치안이 다 나온다(ksplice·FIPS 는 어느 경우든 조치안이 아니다).
//   OL8 정의: el8_10 + 섞인 el9 + 모듈러 · OL9 정의: el9_5 = 4행
$ol = vg_rhoval_parse(__DIR__ . '/fixtures/rhel-oval/oracle.oval.xml');
$eq('Oracle 행 4개(ksplice·FIPS 는 빠진다)', count($ol), 4);
$eq('ELSA 권고 ID', $ol[0]['advisory'] ?? null, 'ELSA-2024-5962');
$eq('오라클은 한 파일에 여러 릴리스', vg_rhoval_is_combined('oracle'), true);
$eq('레드햇은 릴리스별 파일',         vg_rhoval_is_combined('redhat'), false);

// **릴리스 필터 경로**(수집이 실제로 쓰는 길). 전 릴리스를 메모리에 이고 가면 죽으므로
//   파서가 대상 릴리스만 붙잡는다. 여기서 걸린 함정: PHP 는 '9' 같은 숫자 문자열 키를 정수로
//   캐스팅해서 in_array('9', array_keys($majors), true) 가 늘 false 였다 → 전 행이 사라졌다.
$ol9 = vg_rhoval_parse(__DIR__ . '/fixtures/rhel-oval/oracle.oval.xml', '9');
$eq('OL9 만 남는다',        count($ol9), 1);
$eq('OL9 조치 EVR(필터)',   $ol9[0]['evr'] ?? null, '0:3.0.7-27.el9_5');
$ol8 = vg_rhoval_parse(__DIR__ . '/fixtures/rhel-oval/oracle.oval.xml', '8');
// el8_10(일반) + module+el8.10.0(모듈러) 2행. ksplice·FIPS·el9 는 버려진다.
$eq('OL8 는 2행(일반 + 모듈러)', count($ol8), 2);
$evrs8 = array_column($ol8, 'evr');
$eq('일반 EVR',   in_array('0:3.0.7-24.el8_10', $evrs8, true), true);
// 모듈러 EVR 은 `.el8` 이 아니라 `+el8` 이다 — `\.el8` 로만 거르면 python39·nodejs 가 통째로 사라진다.
$eq('모듈러 EVR', in_array('0:3.9.19-7.module+el8.10.0+90000+abcd', $evrs8, true), true);

// Ksplice 전용 권고를 조치안으로 쓰면 **정상 최신 시스템이 통째로 취약**해진다:
//   설치 0:3.0.7-30.el8_10 < 조치 2:3.0.7-24.0.1.ksplice2.el8 (epoch 가 우선한다)
//   실측 oraclelinux:8 — glibc 계열 90건이 오탐으로 남았다. Trivy 도 같은 이유로 제외한다.
$eq('ksplice EVR 은 조치안이 아니다',
    array_filter(array_merge($ol8, $ol9), static fn($r) => stripos($r['evr'], 'ksplice') !== false), []);
$eq('FIPS EVR(epoch 10)도 조치안이 아니다',
    array_filter(array_merge($ol8, $ol9), static fn($r) => stripos($r['evr'], '_fips') !== false), []);
// 같은 권고에 섞인 다른 릴리스 EVR(el9)이 OL8 행에 들어오면, 설치본(el8)이 영원히 미조치가 된다.
$eq('OL8 행에 el9 EVR 이 안 들어온다',
    array_filter($ol8, static fn($r) => strpos($r['evr'], '.el9') !== false), []);
$eq('없는 릴리스는 0행',    count(vg_rhoval_parse(__DIR__ . '/fixtures/rhel-oval/oracle.oval.xml', '7')), 0);

// 릴리스별 파일(레드햇)의 정의엔 platform 이 없어도 무해해야 한다.
$eq('레드햇 행엔 majors 가 비어 있다', $rows[0]['majors'], []);

if ($fail === 0) {
    echo "rhoval: 모든 검사 통과\n";
    exit(0);
}
printf("rhoval: %d 개 실패\n", $fail);
exit(1);
