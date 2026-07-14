<?php
declare(strict_types=1);

/**
 * kernelcve 단위 테스트 — 커널 CNA 레코드 파서(feeds/kcve.php)와 업스트림 판정(src/kernelcve.php).
 *   네트워크·DB 없이 돈다. tar 스캐너는 테스트 안에서 tar.gz 를 만들어 검사한다.
 *
 * 왜 중요한가: 이 판정이 **억제**를 만든다. 느슨하면 진짜 커널 취약점을 "고쳐졌다"고 지운다(미탐).
 *   특히 커널은 스트림(6.1.y · 6.18.y)마다 수정 버전이 다르고, 내 스트림에 수정본이 없으면
 *   "다른 스트림에서 고쳐졌다"는 건 나와 무관하다 — 그걸 fixed 로 읽으면 조용히 취약점이 사라진다.
 *
 * 실행: docker run --rm -v "$PWD:/w" -w /w php:8.3-cli php tests/kernelcve_test.php
 */

require_once __DIR__ . '/../server/src/feeds.php';       // VgFeedConnector 계약 + kcve 로드
require_once __DIR__ . '/../server/src/kernelcve.php';

$fail = 0;
$eq = static function (string $label, $got, $want) use (&$fail): void {
    if ($got !== $want) {
        printf("  ✗ [%s] 기대 %s, 실제 %s\n", $label, var_export($want, true), var_export($got, true));
        $fail++;
    }
};

// ── uname → 업스트림 버전 ──────────────────────────────────────────────────
$eq('라즈베리 커널',   vg_kernel_upstream_ver('6.18.34+rpt-rpi-2712'), '6.18.34');
$eq('데비안 커널',     vg_kernel_upstream_ver('6.1.0-28-arm64'),       '6.1.0');
$eq('우분투 커널',     vg_kernel_upstream_ver('5.15.0-125-generic'),   '5.15.0');
$eq('두 자리도 허용',  vg_kernel_upstream_ver('6.18-rc1'),             '6.18');
$eq('버전 아니면 빈값', vg_kernel_upstream_ver('unknown'),             '');

// ── 버전 비교(자리수가 달라도 맞아야 한다) ────────────────────────────────
$eq('6.18 < 6.18.34',    vg_kernel_ver_cmp('6.18', '6.18.34') < 0,   true);
$eq('6.18.34 > 6.6.17',  vg_kernel_ver_cmp('6.18.34', '6.6.17') > 0, true);  // 문자열 비교면 틀린다
$eq('6.1.78 == 6.1.78',  vg_kernel_ver_cmp('6.1.78', '6.1.78'),      0);

// ── 판정 ──────────────────────────────────────────────────────────────────
$streams = ['5.15' => '5.15.149', '6.1' => '6.1.78', '6.6' => '6.6.17'];

$eq('내 스트림 수정본 이상 → fixed',
    vg_kernel_cve_verdict('6.5', '6.8', $streams + ['6.18' => '6.18.20'], '6.18.34'), 'fixed');
$eq('내 스트림 수정본 미만 → vulnerable',
    vg_kernel_cve_verdict('6.5', '6.8', $streams + ['6.18' => '6.18.40'], '6.18.34'), 'vulnerable');
$eq('내 스트림에 수정본이 없고 메인라인 수정본보다 낮으면 vulnerable',
    vg_kernel_cve_verdict('6.3', '7.0', ['6.19' => '6.19.7'], '6.18.34'), 'vulnerable');
$eq('내 스트림에 수정본이 없어도 메인라인 수정본 이상이면 fixed',
    vg_kernel_cve_verdict('6.5', '6.8', $streams, '6.18.34'), 'fixed');
$eq('취약 코드가 들어오기 전 버전 → fixed(해당 없음)',
    vg_kernel_cve_verdict('6.5', '6.8', $streams, '5.4.100'), 'fixed');
$eq('데이터가 없으면 unknown(억제 금지)',
    vg_kernel_cve_verdict(null, null, [], '6.18.34'), 'unknown');
$eq('구동 커널 버전을 모르면 unknown',
    vg_kernel_cve_verdict('6.5', '6.8', $streams, ''), 'unknown');

// 다른 스트림에서만 고쳐진 것을 내 것으로 읽으면 안 된다(미탐 유발 1순위).
$eq('6.1.y 만 고친 CVE 를 6.6.5 가 fixed 로 읽지 않는다',
    vg_kernel_cve_verdict('6.0', null, ['6.1' => '6.1.78'], '6.6.5'), 'unknown');

// ── CVE 레코드 파싱 ────────────────────────────────────────────────────────
$rec = vg_kcve_parse_record(json_encode([
    'cveMetadata' => ['cveId' => 'CVE-2024-26581'],
    'containers'  => ['cna' => ['affected' => [
        // git 해시 블록 — 우리 소관이 아니다(버전이 아니라 커밋).
        ['defaultStatus' => 'unaffected', 'versions' => [
            ['version' => '8284a79136c3', 'lessThan' => 'c60d252949ca', 'status' => 'affected', 'versionType' => 'git'],
        ]],
        ['defaultStatus' => 'affected', 'versions' => [
            ['version' => '6.5', 'status' => 'affected'],
            ['version' => '0', 'lessThan' => '6.5', 'status' => 'unaffected', 'versionType' => 'semver'],
            ['version' => '6.1.78', 'lessThanOrEqual' => '6.1.*', 'status' => 'unaffected', 'versionType' => 'semver'],
            ['version' => '6.6.17', 'lessThanOrEqual' => '6.6.*', 'status' => 'unaffected', 'versionType' => 'semver'],
            ['version' => '6.8', 'lessThanOrEqual' => '*', 'status' => 'unaffected', 'versionType' => 'original_commit_for_fix'],
        ]],
    ]]],
], JSON_UNESCAPED_SLASHES));

$eq('CVE ID',            $rec['cve'] ?? null,        'CVE-2024-26581');
$eq('최초 취약 버전',    $rec['introduced'] ?? null, '6.5');
$eq('메인라인 수정본',   $rec['mainline'] ?? null,   '6.8');
$eq('스트림 2개',        $rec['streams'] ?? [],      ['6.1' => '6.1.78', '6.6' => '6.6.17']);
$eq('커밋 해시는 안 들어온다', isset($rec['streams']['8284a79136c3']), false);

$eq('빈 JSON 은 null', vg_kcve_parse_record('{}'), null);

// ── tar 스캐너(gz 스트림 위에서 필요한 항목만 뽑는다) ──────────────────────
$tarEntry = static function (string $name, string $body): string {
    $hdr = str_pad($name, 100, "\0");                  // 이름
    $hdr .= str_pad('0000644', 8, "\0");               // mode
    $hdr .= str_pad('0000000', 8, "\0") . str_pad('0000000', 8, "\0");   // uid/gid
    $hdr .= str_pad(sprintf('%011o', strlen($body)), 12, "\0");           // size(8진수)
    $hdr .= str_pad('00000000000', 12, "\0");          // mtime
    $hdr .= str_repeat(' ', 8);                        // checksum(자리만 — 우리는 안 본다)
    $hdr .= '0';                                       // typeflag: 일반 파일
    $hdr  = str_pad($hdr, 512, "\0");
    return $hdr . $body . str_repeat("\0", (512 - (strlen($body) % 512)) % 512);
};

$json = json_encode([
    'cveMetadata' => ['cveId' => 'CVE-2025-0001'],
    'containers'  => ['cna' => ['affected' => [
        ['defaultStatus' => 'affected', 'versions' => [
            ['version' => '6.10', 'status' => 'affected'],
            ['version' => '6.12.5', 'lessThanOrEqual' => '6.12.*', 'status' => 'unaffected', 'versionType' => 'semver'],
        ]],
    ]]],
]);
$tar  = $tarEntry('vulns-master/cve/published/2025/CVE-2025-0001.json', $json);
$tar .= $tarEntry('vulns-master/cve/published/2025/CVE-2025-0001.mbox', str_repeat('x', 1000));  // 건너뛴다
$tar .= $tarEntry('vulns-master/README', 'hello');                                                // 건너뛴다
$tar .= str_repeat("\0", 1024);

$gz = tempnam(sys_get_temp_dir(), 'vgk') . '.tar.gz';
file_put_contents($gz, gzencode($tar));

$got = [];
$n   = vg_kcve_scan_tar($gz, static function (string $j) use (&$got): void { $got[] = vg_kcve_parse_record($j); });
@unlink($gz);

$eq('json 항목만 넘어온다', $n, 1);
$eq('mbox 를 건너뛰고도 다음 항목을 제대로 읽는다', $got[0]['cve'] ?? null, 'CVE-2025-0001');
$eq('스트림 수정본', $got[0]['streams'] ?? [], ['6.12' => '6.12.5']);

if ($fail === 0) {
    echo "kernelcve_test: 통과\n";
    exit(0);
}
printf("kernelcve_test: %d건 실패\n", $fail);
exit(1);
