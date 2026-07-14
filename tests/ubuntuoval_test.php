<?php
declare(strict_types=1);

/**
 * ubuntuoval 단위 테스트 — 우분투 보안 OVAL 파서(feeds/ubuntuoval.php)와 코드명 매핑.
 *   네트워크·DB 없이 픽스처(tests/fixtures/ubuntu-oval/sample.oval.xml)로 돈다.
 *
 * 왜 중요한가: 이 데이터가 **억제와 조치 불가 표시를 동시에** 만든다.
 *   · state 있는 테스트  → 조치 EVR. 잘못 읽으면 이미 고친 걸 취약이라 하거나(오탐),
 *                          안 고친 걸 고쳤다 한다(미탐).
 *   · state 없는 테스트  → "아직 수정본 없음". **이걸 버리면 조치 불가가 통째로 사라진다.**
 *   · dpkg 아닌 테스트(커널 uname) → 우리 판정 대상이 아니다. 들어오면 오탐.
 *
 * 실행: docker run --rm -v "$PWD:/w" -w /w php:8.3-cli php tests/ubuntuoval_test.php
 */

require_once __DIR__ . '/../server/src/feeds.php';       // VgFeedConnector 계약 + ubuntuoval 로드

$fail = 0;
$eq = static function (string $label, $got, $want) use (&$fail): void {
    if ($got !== $want) {
        printf("  ✗ [%s] 기대 %s, 실제 %s\n", $label, var_export($want, true), var_export($got, true));
        $fail++;
    }
};

$rows = vg_ubuntu_oval_parse(__DIR__ . '/fixtures/ubuntu-oval/sample.oval.xml');

// perl 바이너리 3개(고쳐짐) + shadow 바이너리 2개(미수정) = 5행. 커널 uname·플랫폼 검사는 버린다.
$eq('행 5개(uname·플랫폼 검사는 버림)', count($rows), 5);

$byPkg = [];
foreach ($rows as $r) { $byPkg[$r['pkg']] = $r; }

$eq('소스가 아니라 **바이너리** 이름으로 펼친다', isset($byPkg['perl-base']), true);
$eq('조치 EVR',        $byPkg['perl-base']['evr'] ?? null, '0:5.38.2-3.2ubuntu0.1');
$eq('CVE',             $byPkg['perl-base']['cve'] ?? null, 'CVE-2024-56406');
$eq('심각도',          $byPkg['libperl5.38t64']['severity'] ?? null, 'Medium');

// state 가 없는 테스트 = 아직 수정본 없음 → evr 이 null 로 남아야 한다(버리면 조치 불가가 미탐).
$eq('미수정 CVE 는 evr=null', array_key_exists('evr', $byPkg['passwd'] ?? []) ? $byPkg['passwd']['evr'] : 'X', null);
$eq('미수정 CVE 도 행으로 남는다', $byPkg['login']['cve'] ?? null, 'CVE-2024-99999');

// 커널 uname 테스트만 가진 정의는 dpkg 행이 없다 → 어떤 패키지에도 안 붙어야 한다.
$cves = array_column($rows, 'cve');
$eq('uname 검사 CVE 는 안 들어온다', in_array('CVE-2024-11111', $cves, true), false);

// ── 코드명 매핑 — OVAL 은 코드명으로만 배포된다 ────────────────────────────
$eq('24.04 → noble', vg_ubuntu_codename('24.04'), 'noble');
$eq('22.04 → jammy', vg_ubuntu_codename('22.04'), 'jammy');
$eq('모르는 버전 → 빈값(억제 안 함)', vg_ubuntu_codename('30.04'), '');
$eq('빈값 → 빈값', vg_ubuntu_codename(null), '');

if ($fail === 0) {
    echo "ubuntuoval_test: 통과\n";
    exit(0);
}
printf("ubuntuoval_test: %d건 실패\n", $fail);
exit(1);
