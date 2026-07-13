<?php
declare(strict_types=1);

/**
 * distro 단위 테스트 — 패키지 출처·커널 판정(server/src/distro.php).
 *   이 판정 하나가 findings 수천 건을 좌우한다(커널 소스 21개 패키지 × CVE 369건 = LOW 7,925).
 *   DB 없이 도는 순수 함수라 스모크 앞단에서 돌린다.
 *
 * 실행:
 *   docker run --rm -v "$PWD:/w" -w /w php:8.3-cli php tests/distro_test.php
 */

require_once __DIR__ . '/../server/src/distro.php';

$fail = 0;
$eq = static function (string $label, $got, $want) use (&$fail): void {
    if ($got !== $want) {
        printf("  ✗ [%s] 기대 %s, 실제 %s\n", $label, var_export($want, true), var_export($got, true));
        $fail++;
    }
};

// ── 커널 소스 판정 ─────────────────────────────────────────────────────────
$eq('데비안 커널 소스',   vg_is_kernel_source('linux'),      true);
$eq('RHEL 커널 소스',     vg_is_kernel_source('kernel'),     true);
$eq('linux-base 는 별개 소스', vg_is_kernel_source('linux-base'), false);
$eq('출처 없음',          vg_is_kernel_source(null),         false);

// ── 커널 코드가 든 바이너리인가 ────────────────────────────────────────────
//   실측(raspberrypi5-00): source_pkg=linux 인 패키지 21개 중 커널 이미지는 6개뿐이었다.
//   나머지는 헤더·빌드스크립트·메타 → 커널 CVE 와 무관한데 369건씩 달려 있었다.
$eq('커널 이미지',        vg_is_kernel_code_pkg('linux-image-6.18.34+rpt-rpi-2712'), true);
$eq('커널 이미지 메타',   vg_is_kernel_code_pkg('linux-image-rpi-2712'),             true);
$eq('rpm 커널',           vg_is_kernel_code_pkg('kernel'),                           true);
$eq('rpm kernel-core',    vg_is_kernel_code_pkg('kernel-core'),                      true);

$eq('헤더는 코드가 아니다',      vg_is_kernel_code_pkg('linux-headers-6.18.34+rpt-rpi-v8'), false);
$eq('헤더 메타도 아니다',        vg_is_kernel_code_pkg('linux-headers-rpi-2712'),           false);
$eq('libc-dev 는 헤더',          vg_is_kernel_code_pkg('linux-libc-dev'),                   false);
$eq('kbuild 는 빌드스크립트',    vg_is_kernel_code_pkg('linux-kbuild-6.18.34+rpt'),         false);
$eq('base 는 메타패키지',        vg_is_kernel_code_pkg('linux-base-rpi-v8'),                false);

// ── 출처(origin) 판정 — 회귀 방지(서드파티를 배포판으로 오인하면 미탐) ─────
$eq('데비안 라벨',        vg_is_distro_pkg('Debian', 'debian'),                  true);
$eq('라즈베리 재빌드',    vg_is_distro_pkg('Raspberry Pi Foundation', 'debian'), false);
$eq('수동 .deb(LOCAL)',   vg_is_distro_pkg('LOCAL', 'debian'),                   false);
$eq('정보 없음 → 보류',   vg_is_distro_pkg(null, 'debian'),                      true);

if ($fail === 0) {
    echo "distro: 모든 검사 통과\n";
    exit(0);
}
printf("distro: %d 개 실패\n", $fail);
exit(1);
