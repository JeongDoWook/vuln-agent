<?php
declare(strict_types=1);

/**
 * vercmp 단위 테스트 — 배포판 버전 비교.
 *
 * 기대값은 **실제 도구에서 뽑았다**(추측 아님):
 *   deb : dpkg --compare-versions A lt|gt B         (php:8.3-cli 컨테이너에 dpkg 내장)
 *   rpm : rpm --eval '%{lua:print(rpm.vercmp(A,B))}' (rockylinux:9)
 *
 * 실행:
 *   docker run --rm -v "$PWD:/w" -w /w php:8.3-cli php tests/vercmp_test.php
 */

require_once __DIR__ . '/../server/src/vercmp.php';

$fail = 0;
$run = static function (string $label, array $cases, callable $fn) use (&$fail): void {
    foreach ($cases as [$a, $b, $want]) {
        $got = $fn($a, $b);
        if ($got !== $want) {
            printf("  ✗ [%s] %s vs %s → 기대 %d, 실제 %d\n", $label, $a, $b, $want, $got);
            $fail++;
        }
    }
};

// dpkg — epoch, 릴리스, 틸드(~), binNMU(+b1), 데비안 리비전
$run('deb', [
    ['1.1.1f-1ubuntu2.19', '1.1.1f-1ubuntu2.20', -1],
    ['1.1.1f-1ubuntu2.19', '1.1.1f-1ubuntu2.9',   1],  // 19 > 9 (문자열이면 반대)
    ['1:1.1.1',            '2.0',                 1],  // epoch 우선
    ['1.0~rc1',            '1.0',                -1],  // 틸드는 이전
    ['1.0',                '1.0-1',              -1],
    ['2.30-3',             '2.30-3+deb11u1',     -1],
    ['1.2.3-4+b1',         '1.2.3-4',             1],  // binNMU
    ['0:1.0',              '1.0',                 0],
    ['5.4.0-150.167',      '5.4.0-90.101',        1],
    ['1.10',               '1.9',                 1],
    ['1.0-1',              '1.0-1~bpo11+1',       1],  // 백포트는 이전
    ['3.0.11-1~deb12u2',   '3.0.11-1~deb12u1',    1],
    ['2.38-1',             '2.38-1',              0],
    ['7.88.1-10+deb12u5',  '7.88.1-10+deb12u12', -1],
], static fn(string $a, string $b): int => vg_ver_cmp($a, $b, 'dpkg'));

// rpm — rpmvercmp 구간 비교(숫자/문자, ~, ^)
$run('rpm-frag', [
    ['1.1.1k',            '1.1.1k',             0],
    ['12.el8_9',          '9.el8',              1],
    ['1.0~rc1',           '1.0',               -1],
    ['97.el7',            '97.el7_9.1',        -1],
    ['513.24.1.el8_9',    '477.27.1.el8_8',     1],
    ['1',                 '1.1',               -1],
    ['1.0^20240101',      '1.0',                1],  // ^ 는 이후
    ['0.4.0',             '0.4',                1],
    ['1.0a',              '1.0',                1],
    ['2.el9',             '2.el9_4',           -1],
    ['1.0',               '1.0.0',             -1],
], 'vg_rpm_cmp_frag');

// rpm — 전체 EVR. rpm -qa 는 에포크가 없으면 "(none)" 을 찍는다 → 0 으로 봐야 한다.
$run('rpm-evr', [
    ['(none):1.2-3',            '1.2-3',                   0],
    ['1:1.2-3',                 '2.0-1',                   1],   // epoch 우선
    ['1.1.1k-12.el8_9',         '1.1.1k-9.el8',            1],
    ['4.18.0-513.24.1.el8_9',   '4.18.0-477.27.1.el8_8',   1],
    ['1.0-1',                   '1.0-1.1',                -1],
], static fn(string $a, string $b): int => vg_ver_cmp($a, $b, 'rpm'));

if ($fail === 0) {
    echo "vercmp: 전체 통과\n";
    exit(0);
}
printf("vercmp: %d건 실패\n", $fail);
exit(1);
