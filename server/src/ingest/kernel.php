<?php
declare(strict_types=1);

/**
 * ingest/kernel.php — 실행 중인 커널 vs 설치된 최신 커널 → 재부팅 필요 판정.
 *   이 저장소에서 **수집 단계가 버전을 비교하는 유일한 자리**다(vg_ver_cmp). 그래서 나머지
 *   문자열 파서와 성격이 달라 따로 뒀다 — flavor(기종·아키)를 무시하고 비교하면 안 쓰는 기종의
 *   커널이 "더 최신"으로 뽑혀 재부팅 필요가 잘못 붙는다(함수 안 주석의 라즈베리 실측).
 *
 * ingest_parse.php 가 require 한다(vg_ver_cmp 는 거기서 먼저 로드된다).
 */

// ── 커널: 실행 중인 커널 vs 설치된 최신 커널 → 재부팅 필요 판정 ───────────
//   반환: ['running' => string, 'latest' => string, 'reboot_needed' => 0|1]
function vg_ingest_parse_kernel(string $manager, string $runningKernel, string $installedKernelsText): array
{
    $kernelLatest = '';
    $kernelReboot = 0;
    $kernelCands  = [];
    foreach (preg_split('/\r?\n/', $installedKernelsText) as $line) {
        $line = trim($line);
        if ($line === '' || stripos($line, 'not installed') !== false) { continue; }
        if ($manager === 'rpm') {
            if (preg_match('/^kernel(?:-core)?-(\d.+)$/', $line, $m)) { $kernelCands[] = $m[1]; }
        } else {
            $f = preg_split('/\s+/', $line);
            if (isset($f[0]) && preg_match('/^linux-image-(\d.+)$/', $f[0], $m)) { $kernelCands[] = $m[1]; }
        }
    }
    if ($kernelCands) {
        // 문자열 비교로는 틀린다(5.14.0-687 vs 5.14.0-70) — 배포판 규칙으로 최신을 고른다.
        $mgrForKernel = $manager === 'rpm' ? 'rpm' : 'dpkg';

        // **같은 flavor 끼리만 비교한다.** 한 호스트에 기종·아키가 다른 커널이 여러 개 깔린다
        //   (라즈베리파이: rpi-2712 = Pi5, rpi-v8 = 그 외). 전부를 한 줄로 세우면 **안 쓰는 기종의
        //   커널이 "더 최신"으로 뽑혀** 실행 중 커널이 낡은 것처럼 보이고, 재부팅 필요가 잘못 붙는다
        //   (실측: 실행 6.18.34+rpt-rpi-2712 인데 설치된 6.18.34+rpt-rpi-v8 을 최신으로 골랐다).
        //   같은 flavor 후보가 하나도 없으면(그 커널이 제거된 경우) 옛 방식대로 전체를 본다 — 여기서
        //   비교를 포기하면 진짜 재부팅 필요를 놓친다(미탐).
        $runFlavor  = vg_kernel_flavor($runningKernel, $mgrForKernel);
        $sameFlavor = $runFlavor === '' ? [] : array_values(array_filter(
            $kernelCands,
            static fn(string $k): bool => vg_kernel_flavor($k, $mgrForKernel) === $runFlavor
        ));
        $pool = $sameFlavor ?: $kernelCands;

        $kernelLatest = $pool[0];
        foreach ($pool as $k) {
            if (vg_ver_cmp($k, $kernelLatest, $mgrForKernel) > 0) { $kernelLatest = $k; }
        }
        if ($runningKernel !== '' && vg_ver_cmp($runningKernel, $kernelLatest, $mgrForKernel) < 0) {
            $kernelReboot = 1;
        }
    }
    return ['running' => $runningKernel, 'latest' => $kernelLatest, 'reboot_needed' => $kernelReboot];
}

/**
 * 커널 릴리스에서 flavor(기종·아키)를 뽑는다. 버전 비교는 **같은 flavor 안에서만** 뜻이 있다.
 *   dpkg : 마지막 '-' 뒤   6.1.0-18-amd64 → amd64 · 6.18.34+rpt-rpi-2712 → 2712 · …-rpi-v8 → v8
 *   rpm  : 마지막 '.' 뒤   5.14.0-503.11.1.el9_5.x86_64 → x86_64
 *          (rpm 은 마이너 릴리스가 el9_4/el9_5 로 문자열에 박히므로 아키만 flavor 로 본다.)
 */
function vg_kernel_flavor(string $release, string $manager): string
{
    $r = trim($release);
    if ($r === '') { return ''; }
    $sep = $manager === 'rpm' ? '.' : '-';
    $pos = strrpos($r, $sep);
    return $pos === false ? '' : substr($r, $pos + 1);
}
