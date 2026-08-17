<?php
declare(strict_types=1);

/**
 * kernelcve.php — 커널 CVE **판정**(매처가 쓴다). 수집은 feeds/kcve.php.
 *
 *   판정 기준은 **구동 커널의 업스트림 버전**이다(uname). 설치된 커널 패키지의 배포판 EVR 이 아니다.
 *   커널은 배포판마다 버전 체계가 다르고(라즈베리 `1:6.18.34-1+rpt1`), 그 체계는 kernel.org 의
 *   조치 버전과 비교할 수 없다. 반면 업스트림 버전(6.18.34)은 CNA 데이터와 바로 대조된다.
 *
 *   **억제 방향으로만** 쓴다 — "이 구동 커널은 그 수정본을 포함한다" 가 확실할 때만 억제하고,
 *   애매하면 남긴다. 배포판이 업스트림보다 먼저 백포트한 경우는 트래커·OVAL 이 답한다.
 */

/** uname 문자열 → 업스트림 버전(6.18.34+rpt-rpi-2712 → 6.18.34). 못 뽑으면 빈 문자열. */
function vg_kernel_upstream_ver(string $release): string {
    return preg_match('/^(\d+\.\d+(?:\.\d+)?)/', trim($release), $m) === 1 ? $m[1] : '';
}

/** 커널 버전 비교 — 순수 업스트림 버전끼리만(6.18 vs 6.18.34 → 자리수는 0으로 채운다). */
function vg_kernel_ver_cmp(string $a, string $b): int {
    $pa = array_map('intval', explode('.', $a));
    $pb = array_map('intval', explode('.', $b));
    $n  = max(count($pa), count($pb));
    for ($i = 0; $i < $n; $i++) {
        $x = $pa[$i] ?? 0;
        $y = $pb[$i] ?? 0;
        if ($x !== $y) { return $x < $y ? -1 : 1; }
    }
    return 0;
}

/**
 * 구동 커널이 이 CVE 를 이미 넘어섰나.
 *   1) 같은 stable 시리즈(6.18.x)에 수정 버전이 있으면 그것과 비교한다 — 가장 정확하다.
 *   2) 없으면 최초 취약 버전(introduced)보다 이전인지 본다 → 이전이면 애초에 해당 없음.
 *   3) 그래도 모르면 메인라인 수정 버전과 비교한다(그 이상이면 포함).
 *   판정 불가(데이터 없음)는 'unknown' — 억제하지 않는다(모르는 것을 안전하다고 하지 않는다).
 *
 * @param array<string,string> $streams  시리즈 => 수정 버전  ['6.1'=>'6.1.78', …]
 * @return 'fixed'|'vulnerable'|'unknown'
 */
function vg_kernel_cve_verdict(?string $introduced, ?string $mainline, array $streams, string $ver): string {
    if ($ver === '') { return 'unknown'; }

    $parts  = explode('.', $ver);
    $series = count($parts) >= 2 ? $parts[0] . '.' . $parts[1] : '';

    if ($series !== '' && isset($streams[$series])) {
        return vg_kernel_ver_cmp($ver, $streams[$series]) >= 0 ? 'fixed' : 'vulnerable';
    }
    if ($introduced !== null && $introduced !== '' && vg_kernel_ver_cmp($ver, $introduced) < 0) {
        return 'fixed';   // 취약 코드가 들어오기 전 버전 — 해당 없음(억제 사유는 같다)
    }
    if ($mainline !== null && $mainline !== '') {
        return vg_kernel_ver_cmp($ver, $mainline) >= 0 ? 'fixed' : 'vulnerable';
    }
    return 'unknown';
}

/**
 * 구동 커널 기준으로 "이미 수정됨/해당 없음" 인 CVE 집합.
 *   반환: cve_id => 억제 사유(사람이 읽는 문장)
 *   대상 CVE 만 조회한다(스캔 하나가 보는 커널 CVE 는 수백 건 — 전량 적재 금지, 매처 메모리 초과 방지).
 *
 * @param string[] $cveIds
 * @return array<string,string>
 */
function vg_kernel_fixed_set(PDO $pdo, string $runningKernel, array $cveIds): array {
    $ver = vg_kernel_upstream_ver($runningKernel);
    if ($ver === '' || !$cveIds) { return []; }

    $recs = [];
    foreach (array_chunk(array_values(array_unique($cveIds)), 500) as $chunk) {
        $in = implode(',', array_fill(0, count($chunk), '?'));

        $st = $pdo->prepare("SELECT cve_id, introduced_version, mainline_fixed FROM tb_kernel_cve WHERE cve_id IN ($in)");
        $st->execute($chunk);
        foreach ($st->fetchAll() as $r) {
            $recs[(string) $r['cve_id']] = [
                'intro'    => $r['introduced_version'] !== null ? (string) $r['introduced_version'] : null,
                'mainline' => $r['mainline_fixed'] !== null ? (string) $r['mainline_fixed'] : null,
                'streams'  => [],
            ];
        }

        $st = $pdo->prepare("SELECT cve_id, stream, fixed_version FROM tb_kernel_cve_fix WHERE cve_id IN ($in)");
        $st->execute($chunk);
        foreach ($st->fetchAll() as $r) {
            $cve = (string) $r['cve_id'];
            if (isset($recs[$cve])) { $recs[$cve]['streams'][(string) $r['stream']] = (string) $r['fixed_version']; }
        }
    }

    $out = [];
    foreach ($recs as $cve => $rec) {
        if (vg_kernel_cve_verdict($rec['intro'], $rec['mainline'], $rec['streams'], $ver) !== 'fixed') { continue; }

        $parts  = explode('.', $ver);
        $series = $parts[0] . '.' . ($parts[1] ?? '0');
        if (isset($rec['streams'][$series])) {
            $out[$cve] = sprintf('kernel.org CNA: 구동 커널 %s ≥ %s.y 수정본 %s → 이미 포함됨', $ver, $series, $rec['streams'][$series]);
        } elseif ($rec['intro'] !== null && vg_kernel_ver_cmp($ver, $rec['intro']) < 0) {
            $out[$cve] = sprintf('kernel.org CNA: 취약 코드는 %s 부터 — 구동 커널 %s 는 해당 없음', $rec['intro'], $ver);
        } else {
            $out[$cve] = sprintf('kernel.org CNA: 구동 커널 %s ≥ 메인라인 수정본 %s → 이미 포함됨', $ver, (string) $rec['mainline']);
        }
    }
    return $out;
}
