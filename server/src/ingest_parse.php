<?php
declare(strict_types=1);

/**
 * ingest_parse.php — ingest.php 가 받는 에이전트 원시 페이로드를 정규화된 배열로
 *   바꾸는 **순수 함수만** 모은다. DB·인증·감사로그는 여기 없다(ingest.php 에 남는다).
 *   모든 함수는 같은 입력엔 같은 출력을 내고 부작용이 없다 — tests/ingest_parse_test.php 참고.
 */

require_once __DIR__ . '/vercmp.php';   // vg_ver_cmp — vg_ingest_parse_kernel 에서 커널 버전 비교용

// ── collected_at (ISO-8601) → MySQL DATETIME ──────────────────────────────
function vg_ingest_parse_collected_at($raw): ?string
{
    if (empty($raw)) { return null; }
    $ts = strtotime((string) $raw);
    if ($ts === false) { return null; }
    return date('Y-m-d H:i:s', $ts);
}

// ── 패키지 목록 (매니저별 TSV) ─────────────────────────────────────────────
//   rpm : name \t epoch:version-release \t arch \t sourcerpm \t vendor
//   dpkg: name \t version \t arch \t source_pkg \t source_version \t status ('ii' 아니면 버림)
function vg_ingest_parse_packages(string $manager, string $list): array
{
    $rows = [];
    foreach (preg_split('/\r?\n/', $list) as $line) {
        if ($line === '') { continue; }
        $f    = explode("\t", $line);
        $name = trim($f[0] ?? '');
        if ($name === '') { continue; }
        if ($manager === 'rpm') {
            $rows[] = [$name, $f[1] ?? '', $f[2] ?? '', $f[3] ?? '', '', $f[4] ?? ''];
        } else {
            $st = trim($f[5] ?? '');
            if ($st !== '' && substr($st, 1, 1) !== 'i') { continue; }
            $rows[] = [$name, $f[1] ?? '', $f[2] ?? '', $f[3] ?? '', $f[4] ?? '', ''];
        }
    }
    return $rows;
}

// ── 패키지 출처(Origin) 라벨 — "name\tOrigin" 줄 목록 ──────────────────────
function vg_ingest_parse_origins(string $originsText): array
{
    $map = [];
    foreach (preg_split('/\r?\n/', $originsText) as $line) {
        $f = explode("\t", trim($line));
        if (count($f) < 2 || $f[0] === '' || $f[1] === '') { continue; }
        $map[$f[0]] = mb_strimwidth($f[1], 0, 128, '');
    }
    return $map;
}

// ── 언어 패키지 (pip/npm/gem/composer) ─────────────────────────────────────
function vg_ingest_parse_langpkgs(array $lang): array
{
    $rows = [];
    $add = static function (string $mgr, string $name, string $ver) use (&$rows): void {
        $name = trim($name); $ver = trim($ver);
        if ($name === '' || $ver === '') { return; }
        $rows["$mgr|$name"] = [$mgr, mb_strimwidth($name, 0, 255, ''), mb_strimwidth($ver, 0, 255, '')];
    };
    foreach (preg_split('/\r?\n/', (string) ($lang['pip'] ?? '')) as $line) {
        if (preg_match('/^([A-Za-z0-9._-]+)==(\S+)$/', trim($line), $m)) { $add('pip', $m[1], $m[2]); }
    }
    foreach (preg_split('/\r?\n/', (string) ($lang['npm_global'] ?? '')) as $line) {
        $t = trim(preg_replace('/^[\s|`+\x{2500}-\x{257F}-]+/u', '', $line) ?? '');
        if (preg_match('/^(@?[^@\s]+(?:\/[^@\s]+)?)@(\S+)$/', $t, $m)) { $add('npm', $m[1], $m[2]); }
    }
    foreach (preg_split('/\r?\n/', (string) ($lang['gem'] ?? '')) as $line) {
        if (preg_match('/^(\S+)\s+\((?:default:\s*)?([^,)]+)/', trim($line), $m)) { $add('gem', $m[1], $m[2]); }
    }
    foreach (preg_split('/\r?\n/', (string) ($lang['composer'] ?? '')) as $line) {
        if (preg_match('#^(\S+/\S+)\s+(\S+)#', trim($line), $m)) { $add('composer', $m[1], $m[2]); }
    }
    return array_values($rows);
}

// ── 노출 상관 (pipe 구분, 첫 줄 헤더) ──────────────────────────────────────
//   pid|proc|proto|bind|port|scope|exe_pkg|loaded_pkgs
function vg_ingest_parse_exposures(string $correlation): array
{
    $rows = [];
    foreach (preg_split('/\r?\n/', $correlation) as $line) {
        if ($line === '') { continue; }
        if (strncmp($line, 'pid|proc|proto', 14) === 0) { continue; }
        $f = explode('|', $line);
        if (count($f) < 8) { continue; }
        $rows[] = $f;
    }
    return $rows;
}

// ── 실행 프로세스 (pipe, 첫 줄 헤더) ───────────────────────────────────────
//   pid|comm|user|exe_pkg|loaded_pkgs
function vg_ingest_parse_processes(string $processesText): array
{
    $rows = [];
    foreach (preg_split('/\r?\n/', $processesText) as $line) {
        if ($line === '') { continue; }
        if (strncmp($line, 'pid|comm|user', 13) === 0) { continue; }
        $f = explode('|', $line);
        if (count($f) < 5) { continue; }
        $rows[] = $f;
    }
    return $rows;
}

// ── 재시작 필요(stale libs) (pipe, 첫 줄 헤더) ────────────────────────────
//   pid|comm|pkg|lib
function vg_ingest_parse_stale(string $staleText): array
{
    $rows = [];
    foreach (preg_split('/\r?\n/', $staleText) as $line) {
        if ($line === '') { continue; }
        if (strncmp($line, 'pid|comm|pkg', 12) === 0) { continue; }
        $f = explode('|', $line);
        if (count($f) < 4 || trim($f[2]) === '') { continue; }
        $rows[] = $f;
    }
    return $rows;
}

// ── changelog CVE (패키지명 => changelog 텍스트) ──────────────────────────
function vg_ingest_parse_changelog(array $clog): array
{
    $rows = [];
    foreach ($clog as $pkgName => $text) {
        $pkgName = trim((string) $pkgName);
        if ($pkgName === '' || !is_string($text) || $text === '') { continue; }
        foreach (preg_split('/\r?\n/', $text) as $line) {
            if (!preg_match_all('/CVE-\d{4}-\d{4,}/i', $line, $m)) { continue; }
            foreach (array_unique($m[0]) as $cve) {
                $cve = strtoupper($cve);
                $k = $pkgName . '|' . $cve;
                if (isset($rows[$k])) { continue; }   // (패키지,CVE)당 첫 근거 줄만
                $rows[$k] = [$pkgName, $cve, mb_strimwidth(trim($line), 0, 255, '')];
            }
        }
    }
    return array_values($rows);
}

// ── errata CVE — `dnf updateinfo list installed --with-cve` 형식 ─────────
//   "CVE-2022-3715  Moderate/Sec.  bash-5.1.8-6.el9_1.x86_64"
function vg_ingest_parse_errata(string $errataText): array
{
    $rows = [];
    foreach (preg_split('/\r?\n/', $errataText) as $line) {
        if (!preg_match('/^\s*(CVE-\d{4}-\d{4,})\s+\S+\s+(\S+)\s*$/i', $line, $m)) { continue; }
        $cve   = strtoupper($m[1]);
        $nevra = $m[2];
        $base  = preg_replace('/\.(x86_64|i686|aarch64|noarch|ppc64le|s390x)$/', '', $nevra);
        $parts = explode('-', (string) $base);
        if (count($parts) < 3) { continue; }
        array_pop($parts); array_pop($parts);   // name-version-release → name
        $pkgName = implode('-', $parts);
        if ($pkgName === '') { continue; }
        $k = $pkgName . '|' . $cve;
        if (isset($rows[$k])) { continue; }
        $rows[$k] = [$pkgName, $cve, mb_strimwidth(trim($nevra), 0, 255, '')];
    }
    return array_values($rows);
}

// ── debsecan — "CVE-2026-13595 bsdutils" (debsecan --format simple) ──────
function vg_ingest_parse_debsecan(string $debsecanText): array
{
    $rows = [];
    foreach (preg_split('/\r?\n/', $debsecanText) as $line) {
        if (!preg_match('/^\s*(CVE-\d{4}-\d{4,})\s+(\S+)\s*$/i', $line, $m)) { continue; }
        $k = strtoupper($m[1]) . '|' . $m[2];
        $rows[$k] = [strtoupper($m[1]), mb_strimwidth($m[2], 0, 255, '')];
    }
    return array_values($rows);
}

// ── 컨테이너 목록 — cid|name|image|os_id|os_version|manager|pkg_count ────
//   cid 로 유일(키가 cid) — ingest.php 가 tb_containers insert 후 id 매핑에 그대로 쓴다.
function vg_ingest_parse_container_list(string $listText): array
{
    $rows = [];
    foreach (preg_split('/\r?\n/', $listText) as $line) {
        if ($line === '' || strncmp($line, 'cid|name|image', 14) === 0) { continue; }
        $f = explode('|', $line);
        if (count($f) < 7 || trim($f[0]) === '') { continue; }
        $rows[$f[0]] = $f;
    }
    return $rows;
}

// ── 컨테이너 내부 패키지 — cid|manager|name|version|source ───────────────
function vg_ingest_parse_container_packages(string $packagesText): array
{
    $rows = [];
    foreach (preg_split('/\r?\n/', $packagesText) as $line) {
        if ($line === '' || strncmp($line, 'cid|manager|name', 16) === 0) { continue; }
        $f = explode('|', $line);
        if (count($f) < 4 || trim($f[0]) === '' || trim($f[2]) === '' || trim($f[3]) === '') { continue; }
        $rows[] = $f;
    }
    return $rows;
}

// ── 컨테이너 런타임 증거: 프로세스 — cid|pid|comm|user|exe_pkg|loaded_pkgs ─
function vg_ingest_parse_container_processes(string $processesText): array
{
    $rows = [];
    foreach (preg_split('/\r?\n/', $processesText) as $line) {
        if ($line === '' || strncmp($line, 'cid|pid|comm', 12) === 0) { continue; }
        $f = explode('|', $line);
        if (count($f) < 6 || trim($f[0]) === '' || trim($f[1]) === '') { continue; }
        $rows[] = $f;
    }
    return $rows;
}

// ── 컨테이너 런타임 증거: 노출 — cid|pid|proc|proto|bind|port|scope|exe_pkg|loaded_pkgs
function vg_ingest_parse_container_exposures(string $exposureText): array
{
    $rows = [];
    foreach (preg_split('/\r?\n/', $exposureText) as $line) {
        if ($line === '' || strncmp($line, 'cid|pid|proc', 12) === 0) { continue; }
        $f = explode('|', $line);
        if (count($f) < 9 || trim($f[0]) === '' || trim($f[5]) === '') { continue; }
        $rows[] = $f;
    }
    return $rows;
}

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
        $kernelLatest = $kernelCands[0];
        foreach ($kernelCands as $k) {
            if (vg_ver_cmp($k, $kernelLatest, $mgrForKernel) > 0) { $kernelLatest = $k; }
        }
        if ($runningKernel !== '' && vg_ver_cmp($runningKernel, $kernelLatest, $mgrForKernel) < 0) {
            $kernelReboot = 1;
        }
    }
    return ['running' => $runningKernel, 'latest' => $kernelLatest, 'reboot_needed' => $kernelReboot];
}

// ── 내용 해시 — "바뀔 때만 스냅샷" 판정에 쓰는 정규화 해시 ────────────────
//   PID 는 절대 넣지 않는다 — 재부팅·프로세스 재시작마다 바뀌어서 매번 "변경됨"이 된다.
function vg_ingest_content_hash(
    array $pkgRows,
    string $manager,
    array $langRows,
    array $expRows,
    array $staleRows,
    array $ctrPkgRows,
    array $ctrRows,
    array $ctrExpRows,
    string $runningKernel,
    string $kernelLatest,
    int $kernelReboot,
    array $vm,
    array $sys
): string {
    $hashParts = [];
    foreach ($pkgRows as $r)  { $hashParts[] = "p|$manager|{$r[0]}|{$r[1]}"; }
    foreach ($langRows as $r) { $hashParts[] = "l|{$r[0]}|{$r[1]}|{$r[2]}"; }
    foreach ($expRows as $f)  { $hashParts[] = 'e|' . implode('|', array_slice($f, 1, 7)); }   // pid 제외
    foreach ($staleRows as $r) { $hashParts[] = "s|{$r[2]}|{$r[3]}"; }
    foreach ($ctrPkgRows as $r) { $hashParts[] = "c|{$r[0]}|{$r[1]}|{$r[2]}|{$r[3]}"; }
    foreach ($ctrRows as $r)    { $hashParts[] = "C|{$r[0]}|{$r[2]}|{$r[3]}|{$r[4]}"; }   // cid|image|os
    foreach ($ctrExpRows as $f) { $hashParts[] = 'CE|' . $f[0] . '|' . implode('|', array_slice($f, 2, 7)); }   // pid 제외
    $hashParts[] = 'k|' . $runningKernel . '|' . $kernelLatest . '|' . $kernelReboot;
    $hashParts[] = 'o|' . ($vm['distro_id'] ?? '') . '|' . ($vm['distro_version'] ?? '')
                 . '|' . ($sys['kernel_release'] ?? ($sys['kernel'] ?? ''));
    sort($hashParts);
    return hash('sha256', implode("\n", $hashParts));
}

// ── 패키지 변경 이력 계산 (직전 스냅샷과 비교) ────────────────────────────
//   manager|name(OS 패키지) 또는 lang_manager|name(언어 패키지) 를 키로 쓴다.
function vg_ingest_build_pkg_map(string $manager, array $pkgRows, array $langRows): array
{
    $map = [];
    foreach ($pkgRows as $r)  { $map[$manager . '|' . $r[0]] = (string) $r[1]; }
    foreach ($langRows as $r) { $map[$r[0] . '|' . $r[1]]    = (string) $r[2]; }
    return $map;
}

// ── 두 스냅샷의 패키지 맵을 비교해 설치/제거/업그레이드/다운그레이드 목록을 낸다 ──
//   반환 원소: [키(manager|name), change_type, old_version, new_version]
//   $verCmp 는 vg_ver_cmp(string $a, string $b, string $manager): int 와 같은 시그니처.
function vg_ingest_diff_packages(array $prevPkgs, array $curPkgs, callable $verCmp): array
{
    $changes = [];
    foreach ($curPkgs as $k => $v) {
        if (!isset($prevPkgs[$k])) {
            $changes[] = [$k, 'installed', null, $v];
        } elseif ($prevPkgs[$k] !== $v) {
            [$mgr] = explode('|', $k, 2);
            $up = $verCmp($v, $prevPkgs[$k], $mgr) >= 0;
            $changes[] = [$k, $up ? 'upgraded' : 'downgraded', $prevPkgs[$k], $v];
        }
    }
    foreach ($prevPkgs as $k => $v) {
        if (!isset($curPkgs[$k])) { $changes[] = [$k, 'removed', $v, null]; }
    }
    return $changes;
}
