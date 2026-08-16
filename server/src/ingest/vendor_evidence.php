<?php
declare(strict_types=1);

/**
 * ingest/vendor_evidence.php — 매처의 **억제 근거**가 될 벤더/배포판 신호의 파서.
 *   changelog 의 CVE 기록(백포트) · dnf updateinfo errata · debsecan.
 *   여기서는 해석하지 않는다 — "무엇이 적혀 있었나"만 행으로 만들고, 그것이 무엇을 억제하는지는
 *   server/src/matcher/decide.php 가 정한다(같은 근거라도 걸리는 가드가 다르다 — #371).
 *
 * ingest_parse.php 가 require 한다.
 */

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
