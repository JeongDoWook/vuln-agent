<?php
declare(strict_types=1);

/**
 * ingest/packages.php — "이 호스트에 무엇이 깔려 있나" 스트림의 파서.
 *   OS 패키지 목록(매니저별 TSV) · 출처(Origin) 라벨 · 언어 패키지 · 언어 패키지 라이선스.
 *   **먼저 수집된 소스가 이긴다**는 계약이 여기 산다(#466): 선언 파일 유래 값($weak)은
 *   이미 다른 소스가 잡은 값을 절대 덮어쓰지 않는다. 순서를 바꾸면 그 계약이 깨진다.
 *
 * ingest_parse.php 가 require 한다(vg_license_normalize_token 은 거기서 먼저 로드된다).
 */

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
    // $weak = 선언 파일(go.mod/requirements.txt/pom.xml)에서 읽은 "보충" 값. 설치본이 아니라
    // 선언이라 실제 배포 버전과 다를 수 있고, 스캔 루트에 파일 한 줄만 심어도 만들어낼 수 있다 —
    // 그래서 이미 다른 소스가 잡은 값이 있으면 절대 덮어쓰지 않는다.
    // 그 외 소스(설치본 조회)는 예전 그대로 나중 값이 이긴다.
    $add = static function (string $mgr, string $name, string $ver, bool $weak = false) use (&$rows): void {
        $name = trim($name); $ver = trim($ver);
        if ($name === '' || $ver === '') { return; }
        $key = "$mgr|$name";
        if ($weak && isset($rows[$key])) { return; }
        $rows[$key] = [$mgr, mb_strimwidth($name, 0, 255, ''), mb_strimwidth($ver, 0, 255, '')];
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
    // inventory: "manager|name|version" (+ 선언 파일 유래면 네 번째 필드 'weak').
    // 필드가 4개인데 마지막이 'weak' 가 아니면 name/version 에 '|' 가 섞여 자리가 밀린 오염 줄이다 → 버린다.
    $invMgrs = ['pip','npm','gem','composer','maven','nuget','cargo','go'];
    foreach (preg_split('/\r?\n/', (string) ($lang['inventory'] ?? '')) as $line) {
        $f = explode('|', trim($line), 4);
        $n = count($f);
        if ($n < 3 || !in_array($f[0], $invMgrs, true)) { continue; }
        if ($n === 4 && $f[3] !== 'weak') { continue; }
        if (!preg_match('/^\S+$/', $f[1]) || !preg_match('/^\S+$/', $f[2])) { continue; }
        $add($f[0], $f[1], $f[2], $n === 4);
    }
    foreach (preg_split('/\r?\n/', (string) ($lang['maven'] ?? '')) as $line) {
        if (preg_match('/^([^:\s]+:[^:\s]+)\s+(\S+)$/', trim($line), $m)) { $add('maven', $m[1], $m[2]); }
    }
    foreach (preg_split('/\r?\n/', (string) ($lang['nuget'] ?? '')) as $line) {
        if (preg_match('/^(\S+)\s+(\S+)$/', trim($line), $m)) { $add('nuget', $m[1], $m[2]); }
    }
    foreach (preg_split('/\r?\n/', (string) ($lang['cargo'] ?? '')) as $line) {
        if (preg_match('/^(\S+)\s+v([^:\s]+):$/', trim($line), $m)) { $add('cargo', $m[1], $m[2]); }
    }
    return array_values($rows);
}

// ── 언어 패키지 라이선스 — 별도 4필드 스트림("mgr|name|version|spdx") ─────────
//   기존 $lang['inventory'](3필드)에 얹지 않는다. 필드수를 다르게 둬야 자리 밀림(파이프
//   인젝션으로 name/version 에 '|' 가 섞인 오염 줄)이 조용히 4번째 칸을 라이선스로
//   오인하는 사고를 막을 수 있다.
function vg_ingest_parse_pkg_license(string $text): array
{
    $rows = [];
    $mgrs = ['pip', 'npm', 'gem', 'composer', 'maven', 'nuget', 'cargo', 'go'];
    foreach (preg_split('/\r?\n/', $text) as $line) {
        $line = trim($line);
        if ($line === '') { continue; }
        // limit 을 주지 않는다 — limit(4) 이면 name/version 에 '|' 가 섞인 오염 줄이 필드 밀림으로
        //   통과한다(PR#466 과 같은 클래스의 버그). 정확히 4필드가 아니면 엄격히 거부한다.
        $f = explode('|', $line);
        if (count($f) !== 4 || !in_array($f[0], $mgrs, true)) { continue; }
        [$mgr, $name, $ver, $lic] = array_map('trim', $f);
        if ($name === '' || $ver === '' || $lic === '') { continue; }
        // 별칭 정규화(자유서술→SPDX)를 화이트리스트 검증보다 먼저 적용한다 — 순서를 바꾸면
        //   대부분의 자유서술 표기("BSD License" 등)가 정규화 전에 걸려 통째로 버려진다.
        $lic = vg_license_normalize_token($lic);
        // SPDX 표현식 문자셋만 허용 — 저작권 문구·파이프 잔존 등 오염값을 걸러낸다.
        if (!preg_match('/^[A-Za-z0-9.\-+ ()]+$/', $lic)) { continue; }
        $rows["$mgr|$name|$ver"] = [
            $mgr, mb_strimwidth($name, 0, 255, ''), mb_strimwidth($ver, 0, 255, ''), mb_strimwidth($lic, 0, 255, ''),
        ];
    }
    return array_values($rows);
}

// ── langRows(mgr,name,version) 에 라이선스 스트림을 매칭해 4번째 필드로 붙인다 ──
//   매칭 안 되면 4번째 필드는 ''(라이선스 미상). langRows 의 앞 3필드 구조는 그대로라
//   기존 dedup·diff 로직(vg_ingest_build_pkg_map 등)은 건드리지 않는다.
//
//   **버전이 어긋나도 잃지 않는다** — langRows 는 `mgr|name` 으로 dedup 되어(위 $add) 한 이름에
//   버전이 하나만 남지만, 라이선스는 `mgr|name|version` 단위로 온다. 에이전트가 같은 패키지를
//   두 소스에서 서로 다른 버전으로 낼 수 있어(실측: 시스템 gemspec `json 2.6.3`(라이선스 있음) +
//   앱 `Gemfile.lock` 의 `json (2.7.1)`(라이선스 없음) / venv METADATA `urllib3 1.26.18` +
//   다른 앱 poetry.lock 의 `urllib3 2.0.7`), 정확 일치만 보면 라이선스가 조용히 미상이 됐다.
//   그래서 **정확 일치 우선 → 실패 시 이름 단위 폴백** 2단계로 찾는다.
//   폴백에서 같은 이름에 서로 다른 라이선스가 잡히면 **아무것도 붙이지 않는다** — 이 저장소는
//   라이선스 판정에서 "미탐이 과탐보다 낫다"를 원칙으로 삼는다(license_risk.php).
function vg_ingest_attach_pkg_license(array $langRows, array $licenseRows): array
{
    $byKey  = [];
    $byName = [];   // "mgr|name" => 라이선스 값. 값이 서로 다른 게 둘 이상이면 false(=폴백 포기)
    foreach ($licenseRows as $r) {
        $byKey["{$r[0]}|{$r[1]}|{$r[2]}"] = $r[3];
        $nk = "{$r[0]}|{$r[1]}";
        if (!array_key_exists($nk, $byName)) { $byName[$nk] = $r[3]; }
        elseif ($byName[$nk] !== $r[3])      { $byName[$nk] = false; }
    }
    $out = [];
    foreach ($langRows as $r) {
        $lic = $byKey["{$r[0]}|{$r[1]}|{$r[2]}"] ?? null;
        if ($lic === null) {
            $cand = $byName["{$r[0]}|{$r[1]}"] ?? false;
            $lic  = $cand === false ? '' : $cand;
        }
        $out[] = [$r[0], $r[1], $r[2], $lic];
    }
    return $out;
}
