<?php
declare(strict_types=1);

/**
 * vercmp.php — 배포판 패키지 버전 비교 (dpkg / rpm / apk).
 *
 * 왜 필요한가: 매칭이 "설치버전 >= 수정버전이면 이미 패치됨"을 판정하려면 배포판 규칙대로
 * 비교해야 한다. PHP version_compare 로는 불가능하다 —
 *   · epoch:  `1:1.1.1` 은 `2.0` 보다 최신이다(에포크가 우선).
 *   · 릴리스: `1.1.1f-1ubuntu2.19` 의 `-1ubuntu2.19` 까지 비교해야 백포트를 인식한다.
 *   · 틸드:   `1.0~rc1` 은 `1.0` 보다 **이전**이다(version_compare 는 반대로 본다).
 *
 * 알고리즘은 dpkg(Debian policy §5.6.12)와 rpm(rpmvercmp)을 각각 그대로 옮겼다.
 * 두 규칙은 미묘하게 달라(문자 순서·'^' 처리) 하나로 합치지 않는다.
 */

/** dpkg 문자 순서: '~' < 없음 < 알파벳 < 그 외 기호. 숫자는 0(구간 종료로 취급). */
function vg_deb_order(string $c): int
{
    if ($c === '')                       { return 0; }
    if (ctype_digit($c))                 { return 0; }
    if ($c === '~')                      { return -1; }
    if (ctype_alpha($c))                 { return ord($c); }
    return ord($c) + 256;
}

/** dpkg 의 upstream/revision 한 조각 비교. -1 / 0 / 1 */
function vg_deb_cmp_frag(string $a, string $b): int
{
    $i = 0; $j = 0; $la = strlen($a); $lb = strlen($b);
    while ($i < $la || $j < $lb) {
        // 1) 비숫자 구간 — 문자별로 dpkg 순서 비교
        while (($i < $la && !ctype_digit($a[$i])) || ($j < $lb && !ctype_digit($b[$j]))) {
            $ac = $i < $la ? vg_deb_order($a[$i]) : 0;
            $bc = $j < $lb ? vg_deb_order($b[$j]) : 0;
            if ($ac !== $bc) { return $ac < $bc ? -1 : 1; }
            $i++; $j++;
        }
        // 2) 숫자 구간 — 선행 0 무시하고 수치 비교
        while ($i < $la && $a[$i] === '0') { $i++; }
        while ($j < $lb && $b[$j] === '0') { $j++; }
        $na = ''; while ($i < $la && ctype_digit($a[$i])) { $na .= $a[$i]; $i++; }
        $nb = ''; while ($j < $lb && ctype_digit($b[$j])) { $nb .= $b[$j]; $j++; }
        if (strlen($na) !== strlen($nb)) { return strlen($na) < strlen($nb) ? -1 : 1; }
        if ($na !== $nb)                 { return $na < $nb ? -1 : 1; }
    }
    return 0;
}

/** dpkg 전체 버전 비교: [epoch:]upstream[-revision] */
function vg_deb_cmp(string $a, string $b): int
{
    $split = static function (string $v): array {
        $v = trim($v);
        $epoch = 0;
        if (preg_match('/^(\d+):(.*)$/s', $v, $m)) { $epoch = (int) $m[1]; $v = $m[2]; }
        $rev = '';
        $pos = strrpos($v, '-');
        if ($pos !== false) { $rev = substr($v, $pos + 1); $v = substr($v, 0, $pos); }
        return [$epoch, $v, $rev];
    };
    [$ea, $ua, $ra] = $split($a);
    [$eb, $ub, $rb] = $split($b);
    if ($ea !== $eb) { return $ea < $eb ? -1 : 1; }
    $c = vg_deb_cmp_frag($ua, $ub);
    if ($c !== 0) { return $c; }
    return vg_deb_cmp_frag($ra, $rb);
}

/** rpmvercmp — 영숫자 구간 단위 비교. '~'(이전) 과 '^'(이후) 를 특별 취급한다. */
function vg_rpm_cmp_frag(string $a, string $b): int
{
    if ($a === $b) { return 0; }
    $i = 0; $j = 0; $la = strlen($a); $lb = strlen($b);
    while ($i < $la || $j < $lb) {
        // 구분자(영숫자·~·^ 아닌 것) 건너뛰기
        while ($i < $la && !ctype_alnum($a[$i]) && $a[$i] !== '~' && $a[$i] !== '^') { $i++; }
        while ($j < $lb && !ctype_alnum($b[$j]) && $b[$j] !== '~' && $b[$j] !== '^') { $j++; }

        // '~' 는 무엇보다 이전(1.0~rc1 < 1.0)
        $ta = $i < $la && $a[$i] === '~';
        $tb = $j < $lb && $b[$j] === '~';
        if ($ta || $tb) {
            if (!$ta) { return 1; }
            if (!$tb) { return -1; }
            $i++; $j++;
            continue;
        }
        // '^' 는 무엇보다 이후지만, 문자열이 끝났으면 그쪽이 이전
        $ca = $i < $la && $a[$i] === '^';
        $cb = $j < $lb && $b[$j] === '^';
        if ($ca || $cb) {
            if (!$ca) { return $i >= $la ? -1 : 1; }
            if (!$cb) { return $j >= $lb ? 1 : -1; }
            $i++; $j++;
            continue;
        }

        if ($i >= $la || $j >= $lb) { break; }

        // 영숫자 구간 하나씩
        $isNum = ctype_digit($a[$i]);
        $sa = ''; $sb = '';
        if ($isNum) {
            while ($i < $la && ctype_digit($a[$i])) { $sa .= $a[$i]; $i++; }
            while ($j < $lb && ctype_digit($b[$j])) { $sb .= $b[$j]; $j++; }
        } else {
            while ($i < $la && ctype_alpha($a[$i])) { $sa .= $a[$i]; $i++; }
            while ($j < $lb && ctype_alpha($b[$j])) { $sb .= $b[$j]; $j++; }
        }
        // 한쪽이 숫자, 다른 쪽이 문자 → 숫자가 더 최신
        if ($sb === '') { return $isNum ? 1 : -1; }

        if ($isNum) {
            $sa = ltrim($sa, '0'); $sb = ltrim($sb, '0');
            if (strlen($sa) !== strlen($sb)) { return strlen($sa) < strlen($sb) ? -1 : 1; }
        }
        if ($sa !== $sb) { return $sa < $sb ? -1 : 1; }
    }
    // 남은 쪽이 더 최신
    if ($i >= $la && $j >= $lb) { return 0; }
    return $i >= $la ? -1 : 1;
}

/** rpm 전체 EVR 비교: [epoch:]version[-release]. 에포크 없음/"(none)" 은 0. */
function vg_rpm_cmp(string $a, string $b): int
{
    $split = static function (string $v): array {
        $v = trim($v);
        $epoch = 0;
        if (preg_match('/^([^:]*):(.*)$/s', $v, $m)) {
            // rpm -qa 는 에포크가 없으면 "(none)" 을 찍는다 → 0 으로 본다.
            $epoch = ctype_digit($m[1]) ? (int) $m[1] : 0;
            $v = $m[2];
        }
        $rel = '';
        $pos = strrpos($v, '-');
        if ($pos !== false) { $rel = substr($v, $pos + 1); $v = substr($v, 0, $pos); }
        return [$epoch, $v, $rel];
    };
    [$ea, $va, $ra] = $split($a);
    [$eb, $vb, $rb] = $split($b);
    if ($ea !== $eb) { return $ea < $eb ? -1 : 1; }
    $c = vg_rpm_cmp_frag($va, $vb);
    if ($c !== 0) { return $c; }
    // 한쪽만 릴리스가 있으면 비교하지 않는다(피드의 fixed 가 릴리스를 생략하는 경우).
    if ($ra === '' || $rb === '') { return 0; }
    return vg_rpm_cmp_frag($ra, $rb);
}

/**
 * 언어 패키지(PyPI/npm/RubyGems/Packagist) 버전 비교.
 *
 * 배포판 규칙(epoch·릴리스번호)이 없고 semver/PEP440 이다. PHP version_compare 가
 * 프리릴리스 순서(dev < alpha < beta < RC < 정식 < pl)를 처리하므로 그대로 쓴다.
 * EVR 비교기를 여기 쓰면 안 된다 — '1.0.0-rc1' 의 '-rc1' 을 데비안 리비전으로 읽어
 * 정식 릴리스보다 **최신**으로 판단해 버린다(취약한데 패치됨으로 오억제 = 미탐).
 */
function vg_lang_cmp(string $a, string $b): int
{
    return version_compare(trim($a), trim($b));   // -1 / 0 / 1
}

/**
 * Go 모듈 버전 정규화 — 앞의 'v' 와 빌드 메타데이터('+…')를 뗀다.
 *
 * 'v': Go 모듈 버전은 "v1.2.3" 이지만 OSV 의 조치안은 "1.2.3" 으로 온다. 그대로 비교하면 어긋난다.
 * '+': semver 는 빌드 메타데이터를 **우선순위 비교에서 무시**한다 — 실측(golang.org/x/mod/semver
 *      v0.17.0): Compare("v1.0.0+incompatible", "v1.0.0") == 0. 안 떼면 PHP version_compare 가
 *      'incompatible' 을 프리릴리스처럼 읽어 -1 을 돌려주고, 설치본이 조치안보다 낮아 보여
 *      이미 고쳐진 모듈에 오탐이 남는다. '+incompatible' 은 go.mod 없는 major≥2 모듈에 붙어
 *      Go 바이너리 SBOM 에 흔하다.
 */
function vg_go_norm(string $v): string
{
    $v = ltrim(trim($v), 'vV');
    $pos = strpos($v, '+');
    return $pos === false ? $v : substr($v, 0, $pos);
}

/**
 * apk 접미사 순위. 실측(alpine:3.19 의 `apk version -t`)한 순서는 이렇다:
 *   _alpha < _beta < _pre < _rc < (접미사 없음) < _cvs < _svn < _git < _hg < _p
 * 접미사 없는 정식 릴리스를 0 으로 두어 프리릴리스는 음수, 포스트릴리스는 양수가 된다.
 * 모르는 접미사는 null — 순서를 추측하지 않는다(호출부가 dpkg 규칙으로 되돌린다).
 */
function vg_apk_suffix_rank(string $s): ?int
{
    static $rank = [
        'alpha' => -4, 'beta' => -3, 'pre' => -2, 'rc' => -1,
        'cvs'   =>  1, 'svn'  =>  2, 'git' =>  3, 'hg' =>  4, 'p' => 5,
    ];
    return $rank[$s] ?? null;
}

/**
 * apk 버전을 조각으로 나눈다 → [숫자구간, 뒤에 붙는 문자, 접미사목록, 리비전].
 * 형식: <숫자>{.<숫자>}[문자][_접미사[번호]]…[-r<리비전>]
 * 규격 밖이면 null.
 */
function vg_apk_parse(string $v): ?array
{
    $v = trim($v);
    $rev = -1;                       // 리비전 없음은 -r0 보다 이전이다(실측: `1.0` < `1.0-r0`).
    if (preg_match('/^(.*)-r(\d+)$/', $v, $m)) { $v = $m[1]; $rev = (int) $m[2]; }
    if (!preg_match('/^(\d+(?:\.\d+)*)([a-z]?)((?:_[a-z]+\d*)*)$/', $v, $m)) { return null; }

    $sufs = [];
    if ($m[3] !== '') {
        preg_match_all('/_([a-z]+)(\d*)/', $m[3], $ms, PREG_SET_ORDER);
        foreach ($ms as $s) {
            $rank = vg_apk_suffix_rank($s[1]);
            if ($rank === null) { return null; }
            // 번호 없는 접미사는 번호 0 보다 이전이다(실측: `1.0_p` < `1.0_p0`).
            $sufs[] = [$rank, $s[2] === '' ? -1 : (int) $s[2]];
        }
    }
    return [array_map('intval', explode('.', $m[1])), $m[2], $sufs, $rev];
}

/**
 * apk(알파인) 버전 비교.
 *
 * dpkg 규칙을 그대로 쓰면 **프리릴리스가 반대로 나온다.** dpkg 가 "정식보다 이전"으로 아는
 * 문자는 '~' 하나뿐인데 apk 는 '_alpha'·'_beta'·'_pre'·'_rc' 를 쓴다 — vg_deb_order 에서
 * '_' 는 그냥 기호(ord+256)라 문자열이 끝난 쪽(0)보다 커서 `1.0_rc1` > `1.0` 이 됐다.
 * 실제 apk 는 `<` 다. 방향이 미탐 쪽이었다: 억제 게이트(matcher/decide.php)가 rc 빌드를
 * "이미 패치됨"으로 보고 억제해 위험 집계에서 지워 버린다.
 * 리비전(-rN)·자릿수는 dpkg 와 같으므로 그 부분의 종전 판정은 바뀌지 않는다.
 *
 * 한계: 0 으로 채운 소수 자리(`1.01` vs `1.1`)는 apk 가 문자열로 비교하지만 여기서는
 * 숫자로 본다. 알파인 공식 패키지에 그런 표기가 없어 실사용 경로에 영향이 없다.
 * 규격 밖 문자열은 dpkg 규칙으로 되돌린다 — 새 순서를 추측하는 것보다 종전 동작이 안전하다.
 */
function vg_apk_cmp(string $a, string $b): int
{
    $pa = vg_apk_parse($a);
    $pb = vg_apk_parse($b);
    if ($pa === null || $pb === null) { return vg_deb_cmp($a, $b); }
    [$na, $la, $sa, $ra] = $pa;
    [$nb, $lb, $sb, $rb] = $pb;

    // 1) 숫자 구간 — 자리가 모자란 쪽이 이전(실측: `1.0` < `1.0.0`)
    $n = max(count($na), count($nb));
    for ($i = 0; $i < $n; $i++) {
        $x = $na[$i] ?? -1; $y = $nb[$i] ?? -1;
        if ($x !== $y) { return $x < $y ? -1 : 1; }
    }
    // 2) 뒤에 붙는 문자 한 자(실측: `1.2.3` < `1.2.3a` < `1.2.3b`)
    if ($la !== $lb) { return $la < $lb ? -1 : 1; }
    // 3) 접미사 — 순위 먼저, 같으면 번호. 없는 쪽은 정식 릴리스(순위 0)로 본다.
    $n = max(count($sa), count($sb));
    for ($i = 0; $i < $n; $i++) {
        [$xr, $xv] = $sa[$i] ?? [0, -1];
        [$yr, $yv] = $sb[$i] ?? [0, -1];
        if ($xr !== $yr) { return $xr < $yr ? -1 : 1; }
        if ($xv !== $yv) { return $xv < $yv ? -1 : 1; }
    }
    // 4) 리비전(-rN)
    return $ra === $rb ? 0 : ($ra < $rb ? -1 : 1);
}

/**
 * 패키지 매니저에 맞는 버전 비교. $manager: 'rpm' | 'dpkg' | 'apk' | 'pip'|'npm'|'gem'|'composer'.
 * 반환 -1(a<b) / 0(같음) / 1(a>b).
 */
function vg_ver_cmp(string $a, string $b, string $manager): int
{
    switch (strtolower($manager)) {
        case 'rpm':      return vg_rpm_cmp($a, $b);
        case 'pip':
        case 'npm':
        case 'gem':
        case 'composer': return vg_lang_cmp($a, $b);
        // Go 모듈 버전은 "v1.2.3+incompatible" 처럼 v 접두와 빌드 메타데이터가 붙는다.
        // 둘 다 떼고 semver 로 비교한다(사유는 vg_go_norm 주석).
        case 'go':       return vg_lang_cmp(vg_go_norm($a), vg_go_norm($b));
        // 업스트림 앱 버전(바이너리에서 뽑은 nginx 1.28.2 등) — 배포판 리비전이 없는 순수 semver.
        case 'upstream': return vg_lang_cmp($a, $b);
        // apk(알파인)는 "1.2.3-r0" 꼴이라 리비전·숫자만 보면 dpkg 와 같지만 프리릴리스가 다르다 —
        // dpkg 의 프리릴리스 표기는 '~' 하나뿐인데 apk 는 '_alpha'·'_beta'·'_pre'·'_rc' 를 쓴다.
        // dpkg 규칙으로 보면 `1.0_rc1` 이 `1.0` 보다 최신이 돼 rc 빌드를 오억제(미탐)했다.
        case 'apk':      return vg_apk_cmp($a, $b);
        default:         return vg_deb_cmp($a, $b);
    }
}
