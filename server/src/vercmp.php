<?php
declare(strict_types=1);

/**
 * vercmp.php — 배포판 패키지 버전 비교 (dpkg / rpm).
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
 * 패키지 매니저에 맞는 버전 비교. $manager: 'rpm' | 'dpkg' | 'pip'|'npm'|'gem'|'composer'.
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
        default:         return vg_deb_cmp($a, $b);
    }
}
