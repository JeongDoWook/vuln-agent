<?php
declare(strict_types=1);

/**
 * cce/parse.php — 수집 원자료를 읽는 파서와 판정 임계값.
 *   판정 자체는 하지 않는다. "값을 못 읽었다"는 null 로 돌려주고, 그걸 NA 로 옮기는 건
 *   각 점검(cce/checks/*.php)의 몫이다 — 모르면 NA 여야지 0 으로 읽어 FAIL 을 만들면 안 된다.
 *
 *   ※ cce.php 가 로드한다(그 파일의 중복 로드 가드 안에서).
 */

// 판정 임계값 — 코드에 숫자를 박지 않는다(하드코딩 금지). 근거는 각 상수 주석 참고.
define('VG_CCE_TIME_OFFSET_MAX_SEC', 1.0);   // 로그 상관분석이 흔들리기 시작하는 경계(초)
define('VG_CCE_LOG_RETENTION_DAYS', 90);     // ISMS-P 2.9.4 통상 요구 보존기간(일)

/**
 * systemd 시간 표기 → 초. "90d" · "2592000" · "1month" · "1h30m" 를 받는다.
 *   해석할 수 없으면 null — 모르면 NA 로 가야지 0 으로 읽어 FAIL 을 만들면 안 된다.
 */
function vg_cce_timespan_sec(string $v): ?float {
    $v = trim($v);
    if ($v === '' || !preg_match_all('/(\d+(?:\.\d+)?)\s*([A-Za-z]*)/', $v, $ms, PREG_SET_ORDER)) {
        return null;
    }
    // systemd 는 대문자 M 만 "달"이고 소문자 m 은 "분"이다 → 소문자화 전에 가른다.
    $unit = [
        ''    => 1.0,       'us'  => 0.000001, 'ms'  => 0.001,
        's'   => 1.0,       'sec' => 1.0,      'secs' => 1.0, 'second' => 1.0, 'seconds' => 1.0,
        'm'   => 60.0,      'min' => 60.0,     'mins' => 60.0, 'minute' => 60.0, 'minutes' => 60.0,
        'h'   => 3600.0,    'hr'  => 3600.0,   'hour' => 3600.0, 'hours' => 3600.0,
        'd'   => 86400.0,   'day' => 86400.0,  'days' => 86400.0,
        'w'   => 604800.0,  'week' => 604800.0, 'weeks' => 604800.0,
        'month' => 2629800.0, 'months' => 2629800.0,
        'y'   => 31557600.0, 'year' => 31557600.0, 'years' => 31557600.0,
    ];
    $total = 0.0;
    foreach ($ms as $m) {
        $u = ($m[2] === 'M') ? 'month' : strtolower($m[2]);
        if (!isset($unit[$u])) { return null; }
        $total += (float) $m[1] * $unit[$u];
    }
    return $total;
}

/**
 * chronyc tracking / ntpq -pn 출력에서 현재 시간 오차(초, 절대값)를 뽑는다.
 *   못 뽑으면 null(→ NA). 값을 지어내지 않는다.
 */
function vg_cce_time_offset(string $tracking): ?float {
    // chronyc: "System time : 0.000000123 seconds fast of NTP time"
    if (preg_match('/System time\s*:\s*([0-9.]+(?:e-?\d+)?)\s*seconds/i', $tracking, $m)) {
        return abs((float) $m[1]);
    }
    // chronyc: "Last offset : +0.000000123 seconds"
    if (preg_match('/Last offset\s*:\s*([+-]?[0-9.]+(?:e-?\d+)?)\s*seconds/i', $tracking, $m)) {
        return abs((float) $m[1]);
    }
    // ntpq -pn: 선택된 피어(*) 행의 9번째 칼럼이 offset(ms).
    foreach (preg_split('/\r?\n/', $tracking) as $line) {
        $line = trim($line);
        if ($line === '' || $line[0] !== '*') { continue; }
        $f = preg_split('/\s+/', $line);
        if (count($f) >= 10 && is_numeric($f[8])) { return abs((float) $f[8]) / 1000.0; }
    }
    return null;
}

// sshd 설정값 조회: sshd -T(권위, 소문자키) 우선, 없으면 sshd_config grep 폴백.
//   반환: 소문자 값 문자열, 못 찾으면 null.
function vg_sshd_val(string $eff, string $cfg, string $key): ?string {
    $key = strtolower($key);
    foreach ([$eff, $cfg] as $src) {
        foreach (preg_split('/\r?\n/', $src) as $line) {
            $line = trim($line);
            if ($line === '' || $line[0] === '#') { continue; }
            $p = preg_split('/\s+/', $line, 2);
            if (isset($p[0]) && strtolower($p[0]) === $key) {
                return strtolower(trim($p[1] ?? ''));
            }
        }
    }
    return null;
}
