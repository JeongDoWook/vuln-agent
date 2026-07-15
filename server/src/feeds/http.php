<?php
declare(strict_types=1);

/**
 * feeds/http.php — 피드 커넥터 공용 HTTP 계층.
 *   SSRF 방어(호스트 resolve → 사설·루프백·링크로컬·예약 대역 차단) + curl 요청 래퍼
 *   (리다이렉트 홉마다 재검사, JSON/raw, maxBytes 스트리밍 중단) + 커넥터 URL 선택.
 *   모든 커넥터(kev/osv/nvd/kisa/epss)가 이 파일만 통해 외부로 나간다.
 */

// 커넥터 URL 을 고른다. 빈 값이면 기본 URL.
//
// `$conn['url'] ?? $default` 는 안 된다. connectors.php 의 저장 폼이 url 키를 항상 넣기
// 때문에(빈 문자열 포함) `??` 가 절대 발동하지 않는다 — URL 을 비워둔 KISA/EPSS 커넥터가
// 빈 문자열을 curl 에 넘겨 HTTP 0 으로 죽던 원인.
function vg_conn_url(array $conn, string $default): string {
    $u = trim((string) ($conn['url'] ?? ''));
    return $u !== '' ? $u : $default;
}

// ─────────────────────────────────────────────────────────────────────────
// SSRF 방어
// ─────────────────────────────────────────────────────────────────────────
/**
 * 차단 대역(사설·루프백·링크로컬·예약). IPv4-mapped IPv6(::ffff:a.b.c.d)는
 * vg_ssrf_ip_blocked() 가 내부 IPv4 로 벗겨내고 검사하므로 여기 따로 안 둔다.
 */
const VG_SSRF_BLOCKED_CIDRS = [
    '0.0.0.0/8', '10.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16',   // 169.254.169.254 = 클라우드 메타데이터
    '172.16.0.0/12', '192.168.0.0/16',
    '::1/128', 'fc00::/7', 'fe80::/10',
];

/** $ip 가 $cidr(예: '10.0.0.0/8') 안에 있는지. inet_pton 바이트 비교라 IPv4/IPv6 겸용. */
function vg_ip_in_cidr(string $ip, string $cidr): bool {
    [$subnet, $bits] = explode('/', $cidr);
    $bits   = (int) $bits;
    $ipBin  = @inet_pton($ip);
    $subBin = @inet_pton($subnet);
    if ($ipBin === false || $subBin === false || strlen($ipBin) !== strlen($subBin)) {
        return false; // 주소 체계(v4/v6) 불일치 → 이 CIDR 은 대상이 아님
    }
    $bytes = intdiv($bits, 8);
    if ($bytes > 0 && substr($ipBin, 0, $bytes) !== substr($subBin, 0, $bytes)) {
        return false;
    }
    $remBits = $bits % 8;
    if ($remBits === 0) { return true; }
    $mask = chr((0xFF << (8 - $remBits)) & 0xFF);
    return (substr($ipBin, $bytes, 1) & $mask) === (substr($subBin, $bytes, 1) & $mask);
}

function vg_ssrf_ip_blocked(string $ip): bool {
    // IPv4-mapped IPv6(::ffff:a.b.c.d)는 위 CIDR 목록이 IPv6 로 안 봐서 그냥 통과한다 → 벗겨서 재검사.
    if (stripos($ip, '::ffff:') === 0) {
        $mapped = substr($ip, 7);
        if (filter_var($mapped, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $ip = $mapped;
        }
    }
    foreach (VG_SSRF_BLOCKED_CIDRS as $cidr) {
        if (vg_ip_in_cidr($ip, $cidr)) { return true; }
    }
    return false;
}

/** 호스트명을 A/AAAA 로 resolve. 이미 IP 리터럴이면 그대로 돌려준다. */
function vg_ssrf_resolve_ips(string $host): array {
    if (filter_var($host, FILTER_VALIDATE_IP)) {
        return [$host];
    }
    $ips = [];
    foreach (@dns_get_record($host, DNS_A + DNS_AAAA) ?: [] as $rec) {
        if (isset($rec['ip']))   { $ips[] = $rec['ip']; }
        if (isset($rec['ipv6'])) { $ips[] = $rec['ipv6']; }
    }
    if (!$ips) {
        // dns_get_record 가 막힌 환경(일부 컨테이너·방화벽) 대비 폴백. A 레코드만 준다.
        $v4 = @gethostbyname($host);
        if ($v4 !== $host && filter_var($v4, FILTER_VALIDATE_IP)) { $ips[] = $v4; }
    }
    return $ips;
}

/**
 * 커넥터 URL 은 사용자 입력이다(connectors.php 가 operator 권한으로 저장하고, feed_preview.php
 * 가 응답을 호출자에게 그대로 반사한다). CURLOPT_PROTOCOLS 는 스킴(http/https)만 막을 뿐 목적지
 * IP 는 안 거르므로, 요청 직전 호스트를 DNS resolve 해 사설·루프백·링크로컬·예약 대역
 * (169.254.169.254 클라우드 메타데이터 포함)이면 막는다.
 * vg_http_follow() 가 최초 URL 과 리다이렉트 목적지마다 이걸 부른다.
 */
function vg_ssrf_guard_url(string $url): void {
    $p      = parse_url($url);
    $scheme = strtolower((string) ($p['scheme'] ?? ''));
    // parse_url 은 IPv6 host 를 'http://[::1]/' 처럼 대괄호를 안 벗기고 돌려준다(PHP 8.3 실측).
    // 대괄호가 남으면 filter_var(FILTER_VALIDATE_IP)·DNS resolve 가 전부 실패해 "resolve 불가"로
    // 걸러지긴 하지만(fail-closed) 공개 IPv6 리터럴까지 엉뚱한 사유로 막히므로 여기서 벗긴다.
    $host = trim((string) ($p['host'] ?? ''), '[]');
    if (!in_array($scheme, ['http', 'https'], true) || $host === '') {
        throw new RuntimeException("SSRF 방어: 잘못된 URL ($url)");
    }
    $ips = vg_ssrf_resolve_ips($host);
    if (!$ips) {
        throw new RuntimeException("SSRF 방어: 호스트를 resolve 할 수 없음 ($host)");
    }
    foreach ($ips as $ip) {
        if (vg_ssrf_ip_blocked($ip)) {
            throw new RuntimeException("SSRF 방어: 차단된 대상 IP ($host → $ip)");
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// HTTP (curl)
// ─────────────────────────────────────────────────────────────────────────
/**
 * SSRF 를 막으면서 리다이렉트를 따라간다.
 *   CURLOPT_FOLLOWLOCATION 을 켜두면 curl 이 재검사 없이 302 로 내부 IP 까지 가버린다.
 *   그렇다고 리다이렉트 자체를 끌 수도 없다 — EPSS 는 실제로 epss.cyentia.com 이
 *   epss.empiricalsecurity.com 으로 301 리다이렉트한다(2026-07-13 실측, 다른 4개 피드는 무리다이렉트).
 *   그래서 FOLLOWLOCATION 은 끄고 여기서 홉마다 vg_ssrf_guard_url 로 재검사하며 최대 5홉을 따라간다.
 * @return array{code:int,body:string,error:string}
 */
function vg_http_follow(string $url, array $curlOpts, int $maxRedirects = 5): array {
    vg_ssrf_guard_url($url);
    for ($hop = 0; ; $hop++) {
        $ch = curl_init($url);
        curl_setopt_array($ch, $curlOpts);
        $raw  = curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err  = curl_error($ch);
        $next = curl_getinfo($ch, CURLINFO_REDIRECT_URL);
        curl_close($ch);

        if (in_array($code, [301, 302, 303, 307, 308], true) && $next) {
            if ($hop >= $maxRedirects) {
                return ['code' => 0, 'body' => '', 'error' => 'SSRF 방어: 리다이렉트 한도 초과'];
            }
            vg_ssrf_guard_url($next);
            $url = $next;
            continue;
        }
        return ['code' => $code, 'body' => is_string($raw) ? $raw : '', 'error' => $err];
    }
}

// $maxBytes>0 이면 응답이 그 크기를 넘는 순간 전송을 중단한다(OSV 커널 등 거대 응답 OOM 방어).
function vg_http_json(string $method, string $url, $body = null, array $headers = [], int $timeout = 90, int $maxBytes = 0): array {
    $hdr = array_merge(['Accept: application/json'], $headers);
    $opt = [
        CURLOPT_RETURNTRANSFER  => true,
        CURLOPT_FOLLOWLOCATION  => false,  // vg_http_follow 가 SSRF 재검사하며 직접 따라간다
        CURLOPT_TIMEOUT         => $timeout,
        CURLOPT_CONNECTTIMEOUT  => 20,
        CURLOPT_CUSTOMREQUEST   => $method,
        CURLOPT_USERAGENT       => 'vuln-agent-feed/1.0',
        CURLOPT_PROTOCOLS       => CURLPROTO_HTTP | CURLPROTO_HTTPS,   // file://·gopher:// 등 차단
        CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
    ];
    if ($body !== null) {
        $opt[CURLOPT_POSTFIELDS] = is_string($body) ? $body : json_encode($body);
        $hdr[] = 'Content-Type: application/json';
    }
    if ($maxBytes > 0) {
        $opt[CURLOPT_NOPROGRESS]       = false;
        $opt[CURLOPT_PROGRESSFUNCTION] = static function ($ch, $dltotal, $dlnow) use ($maxBytes) {
            return ($dlnow > $maxBytes || $dltotal > $maxBytes) ? 1 : 0; // 넘으면 중단
        };
    }
    $opt[CURLOPT_HTTPHEADER] = $hdr;
    $r = vg_http_follow($url, $opt);
    if ($maxBytes > 0 && $r['code'] === 0) {
        return ['code' => 0, 'json' => null, 'error' => $r['error'] !== '' ? $r['error'] : "응답이 상한({$maxBytes}B) 초과로 건너뜀"];
    }
    $decoded = $r['body'] !== '' ? json_decode($r['body'], true) : null;
    return ['code' => $r['code'], 'json' => is_array($decoded) ? $decoded : null, 'error' => $r['error']];
}

/**
 * 여러 URL 을 curl_multi 로 **동시에** GET 한다. 건별 조회가 많은 커넥터(rhunfixed 의 컴포넌트
 *   목록·CVE 상세)에서 순차 왕복 지연을 없앤다 — 실측: 57개 컴포넌트 목록이 순차 210초.
 *
 *   SSRF 는 유지한다: **호스트별로 한 번** resolve 검사하고(같은 URL 뭉치는 대개 한 호스트다),
 *   차단 대역이면 통째로 던진다(부분 병렬 실패보다 전체 거부가 안전하다). FOLLOWLOCATION 은 끈다
 *   — 3xx 는 그대로 돌려주니, 리다이렉트가 필요한 호출자는 그 URL 만 vg_http_json 으로 순차 폴백한다.
 *   (rhunfixed 대상 access.redhat.com 은 리다이렉트하지 않는다.)
 *
 *   동시성은 대상 API 부담을 고려해 제한한다(기본 6). 슬라이딩 윈도우로 항상 최대 N개만 in-flight.
 *
 *   $maxBytes>0 이면 응답이 그 크기를 넘는 순간 그 핸들만 중단한다(거대 advisory 로 OOM 방지 —
 *   vg_http_json 과 같은 방식). 중단된 URL 은 code=0 으로 표시되니 호출자가 순차 폴백할 수 있다.
 *
 * @param string[] $urls
 * @return array<string, array{code:int,body:string,error:string}>  url => 결과(요청 안 된 url 은 없음)
 */
function vg_http_get_many(array $urls, int $concurrency = 6, int $timeout = 30, array $headers = [], int $maxBytes = 0): array {
    $urls = array_values(array_unique(array_filter($urls, 'strlen')));
    if (!$urls) { return []; }

    // 호스트별 SSRF 1회 검사(resolve → 차단대역). 하나라도 막히면 전체를 던진다.
    $seen = [];
    foreach ($urls as $u) {
        $h = strtolower((string) parse_url($u, PHP_URL_HOST));
        if ($h !== '' && !isset($seen[$h])) { vg_ssrf_guard_url($u); $seen[$h] = true; }
    }

    $concurrency = max(1, min($concurrency, count($urls)));
    $opt = [
        CURLOPT_RETURNTRANSFER  => true,
        CURLOPT_FOLLOWLOCATION  => false,
        CURLOPT_TIMEOUT         => $timeout,
        CURLOPT_CONNECTTIMEOUT  => 20,
        CURLOPT_USERAGENT       => 'vuln-agent-feed/1.0',
        CURLOPT_PROTOCOLS       => CURLPROTO_HTTP | CURLPROTO_HTTPS,
        CURLOPT_HTTPHEADER      => array_merge(['Accept: application/json'], $headers),
    ];
    if ($maxBytes > 0) {
        $opt[CURLOPT_NOPROGRESS]       = false;
        $opt[CURLOPT_PROGRESSFUNCTION] = static function ($ch, $dltotal, $dlnow) use ($maxBytes) {
            return ($dlnow > $maxBytes || $dltotal > $maxBytes) ? 1 : 0;   // 상한 초과 시 이 핸들만 중단
        };
    }

    $results = [];
    $mh      = curl_multi_init();
    $inflight = [];   // spl_object_id => ['url'=>, 'ch'=>]   (curl 핸들은 PHP8 에서 객체 → int 캐스팅 불가)
    $i = 0;
    $n = count($urls);

    $launch = static function () use (&$i, $n, $urls, $opt, $mh, &$inflight): void {
        if ($i >= $n) { return; }
        $u  = $urls[$i++];
        $ch = curl_init($u);
        curl_setopt_array($ch, $opt);
        curl_multi_add_handle($mh, $ch);
        $inflight[spl_object_id($ch)] = ['url' => $u, 'ch' => $ch];
    };
    for ($k = 0; $k < $concurrency; $k++) { $launch(); }

    do {
        curl_multi_exec($mh, $running);
        curl_multi_select($mh, 1.0);   // 이벤트 대기(바쁜 대기 방지)
        while ($info = curl_multi_info_read($mh)) {
            $ch  = $info['handle'];
            $key = spl_object_id($ch);
            $u   = $inflight[$key]['url'] ?? '';
            if ($u !== '') {
                $results[$u] = [
                    'code'  => (int) curl_getinfo($ch, CURLINFO_HTTP_CODE),
                    'body'  => (string) curl_multi_getcontent($ch),
                    'error' => curl_error($ch),
                ];
            }
            curl_multi_remove_handle($mh, $ch);
            curl_close($ch);
            unset($inflight[$key]);
            $launch();   // 빈 슬롯을 다음 URL 로 채운다
        }
    } while ($running > 0 || $inflight);

    curl_multi_close($mh);
    return $results;
}

// raw 응답 (XML/RSS 등 non-JSON 소스용)
function vg_http_raw(string $method, string $url, array $headers = [], int $timeout = 60): array {
    return vg_http_follow($url, [
        CURLOPT_RETURNTRANSFER   => true,
        CURLOPT_FOLLOWLOCATION   => false,  // vg_http_follow 가 SSRF 재검사하며 직접 따라간다
        CURLOPT_TIMEOUT          => $timeout,
        CURLOPT_CONNECTTIMEOUT   => 20,
        CURLOPT_CUSTOMREQUEST    => $method,
        CURLOPT_USERAGENT        => 'vuln-agent-feed/1.0',
        CURLOPT_PROTOCOLS        => CURLPROTO_HTTP | CURLPROTO_HTTPS,   // file://·gopher:// 등 차단
        CURLOPT_REDIR_PROTOCOLS  => CURLPROTO_HTTP | CURLPROTO_HTTPS,
        CURLOPT_HTTPHEADER       => $headers,
    ]);
}
