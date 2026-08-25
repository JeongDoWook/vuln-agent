<?php
declare(strict_types=1);

/**
 * discovery_enrich.php — 발견한 IP 에 "이게 뭔지" 를 채우는 수집기.
 *   discovery.php 가 "어디에 무엇이 떠 있나"(IP·열린 포트)를 모으면, 이 파일은 그 결과에
 *   역DNS 호스트명 · 포트 기반 서비스 힌트 · 가벼운 배너(HTTP Server 헤더 · TLS 인증서 CN)를
 *   붙인다. 스윕(소켓 다루기)과 정체 파악은 책임이 다르므로 파일을 나눈다.
 *
 * ## 왜 필요했나
 *   첫 운영 스캔이 `10.3.142.0/24` 에서 미관리 3건을 찾았는데 화면에 IP 와 포트뿐이라
 *   "이게 뭔지" 를 사람이 손으로 조사해야 했다. 그 조사가 전부 여기 들어 있다 —
 *   `.1` 은 역DNS 로 `OpenWrt.lan`(라우터), `.109` 는 `lenovo-thinkpad3.lan` + 9100 은
 *   node_exporter, `.230` 은 TLS 인증서 CN 이 `TRAEFIK DEFAULT CERT`(인그레스 VIP).
 *
 * ## 하지 않는 것 — MAC 주소
 *   엔진은 web 컨테이너 안에서 돈다. 컨테이너의 `/proc/net/arp` 에는 도커 브리지(172.18.0.x)만
 *   있고 스캔 대상 대역은 게이트웨이 너머라 컨테이너가 ARP 를 하지 않는다(실측). 그래서
 *   `arp`/`ip neigh` 를 부르는 코드는 항상 빈 결과다 — 넣지 않는다. 그 결과 같은 MAC 을
 *   공유하는 가상 IP(MetalLB/Traefik VIP)는 자동으로 못 걸러낸다. 그건 사람이 '제외' 로 찍는다.
 *
 * ## 시간 예산이 이 파일의 설계 제약이다
 *   강화 전 `/24` × 100포트가 5.13초였다. 강화가 몇 분씩 늘리면 기능 자체가 못 쓰게 된다.
 *   그래서 세 가지를 지킨다:
 *     · 살아있는 IP 에만 건다(1단계 통과분).
 *     · 역DNS 는 **전체가 하나의 마감시각**을 공유한다 — IP 수와 무관하게 상한이 고정이다.
 *     · 배너는 웹 포트에만, 건수 상한 + 전체 시간 예산 + 소켓당 짧은 타임아웃.
 *   전부 실패해도 조용히 비워 두고 스캔은 성공으로 끝난다(강화는 부가정보다).
 */

require_once __DIR__ . '/setting.php';

// ─────────────────────────────────────────────────────────────────────────────
// 상수 — 전부 tb_setting 으로 덮을 수 있다(스캔 파라미터와 같은 규칙)
// ─────────────────────────────────────────────────────────────────────────────

/** 역DNS 배치 전체의 마감시각(ms). IP 가 1개든 254개든 이 값을 넘지 않는다. */
const VG_DISCOVERY_DNS_BUDGET_MS = 2000;
/** 한 스캔에서 역DNS 를 물어볼 IP 수 상한. 넘는 만큼은 조회하지 않는다(다음 스캔에서 채워진다). */
const VG_DISCOVERY_DNS_MAX_IPS   = 256;
/** 배너 소켓 하나의 타임아웃(ms). connect 와 응답 대기에 각각 적용된다. */
const VG_DISCOVERY_BANNER_TIMEOUT_MS = 1000;
/** 한 스캔의 배너 시도 건수 상한. */
const VG_DISCOVERY_BANNER_MAX = 64;
/** 배너 단계 전체의 시간 예산(ms). 다음 시도를 **시작하기 전**에만 본다. */
const VG_DISCOVERY_BANNER_BUDGET_MS = 15000;
/** 배너에서 읽는 최대 바이트. 응답 본문은 읽지 않는다 — 헤더 몇 줄이면 충분하다. */
const VG_DISCOVERY_BANNER_MAX_BYTES = 2048;

/**
 * 포트 → 서비스 힌트. **관례일 뿐 확정이 아니다**(22 에 SSH 가 아닌 것이 떠 있을 수 있다).
 *   그래서 화면은 이 값을 단정형으로 쓰지 않고 '추측' 으로 표기한다.
 *   고정된 알려진 값이라 설정이 아니라 코드 상수로 둔다(고정 피드 스키마 매핑과 같은 예외).
 *   **이 표는 여기 한 곳에만 있다** — 화면도 vg_discovery_service_hint() 를 통해 본다.
 */
const VG_DISCOVERY_SERVICE_HINTS = [
    21   => 'FTP',        22   => 'SSH',        23   => 'Telnet',     25   => 'SMTP',
    53   => 'DNS',        80   => 'HTTP',       88   => 'Kerberos',   110  => 'POP3',
    111  => 'RPC',        135  => 'MS-RPC',     139  => 'NetBIOS',    143  => 'IMAP',
    161  => 'SNMP',       179  => 'BGP',        389  => 'LDAP',       443  => 'HTTPS',
    445  => 'SMB',        465  => 'SMTPS',      514  => 'Syslog',     515  => '프린터(LPD)',
    548  => 'AFP',        587  => 'SMTP',       631  => 'IPP(프린터)', 873  => 'rsync',
    993  => 'IMAPS',      995  => 'POP3S',      1433 => 'MSSQL',      1521 => 'Oracle',
    1723 => 'PPTP',       1883 => 'MQTT',       1900 => 'SSDP',       2049 => 'NFS',
    2375 => 'Docker API', 2376 => 'Docker TLS', 3000 => '웹(개발)',    3128 => 'HTTP 프록시',
    3306 => 'MySQL',      3389 => 'RDP',        5000 => '웹(개발)',    5432 => 'PostgreSQL',
    5601 => 'Kibana',     5900 => 'VNC',        6379 => 'Redis',      8000 => 'HTTP(대체)',
    8006 => 'Proxmox',    8008 => 'HTTP(대체)',  8080 => 'HTTP(대체)',  8081 => 'HTTP(대체)',
    8443 => 'HTTPS(대체)', 8888 => 'HTTP(대체)',  9000 => 'HTTP(대체)',  9090 => 'Prometheus',
    9100 => 'node_exporter 또는 프린터',
    9200 => 'Elasticsearch', 9443 => 'HTTPS(대체)', 10000 => 'Webmin',
    11211 => 'Memcached', 27017 => 'MongoDB',
];

/** 평문 HTTP 로 HEAD 를 던져 볼 포트. */
const VG_DISCOVERY_HTTP_PORTS = [80, 3000, 5000, 8000, 8008, 8080, 8081, 8888, 9000];
/** TLS 핸드셰이크로 인증서 CN 만 볼 포트. */
const VG_DISCOVERY_TLS_PORTS  = [443, 8443, 9443, 8006];

/**
 * 이 프로세스가 쓸 강화 파라미터. 스캔 파라미터(vg_discovery_config)와 같은 방식으로 읽는다.
 * @return array{dns_budget_ms:int, dns_max_ips:int, banner_timeout_ms:int, banner_max:int, banner_budget_ms:int}
 */
function vg_discovery_enrich_config(): array
{
    return [
        // 0 이면 그 단계를 통째로 끈다(DNS 가 없는 폐쇄망에서 운영자가 급히 잠글 수 있게).
        'dns_budget_ms'     => max(0, vg_setting_int('discovery.dns_budget_ms', VG_DISCOVERY_DNS_BUDGET_MS)),
        'dns_max_ips'       => max(0, vg_setting_int('discovery.dns_max_ips', VG_DISCOVERY_DNS_MAX_IPS)),
        'banner_timeout_ms' => max(100, vg_setting_int('discovery.banner_timeout_ms', VG_DISCOVERY_BANNER_TIMEOUT_MS)),
        'banner_max'        => max(0, vg_setting_int('discovery.banner_max', VG_DISCOVERY_BANNER_MAX)),
        'banner_budget_ms'  => max(0, vg_setting_int('discovery.banner_budget_ms', VG_DISCOVERY_BANNER_BUDGET_MS)),
    ];
}

// ─────────────────────────────────────────────────────────────────────────────
// ① 역DNS — PTR 질의를 직접 만든다
// ─────────────────────────────────────────────────────────────────────────────

/**
 * ★ 왜 gethostbyaddr() 를 안 쓰는가
 *   PHP 의 gethostbyaddr()·dns_get_record() 에는 **타임아웃 인자가 없다.** 리졸버가 죽어 있으면
 *   glibc 기본값(5초 × 2회 × 네임서버 수)을 그대로 기다린다 — 살아있는 IP 10대면 스캔이
 *   5초에서 100초로 늘어난다. 게다가 실패 시 **입력 IP 를 그대로 돌려줘서** 호출부가
 *   "호스트명을 찾았다"로 착각하기 쉽다.
 *   그래서 PTR 질의(UDP 53)를 직접 만들어 던지고, 전체 배치가 마감시각 하나를 공유한다.
 *   IP 수와 무관하게 이 단계의 상한이 고정되는 것이 핵심이다.
 */

/**
 * /etc/resolv.conf 의 네임서버(IPv4). 파일이 없거나 항목이 없으면 빈 배열 —
 *   그때는 역DNS 단계를 통째로 건너뛴다(폐쇄망에서 스캔이 멈추면 안 된다).
 * @return string[]
 */
function vg_discovery_resolvers(): array
{
    static $cache = null;
    if ($cache !== null) { return $cache; }

    $cache = [];
    $raw = @file_get_contents('/etc/resolv.conf');
    if ($raw === false) { return $cache; }
    foreach (preg_split('/\R/', $raw) ?: [] as $line) {
        if (!preg_match('/^\s*nameserver\s+(\S+)/', $line, $m)) { continue; }
        if (filter_var($m[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) { continue; }  // IPv6 리졸버는 쓰지 않는다
        $cache[] = $m[1];
        if (count($cache) >= 2) { break; }   // 첫 두 개면 충분하다 — 재시도를 하지 않으므로
    }
    return $cache;
}

/** IPv4 를 PTR 질의 이름으로: 10.3.142.1 → 1.142.3.10.in-addr.arpa */
function vg_discovery_ptr_name(string $ip): ?string
{
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) { return null; }
    return implode('.', array_reverse(explode('.', $ip))) . '.in-addr.arpa';
}

/** DNS 질의 패킷 하나(헤더 + 질문). $id 는 응답과 짝짓는 데 쓴다. */
function vg_discovery_dns_query(int $id, string $qname): string
{
    $q = pack('nnnnnn', $id, 0x0100, 1, 0, 0, 0);   // RD=1, QDCOUNT=1
    foreach (explode('.', $qname) as $label) {
        $q .= chr(strlen($label)) . $label;
    }
    return $q . "\0" . pack('nn', 12, 1);           // QTYPE=PTR(12), QCLASS=IN(1)
}

/**
 * 메시지 안의 이름 하나를 읽는다(압축 포인터 지원). $off 는 **읽은 만큼 전진한다**.
 *   포인터를 만나면 이름은 그쪽에서 이어 읽되 $off 는 포인터 뒤로만 전진한다(RFC 1035).
 *   무한 루프(자기 자신을 가리키는 포인터)는 점프 횟수로 막는다.
 */
function vg_discovery_dns_read_name(string $msg, int &$off): ?string
{
    $labels = [];
    $jumps  = 0;
    $cur    = $off;
    $ended  = false;
    $len    = strlen($msg);

    while (true) {
        if ($cur >= $len) { return null; }
        $n = ord($msg[$cur]);
        if ($n === 0) {
            $cur++;
            if (!$ended) { $off = $cur; }
            break;
        }
        if (($n & 0xC0) === 0xC0) {                 // 압축 포인터(상위 2비트가 11)
            if ($cur + 1 >= $len || ++$jumps > 16) { return null; }
            $ptr = (($n & 0x3F) << 8) | ord($msg[$cur + 1]);
            if (!$ended) { $off = $cur + 2; $ended = true; }
            $cur = $ptr;
            continue;
        }
        if ($cur + 1 + $n > $len) { return null; }
        $labels[] = substr($msg, $cur + 1, $n);
        $cur += 1 + $n;
        if (!$ended) { $off = $cur; }
    }
    return implode('.', $labels);
}

/**
 * PTR 응답에서 호스트명을 뽑는다. 응답이 아니거나(QR=0) 답이 없으면 null.
 *   질의 id 는 호출부가 대조하므로 여기서는 보지 않는다.
 */
function vg_discovery_dns_parse_ptr(string $msg): ?string
{
    if (strlen($msg) < 12) { return null; }
    $h = unpack('nid/nflags/nqd/nan/nns/nar', substr($msg, 0, 12));
    if ($h === false || ($h['flags'] & 0x8000) === 0 || ($h['flags'] & 0x000F) !== 0 || $h['an'] < 1) {
        return null;   // 응답 아님 / RCODE != 0 (NXDOMAIN 등) / 답 없음
    }
    $off = 12;
    for ($i = 0; $i < $h['qd']; $i++) {
        if (vg_discovery_dns_read_name($msg, $off) === null) { return null; }
        $off += 4;                                  // QTYPE + QCLASS
    }
    for ($i = 0; $i < $h['an']; $i++) {
        if (vg_discovery_dns_read_name($msg, $off) === null) { return null; }
        if ($off + 10 > strlen($msg)) { return null; }
        $rr = unpack('ntype/nclass/Nttl/nrdlen', substr($msg, $off, 10));
        if ($rr === false) { return null; }
        $off += 10;
        if ($rr['type'] === 12) {                   // PTR
            $p = $off;
            $name = vg_discovery_dns_read_name($msg, $p);
            if ($name !== null && $name !== '') { return $name; }
        }
        $off += $rr['rdlen'];                       // PTR 이 아니면(CNAME 등) 건너뛴다
    }
    return null;
}

/** 호스트명으로 받아들일 값인가. IP 를 그대로 돌려받은 것은 호스트명이 아니다. */
function vg_discovery_valid_hostname(string $name, string $ip): bool
{
    $name = rtrim($name, '.');
    if ($name === '' || strlen($name) > 255) { return false; }
    if ($name === $ip) { return false; }
    return (bool) preg_match('/^[A-Za-z0-9][A-Za-z0-9._-]*$/', $name);
}

/**
 * 살아있는 IP 들의 역DNS 를 **한 번에** 물어본다. 소켓을 전부 열어 질의를 던지고
 *   하나의 마감시각까지 stream_select 로 응답을 거둔다 — 스윕과 같은 구조다.
 *   못 찾은 IP 는 결과에 아예 넣지 않는다(빈 문자열도 넣지 않는다 — 저장부가 그것으로
 *   기존 호스트명을 덮지 않게).
 *
 * @param string[] $ips
 * @return array<string,string> ip => hostname
 */
function vg_discovery_reverse_dns(array $ips, ?array $cfg = null): array
{
    $cfg = $cfg ?? vg_discovery_enrich_config();
    if ($cfg['dns_budget_ms'] <= 0 || $cfg['dns_max_ips'] <= 0 || $ips === []) { return []; }

    $ns = vg_discovery_resolvers();
    if ($ns === []) { return []; }                  // 리졸버가 없다 = 조회 불가. 조용히 건너뛴다.
    $server = $ns[0];

    $ips  = array_slice(array_values(array_unique($ips)), 0, $cfg['dns_max_ips']);
    $out  = [];
    $live = [];                                     // resource_id => ['sock'=>r,'ip'=>string,'id'=>int]
    $id   = 1;

    foreach ($ips as $ip) {
        $qname = vg_discovery_ptr_name($ip);
        if ($qname === null) { continue; }
        $errno = 0; $errstr = '';
        $sock = @stream_socket_client("udp://{$server}:53", $errno, $errstr, 0, STREAM_CLIENT_CONNECT);
        if ($sock === false) { continue; }
        stream_set_blocking($sock, false);
        $qid = $id++ & 0xFFFF;
        if (@fwrite($sock, vg_discovery_dns_query($qid, $qname)) === false) { fclose($sock); continue; }
        $live[get_resource_id($sock)] = ['sock' => $sock, 'ip' => $ip, 'id' => $qid];
    }

    $deadline = microtime(true) + ($cfg['dns_budget_ms'] / 1000);
    while ($live !== []) {
        $remain = $deadline - microtime(true);
        if ($remain <= 0) { break; }
        $read = [];
        foreach ($live as $rid => $c) { $read[$rid] = $c['sock']; }
        $write = null; $except = null;
        $n = @stream_select($read, $write, $except, (int) $remain, (int) (fmod($remain, 1.0) * 1000000));
        if ($n === false || $n === 0) { break; }

        foreach ($read as $sock) {
            $rid = get_resource_id($sock);
            if (!isset($live[$rid])) { continue; }
            $c   = $live[$rid];
            $buf = @fread($sock, 4096);
            fclose($sock);
            unset($live[$rid]);
            if ($buf === false || strlen($buf) < 12) { continue; }
            $h = unpack('nid', substr($buf, 0, 2));
            if ($h === false || $h['id'] !== $c['id']) { continue; }   // 짝이 안 맞는 응답은 버린다
            $name = vg_discovery_dns_parse_ptr($buf);
            if ($name === null) { continue; }
            $name = rtrim($name, '.');
            if (vg_discovery_valid_hostname($name, $c['ip'])) {
                $out[$c['ip']] = substr($name, 0, 255);
            }
        }
    }
    foreach ($live as $c) { fclose($c['sock']); }   // 마감시각까지 답이 없던 소켓 회수
    return $out;
}

// ─────────────────────────────────────────────────────────────────────────────
// ② 포트 → 서비스 힌트
// ─────────────────────────────────────────────────────────────────────────────

/** 포트 관례에서 유추한 서비스명. 모르면 null. **추측이므로 표기는 화면이 완화한다.** */
function vg_discovery_service_hint(int $port): ?string
{
    return VG_DISCOVERY_SERVICE_HINTS[$port] ?? null;
}

// ─────────────────────────────────────────────────────────────────────────────
// ③ 가벼운 배너 — HTTP Server 헤더 · TLS 인증서 CN
// ─────────────────────────────────────────────────────────────────────────────

/** 배너를 볼 포트인가. 웹 포트에만 건다 — 아무 포트에나 말을 걸지 않는다. */
function vg_discovery_banner_kind(int $port): ?string
{
    if (in_array($port, VG_DISCOVERY_TLS_PORTS, true))  { return 'tls'; }
    if (in_array($port, VG_DISCOVERY_HTTP_PORTS, true)) { return 'http'; }
    return null;
}

/** 배너 문자열 정리 — 제어문자·bidi 오버라이드(U+202E 등)를 빼고 컬럼 길이(255)에 맞춘다.
 *   /u 플래그로 유니코드 단위 매칭한다 — 바이트 모드([[:cntrl:]])는 U+202E 계열을 못 거른다
 *   (표시 시점의 vg_strip_ctrl() 과 같은 범위를 쓴다, server/src/format/text.php). */
function vg_discovery_clean_banner(string $s): string
{
    $s = preg_replace('/[\x00-\x1F\x7F\x{200E}\x{200F}\x{202A}-\x{202E}\x{2066}-\x{2069}]+/u', ' ', $s) ?? '';
    return mb_substr(trim($s), 0, 255);
}

/**
 * HTTP `Server` 헤더 한 줄. HEAD 로 묻고 **응답 본문은 읽지 않는다**(바이트 상한도 건다).
 *   실패하면 null — 배너는 부가정보라 스캔을 실패시키지 않는다.
 */
function vg_discovery_http_banner(string $ip, int $port, int $timeoutMs): ?string
{
    $errno = 0; $errstr = '';
    $sock = @stream_socket_client(
        sprintf('tcp://%s:%d', $ip, $port), $errno, $errstr, $timeoutMs / 1000, STREAM_CLIENT_CONNECT
    );
    if ($sock === false) { return null; }
    stream_set_timeout($sock, 0, $timeoutMs * 1000);

    $req = "HEAD / HTTP/1.0\r\nHost: {$ip}\r\nUser-Agent: vuln-agent-discovery\r\nConnection: close\r\n\r\n";
    if (@fwrite($sock, $req) === false) { fclose($sock); return null; }

    $buf = '';
    while (strlen($buf) < VG_DISCOVERY_BANNER_MAX_BYTES) {
        $chunk = @fread($sock, 512);
        if ($chunk === false || $chunk === '') { break; }
        $buf .= $chunk;
        $meta = stream_get_meta_data($sock);
        if (!empty($meta['timed_out']) || !empty($meta['eof'])) { break; }
    }
    fclose($sock);

    if (preg_match('/^Server:[ \t]*(.+)$/mi', $buf, $m)) {
        $v = vg_discovery_clean_banner($m[1]);
        return $v !== '' ? $v : null;
    }
    return null;
}

/**
 * TLS 인증서의 subject CN. 핸드셰이크만 하고 요청은 보내지 않는다.
 *
 *   ★ 인증서 검증을 끈다(verify_peer/verify_peer_name = false). 스캔 대상은 자체서명
 *     인증서를 쓰는 장비가 대부분이라 검증을 켜면 정작 알고 싶은 장비에서 전부 실패한다.
 *     여기서 얻은 CN 은 **신원 증명이 아니라 식별 힌트**로만 쓴다(화면도 그렇게 표기한다).
 *     이 연결로 자격증명·데이터를 주고받지 않으므로 MITM 위험이 붙을 표면이 없다.
 */
function vg_discovery_tls_banner(string $ip, int $port, int $timeoutMs): ?string
{
    if (!extension_loaded('openssl')) { return null; }
    $ctx = stream_context_create(['ssl' => [
        'verify_peer'       => false,
        'verify_peer_name'  => false,
        'allow_self_signed' => true,
        'capture_peer_cert' => true,
        'SNI_enabled'       => false,   // IP 로 접속한다 — SNI 로 보낼 이름이 없다
    ]]);
    $errno = 0; $errstr = '';
    $sock = @stream_socket_client(
        sprintf('ssl://%s:%d', $ip, $port), $errno, $errstr, $timeoutMs / 1000,
        STREAM_CLIENT_CONNECT, $ctx
    );
    if ($sock === false) { return null; }
    $params = @stream_context_get_params($sock);
    fclose($sock);

    $cert = $params['options']['ssl']['peer_certificate'] ?? null;
    if ($cert === null) { return null; }
    $info = @openssl_x509_parse($cert);
    if (!is_array($info)) { return null; }
    // CN 이 여러 개인 인증서는 배열로 온다 — 먼저 배열 여부를 보고 나서 문자열로 만든다
    //   (거꾸로 하면 배열을 (string) 으로 캐스팅해 "Array" 가 배너로 저장된다).
    $cn = $info['subject']['CN'] ?? '';
    if (is_array($cn)) { $cn = $cn[0] ?? ''; }
    $cn = vg_discovery_clean_banner((string) $cn);
    return $cn !== '' ? $cn : null;
}

/**
 * 열린 포트들 중 **웹 포트에만** 배너를 시도한다.
 *   건수 상한과 전체 시간 예산을 둘 다 건다 — 예산은 다음 시도를 **시작하기 전**에만 보므로
 *   실제 소요는 마지막 시도의 소켓 타임아웃만큼 넘을 수 있다(상한이 예측 가능하다).
 *
 * @param array<string, array<int,string>> $open ip => [port => proto]
 * @return array<string, array<int,string>> ip => [port => banner]
 */
function vg_discovery_collect_banners(array $open, ?array $cfg = null): array
{
    $cfg = $cfg ?? vg_discovery_enrich_config();
    if ($cfg['banner_max'] <= 0 || $cfg['banner_budget_ms'] <= 0) { return []; }

    $out   = [];
    $tries = 0;
    $t0    = microtime(true);
    foreach ($open as $ip => $ports) {
        foreach (array_keys($ports) as $port) {
            $kind = vg_discovery_banner_kind((int) $port);
            if ($kind === null) { continue; }
            if ($tries >= $cfg['banner_max']) { return $out; }
            if ((microtime(true) - $t0) * 1000 >= $cfg['banner_budget_ms']) { return $out; }
            $tries++;
            $banner = $kind === 'tls'
                ? vg_discovery_tls_banner((string) $ip, (int) $port, $cfg['banner_timeout_ms'])
                : vg_discovery_http_banner((string) $ip, (int) $port, $cfg['banner_timeout_ms']);
            if ($banner !== null) { $out[(string) $ip][(int) $port] = $banner; }
        }
    }
    return $out;
}
