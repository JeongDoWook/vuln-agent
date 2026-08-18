<?php
declare(strict_types=1);

/**
 * ingest/network.php — "이 호스트가 어떤 IP 를 갖고 있나 / 어디에 붙어 있나" 스트림의 파서.
 *
 *   vg_ingest_parse_host_addresses(): 에이전트가 `cap net interfaces 'ip -o addr 2>/dev/null
 *   || ifconfig -a'` 로 보내는 원문에서 인터페이스명 + IPv4 만 뽑는다. 지금까지 이 값은
 *   tb_scan.raw_json 안에만 있었고 어떤 테이블로도 파싱되지 않아, 자산 탐색이 발견한 IP 를
 *   기존 자산과 대조할 방법이 없었다.
 *
 *   범위를 좁게 잡은 이유:
 *     - 넷마스크·브로드캐스트·MAC 은 저장하지 않는다. 대조에 쓰는 건 IP 뿐이다(YAGNI).
 *     - IPv6 는 대조 상대가 없다 — 발견 스캔이 IPv4 전용이다.
 *     - 루프백(127.0.0.0/8)·링크로컬(169.254.0.0/16)은 어느 호스트에나 있어 식별에 못 쓴다.
 *
 *   vg_ingest_parse_host_routes(): `cap net routes 'ip route 2>/dev/null || route -n'` 원문에서
 *   기본 게이트웨이와 직결 서브넷을 뽑는다 — 세그먼트 맵(망 구조 화면)이 대역·게이트웨이를
 *   그리는 데이터 원천이다.
 *
 * ingest_parse.php 가 require 한다.
 */

require_once __DIR__ . '/../netiface.php';   // vg_iface_is_virtual() — 가상 인터페이스 판별

// 한 호스트의 주소 행 상한. 에이전트 출력은 보통 수 줄이지만, 컨테이너 브리지가 수백 개인
//   호스트나 조작된 페이로드가 무한정 밀어 넣지 못하게 이중 방어로 막는다.
const VG_HOST_ADDR_MAX_ROWS = 256;

/**
 * net.interfaces 원문 → [[iface, ip], ...]  (같은 IP 는 처음 본 인터페이스 하나만 남긴다:
 *   tb_host_address 의 유니크 키가 (host_id, ip) 라 IP 가 곧 행 하나다.)
 * 값이 없거나 형식을 못 알아보면 빈 배열. 추측해서 채우지 않는다.
 */
function vg_ingest_parse_host_addresses(string $ifaceText): array
{
    $rows = [];
    $seen = [];       // ip => true
    $curIface = '';   // ifconfig 형식은 헤더 줄에서 인터페이스명을 물고 내려온다

    foreach (preg_split('/\r?\n/', $ifaceText) as $line) {
        if (trim($line) === '') { continue; }

        // ── `ip -o addr` 형식 ──────────────────────────────────────────────
        //   2: eth0    inet 10.3.142.200/24 brd 10.3.142.255 scope global eth0
        //   한 줄에 인터페이스명과 주소가 같이 있어 상태를 물고 다닐 필요가 없다.
        if (preg_match('/^\s*\d+:\s*(\S+)\s+inet\s+(\d{1,3}(?:\.\d{1,3}){3})/', $line, $m)) {
            vg_ingest_addr_push($rows, $seen, $m[1], $m[2]);
            if (count($rows) >= VG_HOST_ADDR_MAX_ROWS) { break; }
            continue;
        }
        // 주소 없는 인덱스 줄(`2: eth0: <BROADCAST,...>` 헤더나 inet6 줄)은 인터페이스명만 물고 넘어간다.
        //   에이전트는 `ip -o addr` 로 한 줄 형식을 보내지만, 사람이 붙여 넣은 `ip addr` 여러 줄
        //   출력(헤더 줄 + 들여쓴 inet 줄)도 같은 경로로 읽힌다.
        if (preg_match('/^\s*\d+:\s*(\S+?):?\s/', $line, $m)) {
            $curIface = $m[1];
            continue;
        }

        // ── `ifconfig -a` 형식 ─────────────────────────────────────────────
        //   헤더 줄(들여쓰기 없음)에서 인터페이스명을 잡고, 이어지는 들여쓴 inet 줄에 붙인다.
        //     eth0: flags=4163<UP,...>  mtu 1500        (net-tools 2.x)
        //     eth0      Link encap:Ethernet  HWaddr ..  (net-tools 1.x)
        if (preg_match('/^(\S+?):?\s/', $line, $m) && $line[0] !== ' ' && $line[0] !== "\t") {
            $curIface = $m[1];
        }
        //   inet 10.3.142.200  netmask 255.255.255.0     (net-tools 2.x)
        //   inet addr:10.3.142.200  Bcast:...            (net-tools 1.x)
        if (preg_match('/\binet\s+(?:addr:)?(\d{1,3}(?:\.\d{1,3}){3})\b/', $line, $m)) {
            vg_ingest_addr_push($rows, $seen, $curIface, $m[1]);
            if (count($rows) >= VG_HOST_ADDR_MAX_ROWS) { break; }
        }
    }

    return $rows;
}

/** 주소 1건 검증 후 누적. 루프백·링크로컬·비정상 표기는 여기서 걸러진다. */
function vg_ingest_addr_push(array &$rows, array &$seen, string $iface, string $ip): void
{
    // "10.3.142.300" 같은 형식만 그럴듯한 값은 여기서 떨어진다.
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) { return; }
    if (strncmp($ip, '127.', 4) === 0)      { return; }   // 루프백 127.0.0.0/8
    if (strncmp($ip, '169.254.', 8) === 0)  { return; }   // 링크로컬 169.254.0.0/16
    if ($ip === '0.0.0.0')                  { return; }
    if (isset($seen[$ip]))                  { return; }

    $seen[$ip] = true;
    $iface = trim($iface);
    $rows[] = [($iface !== '' ? mb_strimwidth($iface, 0, 64, '') : null), $ip];
}

// 한 호스트의 직결 서브넷 상한. 물리 인터페이스가 수십 개인 호스트는 실제로 없다 —
//   조작된 페이로드가 무한정 밀어 넣지 못하게 막는 이중 방어다(vg_ingest_addr_push 와 같은 이유).
const VG_HOST_ROUTE_MAX_ROWS = 64;

/**
 * net.routes 원문(`ip route` 우선, 없으면 `route -n`) → 기본 게이트웨이 + 직결 서브넷.
 *   가상 인터페이스(vg_iface_is_virtual, docker·br-·virbr 등)가 물린 라우팅은 **뺀다** —
 *   실제 망 구조가 아니라 컨테이너·오버레이가 만든 것이라 세그먼트 맵에 올리면 그림이
 *   가짜 노드로 덮인다(자산 목록의 대표 IP 선정과 같은 판단, netiface.php 참고).
 *
 *   라우팅 너머(게이트웨이 건너 도달하는 서브넷)는 다루지 않는다 — 그건 "직결"이 아니고,
 *   지금 화면이 그리는 건 이 호스트가 물리적으로 붙어 있는 대역뿐이다.
 *
 * 못 알아보면 게이트웨이 null·서브넷 빈 배열. 추측해서 채우지 않는다.
 *
 * @return array{gateway: ?array{ip: string, iface: string}, subnets: list<array{cidr: string, iface: string}>}
 */
function vg_ingest_parse_host_routes(string $routeText): array
{
    $gateway = null;
    $subnets = [];
    $seenCidr = [];

    foreach (preg_split('/\r?\n/', $routeText) as $line) {
        $line = trim($line);
        if ($line === '' || stripos($line, 'Destination') === 0 || stripos($line, 'Kernel IP') === 0) {
            continue;
        }

        // ── `ip route` : 기본 게이트웨이 ────────────────────────────────────
        //   default via 10.3.142.1 dev enp1s0 proto dhcp src 10.3.142.200 metric 100
        if ($gateway === null && preg_match('/^default\s+via\s+(\d{1,3}(?:\.\d{1,3}){3})\s+dev\s+(\S+)/', $line, $m)) {
            $gw = vg_ingest_route_gateway($m[1], $m[2]);
            if ($gw !== null) { $gateway = $gw; }
            continue;
        }
        // ── `ip route` : 직결 서브넷(게이트웨이 없이 dev 로만 붙는 줄) ───────
        //   10.3.142.0/24 dev enp1s0 proto kernel scope link src 10.3.142.200
        if (!str_contains($line, ' via ')
            && preg_match('#^(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\s+dev\s+(\S+)#', $line, $m)) {
            vg_ingest_route_subnet_push($subnets, $seenCidr, $m[1], $m[2]);
            if (count($subnets) >= VG_HOST_ROUTE_MAX_ROWS) { continue; }
            continue;
        }

        // ── `route -n` : "Destination Gateway Genmask Flags ... Iface" ─────
        //   0.0.0.0         10.3.142.1      0.0.0.0         UG    enp1s0
        //   10.3.142.0      0.0.0.0         255.255.255.0   U     enp1s0
        $tok = preg_split('/\s+/', $line);
        if (count($tok) < 5
            || filter_var($tok[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false
            || filter_var($tok[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false
            || filter_var($tok[2], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false
        ) {
            continue;
        }
        $dest = $tok[0]; $gw = $tok[1]; $mask = $tok[2]; $iface = (string) end($tok);

        if ($dest === '0.0.0.0' && $gw !== '0.0.0.0') {
            if ($gateway === null) {
                $found = vg_ingest_route_gateway($gw, $iface);
                if ($found !== null) { $gateway = $found; }
            }
            continue;
        }
        if ($gw === '0.0.0.0' && $dest !== '0.0.0.0') {
            $prefix = vg_ingest_route_prefix_from_mask($mask);
            if ($prefix !== null && count($subnets) < VG_HOST_ROUTE_MAX_ROWS) {
                vg_ingest_route_subnet_push($subnets, $seenCidr, $dest . '/' . $prefix, $iface);
            }
        }
    }

    return ['gateway' => $gateway, 'subnets' => $subnets];
}

/** 게이트웨이 후보 1건 검증. 가상 인터페이스면 채택하지 않는다(null). */
function vg_ingest_route_gateway(string $ip, string $iface): ?array
{
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) { return null; }
    $iface = trim($iface);
    if ($iface === '' || vg_iface_is_virtual($iface)) { return null; }
    return ['ip' => $ip, 'iface' => mb_strimwidth($iface, 0, 64, '')];
}

/** 직결 서브넷 1건 검증 후 누적. 가상 인터페이스·중복 CIDR 은 여기서 걸러진다. */
function vg_ingest_route_subnet_push(array &$subnets, array &$seenCidr, string $cidr, string $iface): void
{
    $parts = explode('/', $cidr);
    if (count($parts) !== 2 || filter_var($parts[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) { return; }
    if (!ctype_digit($parts[1]) || (int) $parts[1] > 32) { return; }
    $iface = trim($iface);
    if ($iface === '' || vg_iface_is_virtual($iface)) { return; }
    if (isset($seenCidr[$cidr])) { return; }

    $seenCidr[$cidr] = true;
    $subnets[] = ['cidr' => $cidr, 'iface' => mb_strimwidth($iface, 0, 64, '')];
}

/** `route -n` 의 Genmask(255.255.255.0 등) → CIDR 프리픽스 길이. 못 알아보면 null. */
function vg_ingest_route_prefix_from_mask(string $mask): ?int
{
    if (filter_var($mask, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) { return null; }
    $long = ip2long($mask);
    if ($long === false) { return null; }
    // 32비트 부호 있는 int 로 넘어오는 상위 비트 마스크(예: 255.0.0.0)를 대비해 unsigned 로 다룬다.
    $unsigned = sprintf('%u', $long);
    $bin = str_pad(decbin((int) $unsigned), 32, '0', STR_PAD_LEFT);
    // 연속된 1 뒤에 0 만 남는 정상 넷마스크인지 확인 — 아니면 못 알아본 값으로 버린다.
    if (!preg_match('/^1*0*$/', $bin)) { return null; }
    return substr_count($bin, '1');
}
