<?php
declare(strict_types=1);

/**
 * ingest/network.php — "이 호스트가 어떤 IP 를 갖고 있나" 스트림의 파서.
 *   에이전트가 `cap net interfaces 'ip -o addr 2>/dev/null || ifconfig -a'` 로 보내는 원문에서
 *   인터페이스명 + IPv4 만 뽑는다. 지금까지 이 값은 tb_scan.raw_json 안에만 있었고 어떤
 *   테이블로도 파싱되지 않아, 자산 탐색이 발견한 IP 를 기존 자산과 대조할 방법이 없었다.
 *
 *   범위를 좁게 잡은 이유:
 *     - 넷마스크·브로드캐스트·MAC 은 저장하지 않는다. 대조에 쓰는 건 IP 뿐이다(YAGNI).
 *     - IPv6 는 대조 상대가 없다 — 발견 스캔이 IPv4 전용이다.
 *     - 루프백(127.0.0.0/8)·링크로컬(169.254.0.0/16)은 어느 호스트에나 있어 식별에 못 쓴다.
 *
 * ingest_parse.php 가 require 한다.
 */

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
