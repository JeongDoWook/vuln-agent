<?php
declare(strict_types=1);

/**
 * discovery.php — 자산 탐색(섀도우 IT) 스캔 엔진. 등록된 대역을 TCP connect 로 훑어
 *   살아있는 IP 와 열린 포트를 모은다. 취약점 파이프라인(에이전트·매처)과 접점이 없다 —
 *   유일한 접점은 발견 IP 를 tb_host_address 와 대조하는 한 곳뿐이다.
 *
 *   공용 라이브러리라 URL 로 열리지 않는다. 실행은 스케줄러 틱(server/bin/scheduler.php)과
 *   수동 CLI(server/bin/discover.php)만 하고, 둘 다 vg_discovery_run_pending() 한 곳을 쓴다 —
 *   수백 소켓을 수십 초 동안 드는 작업이라 웹 요청에서 돌리면 요청이 그만큼 묶인다.
 *
 * ## 왜 2단계인가 (성능의 전부)
 *   /24 × 100포트를 전부 던지면 25,400 조합이고, 총 실행시간은 **죽은 IP 의 타임아웃**이
 *   지배한다. 그래서 1단계에서 탐침 포트 몇 개로 살아있는 IP 만 추리고(254×6=1,524),
 *   2단계는 그 IP 에만 전체 포트를 던진다(살아있는 게 10대면 ~1,000). 조합이 한 자릿수 배로 준다.
 *   1단계에서 아무 응답도 없던 IP 는 2단계를 통째로 건너뛴다.
 *
 * ## 왜 한 프로세스인가
 *   STREAM_CLIENT_ASYNC_CONNECT 로 수백 개를 한꺼번에 열고 stream_select() 의 write 집합으로
 *   완료를 기다린다. 프로세스를 여러 개 띄우는 것보다 단순하고, 소켓 회수 지점이 한 곳이다.
 *
 * ## 하지 않는 것
 *   OS 추정·UDP 스캔·재시도. 이 제품의 원칙은 "수집만 하고 능동 접속은 최소" 라,
 *   포트 판정 이상으로 상대에게 말을 걸지 않는다 — **단 하나의 예외가 정체 파악이다**:
 *   살아있는 IP 의 역DNS 와, 웹 포트 한정의 가벼운 배너(HTTP Server 헤더 · TLS 인증서 CN)는
 *   discovery_enrich.php 가 수집한다. IP 와 포트 번호만으로는 "이게 뭔지" 를 사람이 매번
 *   손으로 조사해야 했기 때문이다. MAC 은 수집하지 않는다(컨테이너에서 구조적으로 불가 —
 *   discovery_enrich.php 참고).
 */

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/setting.php';
require_once __DIR__ . '/audit.php';
require_once __DIR__ . '/discovery_enrich.php';   // 역DNS·서비스 힌트·배너(정체 파악)

/**
 * 기본값 — 전부 tb_setting 으로 덮을 수 있다(코드에 박아두지 않는다는 원칙).
 *   설정 화면(vg_setting_defs)에 항목이 없어도 vg_setting_int() 는 DB 값을 읽으므로,
 *   운영에서 급히 조일 일이 생기면 tb_setting 에 행 하나만 넣으면 된다.
 */
const VG_DISCOVERY_CONCURRENCY = 512;    // 동시 소켓 수. FD_SETSIZE(1024) 아래여야 한다
const VG_DISCOVERY_TIMEOUT_MS  = 1000;   // connect 타임아웃. LAN RTT 는 1ms 미만이지만
                                         //   총 시간은 '죽은 IP 가 이 값을 다 쓰는 것'이 지배한다
const VG_DISCOVERY_MIN_PREFIX  = 22;     // 허용 최소 프리픽스 = 최대 대역 크기(/22 = 1,022 IP)
const VG_DISCOVERY_MAX_PORTS   = 1024;   // 대역당 2단계 포트 수 상한

/**
 * 스케줄러 틱 한 번이 집행할 자산 탐색 상한. 스캔은 대역 크기에 비례해 길어지므로
 *   (실측: /24 × 포트 100개 = 4.1초, /22 는 그 4배) 상한이 없으면 pending 이 쌓인 만큼
 *   한 틱이 길어져 같은 프로세스의 피드 수집이 그만큼 밀린다.
 *   둘 다 tb_setting 으로 덮을 수 있고, 0 이면 무제한이다(수동 CLI 가 그렇게 쓴다).
 */
const VG_DISCOVERY_TICK_MAX_RUNS   = 1;    // 한 틱에 집행할 run 수
const VG_DISCOVERY_TICK_BUDGET_SEC = 45;   // 한 틱의 집행 시간 예산(초)

/**
 * 'running' 으로 굳은 run 을 실패로 마감하는 임계시간(분).
 *   스캔 도중 프로세스가 죽으면(OOM·컨테이너 재기동) catch 가 못 돌아 run 이 영원히
 *   'running' 으로 남고, 선점 조건이 pending 이라 그 대역은 다시는 집행되지 않는다.
 *   피드 로그의 vg_feed_reap_stale() 과 같은 해법이다(단위만 분 — 스캔은 분 단위로 끝난다).
 */
const VG_DISCOVERY_STALE_MINUTES = 30;

/** select(2) 의 FD_SETSIZE. 이 수를 넘는 fd 가 집합에 들어가면 stream_select 가 조용히 오동작한다. */
const VG_DISCOVERY_FD_SETSIZE = 1024;

/** 1단계 탐침 포트 — 살아있는 장비라면 이 중 하나는 응답(open 이든 closed 든)할 가능성이 높다. */
const VG_DISCOVERY_PROBE_PORTS = '22,80,443,3389,445,8080';

/** 2단계 기본 포트(대역에 ports 가 비어 있을 때). nmap 상위권 100개. */
const VG_DISCOVERY_DEFAULT_PORTS =
    '7,20,21,22,23,25,26,53,79,80,81,88,106,110,111,113,119,135,139,143,144,179,199,389,427,443,'
    . '444,445,465,513,514,515,543,544,548,554,587,631,646,873,990,993,995,1025,1026,1027,1028,'
    . '1029,1110,1433,1720,1723,1755,1900,2000,2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,'
    . '5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000,6001,6379,6646,7070,8000,'
    . '8008,8009,8080,8081,8443,8888,9100,9999,10000,27017,32768,49152,49153,49154,49155,49156,49157';

/** 결과 상태 어휘 — 팀원의 cscan v0.4 JSON schema 와 같은 값이다. 임의로 늘리지 않는다. */
const VG_DISCOVERY_STATES = ['open', 'closed', 'timeout', 'unreachable', 'error'];

/** 결과 문서 스키마 버전(cscan v0.4 와 동일). */
const VG_DISCOVERY_SCHEMA_VERSION = 1;

// ─────────────────────────────────────────────────────────────────────────────
// 설정
// ─────────────────────────────────────────────────────────────────────────────

/**
 * 문자열 설정값. 예전엔 setting.php 에 정수 리더(vg_setting_int)밖에 없어서 여기 따로 있었다 —
 *   지금은 같은 구현이 vg_setting_str() 로 올라갔으므로 호출부를 안 건드리고 위임만 한다.
 */
function vg_discovery_setting_str(string $key, string $default): string {
    return vg_setting_str($key, $default);
}

/**
 * 이 프로세스가 실제로 쓸 스캔 파라미터.
 *   동시 소켓 수는 설정값을 그대로 믿지 않고 FD_SETSIZE 아래로 잘라낸다 — 넘기면
 *   stream_select 가 오동작(조용한 미탐)하므로, 설정 실수로 스캔 결과가 틀리면 안 된다.
 * @return array{concurrency:int, timeout_ms:int, min_prefix:int, max_ports:int, probe_ports:int[], default_ports:string}
 */
function vg_discovery_config(): array {
    $conc = vg_setting_int('discovery.concurrency', VG_DISCOVERY_CONCURRENCY);
    // 여유 64 는 PDO 접속·표준입출력 등 이 프로세스가 이미 들고 있는 fd 몫.
    $conc = max(1, min($conc, VG_DISCOVERY_FD_SETSIZE - 64));
    return [
        'concurrency'   => $conc,
        'timeout_ms'    => max(50, vg_setting_int('discovery.timeout_ms', VG_DISCOVERY_TIMEOUT_MS)),
        'min_prefix'    => max(8, min(32, vg_setting_int('discovery.min_prefix', VG_DISCOVERY_MIN_PREFIX))),
        'max_ports'     => max(1, vg_setting_int('discovery.max_ports', VG_DISCOVERY_MAX_PORTS)),
        'probe_ports'   => vg_discovery_parse_ports(
            vg_discovery_setting_str('discovery.probe_ports', VG_DISCOVERY_PROBE_PORTS),
            VG_DISCOVERY_MAX_PORTS
        ),
        'default_ports' => vg_discovery_setting_str('discovery.default_ports', VG_DISCOVERY_DEFAULT_PORTS),
    ];
}

// ─────────────────────────────────────────────────────────────────────────────
// 대역·포트 파싱
// ─────────────────────────────────────────────────────────────────────────────

/**
 * CIDR 을 스캔 대상 IPv4 목록으로 편다.
 *   상한을 넘으면 **거부한다.** 조용히 잘라내면 잘린 결과를 "다 스캔했다"로 읽어 미탐이 된다.
 *   /31·/32 는 네트워크·브로드캐스트 개념이 없으므로 주소를 그대로 쓴다.
 * @return string[]
 * @throws InvalidArgumentException 형식 오류·상한 초과(메시지는 사용자에게 보여도 되는 수준)
 */
function vg_discovery_expand_cidr(string $cidr, int $minPrefix = VG_DISCOVERY_MIN_PREFIX): array {
    $cidr = trim($cidr);
    if (!preg_match('#^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$#', $cidr, $m)) {
        throw new InvalidArgumentException('대역 형식이 올바르지 않습니다(예: 10.3.142.0/24).');
    }
    [$base, $bits] = [$m[1], (int) $m[2]];
    if (filter_var($base, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false || $bits > 32) {
        throw new InvalidArgumentException('대역 형식이 올바르지 않습니다(예: 10.3.142.0/24).');
    }
    if ($bits < $minPrefix) {
        throw new InvalidArgumentException(sprintf(
            '대역이 너무 큽니다 — /%d 까지만 탐색합니다(요청: /%d).', $minPrefix, $bits
        ));
    }
    $net  = ip2long($base) & (($bits === 0) ? 0 : (-1 << (32 - $bits)));
    $size = ($bits >= 31) ? (1 << (32 - $bits)) : (1 << (32 - $bits)) - 2;
    $first = ($bits >= 31) ? $net : $net + 1;

    $ips = [];
    for ($i = 0; $i < $size; $i++) {
        $ips[] = long2ip($first + $i);
    }
    return $ips;
}

/**
 * 포트 명세('22,80,8000-8010')를 정수 배열로. 중복 제거 + 정렬.
 *   상한을 넘으면 거부한다(대역 상한과 같은 이유 — 잘린 스캔은 미탐이다).
 * @return int[]
 * @throws InvalidArgumentException
 */
function vg_discovery_parse_ports(string $spec, int $max = VG_DISCOVERY_MAX_PORTS): array {
    $ports = [];
    foreach (preg_split('/[\s,]+/', trim($spec), -1, PREG_SPLIT_NO_EMPTY) ?: [] as $tok) {
        if (preg_match('/^(\d{1,5})-(\d{1,5})$/', $tok, $m)) {
            [$lo, $hi] = [(int) $m[1], (int) $m[2]];
            if ($lo < 1 || $hi > 65535 || $lo > $hi) {
                throw new InvalidArgumentException("포트 범위가 올바르지 않습니다: $tok");
            }
            for ($p = $lo; $p <= $hi; $p++) { $ports[$p] = true; }
        } elseif (preg_match('/^\d{1,5}$/', $tok)) {
            $p = (int) $tok;
            if ($p < 1 || $p > 65535) {
                throw new InvalidArgumentException("포트 번호가 올바르지 않습니다: $tok");
            }
            $ports[$p] = true;
        } else {
            throw new InvalidArgumentException("포트 명세를 해석할 수 없습니다: $tok");
        }
        if (count($ports) > $max) {
            throw new InvalidArgumentException("포트가 너무 많습니다 — 최대 {$max}개까지 탐색합니다.");
        }
    }
    $list = array_keys($ports);
    sort($list);
    return $list;
}

// ─────────────────────────────────────────────────────────────────────────────
// 스윕 (병렬 TCP connect)
// ─────────────────────────────────────────────────────────────────────────────

/** 결과 한 줄. cscan v0.4 와 같은 키·순서. */
function vg_discovery_result(string $ip, int $port, string $state): array {
    return ['host' => $ip, 'port' => $port, 'protocol' => 'tcp', 'state' => $state];
}

/** connect 즉시 실패의 errno 를 상태 어휘로. 라우팅이 없으면 unreachable, 나머지는 error. */
function vg_discovery_errno_state(int $errno): string {
    // 101 ENETUNREACH · 113 EHOSTUNREACH (Linux). 그 외는 우리 쪽 문제일 수 있어 error 로 남긴다.
    return in_array($errno, [101, 113], true) ? 'unreachable' : 'error';
}

/**
 * (IP,포트) 쌍 목록을 병렬로 훑는다. 동시 소켓 수만큼 배치로 쪼개 돈다.
 * @param array<int, array{0:string,1:int}> $pairs
 * @return array<int, array{host:string,port:int,protocol:string,state:string}>
 */
function vg_discovery_sweep(array $pairs, int $timeoutMs, int $concurrency): array {
    $results = [];
    foreach (array_chunk($pairs, max(1, $concurrency)) as $chunk) {
        foreach (vg_discovery_sweep_chunk($chunk, $timeoutMs) as $r) {
            $results[] = $r;
        }
    }
    return $results;
}

/**
 * 배치 하나(최대 동시 소켓 수)를 열고 결과가 나올 때까지 기다린다.
 *
 *   판정: stream_select 의 write 집합에 올라온 소켓에 대해 stream_socket_get_name($s, true) 가
 *   주소를 주면 연결 성공(open), false 면 커널이 거절(closed)한 것이다.
 *
 *   ★ 타임아웃된 소켓은 stream_select 가 알려주지 않으므로 **직접 닫아 회수한다.**
 *     안 닫으면 배치가 진행될수록 fd 가 쌓여 느려지다 결국 열리지 않는다.
 *   ★ 모든 경로에서 소켓은 정확히 한 번만 닫는다 — 판정 직후 fclose + $live 에서 제거,
 *     남은 것은 마지막 루프에서 한 번.
 * @param array<int, array{0:string,1:int}> $chunk
 */
function vg_discovery_sweep_chunk(array $chunk, int $timeoutMs): array {
    $results = [];
    $live    = [];   // resource_id => ['sock'=>resource, 'ip'=>string, 'port'=>int]

    foreach ($chunk as [$ip, $port]) {
        $errno  = 0;
        $errstr = '';
        // 타임아웃 인자(4번째)는 ASYNC 에서 의미가 없다 — 만료는 아래 select 루프가 관리한다.
        $sock = @stream_socket_client(
            sprintf('tcp://%s:%d', $ip, $port),
            $errno,
            $errstr,
            0,
            STREAM_CLIENT_ASYNC_CONNECT | STREAM_CLIENT_CONNECT
        );
        if ($sock === false) {
            $results[] = vg_discovery_result($ip, $port, vg_discovery_errno_state($errno));
            continue;
        }
        stream_set_blocking($sock, false);
        $live[get_resource_id($sock)] = ['sock' => $sock, 'ip' => $ip, 'port' => $port];
    }

    $deadline = microtime(true) + ($timeoutMs / 1000);
    while ($live !== []) {
        $remain = $deadline - microtime(true);
        if ($remain <= 0) { break; }

        $write  = [];
        $except = [];
        foreach ($live as $id => $c) {
            $write[$id]  = $c['sock'];
            $except[$id] = $c['sock'];
        }
        $read = null;
        $n = @stream_select($read, $write, $except, (int) $remain, (int) (fmod($remain, 1.0) * 1000000));
        if ($n === false) {
            // 시그널 등으로 select 가 깨졌다. 남은 소켓은 아래에서 timeout 으로 회수한다.
            break;
        }
        if ($n === 0) { break; }   // 기한 만료

        foreach (array_merge(array_values($write), array_values($except)) as $sock) {
            $id = get_resource_id($sock);
            if (!isset($live[$id])) { continue; }   // write·except 양쪽에 올라온 같은 소켓
            $c = $live[$id];
            $state = (@stream_socket_get_name($sock, true) !== false) ? 'open' : 'closed';
            $results[] = vg_discovery_result($c['ip'], $c['port'], $state);
            fclose($sock);
            unset($live[$id]);
        }
    }

    foreach ($live as $c) {
        fclose($c['sock']);
        $results[] = vg_discovery_result($c['ip'], $c['port'], 'timeout');
    }
    return $results;
}

/**
 * 대역 하나를 2단계로 스캔하고 cscan v0.4 모양의 결과 문서를 만든다.
 *   문서에는 1단계 전체와 2단계의 응답분(open/closed)만 담는다 — 2단계 타임아웃까지 담으면
 *   문서가 조합 수만큼 커지는데, 그 수는 stats 로 이미 정확히 전달된다.
 * @return array{schema_version:int, scan:array, stats:array, results:array}
 */
function vg_discovery_scan_cidr(string $cidr, ?string $portSpec, ?array $cfg = null): array {
    $cfg   = $cfg ?? vg_discovery_config();
    $ips   = vg_discovery_expand_cidr($cidr, $cfg['min_prefix']);
    $probe = $cfg['probe_ports'];
    $ports = vg_discovery_parse_ports(
        ($portSpec !== null && trim($portSpec) !== '') ? $portSpec : $cfg['default_ports'],
        $cfg['max_ports']
    );

    // 1단계 — 대역 전체 × 탐침 포트
    $pairs = [];
    foreach ($ips as $ip) {
        foreach ($probe as $p) { $pairs[] = [$ip, $p]; }
    }
    $stage1  = vg_discovery_sweep($pairs, $cfg['timeout_ms'], $cfg['concurrency']);
    $checked = count($stage1);

    // 응답이 있었으면(open 이든 closed 든) 그 자리에 장비가 있다. 무응답 IP 는 2단계를 건너뛴다.
    $alive = [];
    foreach ($stage1 as $r) {
        if ($r['state'] === 'open' || $r['state'] === 'closed') { $alive[$r['host']] = true; }
    }

    // 2단계 — 살아있는 IP × 전체 포트(1단계에서 이미 본 포트는 뺀다)
    $rest  = array_values(array_diff($ports, $probe));
    $pairs = [];
    foreach (array_keys($alive) as $ip) {
        foreach ($rest as $p) { $pairs[] = [$ip, $p]; }
    }
    $stage2   = vg_discovery_sweep($pairs, $cfg['timeout_ms'], $cfg['concurrency']);
    $checked += count($stage2);

    $results = $stage1;
    foreach ($stage2 as $r) {
        if ($r['state'] !== 'timeout') { $results[] = $r; }
    }

    // 3단계 — 정체 파악. 살아있는 IP 의 역DNS 와, 웹 포트에 한한 배너.
    //   실패는 전부 빈 값으로 흡수된다(강화는 부가정보라 스캔을 실패시키지 않는다).
    //   결과는 results 옆의 **선택 키** enrich 로 나른다 — results 의 모양(cscan v0.4)을
    //   바꾸면 원격 스캐너가 보내는 문서와 갈라지므로, 스키마 버전은 그대로 두고 더하기만 한다.
    $enrichCfg = vg_discovery_enrich_config();
    $openMap   = [];
    foreach ($results as $r) {
        if ($r['state'] === 'open') { $openMap[$r['host']][(int) $r['port']] = $r['protocol']; }
    }
    $enrich = [
        'hostnames' => vg_discovery_reverse_dns(array_keys($alive), $enrichCfg),
        'banners'   => vg_discovery_collect_banners($openMap, $enrichCfg),
    ];

    return [
        'schema_version' => VG_DISCOVERY_SCHEMA_VERSION,
        'scan'  => ['type' => 'tcp-connect', 'timeout_ms' => $cfg['timeout_ms']],
        'stats' => [
            'ip_total'     => count($ips),
            'ip_alive'     => count($alive),
            'port_checked' => $checked,
        ],
        'results' => $results,
        'enrich'  => $enrich,
    ];
}

// ─────────────────────────────────────────────────────────────────────────────
// 저장
// ─────────────────────────────────────────────────────────────────────────────

/**
 * 결과 문서를 DB 에 반영한다. **원격 스캐너(cscan)의 결과도 같은 함수로 들어온다** —
 *   중앙이 결과를 받는 이음매는 이 함수 하나뿐이고, 그 위에 엔진 인터페이스를 두지 않는다.
 *
 *   - tb_discovered_port 에는 open 만 넣는다(closed/timeout 은 집계 port_checked 로만).
 *   - tb_discovered_asset 은 (target, ip) 로 upsert — 대역 기준 누적이라 run 마다 갈아엎지 않는다.
 *   - state='ignored' 는 사람이 정한 값이라 자동 판정이 덮지 않는다.
 *   - 강화값(enrich)은 **선택**이다. 원격 스캐너(cscan)가 안 보내면 그냥 비어 있다.
 *     호스트명은 **빈 값으로 덮지 않는다** — 이번에 DNS 가 안 떴다고 지난번에 얻은 이름을
 *     지우면 정보가 사라진다(COALESCE).
 * @return array{ip_alive:int, open_total:int, port_checked:int, ip_total:int, matched:int, hostnames:int, banners:int}
 */
function vg_discovery_store_results(PDO $pdo, int $runId, array $doc): array {
    if ((int) ($doc['schema_version'] ?? 0) !== VG_DISCOVERY_SCHEMA_VERSION) {
        throw new InvalidArgumentException('결과 문서의 스키마 버전을 지원하지 않습니다.');
    }
    $st = $pdo->prepare('SELECT discovery_target_id FROM tb_discovery_run WHERE discovery_run_id = ?');
    $st->execute([$runId]);
    $targetId = $st->fetchColumn();
    if ($targetId === false) {
        throw new InvalidArgumentException('탐색 기록을 찾을 수 없습니다.');
    }
    $targetId = (int) $targetId;

    $alive = [];   // ip => true
    $open  = [];   // ip => [port => proto]
    $seen  = 0;
    foreach ((array) ($doc['results'] ?? []) as $r) {
        $ip    = (string) ($r['host'] ?? '');
        $port  = (int) ($r['port'] ?? 0);
        $state = (string) ($r['state'] ?? '');
        $proto = (string) ($r['protocol'] ?? 'tcp');
        if (filter_var($ip, FILTER_VALIDATE_IP) === false || $port < 1 || $port > 65535) { continue; }
        if (!in_array($state, VG_DISCOVERY_STATES, true)) { continue; }
        $seen++;
        if ($state === 'open' || $state === 'closed') { $alive[$ip] = true; }
        if ($state === 'open') { $open[$ip][$port] = substr($proto, 0, 8) ?: 'tcp'; }
    }

    /* 강화값 — 문서가 주는 대로 받되 이 자리에서 형식을 확정한다(원격 스캐너도 같은 함수로
     *   들어오므로, 여기가 신뢰 경계다). 유효하지 않은 값은 조용히 버린다. */
    $hostnames = [];
    foreach ((array) (($doc['enrich']['hostnames'] ?? [])) as $ip => $name) {
        $ip   = (string) $ip;
        $name = trim((string) $name);
        if (!isset($alive[$ip]) || $name === '') { continue; }
        if (!vg_discovery_valid_hostname($name, $ip)) { continue; }
        $hostnames[$ip] = mb_substr($name, 0, 255);
    }
    $banners = [];
    foreach ((array) (($doc['enrich']['banners'] ?? [])) as $ip => $ports) {
        foreach ((array) $ports as $port => $banner) {
            $port   = (int) $port;
            $banner = vg_discovery_clean_banner((string) $banner);
            if (!isset($open[(string) $ip][$port]) || $banner === '') { continue; }
            $banners[(string) $ip][$port] = $banner;
        }
    }

    // stats 가 있으면 그것이 정확하다(문서에 안 담은 2단계 타임아웃까지 센 값).
    $stats       = (array) ($doc['stats'] ?? []);
    $ipTotal     = (int) ($stats['ip_total'] ?? count($alive));
    $portChecked = (int) ($stats['port_checked'] ?? $seen);
    $openTotal   = 0;
    foreach ($open as $ports) { $openTotal += count($ports); }

    $now = date('Y-m-d H:i:s');
    $pdo->beginTransaction();
    try {
        $up = $pdo->prepare(
            'INSERT INTO tb_discovered_asset
                (discovery_target_id, ip, hostname, first_seen, last_seen, last_run_id)
             VALUES (?,?,?,?,?,?)
             ON DUPLICATE KEY UPDATE
                last_seen   = VALUES(last_seen),
                last_run_id = VALUES(last_run_id),
                hostname    = COALESCE(VALUES(hostname), hostname),
                is_deleted  = 0,
                deleted_at  = NULL'
        );
        foreach (array_keys($alive) as $ip) {
            $up->execute([$targetId, $ip, $hostnames[$ip] ?? null, $now, $now, $runId]);
        }

        // 방금 upsert 한 행은 전부 last_run_id 가 이 run 이다 — IN 절 없이 한 번에 집는다.
        $sel = $pdo->prepare(
            'SELECT ip, discovered_asset_id FROM tb_discovered_asset
              WHERE discovery_target_id = ? AND last_run_id = ?'
        );
        $sel->execute([$targetId, $runId]);
        $assetId = [];
        foreach ($sel->fetchAll() as $row) {
            $assetId[(string) $row['ip']] = (int) $row['discovered_asset_id'];
        }

        /* 같은 run 을 다시 저장하면(재시도) 힌트·배너는 **채워진 값만** 갱신한다 —
         *   INSERT IGNORE 였다면 두 번째 저장이 통째로 버려져 배너가 영영 안 붙는다. */
        $ins = $pdo->prepare(
            'INSERT INTO tb_discovered_port
                (discovered_asset_id, discovery_run_id, port, proto, service_hint, banner)
             VALUES (?,?,?,?,?,?)
             ON DUPLICATE KEY UPDATE
                service_hint = VALUES(service_hint),
                banner       = COALESCE(VALUES(banner), banner),
                is_deleted   = 0,
                deleted_at   = NULL'
        );
        foreach ($open as $ip => $ports) {
            if (!isset($assetId[$ip])) { continue; }
            foreach ($ports as $port => $proto) {
                $ins->execute([
                    $assetId[$ip], $runId, $port, $proto,
                    vg_discovery_service_hint((int) $port),
                    $banners[$ip][$port] ?? null,
                ]);
            }
        }

        // 기존 자산과 IP 대조. ignored 는 사람의 판단이라 건드리지 않는다.
        //   같은 IP 를 가진 호스트가 여러 개면 가장 작은 host_id 로 고정한다(결정적 선택).
        $match = $pdo->prepare(
            "UPDATE tb_discovered_asset da
                SET da.host_id = (
                      SELECT MIN(ha.host_id) FROM tb_host_address ha
                        JOIN tb_host h ON h.host_id = ha.host_id AND h.is_deleted = 0
                       WHERE ha.ip = da.ip AND ha.is_deleted = 0
                    ),
                    da.state = 'known'
              WHERE da.discovery_target_id = ? AND da.last_run_id = ? AND da.state <> 'ignored'
                AND EXISTS (
                      SELECT 1 FROM tb_host_address ha2
                        JOIN tb_host h2 ON h2.host_id = ha2.host_id AND h2.is_deleted = 0
                       WHERE ha2.ip = da.ip AND ha2.is_deleted = 0
                    )"
        );
        $match->execute([$targetId, $runId]);
        $matched = $match->rowCount();

        // 대조 안 된 것은 섀도우 IT 후보. 예전에 매칭됐다가 호스트가 사라진 경우도 여기로 돌아온다.
        $unmatch = $pdo->prepare(
            "UPDATE tb_discovered_asset da
                SET da.host_id = NULL, da.state = 'new'
              WHERE da.discovery_target_id = ? AND da.last_run_id = ? AND da.state <> 'ignored'
                AND NOT EXISTS (
                      SELECT 1 FROM tb_host_address ha
                        JOIN tb_host h ON h.host_id = ha.host_id AND h.is_deleted = 0
                       WHERE ha.ip = da.ip AND ha.is_deleted = 0
                    )"
        );
        $unmatch->execute([$targetId, $runId]);

        $pdo->commit();
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) { $pdo->rollBack(); }
        throw $e;
    }

    $bannerCount = 0;
    foreach ($banners as $ports) { $bannerCount += count($ports); }

    return [
        'ip_total'     => $ipTotal,
        'ip_alive'     => count($alive),
        'port_checked' => $portChecked,
        'open_total'   => $openTotal,
        'matched'      => $matched,
        'hostnames'    => count($hostnames),
        'banners'      => $bannerCount,
    ];
}

// ─────────────────────────────────────────────────────────────────────────────
// run 수명주기
// ─────────────────────────────────────────────────────────────────────────────

/** 대역 1건에 대해 pending run 을 만든다. 화면(UI)도 같은 상태의 행만 만들고 집행은 CLI 가 한다. */
function vg_discovery_create_run(PDO $pdo, int $targetId, ?int $userId = null): int {
    $st = $pdo->prepare(
        'SELECT discovery_target_id FROM tb_discovery_target
          WHERE discovery_target_id = ? AND is_deleted = 0 AND enabled = 1'
    );
    $st->execute([$targetId]);
    if ($st->fetchColumn() === false) {
        throw new InvalidArgumentException('탐색할 수 있는 대역이 아닙니다(없거나 비활성).');
    }
    $pdo->prepare(
        "INSERT INTO tb_discovery_run (discovery_target_id, status, created_by) VALUES (?, 'pending', ?)"
    )->execute([$targetId, $userId]);
    return (int) $pdo->lastInsertId();
}

/**
 * run 을 선점한다. 두 프로세스가 같은 run 을 집어가지 않게 pending → running 을 조건부 UPDATE 로
 *   바꾸고, 실제로 1행을 바꾼 쪽만 집행한다(SELECT 후 UPDATE 면 사이에 낄 수 있다).
 */
function vg_discovery_claim_run(PDO $pdo, int $runId): bool {
    $st = $pdo->prepare(
        "UPDATE tb_discovery_run SET status = 'running', started_at = NOW(), error_text = NULL
          WHERE discovery_run_id = ? AND status = 'pending' AND is_deleted = 0"
    );
    $st->execute([$runId]);
    return $st->rowCount() === 1;
}

/** 집행 대기 중인 run 의 id 목록(오래된 것부터). */
function vg_discovery_pending_run_ids(PDO $pdo): array {
    $rows = $pdo->query(
        "SELECT discovery_run_id FROM tb_discovery_run
          WHERE status = 'pending' AND is_deleted = 0 ORDER BY discovery_run_id"
    )->fetchAll();
    return array_map(static fn(array $r): int => (int) $r['discovery_run_id'], $rows);
}

/**
 * 시작 후 임계시간을 넘긴 'running' run 을 실패로 마감한다.
 *   반환값은 마감한 건수. 스케줄러 틱이 집행 전에 부른다 — 회수하지 않으면 그 대역은
 *   pending 선점 조건(status='pending')에 영원히 걸리지 않아 다시는 스캔되지 않는다.
 */
function vg_discovery_reap_stale(PDO $pdo, ?int $minutes = null): int {
    // SQL 의 INTERVAL 에 직접 넣으므로 정수로 못박는다(vg_feed_reap_stale 과 같은 이유).
    $minutes = max(1, $minutes ?? vg_setting_int('discovery.stale_minutes', VG_DISCOVERY_STALE_MINUTES));
    $st = $pdo->prepare(
        "UPDATE tb_discovery_run
            SET status = 'failed', finished_at = NOW(), error_text = ?
          WHERE status = 'running' AND is_deleted = 0
            AND started_at IS NOT NULL AND started_at < NOW() - INTERVAL $minutes MINUTE"
    );
    $st->execute(["중단된 탐색으로 판단해 정리(시작 후 {$minutes}분 초과)"]);
    return $st->rowCount();
}

/**
 * 대기 중인 run 을 상한 안에서 집행한다 — **스케줄러 틱과 CLI(--pending)가 같이 쓰는 한 곳**이다.
 *   집행 로직을 두 벌로 만들면 한쪽만 고쳐져 화면과 수동 실행이 다르게 동작한다.
 *
 *   $maxRuns·$budgetSec 은 null 이면 설정(tb_setting)에서 읽고, **0 이면 무제한**이다.
 *   시간 예산은 run 을 **시작하기 전**에만 본다 — 스캔 도중에 끊으면 그 run 이 어중간하게
 *   남으므로, 시작한 것은 끝까지 돌린다(예산은 초과할 수 있고, 초과분은 다음 틱으로 밀린다).
 *
 * @return array{executed:int, ok:int, failed:int, skipped:int, deferred:int, results:array<int,array>}
 */
function vg_discovery_run_pending(PDO $pdo, ?int $maxRuns = null, ?int $budgetSec = null): array {
    $maxRuns   = max(0, $maxRuns   ?? vg_setting_int('discovery.tick_max_runs', VG_DISCOVERY_TICK_MAX_RUNS));
    $budgetSec = max(0, $budgetSec ?? vg_setting_int('discovery.tick_budget_sec', VG_DISCOVERY_TICK_BUDGET_SEC));

    $t0  = microtime(true);
    $out = ['executed' => 0, 'ok' => 0, 'failed' => 0, 'skipped' => 0, 'deferred' => 0, 'results' => []];

    foreach (vg_discovery_pending_run_ids($pdo) as $runId) {
        if ($maxRuns > 0 && $out['executed'] >= $maxRuns) { $out['deferred']++; continue; }
        if ($budgetSec > 0 && (microtime(true) - $t0) >= $budgetSec) { $out['deferred']++; continue; }
        // 선점 실패 = 다른 프로세스(수동 CLI 등)가 이미 집어갔다. 조용히 넘기지 않고 센다.
        if (!vg_discovery_claim_run($pdo, $runId)) { $out['skipped']++; continue; }

        $out['executed']++;
        try {
            $r = vg_discovery_execute_run($pdo, $runId);
        } catch (Throwable $e) {
            // execute_run 은 스캔 실패를 스스로 닫지만, run 행 자체가 사라진 경우 등은 던진다.
            //   한 run 의 실패가 남은 run 과 호출자(스케줄러 틱)를 죽이면 안 된다.
            error_log('[discovery] run ' . $runId . ' 집행 예외: ' . $e->getMessage());
            $r = ['ok' => false, 'run_id' => $runId, 'cidr' => '', 'error' => '대역 탐색을 집행할 수 없습니다.'];
            try {
                $pdo->prepare(
                    "UPDATE tb_discovery_run SET status = 'failed', finished_at = NOW(), error_text = ?
                      WHERE discovery_run_id = ?"
                )->execute([$r['error'], $runId]);
            } catch (Throwable $e2) {
                error_log('[discovery] run ' . $runId . ' 상태 기록 실패: ' . $e2->getMessage());
            }
        }
        $out['results'][] = $r;
        if (!empty($r['ok'])) { $out['ok']++; } else { $out['failed']++; }
    }
    return $out;
}

/**
 * 선점한 run 을 실제로 집행한다(스캔 → 저장 → 집계 반영 → 감사로그).
 *   실패하면 status='failed' 와 **일반화된** error_text 를 남긴다 — 예외 원문(SQL·경로·
 *   스택트레이스)은 서버 로그로만 간다.
 * @return array{ok:bool, run_id:int, cidr:string, elapsed:float, ...}
 */
function vg_discovery_execute_run(PDO $pdo, int $runId, string $actorType = 'SYSTEM', ?int $userId = null): array {
    $st = $pdo->prepare(
        'SELECT r.discovery_run_id, r.discovery_target_id, t.cidr, t.ports
           FROM tb_discovery_run r
           JOIN tb_discovery_target t ON t.discovery_target_id = r.discovery_target_id
          WHERE r.discovery_run_id = ?'
    );
    $st->execute([$runId]);
    $row = $st->fetch();
    if ($row === false) {
        throw new InvalidArgumentException('탐색 기록을 찾을 수 없습니다.');
    }
    $cidr = (string) $row['cidr'];
    $t0   = microtime(true);

    try {
        $doc     = vg_discovery_scan_cidr($cidr, $row['ports'] !== null ? (string) $row['ports'] : null);
        $counts  = vg_discovery_store_results($pdo, $runId, $doc);
        $elapsed = round(microtime(true) - $t0, 2);

        $pdo->prepare(
            "UPDATE tb_discovery_run
                SET status = 'done', finished_at = NOW(), ip_total = ?, ip_alive = ?,
                    port_checked = ?, open_total = ?, elapsed_seconds = ?, error_text = NULL
              WHERE discovery_run_id = ?"
        )->execute([
            $counts['ip_total'], $counts['ip_alive'], $counts['port_checked'],
            $counts['open_total'], $elapsed, $runId,
        ]);

        vg_log_activity(
            $pdo, 'DISCOVERY', $runId, 'discovery_scan',
            sprintf('대역 탐색 완료 — %s', $cidr),
            $counts + ['cidr' => $cidr, 'elapsed_seconds' => $elapsed],
            $userId, $actorType, null, $cidr, 'EXECUTE'
        );

        return ['ok' => true, 'run_id' => $runId, 'cidr' => $cidr, 'elapsed' => $elapsed] + $counts;
    } catch (Throwable $e) {
        error_log('[discovery] run ' . $runId . ' 실패: ' . $e->getMessage());
        // 입력 오류(대역·포트 형식)는 사용자가 고칠 수 있는 정보라 그대로 보여준다.
        //   그 밖의 예외는 원문을 감춘다.
        $msg = $e instanceof InvalidArgumentException
            ? $e->getMessage()
            : '탐색 중 오류가 발생했습니다. 서버 로그를 확인하세요.';
        try {
            $pdo->prepare(
                "UPDATE tb_discovery_run
                    SET status = 'failed', finished_at = NOW(), elapsed_seconds = ?, error_text = ?
                  WHERE discovery_run_id = ?"
            )->execute([round(microtime(true) - $t0, 2), $msg, $runId]);
        } catch (Throwable $e2) {
            error_log('[discovery] run ' . $runId . ' 상태 기록 실패: ' . $e2->getMessage());
        }
        vg_log_activity(
            $pdo, 'DISCOVERY', $runId, 'discovery_scan_fail',
            sprintf('대역 탐색 실패 — %s', $cidr),
            ['cidr' => $cidr, 'reason' => $msg],
            $userId, $actorType, null, $cidr, 'EXECUTE'
        );
        return ['ok' => false, 'run_id' => $runId, 'cidr' => $cidr, 'error' => $msg];
    }
}
