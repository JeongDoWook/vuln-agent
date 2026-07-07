<?php
declare(strict_types=1);

/**
 * ingest.php — 수집 에이전트가 보낸 JSON 을 받아 중앙 DB 에 저장한다.
 *   인증 : 공유 토큰 (헤더 X-Agent-Token 또는 Authorization: Bearer)
 *   본문 : vuln-inventory-agent.sh (jq 모드) 가 만든 JSON
 *   저장 : hosts → scans → packages / exposures  (하나의 트랜잭션)
 */

header('Content-Type: application/json; charset=utf-8');

$cfg = require __DIR__ . '/../src/config.php';
require __DIR__ . '/../src/db.php';

function respond_fail(int $code, string $msg): void {
    http_response_code($code);
    echo json_encode(['ok' => false, 'error' => $msg], JSON_UNESCAPED_UNICODE);
    exit;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    respond_fail(405, 'POST only');
}

// ── 인증 : 공유 토큰 상수시간 비교 ─────────────────────────────
$expected = (string) ($cfg['ingest_token'] ?? '');
$provided = $_SERVER['HTTP_X_AGENT_TOKEN'] ?? '';
if ($provided === '' && !empty($_SERVER['HTTP_AUTHORIZATION'])) {
    if (preg_match('/Bearer\s+(.+)/i', $_SERVER['HTTP_AUTHORIZATION'], $m)) {
        $provided = trim($m[1]);
    }
}
if ($expected === '' || !hash_equals($expected, (string) $provided)) {
    respond_fail(401, 'unauthorized');
}

// ── 본문 파싱 ─────────────────────────────────────────────────
$raw = file_get_contents('php://input');
if ($raw === false || $raw === '') {
    respond_fail(400, 'empty body');
}
$data = json_decode($raw, true);
if (!is_array($data)) {
    respond_fail(400, 'invalid json');
}

$meta = $data['meta']         ?? [];
$vm   = $data['vuln_mapping'] ?? [];
$sys  = $data['system']       ?? [];
$pkg  = $data['pkg']          ?? [];
$exp  = $data['exposure']     ?? [];

$fqdn = trim((string) ($meta['hostname_fqdn'] ?? '')) ?: 'unknown';

// collected_at (ISO-8601) → MySQL DATETIME
$collectedAt = null;
if (!empty($meta['collected_at'])) {
    $ts = strtotime((string) $meta['collected_at']);
    if ($ts !== false) {
        $collectedAt = date('Y-m-d H:i:s', $ts);
    }
}

// ── 패키지 목록 파싱 (매니저별 TSV) ──────────────────────────
$manager = (string) ($pkg['manager'] ?? '');
$pkgRows = [];
if (!empty($pkg['list'])) {
    foreach (preg_split('/\r?\n/', (string) $pkg['list']) as $line) {
        if ($line === '') { continue; }
        $f    = explode("\t", $line);
        $name = trim($f[0] ?? '');
        if ($name === '') { continue; }
        if ($manager === 'rpm') {
            // name \t epoch:version-release \t arch \t sourcerpm \t vendor
            $pkgRows[] = [$name, $f[1] ?? '', $f[2] ?? '', $f[3] ?? '', $f[4] ?? ''];
        } else {
            // dpkg: name \t version \t arch \t source_pkg \t source_version \t status
            $pkgRows[] = [$name, $f[1] ?? '', $f[2] ?? '', $f[3] ?? '', ''];
        }
    }
}
$pkgCount = count($pkgRows);

// ── 노출 상관 파싱 (pipe 구분, 첫 줄은 헤더) ─────────────────
$expRows = [];
if (!empty($exp['correlation'])) {
    foreach (preg_split('/\r?\n/', (string) $exp['correlation']) as $line) {
        if ($line === '') { continue; }
        if (strncmp($line, 'pid|proc|proto', 14) === 0) { continue; } // 헤더 스킵
        $f = explode('|', $line);
        if (count($f) < 8) { continue; }
        $expRows[] = $f; // pid,proc,proto,bind,port,scope,exe_pkg,loaded_pkgs
    }
}
$expCount = count($expRows);

// ── 저장 (트랜잭션) ──────────────────────────────────────────
try {
    $pdo = vg_pdo();
    $pdo->beginTransaction();

    // 호스트 upsert (fqdn 유니크). LAST_INSERT_ID 트릭으로 기존 id 회수.
    $stmt = $pdo->prepare(
        'INSERT INTO hosts (fqdn, hostname, os_id, os_version, first_seen, last_seen)
         VALUES (:fqdn, :hn, :osid, :osver, NOW(), NOW())
         ON DUPLICATE KEY UPDATE
            hostname   = VALUES(hostname),
            os_id      = VALUES(os_id),
            os_version = VALUES(os_version),
            last_seen  = NOW(),
            id         = LAST_INSERT_ID(id)'
    );
    $stmt->execute([
        ':fqdn'  => $fqdn,
        ':hn'    => $fqdn,
        ':osid'  => ($vm['distro_id'] ?? '') ?: null,
        ':osver' => ($vm['distro_version'] ?? '') ?: null,
    ]);
    $hostId = (int) $pdo->lastInsertId();

    // 스캔 1행
    $stmt = $pdo->prepare(
        'INSERT INTO scans
            (host_id, collected_at, agent_version, elapsed_seconds,
             os_id, os_version, kernel, cpe, package_family,
             package_count, exposure_count, raw_json)
         VALUES
            (:h, :ca, :av, :el, :osid, :osver, :kern, :cpe, :fam, :pc, :ec, :raw)'
    );
    $stmt->execute([
        ':h'     => $hostId,
        ':ca'    => $collectedAt,
        ':av'    => ($meta['agent_version'] ?? '') ?: null,
        ':el'    => isset($meta['elapsed_seconds']) ? (int) $meta['elapsed_seconds'] : null,
        ':osid'  => ($vm['distro_id'] ?? '') ?: null,
        ':osver' => ($vm['distro_version'] ?? '') ?: null,
        ':kern'  => ($sys['kernel_release'] ?? ($sys['kernel'] ?? '')) ?: null,
        ':cpe'   => ($vm['cpe_name'] ?? '') ?: null,
        ':fam'   => ($vm['package_family'] ?? '') ?: null,
        ':pc'    => $pkgCount,
        ':ec'    => $expCount,
        ':raw'   => $raw,
    ]);
    $scanId = (int) $pdo->lastInsertId();

    // 패키지 벌크
    if ($pkgCount > 0) {
        $ins = $pdo->prepare(
            'INSERT INTO packages (scan_id, manager, name, version, arch, source_pkg, vendor)
             VALUES (?, ?, ?, ?, ?, ?, ?)'
        );
        foreach ($pkgRows as $r) {
            $ins->execute([$scanId, $manager, $r[0], $r[1], $r[2], $r[3], $r[4]]);
        }
    }

    // 노출 벌크
    if ($expCount > 0) {
        $ins = $pdo->prepare(
            'INSERT INTO exposures
                (scan_id, pid, proc, proto, bind_addr, port, scope, exe_pkg, loaded_pkgs)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
        );
        foreach ($expRows as $f) {
            $ins->execute([
                $scanId,
                ($f[0] !== '' ? (int) $f[0] : null),
                $f[1], $f[2], $f[3],
                ($f[4] !== '' ? (int) $f[4] : null),
                $f[5], $f[6], $f[7],
            ]);
        }
    }

    $pdo->commit();
} catch (Throwable $e) {
    if (isset($pdo) && $pdo->inTransaction()) {
        $pdo->rollBack();
    }
    respond_fail(500, 'db error: ' . $e->getMessage());
}

echo json_encode([
    'ok'        => true,
    'host_id'   => $hostId,
    'scan_id'   => $scanId,
    'fqdn'      => $fqdn,
    'packages'  => $pkgCount,
    'exposures' => $expCount,
], JSON_UNESCAPED_UNICODE);
