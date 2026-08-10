<?php
declare(strict_types=1);

/**
 * sbom.php — 스캔 하나의 설치 패키지 목록을 표준 SBOM 문서로 내보내는 읽기 API.
 *
 *   용도: 외부 SBOM 도구(취약점 스캐너·라이선스 감사·공급망 검증)가 자산별 부품표를 가져간다.
 *   인증: export.php 와 같은 읽기 토큰(X-API-Token 또는 Authorization: Bearer).
 *   범위: **자산 하나당 문서 하나.** host 또는 scan_id 를 반드시 지정한다 —
 *         여러 호스트를 한 문서에 담으면 CycloneDX/SPDX 어느 쪽으로도 의미가 없다.
 *         호스트 자신의 패키지(container_id = 0)만 담는다. 컨테이너별 SBOM 은 범위 밖.
 *         의존 엣지(dependencies/relationships)는 넣지 않는다 — 호스트 패키지는 대부분
 *         엣지가 비어 있어 반쪽짜리 그래프가 나간다(#516).
 *
 *   예:
 *     GET /sbom.php?host=web01.example.com                  (기본 cyclonedx)
 *     GET /sbom.php?host=web01.example.com&format=spdx
 *     GET /sbom.php?scan_id=1234&format=cyclonedx
 *     curl -H "X-API-Token: <토큰>" "https://…/sbom.php?host=web01.example.com" -o sbom.json
 */

require __DIR__ . '/../src/config.php';   // vg_auth_token
require __DIR__ . '/../src/db.php';       // vg_pdo, vg_latest_scan_subq
require_once __DIR__ . '/../src/apitoken.php';
require_once __DIR__ . '/../src/audit.php';
require_once __DIR__ . '/../src/purl.php';

const VG_SBOM_FORMATS       = ['cyclonedx', 'spdx'];
const VG_SBOM_CDX_SPEC      = '1.5';
const VG_SBOM_SPDX_SPEC     = 'SPDX-2.3';
const VG_SBOM_SPDX_LICENSE  = 'CC0-1.0';
const VG_SBOM_NOASSERTION   = 'NOASSERTION';
const VG_SBOM_TOOL_NAME     = 'vuln-agent';
const VG_SBOM_TOOL_VERSION  = '1.0';
// 결정적 UUIDv5 네임스페이스(RFC 4122 부록 C 의 URL 네임스페이스). 같은 스캔이면 항상 같은
// serialNumber 가 나와야 SBOM diff 가 성립한다 — 매 호출 난수는 쓰지 않는다.
const VG_SBOM_UUID_NS       = '6ba7b811-9dad-11d1-80b4-00c04fd430c8';
const VG_SBOM_JSON_FLAGS    = JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT;

function vg_sbom_fail(int $http, string $msg, string $code): void {
    http_response_code($http);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['ok' => false, 'error' => $msg, 'code' => $code, 'ts' => date('c')], JSON_UNESCAPED_UNICODE);
    exit;
}

// ── 메서드 ────────────────────────────────────────────────────
if (!in_array($_SERVER['REQUEST_METHOD'] ?? '', ['GET', 'HEAD'], true)) {
    vg_sbom_fail(405, 'GET only', 'method_not_allowed');
}

// ── 인증: export.php 와 같은 읽기 토큰 ────────────────────────
$provided = vg_auth_token('X-API-Token');
$tokenId  = null;
try {
    $tokenId = vg_api_token_verify(vg_pdo(), (string) $provided);
    if ($tokenId === null) {
        vg_sbom_fail(401, 'unauthorized', 'unauthorized');
    }
} catch (Throwable $e) {
    error_log('[sbom] auth ' . $e->getMessage());
    vg_sbom_fail(500, 'internal error', 'internal_error');
}

// ── 파라미터 ──────────────────────────────────────────────────
$format = strtolower(trim((string) ($_GET['format'] ?? 'cyclonedx')));
if (!in_array($format, VG_SBOM_FORMATS, true)) { $format = 'cyclonedx'; }

$host   = trim((string) ($_GET['host'] ?? ''));
$scanId = (int) ($_GET['scan_id'] ?? 0);
if ($host === '' && $scanId <= 0) {
    vg_sbom_fail(400, 'host or scan_id required', 'target_required');
}

// ── 대상 스캔 + 패키지 조회 ───────────────────────────────────
try {
    $pdo = vg_pdo();

    // 스캔 스코프: export.php 와 같은 규칙(scan_id 지정 우선, 아니면 그 호스트의 최신 스캔).
    if ($scanId > 0) {
        $scanSql = 'SELECT s.scan_id, s.collected_at, s.os_id, s.os_version, s.kernel,
                           s.agent_version, h.fqdn
                      FROM tb_scan s
                      JOIN tb_host h ON h.host_id = s.host_id AND h.is_deleted = 0
                     WHERE s.is_deleted = 0 AND s.scan_id = ?';
        $scanParams = [$scanId];
    } else {
        $scanSql = 'SELECT s.scan_id, s.collected_at, s.os_id, s.os_version, s.kernel,
                           s.agent_version, h.fqdn
                      FROM tb_scan s
                      JOIN tb_host h ON h.host_id = s.host_id AND h.is_deleted = 0
                      JOIN ' . vg_latest_scan_subq() . ' t ON t.mid = s.scan_id
                     WHERE s.is_deleted = 0 AND h.fqdn = ?';
        $scanParams = [$host];
    }
    $st = $pdo->prepare($scanSql . ' LIMIT 1');
    $st->execute($scanParams);
    $scan = $st->fetch(PDO::FETCH_ASSOC);
    if (!$scan) {
        vg_sbom_fail(404, 'scan not found', 'not_found');
    }

    // 호스트 자신의 패키지만. 컨테이너(container_id > 0)는 이번 범위 밖.
    $st = $pdo->prepare(
        'SELECT manager, name, version, arch, source_pkg, origin, vendor, license
           FROM tb_package
          WHERE is_deleted = 0 AND scan_id = ? AND container_id = 0
          ORDER BY manager, name, version'
    );
    $st->execute([(int) $scan['scan_id']]);
    $packages = $st->fetchAll(PDO::FETCH_ASSOC);
} catch (Throwable $e) {
    error_log('[sbom] ' . $e->getMessage());
    vg_sbom_fail(500, 'internal error', 'internal_error');
}

$fqdn    = (string) $scan['fqdn'];
$scanNo  = (int) $scan['scan_id'];
$uuid    = vg_sbom_uuid($scanNo, $fqdn);
// 문서 시각은 "SBOM 을 만든 시각"이 아니라 스캔 수집 시각으로 고정한다 — 같은 스캔을 두 번
// 내려받아도 문서가 같아야 diff 가 된다(serialNumber 를 결정적으로 만드는 이유와 같다).
$created = vg_sbom_epoch((string) ($scan['collected_at'] ?? ''));

$doc = $format === 'spdx'
    ? vg_sbom_spdx($scan, $packages, $uuid, $created)
    : vg_sbom_cyclonedx($scan, $packages, $uuid, $created);

// 누가(토큰)·어느 자산의·어떤 포맷 SBOM 을 몇 건으로 받아갔는지 감사로그.
vg_log_activity(
    $pdo, 'API_TOKEN', $tokenId, 'export_sbom',
    '형식=' . $format . ' 자산=' . $fqdn . ' 컴포넌트 ' . count($packages) . '건 (스캔 #' . $scanNo . ')',
    ['format' => $format, 'host' => $fqdn, 'scan_id' => $scanNo, 'components' => count($packages)],
    null, 'SYSTEM',
    subject: $fqdn, action: 'EXPORT'
);

header('Content-Type: application/json; charset=utf-8');
header('Content-Disposition: attachment; filename="' . vg_sbom_filename($fqdn, $scanNo, $format) . '"');
echo json_encode($doc, VG_SBOM_JSON_FLAGS);

// ── 헬퍼 ──────────────────────────────────────────────────────

/**
 * 스캔 id + fqdn 으로 만드는 결정적 UUID(RFC 4122 v5, SHA-1 기반).
 * 같은 스캔이면 언제 호출해도 같은 값이라 SBOM 을 파일로 보관·비교할 수 있다.
 */
function vg_sbom_uuid(int $scanId, string $fqdn): string {
    $nsHex = str_replace('-', '', VG_SBOM_UUID_NS);
    $hash  = sha1(hex2bin($nsHex) . VG_SBOM_TOOL_NAME . ':' . $scanId . ':' . $fqdn);
    return sprintf(
        '%08s-%04s-%04x-%04x-%12s',
        substr($hash, 0, 8),
        substr($hash, 8, 4),
        (hexdec(substr($hash, 12, 4)) & 0x0fff) | 0x5000,   // 버전 5
        (hexdec(substr($hash, 16, 4)) & 0x3fff) | 0x8000,   // 변형 RFC 4122
        substr($hash, 20, 12)
    );
}

/**
 * DATETIME → 유닉스 시각. 값이 없으면 현재 시각(문서가 시각 없이 나가면 파서가 거부한다).
 * 표기는 포맷마다 다르다 — CycloneDX 는 오프셋 표기(ISO 8601)를 받지만 SPDX 2.3 은
 * **UTC 의 `…Z` 형태만** 받는다(pyspdxtools 가 오프셋 표기를 파싱 에러로 거부한다).
 */
function vg_sbom_epoch(string $dt): int {
    $t = $dt !== '' ? strtotime($dt) : false;
    return $t !== false ? $t : time();
}

/**
 * 다운로드 파일명. 헤더에 그대로 들어가므로 fqdn 을 정제한다(개행·따옴표 주입 차단).
 */
function vg_sbom_filename(string $fqdn, int $scanId, string $format): string {
    $safe = preg_replace('/[^A-Za-z0-9._-]/', '_', $fqdn);
    if ($safe === null || $safe === '') { $safe = 'host'; }
    return substr($safe, 0, 100) . '-' . $scanId . '-' . $format . '.json';
}

/** 빈 문자열·null 을 하나로 다룬다(라이선스·벤더는 빈 문자열로 들어오는 경우가 있다). */
function vg_sbom_val(?string $v): ?string {
    $v = $v !== null ? trim($v) : '';
    return $v !== '' ? $v : null;
}

/** 이 스캔의 패키지 한 건 → purl(만들 수 없으면 null). */
function vg_sbom_purl(array $p, array $scan): ?string {
    return vg_purl(
        (string) ($p['manager'] ?? ''),
        (string) ($p['name'] ?? ''),
        $p['version'] !== null ? (string) $p['version'] : null,
        $p['arch'] !== null ? (string) $p['arch'] : null,
        $scan['os_id'] !== null ? (string) $scan['os_id'] : null
    );
}

/** CycloneDX 1.5 JSON. */
function vg_sbom_cyclonedx(array $scan, array $packages, string $uuid, int $created): array {
    $osLabel = trim(((string) ($scan['os_id'] ?? '')) . ' ' . ((string) ($scan['os_version'] ?? '')));

    $components = [];
    foreach ($packages as $p) {
        $c = [
            'type'    => 'library',
            'name'    => (string) $p['name'],
            'version' => (string) ($p['version'] ?? ''),
        ];
        $purl = vg_sbom_purl($p, $scan);
        if ($purl !== null) { $c['purl'] = $purl; }

        $vendor = vg_sbom_val($p['vendor'] ?? null);
        if ($vendor !== null) { $c['supplier'] = ['name' => $vendor]; }

        // 라이선스가 비어 있으면 licenses 자체를 뺀다 — 빈 문자열을 실으면 파서가 에러를 낸다.
        $license = vg_sbom_val($p['license'] ?? null);
        if ($license !== null) { $c['licenses'] = [['license' => ['name' => $license]]]; }

        $props = [];
        foreach (['origin' => 'vulnagent:origin', 'source_pkg' => 'vulnagent:source_pkg'] as $col => $key) {
            $v = vg_sbom_val($p[$col] ?? null);
            if ($v !== null) { $props[] = ['name' => $key, 'value' => $v]; }
        }
        if ($props) { $c['properties'] = $props; }

        $components[] = $c;
    }

    return [
        'bomFormat'    => 'CycloneDX',
        'specVersion'  => VG_SBOM_CDX_SPEC,
        'serialNumber' => 'urn:uuid:' . $uuid,
        'version'      => 1,
        'metadata'     => [
            'timestamp' => date('c', $created),
            'tools'     => [['name' => VG_SBOM_TOOL_NAME, 'version' => VG_SBOM_TOOL_VERSION]],
            'component' => [
                'type'    => 'operating-system',
                'name'    => (string) $scan['fqdn'],
                'version' => $osLabel !== '' ? $osLabel : VG_SBOM_NOASSERTION,
            ],
        ],
        'components'   => $components,
    ];
}

/** SPDX 2.3 JSON. */
function vg_sbom_spdx(array $scan, array $packages, string $uuid, int $created): array {
    $docId = 'SPDXRef-DOCUMENT';

    $pkgs = $rels = [];
    foreach ($packages as $i => $p) {
        $spdxId = 'SPDXRef-Package-' . ($i + 1);
        $vendor = vg_sbom_val($p['vendor'] ?? null);
        $license = vg_sbom_val($p['license'] ?? null);

        $entry = [
            'SPDXID'           => $spdxId,
            'name'             => (string) $p['name'],
            'versionInfo'      => (string) ($p['version'] ?? ''),
            // 공급자는 SPDX 표기상 "Organization: <이름>" 형태여야 한다. 모르면 NOASSERTION.
            'supplier'         => $vendor !== null ? 'Organization: ' . $vendor : VG_SBOM_NOASSERTION,
            'licenseDeclared'  => $license !== null ? $license : VG_SBOM_NOASSERTION,
            'downloadLocation' => VG_SBOM_NOASSERTION,
        ];
        $purl = vg_sbom_purl($p, $scan);
        if ($purl !== null) {
            $entry['externalRefs'] = [[
                'referenceCategory' => 'PACKAGE-MANAGER',
                'referenceType'     => 'purl',
                'referenceLocator'  => $purl,
            ]];
        }
        $pkgs[] = $entry;
        $rels[] = [
            'spdxElementId'      => $docId,
            'relationshipType'   => 'DESCRIBES',
            'relatedSpdxElement' => $spdxId,
        ];
    }

    return [
        'spdxVersion'       => VG_SBOM_SPDX_SPEC,
        'dataLicense'       => VG_SBOM_SPDX_LICENSE,
        'SPDXID'            => $docId,
        'name'              => (string) $scan['fqdn'] . '-' . (int) $scan['scan_id'],
        // 절대 URI 면 되고 접근 가능할 필요는 없다. 배포 도메인을 코드에 박지 않으려고 urn:uuid 를 쓴다.
        'documentNamespace' => 'urn:uuid:' . $uuid,
        'creationInfo'      => [
            'created'  => gmdate('Y-m-d\TH:i:s\Z', $created),
            'creators' => ['Tool: ' . VG_SBOM_TOOL_NAME . '-' . VG_SBOM_TOOL_VERSION],
        ],
        'packages'          => $pkgs,
        'relationships'     => $rels,
    ];
}
