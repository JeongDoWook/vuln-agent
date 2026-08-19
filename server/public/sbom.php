<?php
declare(strict_types=1);

/**
 * sbom.php — 스캔 하나의 설치 패키지 목록을 표준 SBOM 문서로 내보내는 읽기 API.
 *
 *   용도: 외부 SBOM 도구(취약점 스캐너·라이선스 감사·공급망 검증)가 자산별 부품표를 가져간다.
 *   인증: export.php 와 같은 **웹 로그인 세션**(자산 메뉴 권한). 전용 API 토큰 체계는 폐지했다 —
 *         로그인한 사용자가 브라우저에서 이 URL 을 열면 그대로 파일로 내려받는다.
 *   범위: **대상 하나당 문서 하나.** host 또는 scan_id 를 반드시 지정한다 —
 *         여러 호스트를 한 문서에 담으면 CycloneDX/SPDX 어느 쪽으로도 의미가 없다.
 *         cid 를 함께 주면 **그 컨테이너 하나**의 부품표가 되고, 안 주면 호스트 자신
 *         (container_id = 0)의 부품표다. 두 범위를 한 문서에 섞지 않는다 — 컨테이너는
 *         호스트와 OS·패키지 관리자가 다른 별개 자산이라 섞으면 어느 쪽 부품표도 아니게 된다.
 *         의존 엣지(dependencies/relationships)는 넣지 않는다 — 호스트 패키지는 대부분
 *         엣지가 비어 있어 반쪽짜리 그래프가 나간다(#516).
 *
 *   예:
 *     GET /sbom.php?host=web01.example.com                  (기본 cyclonedx · 호스트)
 *     GET /sbom.php?host=web01.example.com&format=spdx
 *     GET /sbom.php?scan_id=1234&format=cyclonedx
 *     GET /sbom.php?host=web01.example.com&cid=api          (컨테이너 api 하나)
 */

require __DIR__ . '/../src/auth.php';     // 세션·vg_require_menu (config/db/audit 를 함께 로드한다)
require_once __DIR__ . '/../src/purl.php';
vg_require_menu('assets');                // SBOM 은 자산의 부품표다

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

// ── 파라미터 ──────────────────────────────────────────────────
$format = strtolower(trim((string) ($_GET['format'] ?? 'cyclonedx')));
if (!in_array($format, VG_SBOM_FORMATS, true)) { $format = 'cyclonedx'; }
// 시각화 보기. 켜져 있으면 아래 JSON 다운로드 경로 대신 화면을 그린다 — 외부 SBOM 도구가
//   붙는 기본 계약(브라우저로 열면 파일로 내려받는다)은 이 파라미터가 없을 때 그대로다.
$view = strtolower(trim((string) ($_GET['view'] ?? '')));

$host   = trim((string) ($_GET['host'] ?? ''));
$scanId = (int) ($_GET['scan_id'] ?? 0);
if ($host === '' && $scanId <= 0) {
    vg_sbom_fail(400, 'host or scan_id required', 'target_required');
}
// 컨테이너 범위. tb_container 의 자연키는 (scan_id, cid) 이므로 숫자 container_id 가 아니라
//   **cid 문자열**을 받는다 — 숫자 id 는 스캔마다 새로 발급돼 북마크·스크립트가 다음 수집에서 깨진다.
$cid = trim((string) ($_GET['cid'] ?? ''));

// ── 대상 스캔 + 패키지 조회 ───────────────────────────────────
try {
    $pdo = vg_pdo();

    // 스캔 스코프: export.php 와 같은 규칙(scan_id 지정 우선, 아니면 그 호스트의 최신 스캔).
    if ($scanId > 0) {
        $scanSql = 'SELECT s.scan_id, s.collected_at, s.os_id, s.os_version, s.kernel,
                           s.agent_version, h.host_id, h.fqdn
                      FROM tb_scan s
                      JOIN tb_host h ON h.host_id = s.host_id AND h.is_deleted = 0
                     WHERE s.is_deleted = 0 AND s.scan_id = ?';
        $scanParams = [$scanId];
    } else {
        $scanSql = 'SELECT s.scan_id, s.collected_at, s.os_id, s.os_version, s.kernel,
                           s.agent_version, h.host_id, h.fqdn
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

    // 대상 컨테이너 확정. cid 를 줬는데 그 스캔에 없으면 조용히 호스트 SBOM 을 내보내지 않는다 —
    //   요청한 것과 다른 부품표가 나가면 공급망 검증이 엉뚱한 대상을 통과시킨다.
    $container = null;
    if ($cid !== '') {
        $st = $pdo->prepare(
            'SELECT container_id, cid, name, image, image_digest, os_id, os_version, manager
               FROM tb_container
              WHERE is_deleted = 0 AND scan_id = ? AND cid = ? LIMIT 1'
        );
        $st->execute([(int) $scan['scan_id'], $cid]);
        $container = $st->fetch(PDO::FETCH_ASSOC) ?: null;
        if ($container === null) {
            vg_sbom_fail(404, 'container not found', 'not_found');
        }
    }
    $containerId = $container !== null ? (int) $container['container_id'] : 0;

    // 범위는 하나뿐이다 — 호스트면 container_id = 0, 컨테이너면 그 컨테이너 것만.
    $st = $pdo->prepare(
        'SELECT manager, name, version, arch, source_pkg, origin, vendor, license
           FROM tb_package
          WHERE is_deleted = 0 AND scan_id = ? AND container_id = ?
          ORDER BY manager, name, version'
    );
    $st->execute([(int) $scan['scan_id'], $containerId]);
    $packages = $st->fetchAll(PDO::FETCH_ASSOC);
} catch (Throwable $e) {
    error_log('[sbom] ' . $e->getMessage());
    vg_sbom_fail(500, 'internal error', 'internal_error');
}

$fqdn    = (string) $scan['fqdn'];
$hostId  = (int) $scan['host_id'];
$scanNo  = (int) $scan['scan_id'];
$uuid    = vg_sbom_uuid($scanNo, $fqdn, $cid);
// 문서 시각은 "SBOM 을 만든 시각"이 아니라 스캔 수집 시각으로 고정한다 — 같은 스캔을 두 번
// 내려받아도 문서가 같아야 diff 가 된다(serialNumber 를 결정적으로 만드는 이유와 같다).
$created = vg_sbom_epoch((string) ($scan['collected_at'] ?? ''));

/* 문서가 무엇을 서술하는지(metadata.component / SPDX name)와 purl 의 배포판 네임스페이스는
 *   **대상의 OS** 를 따라간다. 컨테이너는 호스트와 배포판이 다른 것이 정상이라(alpine 컨테이너 위
 *   ubuntu 호스트), 스캔의 os_id 를 그대로 쓰면 apk 패키지가 pkg:apk/ubuntu/… 로 나가 오식별된다. */
$subject = $container !== null
    ? ['name'    => (string) ($container['image'] ?? '') !== '' ? (string) $container['image'] : (string) $container['cid'],
       'type'    => 'container',
       'os_id'   => $container['os_id'] ?? null,
       'os_ver'  => $container['os_version'] ?? null,
       'ref'     => $fqdn . '/' . (string) $container['cid'],
       'digest'  => (string) ($container['image_digest'] ?? '')]
    : ['name'    => $fqdn,
       'type'    => 'operating-system',
       'os_id'   => $scan['os_id'] ?? null,
       'os_ver'  => $scan['os_version'] ?? null,
       'ref'     => $fqdn,
       'digest'  => ''];

// 시각화 보기 — 다운로드가 아니라 화면. 조회도 자산 정보 열람이라 감사로그는 남기되
//   실제로 파일을 내보낸 것은 아니므로 action 은 EXPORT 가 아니라 READ.
if ($view === 'html') {
    require_once __DIR__ . '/../src/view.php';
    require_once __DIR__ . '/../src/license_risk.php';
    // GET 요청에서만 남긴다(vg_log_page_view 와 같은 방침, audit.php:184). CSRF 토큰이 없고
    //   쿠키가 SameSite=Lax 인 GET/HEAD 는 공격자가 보낸 링크를 클릭하게만 해도 발생한다 —
    //   HEAD 는 실제 열람 없이도(프리페치·링크 미리보기) 걸릴 수 있어 아예 기록에서 뺀다.
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'GET') {
        vg_log_activity(
            $pdo, 'HOST', $hostId, 'view_sbom',
            '자산=' . $subject['ref'] . ' 컴포넌트 ' . count($packages) . '건 (스캔 #' . $scanNo . ')',
            ['host' => $fqdn, 'container' => $cid !== '' ? $cid : null,
             'scan_id' => $scanNo, 'components' => count($packages)],
            subject: $subject['ref'], action: 'READ'
        );
    }
    // 위에서 이미 이 열람을 구체적으로 기록했다(또는 GET 이 아니라서 아예 안 남겼다) —
    //   vg_header() 가 여는 범용 page_view 로그가 같은 열람을 또 남기지 않게 막는다.
    $GLOBALS['vg_suppress_page_view'] = true;
    vg_sbom_render_html($subject, $packages, $fqdn, $cid, $scanNo, (string) ($scan['collected_at'] ?? ''));
    exit;
}

$doc = $format === 'spdx'
    ? vg_sbom_spdx($scan, $subject, $packages, $uuid, $created)
    : vg_sbom_cyclonedx($subject, $packages, $uuid, $created);

// 누가(로그인 사용자)·어느 자산의·어떤 포맷 SBOM 을 몇 건으로 받아갔는지 감사로그.
//   컨테이너 범위면 그 사실도 남긴다 — 같은 호스트라도 서로 다른 부품표를 받아간 것이다.
vg_log_activity(
    $pdo, 'EXPORT', null, 'export_sbom',
    '형식=' . $format . ' 자산=' . $subject['ref'] . ' 컴포넌트 ' . count($packages) . '건 (스캔 #' . $scanNo . ')',
    ['format' => $format, 'host' => $fqdn, 'container' => $cid !== '' ? $cid : null,
     'scan_id' => $scanNo, 'components' => count($packages)],
    subject: $subject['ref'], action: 'EXPORT'
);

header('Content-Type: application/json; charset=utf-8');
header('Content-Disposition: attachment; filename="' . vg_sbom_filename($fqdn, $cid, $scanNo, $format) . '"');
echo json_encode($doc, VG_SBOM_JSON_FLAGS);

// ── 헬퍼 ──────────────────────────────────────────────────────

/**
 * 스캔 id + fqdn(+ 컨테이너 cid)으로 만드는 결정적 UUID(RFC 4122 v5, SHA-1 기반).
 * 같은 스캔·같은 범위면 언제 호출해도 같은 값이라 SBOM 을 파일로 보관·비교할 수 있다.
 *   cid 가 빈 문자열(호스트)이면 해시 입력에 아예 넣지 않는다 — 넣으면 컨테이너 기능이
 *   생기기 전에 내려받은 호스트 SBOM 과 serialNumber 가 달라져 예전 문서와 diff 가 끊긴다.
 */
function vg_sbom_uuid(int $scanId, string $fqdn, string $cid = ''): string {
    $nsHex = str_replace('-', '', VG_SBOM_UUID_NS);
    $hash  = sha1(hex2bin($nsHex) . VG_SBOM_TOOL_NAME . ':' . $scanId . ':' . $fqdn
                  . ($cid !== '' ? ':' . $cid : ''));
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
 * 다운로드 파일명. 헤더에 그대로 들어가므로 fqdn·cid 를 정제한다(개행·따옴표 주입 차단).
 *   확장자를 포맷별로 나눈다(.cdx.json / .spdx.json) — 두 표준의 관례이고, 파일만 보고
 *   어느 스키마로 파싱해야 하는지 알 수 있어야 SBOM 보관함에서 쓸모가 있다.
 */
function vg_sbom_filename(string $fqdn, string $cid, int $scanId, string $format): string {
    $clean = static function (string $v, string $fallback): string {
        $s = preg_replace('/[^A-Za-z0-9._-]/', '_', $v);
        if ($s === null || $s === '') { $s = $fallback; }
        return substr($s, 0, 100);
    };
    $name = 'sbom-' . $clean($fqdn, 'host');
    if ($cid !== '') { $name .= '-' . $clean($cid, 'container'); }
    return $name . '-' . $scanId . ($format === 'spdx' ? '.spdx.json' : '.cdx.json');
}

/** 빈 문자열·null 을 하나로 다룬다(라이선스·벤더는 빈 문자열로 들어오는 경우가 있다). */
function vg_sbom_val(?string $v): ?string {
    $v = $v !== null ? trim($v) : '';
    return $v !== '' ? $v : null;
}

/** 이 문서 대상의 패키지 한 건 → purl(만들 수 없으면 null). 배포판은 $subject 의 OS 다. */
function vg_sbom_purl(array $p, array $subject): ?string {
    return vg_purl(
        (string) ($p['manager'] ?? ''),
        (string) ($p['name'] ?? ''),
        $p['version'] !== null ? (string) $p['version'] : null,
        $p['arch'] !== null ? (string) $p['arch'] : null,
        $subject['os_id'] !== null ? (string) $subject['os_id'] : null
    );
}

/** CycloneDX 1.5 JSON. */
function vg_sbom_cyclonedx(array $subject, array $packages, string $uuid, int $created): array {
    $osLabel = trim(((string) ($subject['os_id'] ?? '')) . ' ' . ((string) ($subject['os_ver'] ?? '')));

    $components = [];
    foreach ($packages as $p) {
        $c = [
            'type'    => 'library',
            'name'    => (string) $p['name'],
            'version' => (string) ($p['version'] ?? ''),
        ];
        $purl = vg_sbom_purl($p, $subject);
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

    // 문서가 서술하는 대상. 컨테이너면 type=container 이고 이미지 다이제스트를 해시로 싣는다 —
    //   "어느 이미지의 부품표인가" 가 컨테이너 SBOM 의 식별자다(이름·태그는 바뀌어도 다이제스트는 고정).
    $root = [
        'type'    => (string) $subject['type'],
        'name'    => (string) $subject['name'],
        'version' => $osLabel !== '' ? $osLabel : VG_SBOM_NOASSERTION,
    ];
    $digest = vg_sbom_val((string) ($subject['digest'] ?? ''));
    if ($digest !== null && str_starts_with($digest, 'sha256:')) {
        $root['hashes'] = [['alg' => 'SHA-256', 'content' => substr($digest, 7)]];
    }

    return [
        'bomFormat'    => 'CycloneDX',
        'specVersion'  => VG_SBOM_CDX_SPEC,
        'serialNumber' => 'urn:uuid:' . $uuid,
        'version'      => 1,
        'metadata'     => [
            'timestamp' => date('c', $created),
            'tools'     => [['name' => VG_SBOM_TOOL_NAME, 'version' => VG_SBOM_TOOL_VERSION]],
            'component' => $root,
        ],
        'components'   => $components,
    ];
}

/** SPDX 2.3 JSON. */
function vg_sbom_spdx(array $scan, array $subject, array $packages, string $uuid, int $created): array {
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
        $purl = vg_sbom_purl($p, $subject);
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
        // 문서 이름 = 대상 식별(호스트 또는 '호스트/컨테이너') + 스캔 회차.
        'name'              => (string) $subject['ref'] . '-' . (int) $scan['scan_id'],
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

/**
 * SBOM 시각화 보기. 다운로드용 CycloneDX/SPDX 와 같은 조회($packages)를 화면으로 그린다 —
 *   새로 집계하지 않는다. 의존 엣지는 이 화면도 다루지 않는다(sbom.php 머리주석 — 대부분 비어
 *   있어 반쪽짜리 그래프가 된다). 대신 **패키지 관리자(생태계)** 를 뿌리로 묶어 카드/트리로
 *   나눈다 — "이 자산에 뭐가 얼마나 있나" 를 flat JSON 한 덩어리보다 먼저 보여준다.
 *   진짜 의존성 그래프(누가 누구를 끌어왔나)는 host.php 의 depgraph.php 링크가 이미 담당한다.
 */
function vg_sbom_render_html(array $subject, array $packages, string $fqdn, string $cid, int $scanNo, string $collectedAt = ''): void {
    $total = count($packages);

    // 관리자(생태계)별 묶음 — 도넛차트·KPI 는 전건 기준(페이지가 바뀌어도 분포는 그대로 보여야 한다).
    $byManager = [];
    foreach ($packages as $p) {
        $byManager[(string) $p['manager']][] = $p;
    }
    ksort($byManager);

    // 라이선스 위험도 집계(packages.php 의 언어 탭과 같은 순수함수 — 별도 사전집계 없이 즉산). 전건 기준.
    $riskCounts = ['permissive' => 0, 'copyleft' => 0, 'unknown' => 0];
    foreach ($packages as $p) {
        $risk = vg_license_classify($p['license'] ?? null);
        $riskCounts[$risk]++;
    }

    // 컴포넌트 표는 페이지네이션한다 — 운영 서버는 수백~수천 건이 정상이라(dev DB 는 최대
    //   116건이라 스모크에 안 걸림) 전건을 한 화면에 뿌리면 브라우저가 무거워진다. 정렬이
    //   manager,name,version(SQL ORDER BY) 이라 슬라이스해도 관리자별 묶음이 페이지 경계에서만
    //   갈릴 뿐 뒤섞이지 않는다.
    $page    = vg_page();
    $perPage = vg_perpage();
    $pageItems = array_slice($packages, ($page - 1) * $perPage, $perPage);
    $byManagerPage = [];
    foreach ($pageItems as $p) {
        $byManagerPage[(string) $p['manager']][] = $p;
    }
    ksort($byManagerPage);

    $title = (string) $subject['name'] !== '' ? (string) $subject['name'] : $fqdn;
    vg_header('SBOM · ' . $title, 'assets');
    vg_chart_assets();
    ?>
    <?php vg_page_title($title . ' SBOM', '', ['count' => $total, 'count_label' => '개 컴포넌트']); ?>
    <?php // 지금 보고 있는 스캔 회차 — 과거 스캔을 view=html 로 열었을 때 최신인 줄 착각하지 않도록. ?>
    <p class="why">스캔 #<?= $scanNo ?><?= $collectedAt !== '' ? ' · ' . vg_h($collectedAt) . ' 수집' : '' ?></p>

    <div class="cards">
      <div class="kpi kpi--sm"><b><?= number_format($total) ?></b><span>컴포넌트</span></div>
      <div class="kpi kpi--sm"><b><?= number_format(count($byManager)) ?></b><span>패키지 관리자</span></div>
      <div class="kpi kpi--sm<?= $riskCounts['copyleft'] > 0 ? ' tone-high' : '' ?>">
        <b><?= number_format($riskCounts['copyleft']) ?></b><span>카피레프트 라이선스</span>
      </div>
      <div class="kpi kpi--sm tone-muted">
        <b><?= number_format($riskCounts['unknown']) ?></b><span>라이선스 미상</span>
      </div>
    </div>

    <?php if ($total > 0): ?>
      <div class="card">
        <strong>생태계 분포</strong>
        <div class="card__body">
          <?php
          $ecoLabels = array_keys($byManager);
          $ecoData = array_map(static fn($m) => count($byManager[$m]), $ecoLabels);
          vg_chart('doughnut', [
              'labels'   => $ecoLabels,
              'datasets' => [['data' => $ecoData]],
          ], ['size' => 'md', 'alt' => '패키지 관리자별 컴포넌트 분포']);
          ?>
        </div>
      </div>

      <div class="card">
        <strong>라이선스 위험도</strong>
        <div class="card__body">
          <?php
          vg_chart('doughnut', [
              'labels'   => [vg_license_risk_label('permissive'), vg_license_risk_label('copyleft'), vg_license_risk_label('unknown')],
              'datasets' => [['data' => [$riskCounts['permissive'], $riskCounts['copyleft'], $riskCounts['unknown']]]],
          ], ['size' => 'md', 'alt' => '라이선스 위험도 분포']);
          ?>
        </div>
      </div>
    <?php endif; ?>

    <?php if (!$byManagerPage): ?>
      <?php vg_empty(['icon' => 'package', 'title' => '이 대상에서 수집된 컴포넌트가 없습니다.']); ?>
    <?php else: ?>
      <?php foreach ($byManagerPage as $manager => $pkgs): ?>
        <div class="card">
          <div class="ctree__root">
            <span class="ctree__icon" aria-hidden="true"><?= vg_icon('package') ?></span>
            <div class="ctree__rootid">
              <strong><?= vg_h(vg_strip_ctrl($manager !== '' ? $manager : '미상')) ?></strong>
              <span class="why"><?= number_format(count($byManager[$manager] ?? $pkgs)) ?>개 컴포넌트</span>
            </div>
          </div>
          <div class="card__body">
            <?php
            vg_table(
                [
                    ['label' => '컴포넌트', 'width' => '32%', 'class' => 'col-id'],
                    ['label' => '버전', 'width' => '16%'],
                    ['label' => '라이선스', 'width' => '30%'],
                    ['label' => '공급자', 'width' => '22%'],
                ],
                $pkgs,
                [
                    'card' => false,
                    'cell' => [
                        0 => static fn($p) => '<strong>' . vg_h(vg_strip_ctrl((string) $p['name'])) . '</strong>',
                        1 => static fn($p) => '<code>' . vg_h((string) ($p['version'] ?? '')) . '</code>',
                        2 => static function ($p) {
                            $lic = trim(vg_strip_ctrl((string) ($p['license'] ?? '')));
                            if ($lic === '') { return '<span class="why">–</span>'; }
                            $risk = vg_license_classify($lic);
                            return vg_h($lic) . ' ' . vg_badge(vg_license_risk_label($risk), vg_license_risk_tone($risk));
                        },
                        3 => static fn($p) => !empty($p['vendor']) ? vg_h(vg_strip_ctrl((string) $p['vendor'])) : '<span class="why">–</span>',
                    ],
                ]
            );
            ?>
          </div>
        </div>
      <?php endforeach; ?>
    <?php endif; ?>
    <?php vg_page_nav($total, $perPage, $page); ?>

    <?php vg_sbom_links($fqdn, $cid, $scanNo); ?>
    <?php vg_footer();
}
