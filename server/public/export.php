<?php
declare(strict_types=1);

/**
 * export.php — 스캔 취약점 결과를 외부 시스템이 가져가는 읽기 API (JSON / XML).
 *
 *   용도: Python AI 서비스가 결과를 받아 PDF 보고서 등을 생성한다.
 *   인증: 전용 읽기 토큰(헤더 X-API-Token 또는 Authorization: Bearer). 쓰기(ingest)와 분리.
 *   범위: 기본 = 호스트별 최신 스캔의 findings. host / scan_id / severity / kev / min_epss 로 좁힘.
 *   내용: 실행요약(심각도 집계) + 호스트 맥락(OS·커널·수집시각) + finding(CVE·심각도·KEV·EPSS·노출·조치)
 *         + 미조치 사유 3필드(사유·승인자·승인일시) — 조치 워크플로는 이 값을 가져가는 외부 시스템의 몫이다.
 *         설치 패키지 원본은 넣지 않는다(수천 건이라 보고서엔 노이즈).
 *
 *   예:
 *     GET /export.php?format=json
 *     GET /export.php?format=xml&severity=critical,high&kev=1
 *     GET /export.php?host=web01.example.com
 *     curl -H "X-API-Token: <토큰>" "https://…/export.php?format=json&min_epss=0.5"
 */

require __DIR__ . '/../src/config.php';   // vg_auth_token (요청 헤더 파싱 헬퍼)
require __DIR__ . '/../src/db.php';
require_once __DIR__ . '/../src/apitoken.php';
require_once __DIR__ . '/../src/audit.php';    // vg_log_activity (apitoken.php 도 만료 기록에 쓴다)

const VG_EXPORT_SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

function vg_export_fail(int $http, string $msg, string $code): void {
    http_response_code($http);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['ok' => false, 'error' => $msg, 'code' => $code, 'ts' => date('c')], JSON_UNESCAPED_UNICODE);
    exit;
}

// ── 메서드 ────────────────────────────────────────────────────
if (!in_array($_SERVER['REQUEST_METHOD'] ?? '', ['GET', 'HEAD'], true)) {
    vg_export_fail(405, 'GET only', 'method_not_allowed');
}

// ── 인증: 웹에서 발급한 읽기 토큰(DB, SHA-256 대조) ───────────
//   토큰은 api-tokens.php 에서 발급/폐기한다. 폐기(soft-delete)된 토큰은 즉시 거부된다.
$provided = vg_auth_token('X-API-Token');   // 커스텀 헤더 우선, 없으면 Authorization: Bearer
$tokenId  = null;
try {
    $tokenId = vg_api_token_verify(vg_pdo(), (string) $provided);
    if ($tokenId === null) {
        vg_export_fail(401, 'unauthorized', 'unauthorized');
    }
} catch (Throwable $e) {
    error_log('[export] auth ' . $e->getMessage());
    vg_export_fail(500, 'internal error', 'internal_error');
}

// ── 파라미터 ──────────────────────────────────────────────────
$format  = strtolower((string) ($_GET['format'] ?? 'json'));
if (!in_array($format, ['json', 'xml'], true)) { $format = 'json'; }

$host    = trim((string) ($_GET['host'] ?? ''));
$scanId  = (int) ($_GET['scan_id'] ?? 0);
$kevOnly = ((string) ($_GET['kev'] ?? '')) === '1';

$sevFilter = [];
if (($_GET['severity'] ?? '') !== '') {
    foreach (explode(',', (string) $_GET['severity']) as $s) {
        $s = strtoupper(trim($s));
        if (in_array($s, VG_EXPORT_SEVERITIES, true)) { $sevFilter[$s] = true; }
    }
    $sevFilter = array_keys($sevFilter);
}

$minEpss = null;
if (($_GET['min_epss'] ?? '') !== '' && is_numeric($_GET['min_epss'])) {
    $minEpss = max(0.0, min(1.0, (float) $_GET['min_epss']));
}

// ── 대상 스캔 선정 + finding 조회 ─────────────────────────────
try {
    $pdo = vg_pdo();

    // 스캔 스코프: scan_id 지정이면 그것, 아니면 (host 필터 후) 호스트별 최신 스캔.
    if ($scanId > 0) {
        $scanSql = 'SELECT s.scan_id, s.collected_at, s.os_id, s.os_version, s.kernel,
                           s.package_count, s.agent_version, h.fqdn, h.hostname
                      FROM tb_scan s
                      JOIN tb_host h ON h.host_id = s.host_id AND h.is_deleted = 0
                     WHERE s.is_deleted = 0 AND s.scan_id = ?';
        $scanParams = [$scanId];
    } else {
        $scanSql = 'SELECT s.scan_id, s.collected_at, s.os_id, s.os_version, s.kernel,
                           s.package_count, s.agent_version, h.fqdn, h.hostname
                      FROM tb_scan s
                      JOIN tb_host h ON h.host_id = s.host_id AND h.is_deleted = 0
                      JOIN ' . vg_latest_scan_subq() . ' t
                        ON t.mid = s.scan_id
                     WHERE s.is_deleted = 0';
        $scanParams = [];
        if ($host !== '') { $scanSql .= ' AND h.fqdn = ?'; $scanParams[] = $host; }
    }
    $scanSql .= ' ORDER BY h.fqdn';
    $st = $pdo->prepare($scanSql);
    $st->execute($scanParams);
    $scans = $st->fetchAll(PDO::FETCH_ASSOC);

    // scan_id → 호스트 노드. finding 은 아래에서 채운다.
    $hosts = [];
    foreach ($scans as $s) {
        $hosts[(int) $s['scan_id']] = [
            'fqdn'          => (string) $s['fqdn'],
            'os_id'         => $s['os_id'],
            'os_version'    => $s['os_version'],
            'kernel'        => $s['kernel'],
            'agent_version' => $s['agent_version'],
            'scan_id'       => (int) $s['scan_id'],
            'collected_at'  => $s['collected_at'],
            'package_count' => $s['package_count'] !== null ? (int) $s['package_count'] : null,
            'findings'      => [],
        ];
    }

    $summary = ['hosts' => count($hosts), 'findings' => 0, 'kev' => 0, 'exposed' => 0,
                'by_severity' => ['CRITICAL' => 0, 'HIGH' => 0, 'MEDIUM' => 0, 'LOW' => 0]];

    if ($hosts) {
        $ids = array_keys($hosts);
        $in  = implode(',', array_fill(0, count($ids), '?'));
        $where  = "f.is_deleted = 0 AND f.scan_id IN ($in)";
        $params = $ids;
        if ($sevFilter) {
            $where .= ' AND f.severity IN (' . implode(',', array_fill(0, count($sevFilter), '?')) . ')';
            $params = array_merge($params, $sevFilter);
        }
        if ($kevOnly)          { $where .= ' AND f.in_kev = 1'; }
        if ($minEpss !== null) { $where .= ' AND c.epss >= ?'; $params[] = $minEpss; }

        // fixed_version: 조치가 있으면 그 값 하나(findings.php 와 동일 패턴).
        // 미조치 사유 3필드: 본격 조치 워크플로는 이 API 를 가져가는 외부 시스템의 몫이므로,
        //   "왜 지금 안 고치는가 / 누가 언제 그렇게 판단했는가" 는 여기서 함께 내보낸다.
        //   메모의 자연키는 컨테이너 '이름'(호스트 자신은 '')이다 — container_id 는 스캔마다 새로 발급된다.
        $sql = "SELECT f.scan_id, f.cve_id, f.package_name, f.installed_version,
                       f.loaded, f.exposed, f.exposure_scope, f.in_kev, f.cvss, f.severity, f.rationale,
                       c.summary, c.epss, c.epss_percentile,
                       rn.reason AS remediation_reason, rn.approved_at AS remediation_approved_at,
                       ru.username AS remediation_approved_by,
                       " . VG_FIXED_VERSION_SUBQ . "
                  FROM tb_finding f
                  JOIN tb_scan rs ON rs.scan_id = f.scan_id
                  LEFT JOIN tb_container rc ON rc.container_id = f.container_id
                  LEFT JOIN tb_remediation_note rn
                         ON rn.host_id = rs.host_id
                        AND rn.cve_id  = f.cve_id
                        AND rn.package = f.package_name
                        AND rn.cid     = COALESCE(rc.cid, '')
                        AND rn.is_deleted = 0
                  LEFT JOIN tb_user ru ON ru.user_id = rn.approved_by
                  LEFT JOIN tb_cve c ON c.cve_id = f.cve_id AND c.is_deleted = 0
                 WHERE $where
                 ORDER BY f.scan_id,
                          FIELD(f.severity,'CRITICAL','HIGH','MEDIUM','LOW'), c.epss DESC, f.cve_id";
        $st = $pdo->prepare($sql);
        $st->execute($params);

        foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $r) {
            $sid = (int) $r['scan_id'];
            if (!isset($hosts[$sid])) { continue; }
            $sev = (string) $r['severity'];
            $hosts[$sid]['findings'][] = [
                'cve'               => (string) $r['cve_id'],
                'package'           => (string) $r['package_name'],
                'installed_version' => $r['installed_version'],
                'severity'          => $sev,
                'cvss'              => $r['cvss'] !== null ? (float) $r['cvss'] : null,
                'epss'              => $r['epss'] !== null ? (float) $r['epss'] : null,
                'epss_percentile'   => $r['epss_percentile'] !== null ? (float) $r['epss_percentile'] : null,
                'kev'               => (bool) $r['in_kev'],
                'loaded'            => (bool) $r['loaded'],
                'exposed'           => (bool) $r['exposed'],
                'exposure_scope'    => $r['exposure_scope'],
                'fixed_version'     => $r['fixed_version'],
                'rationale'         => $r['rationale'],
                'summary'           => $r['summary'],
                // 미조치 사유(사람의 메모) — 없으면 전부 null.
                'remediation_reason'      => $r['remediation_reason'],
                'remediation_approved_by' => $r['remediation_approved_by'],
                'remediation_approved_at' => $r['remediation_approved_at'],
            ];
            $summary['findings']++;
            if (isset($summary['by_severity'][$sev])) { $summary['by_severity'][$sev]++; }
            if ($r['in_kev'])  { $summary['kev']++; }
            if ($r['exposed']) { $summary['exposed']++; }
        }
    }
} catch (Throwable $e) {
    error_log('[export] ' . $e->getMessage());
    vg_export_fail(500, 'internal error', 'internal_error');
}

$doc = [
    'ok'           => true,
    'generated_at' => date('c'),
    'summary'      => $summary,
    'hosts'        => array_values($hosts),
];

// 누가(토큰)·언제·어떤 필터로·몇 건을 내보냈는지 감사로그. 실패해도 다운로드는 막지 않는다
// (vg_log_activity 자체가 내부 try/catch).
vg_log_activity(
    $pdo, 'API_TOKEN', $tokenId, 'export_data',
    "형식={$format} 건수={$summary['findings']}건 (호스트 {$summary['hosts']}개)",
    ['format' => $format, 'host' => $host, 'scan_id' => $scanId ?: null,
     'severity' => $sevFilter, 'kev' => $kevOnly, 'min_epss' => $minEpss,
     'findings' => $summary['findings'], 'hosts' => $summary['hosts']],
    null, 'SYSTEM',
    // 처리 대상: 내보내기 범위(호스트 지정이 없으면 전체). 수행업무: 내보내기.
    subject: $host !== '' ? $host : '전체 호스트', action: 'EXPORT'
);

// ── 직렬화 ────────────────────────────────────────────────────
if ($format === 'xml') {
    header('Content-Type: application/xml; charset=utf-8');
    echo vg_export_xml($doc);
} else {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($doc, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
}

/**
 * 배열 → XML. DOMDocument 로 만들어 이스케이프를 DOM 에 맡긴다(수작업 escape 버그 방지).
 * 규칙: 리스트는 <hosts><host>…, <findings><finding>… 처럼 단수 요소로 감싼다.
 */
function vg_export_xml(array $doc): string {
    $dom = new DOMDocument('1.0', 'UTF-8');
    $dom->formatOutput = true;
    $root = $dom->createElement('vulnExport');
    $root->setAttribute('generatedAt', (string) $doc['generated_at']);
    $dom->appendChild($root);

    $s = $doc['summary'];
    $sum = $dom->createElement('summary');
    foreach (['hosts', 'findings', 'kev', 'exposed'] as $k) {
        $sum->setAttribute($k, (string) $s[$k]);
    }
    $bs = $dom->createElement('bySeverity');
    foreach ($s['by_severity'] as $sev => $n) {
        $bs->setAttribute(strtolower($sev), (string) $n);
    }
    $sum->appendChild($bs);
    $root->appendChild($sum);

    $hostsEl = $dom->createElement('hosts');
    foreach ($doc['hosts'] as $h) {
        $hEl = $dom->createElement('host');
        foreach (['fqdn' => 'fqdn', 'os_id' => 'osId', 'os_version' => 'osVersion',
                  'kernel' => 'kernel', 'agent_version' => 'agentVersion', 'scan_id' => 'scanId',
                  'collected_at' => 'collectedAt', 'package_count' => 'packageCount'] as $src => $attr) {
            if ($h[$src] !== null && $h[$src] !== '') { $hEl->setAttribute($attr, (string) $h[$src]); }
        }
        $fsEl = $dom->createElement('findings');
        foreach ($h['findings'] as $f) {
            $fEl = $dom->createElement('finding');
            foreach (['cve' => 'cve', 'package' => 'package', 'installed_version' => 'installedVersion',
                      'severity' => 'severity', 'cvss' => 'cvss', 'epss' => 'epss',
                      'epss_percentile' => 'epssPercentile', 'exposure_scope' => 'exposureScope',
                      'fixed_version' => 'fixedVersion',
                      'remediation_approved_by' => 'remediationApprovedBy',
                      'remediation_approved_at' => 'remediationApprovedAt'] as $src => $attr) {
                if ($f[$src] !== null && $f[$src] !== '') { $fEl->setAttribute($attr, (string) $f[$src]); }
            }
            foreach (['kev', 'loaded', 'exposed'] as $b) {
                $fEl->setAttribute($b, $f[$b] ? 'true' : 'false');
            }
            // 긴 텍스트는 요소 본문으로(속성보다 가독성↑). DOM 이 이스케이프 처리.
            foreach (['rationale' => 'rationale', 'summary' => 'summary',
                      'remediation_reason' => 'remediationReason'] as $src => $tag) {
                if ($f[$src] !== null && $f[$src] !== '') {
                    $fEl->appendChild($dom->createElement($tag))
                        ->appendChild($dom->createTextNode((string) $f[$src]));
                }
            }
            $fsEl->appendChild($fEl);
        }
        $hEl->appendChild($fsEl);
        $hostsEl->appendChild($hEl);
    }
    $root->appendChild($hostsEl);

    return (string) $dom->saveXML();
}
