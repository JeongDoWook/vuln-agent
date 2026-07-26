<?php
declare(strict_types=1);

/**
 * feeds/generic_api.php — 화면에서 코드 수정 없이 등록하는 범용 API 커넥터.
 *   connection_json 에 담긴 URL 템플릿 + 인증 헤더 + JSON 응답 필드 매핑만으로 동작하며,
 *   role(identity/priority/vendor/compliance)에 따라 서로 다른 upsert 헬퍼로 라우팅한다.
 *   설계: .omc/plans/generic-api-connector-design.md
 *
 *   1차 범위(이 파일): identity/priority/vendor role + offset 페이징. compliance 는
 *   XCCDF/XML 파싱이 필요해 아직 미구현이라 run() 이 명시적으로 에러를 던진다(설계문서 9장 Q4).
 */

require_once __DIR__ . '/http.php';
require_once __DIR__ . '/upsert.php';

const VG_GENERIC_MAX_PAGES     = 1000;  // 페이징 무한루프 방어(설계문서 R4)
const VG_GENERIC_PREVIEW_LIMIT = 10;

const VG_GENERIC_ROLES = ['identity', 'priority', 'vendor', 'compliance'];

// role별 필수 매핑 키 — 설계문서 4장 매핑표와 동일.
const VG_GENERIC_REQUIRED_FIELDS = [
    'identity'   => ['cve_id'],
    'priority'   => ['cve_id'],
    'vendor'     => ['cve_id', 'vendor', 'release_major', 'pkg_name', 'fixed_evr'],
    'compliance' => ['rule_id', 'title', 'severity'],
];

// ─────────────────────────────────────────────────────────────────────────
// 내부 헬퍼
// ─────────────────────────────────────────────────────────────────────────

/** dot-notation 경로("a.b.0.c")로 값을 추출한다. 배열 인덱스도 숫자 세그먼트로 지원. 없으면 null. */
function vg_generic_extract(array $data, string $path): mixed {
    if ($path === '') { return null; }
    $cur = $data;
    foreach (explode('.', $path) as $seg) {
        if (is_array($cur) && array_key_exists($seg, $cur)) {
            $cur = $cur[$seg];
        } else {
            return null;
        }
    }
    return $cur;
}

/**
 * URL 템플릿의 플레이스홀더 치환. {page}(1-based)/{offset}(0-based)는 페이징 반복마다,
 * {today}/{days_ago_N}은 호출 시점 기준으로 매번 계산한다(run 시작 시 값을 고정하고 싶으면
 * 호출자가 한 번만 부른다). CVE ID 등 데이터 의존 변수는 1차에서 지원하지 않는다.
 */
function vg_generic_render_url(string $template, int $page, int $offset): string {
    return (string) preg_replace_callback('/\{([a-zA-Z0-9_]+)\}/', static function (array $m) use ($page, $offset): string {
        $name = $m[1];
        if ($name === 'page')   { return (string) $page; }
        if ($name === 'offset') { return (string) $offset; }
        if ($name === 'today')  { return gmdate('Y-m-d'); }
        if (preg_match('/^days_ago_(\d+)$/', $name, $mm) === 1) {
            return gmdate('Y-m-d', strtotime("-{$mm[1]} days"));
        }
        return $m[0]; // 알 수 없는 플레이스홀더는 그대로 둔다
    }, $template);
}

/** field_mapping(키 => dot-notation 경로, 선행 "$." 접두는 허용)으로 아이템 하나를 매핑한다. */
function vg_generic_map_item(array $item, array $fieldMapping): array {
    $out = [];
    foreach ($fieldMapping as $key => $path) {
        if (!is_string($path) || $path === '') { continue; }
        $out[$key] = vg_generic_extract($item, ltrim($path, '$.'));
    }
    return $out;
}

/** role의 필수 매핑 키가 다 채워졌는지 검증. 비어있으면 유효, 아니면 누락 키 목록. */
function vg_generic_validate_mapped(string $role, array $mapped): array {
    $missing = [];
    foreach (VG_GENERIC_REQUIRED_FIELDS[$role] ?? [] as $key) {
        $v = $mapped[$key] ?? null;
        if ($v === null || $v === '') { $missing[] = $key; }
    }
    if (!$missing && isset($mapped['cve_id']) && !vg_is_cve_id((string) $mapped['cve_id'])) {
        $missing[] = 'cve_id(형식)';
    }
    return $missing;
}

/** connection_json 검증 + 정규화. role/url_template/field_mapping 이 없으면 저장·실행 모두 막는다. */
function vg_generic_parse_config(array $conn): array {
    $role = (string) ($conn['role'] ?? '');
    if (!in_array($role, VG_GENERIC_ROLES, true)) {
        throw new RuntimeException("generic_api: 잘못된 role ($role)");
    }
    $urlTemplate = trim((string) ($conn['url_template'] ?? ''));
    if ($urlTemplate === '') {
        throw new RuntimeException('generic_api: url_template 이 비어있습니다.');
    }
    $method = strtoupper((string) ($conn['method'] ?? 'GET'));
    $headers = [];
    foreach ((array) ($conn['headers'] ?? []) as $k => $v) {
        if ($k === '' || $v === null || $v === '') { continue; }
        $headers[] = "$k: $v";
    }
    $response     = (array) ($conn['response'] ?? []);
    $fieldMapping = (array) ($response['field_mapping'] ?? []);
    if (!$fieldMapping) {
        throw new RuntimeException('generic_api: field_mapping 이 비어있습니다.');
    }
    $idKey = $role === 'compliance' ? 'rule_id' : 'cve_id';
    if (empty($fieldMapping[$idKey])) {
        throw new RuntimeException("generic_api: field_mapping 에 $idKey 매핑이 없습니다.");
    }
    return [
        'role'          => $role,
        'url_template'  => $urlTemplate,
        'method'        => in_array($method, ['GET', 'POST'], true) ? $method : 'GET',
        'headers'       => $headers,
        'items_path'    => (string) ($response['items_path'] ?? ''),
        'field_mapping' => $fieldMapping,
        'pagination'    => (array) ($conn['pagination'] ?? []),
    ];
}

// ─────────────────────────────────────────────────────────────────────────
// role별 upsert 라우팅(설계문서 4장)
// ─────────────────────────────────────────────────────────────────────────

function vg_generic_upsert_identity(PDO $pdo, array $m): bool {
    $cve  = strtoupper((string) $m['cve_id']);
    $cvss = (isset($m['cvss']) && $m['cvss'] !== null && $m['cvss'] !== '') ? (float) $m['cvss'] : null;
    vg_upsert_cve(
        $pdo, $cve,
        !empty($m['summary']) ? mb_substr((string) $m['summary'], 0, VG_TEXT_MAX) : null,
        $cvss,
        !empty($m['published']) ? (string) $m['published'] : null,
        !empty($m['cvss_vector']) ? (string) $m['cvss_vector'] : null,
        !empty($m['cwe']) ? (string) $m['cwe'] : null
    );
    if (!empty($m['package_name'])) {
        vg_upsert_affected(
            $pdo, $cve,
            !empty($m['ecosystem']) ? (string) $m['ecosystem'] : null,
            (string) $m['package_name'],
            !empty($m['fixed_version']) ? (string) $m['fixed_version'] : null
        );
    }
    return true;
}

function vg_generic_upsert_priority(PDO $pdo, array $m): bool {
    $cve = strtoupper((string) $m['cve_id']);
    $touched = false;

    // KEV 계열 필드가 field_mapping에 하나라도 선언돼 있을 때만 upsert(안 그러면 다른 소스가
    // 채운 note/due_date 등을 null 로 덮어쓴다 -- vg_upsert_kev 는 COALESCE 없이 그대로 VALUES()).
    if (array_key_exists('date_added', $m) || array_key_exists('note', $m)
        || array_key_exists('due_date', $m) || array_key_exists('ransomware', $m)) {
        vg_upsert_kev(
            $pdo, $cve,
            !empty($m['date_added']) ? (string) $m['date_added'] : null,
            isset($m['note']) && $m['note'] !== null ? mb_substr((string) $m['note'], 0, VG_TEXT_MAX) : null,
            !empty($m['due_date']) ? (string) $m['due_date'] : null,
            !empty($m['ransomware'])
        );
        $touched = true;
    }

    // epss 는 EPSS 커넥터와 같은 정책 -- 보유 CVE 만 갱신(COALESCE 라 한쪽만 와도 다른 값 유지).
    if (array_key_exists('epss', $m) || array_key_exists('epss_percentile', $m)) {
        $epss = (isset($m['epss']) && $m['epss'] !== null && $m['epss'] !== '') ? (float) $m['epss'] : null;
        $pct  = (isset($m['epss_percentile']) && $m['epss_percentile'] !== null && $m['epss_percentile'] !== '') ? (float) $m['epss_percentile'] : null;
        $pdo->prepare('UPDATE tb_cve SET epss = COALESCE(?, epss), epss_percentile = COALESCE(?, epss_percentile) WHERE cve_id = ?')
            ->execute([$epss, $pct, $cve]);
        $touched = true;
    }
    return $touched;
}

function vg_generic_upsert_vendor(PDO $pdo, array $m): bool {
    // 1차는 tb_vendor_errata 만 지원(errata/unfixed/debtracker/oval 세분화는 설계문서 9장 미해결질문 1).
    $pdo->prepare(
        'INSERT INTO tb_vendor_errata (vendor, release_major, pkg_name, cve_id, fixed_evr, advisory, severity)
         VALUES (?,?,?,?,?,?,?)
         ON DUPLICATE KEY UPDATE advisory = VALUES(advisory), severity = VALUES(severity)'
    )->execute([
        mb_substr((string) $m['vendor'], 0, 16),
        mb_substr((string) $m['release_major'], 0, 8),
        mb_substr((string) $m['pkg_name'], 0, 255),
        strtoupper((string) $m['cve_id']),
        mb_substr((string) $m['fixed_evr'], 0, 128),
        !empty($m['advisory']) ? mb_substr((string) $m['advisory'], 0, 64) : null,
        !empty($m['severity']) ? mb_substr((string) $m['severity'], 0, 16) : null,
    ]);
    return true;
}

/** role에 맞는 upsert 헬퍼로 라우팅. compliance 는 호출측(run/preview)에서 이미 걸러진다. */
function vg_generic_upsert(PDO $pdo, string $role, array $mapped): bool {
    switch ($role) {
        case 'identity': return vg_generic_upsert_identity($pdo, $mapped);
        case 'priority': return vg_generic_upsert_priority($pdo, $mapped);
        case 'vendor':   return vg_generic_upsert_vendor($pdo, $mapped);
        default:         return false;
    }
}

// ─────────────────────────────────────────────────────────────────────────
// 커넥터
// ─────────────────────────────────────────────────────────────────────────

final class VgGenericApiConnector implements VgFeedConnector {
    public function run(PDO $pdo, array $conn): array {
        $cfg = vg_generic_parse_config($conn);
        if ($cfg['role'] === 'compliance') {
            throw new RuntimeException('generic_api: compliance role은 아직 지원하지 않습니다(설계문서 9장 Q4 참고)');
        }

        $paginationType = (string) ($cfg['pagination']['type'] ?? 'none');
        $pageSize       = (int) ($cfg['pagination']['page_size'] ?? 0);
        // offset 페이징만 1차 지원. 다른 타입(cursor 등)은 1페이지만 처리하고 결과에 안내를 남긴다.
        $singlePageOnly = !in_array($paginationType, ['none', 'offset'], true);

        $fetched = 0; $upserted = 0; $skipped = 0; $offset = 0;
        for ($page = 1; $page <= VG_GENERIC_MAX_PAGES; $page++) {
            $url = vg_generic_render_url($cfg['url_template'], $page, $offset);
            $r   = vg_http_json($cfg['method'], $url, null, $cfg['headers']);
            if ($r['code'] < 200 || $r['code'] >= 300 || $r['json'] === null) {
                if ($page === 1) {
                    throw new RuntimeException("generic_api fetch 실패 (HTTP {$r['code']}) {$r['error']}");
                }
                break; // 이후 페이지 실패는 지금까지 모은 것으로 마감
            }

            $items = $cfg['items_path'] !== '' ? vg_generic_extract($r['json'], $cfg['items_path']) : $r['json'];
            if (!is_array($items) || !$items) { break; }

            $pdo->beginTransaction();
            foreach ($items as $item) {
                if (!is_array($item)) { continue; }
                $fetched++;
                $mapped  = vg_generic_map_item($item, $cfg['field_mapping']);
                $missing = vg_generic_validate_mapped($cfg['role'], $mapped);
                if ($missing) {
                    $skipped++;
                    error_log('[generic_api] 매핑 실패로 skip (role=' . $cfg['role'] . '): ' . implode(',', $missing));
                    continue;
                }
                if (vg_generic_upsert($pdo, $cfg['role'], $mapped)) { $upserted++; }
            }
            $pdo->commit();

            if ($singlePageOnly || $paginationType === 'none') { break; }
            if ($pageSize > 0 && count($items) < $pageSize) { break; } // 마지막 페이지
            $offset += $pageSize > 0 ? $pageSize : count($items);
        }

        $res = ['fetched' => $fetched, 'upserted' => $upserted, 'skipped' => $skipped];
        if ($singlePageOnly) {
            $res['note'] = "pagination.type={$paginationType} 미지원 -- 1페이지만 처리";
        }
        return $res;
    }

    // 미리보기: 저장 없이 첫 페이지 최대 10건 fetch + 매핑 결과 미리보기. 필수 필드 누락은 경고만.
    public function preview(PDO $pdo, array $conn): array {
        try {
            $cfg = vg_generic_parse_config($conn);
        } catch (RuntimeException $e) {
            return ['ok' => false, 'error' => $e->getMessage()];
        }
        if ($cfg['role'] === 'compliance') {
            return ['ok' => false, 'error' => 'compliance role은 아직 지원하지 않습니다.'];
        }

        $url = vg_generic_render_url($cfg['url_template'], 1, 0);
        $r   = vg_http_json($cfg['method'], $url, null, $cfg['headers']);
        if ($r['code'] < 200 || $r['code'] >= 300 || $r['json'] === null) {
            return ['ok' => false, 'error' => "HTTP {$r['code']} {$r['error']}"];
        }

        $items = $cfg['items_path'] !== '' ? vg_generic_extract($r['json'], $cfg['items_path']) : $r['json'];
        if (!is_array($items)) { $items = []; }

        $sample = [];
        foreach (array_slice($items, 0, VG_GENERIC_PREVIEW_LIMIT) as $item) {
            if (!is_array($item)) { continue; }
            $mapped = vg_generic_map_item($item, $cfg['field_mapping']);
            $sample[] = ['mapped' => $mapped, 'missing' => vg_generic_validate_mapped($cfg['role'], $mapped)];
        }
        return ['ok' => true, 'count' => count($items), 'sample' => $sample];
    }
}
