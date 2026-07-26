<?php
declare(strict_types=1);

/**
 * feeds/nvd.php — NVD 2.0 커넥터. 최근 N일 "수정된"(lastMod) CVE → tb_cve (CVSS 포함).
 *   증분 수집(전체 미러 아님). 공통 순회 루틴 vg_nvd_sync 는 주기 수집(커넥터)과
 *   전체 백필(bin/backfill_nvd.php)이 함께 쓴다.
 *   미리보기·주기 수집은 같은 날짜창(lastMod)을 본다 — 발행일 기준으로 어긋나던 버그를 막는다.
 */

require_once __DIR__ . '/http.php';
require_once __DIR__ . '/upsert.php';
require_once __DIR__ . '/../format.php';   // vg_is_safe_http_url — 저장/출력 검증을 한 곳에서 공유

// 커넥터 기본 소스 URL. 커넥터 레코드의 url 이 비어 있으면 이 값을 쓴다(run/미리보기 공용).
const VG_NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

// NVD 2.0 — 최근 N일 공개 CVE → cves (CVSS 포함). 증분 수집(전체 미러 아님).
//   기간 내 결과를 startIndex 로 끝까지 페이지네이션(무음 절단 방지, rate limit 준수).
//
// [페이지 크기] NVD 최대는 2000 이지만 쓰지 않는다. 실측(2026-07-09, API 키 사용):
//     perPage=500  → 2.2MB  43초
//     perPage=1000 → 4.0MB  62초
//     perPage=2000 → 8.4MB 156초   ← 기존 타임아웃 120초를 넘겨 죽는다
//   NVD 는 키가 있어도 50~60KB/s 밖에 주지 않는다. 병목은 rate limit 이 아니라 대역폭이라
//   페이지를 키워도 총 시간은 같다. 타임아웃 위험만 커지므로 500 으로 잡는다.
const VG_NVD_PER_PAGE   = 500;
const VG_NVD_TIMEOUT    = 300;    // 초. 느린 응답(50KB/s)에 여유를 둔다.
const VG_NVD_MAX_RETRY  = 5;      // 일시적 오류(HTTP/2 스트림 끊김·5xx·타임아웃) 재시도 횟수
const VG_NVD_MAX_WINDOW = 120;    // NVD 가 허용하는 최대 날짜 범위(일). 넘으면 404.

/** NVD 응답 1건을 tb_cve 로 upsert. @return bool 실제로 처리했는지 */
function vg_nvd_upsert_item(PDO $pdo, array $item): bool {
    $c  = $item['cve'] ?? [];
    $id = $c['id'] ?? '';
    if ($id === '') { return false; }

    $desc = '';
    foreach ($c['descriptions'] ?? [] as $d) {
        if (($d['lang'] ?? '') === 'en') { $desc = (string) $d['value']; break; }
    }
    // 점수와 벡터는 같은 metric 에서 함께 꺼낸다 — v3.1 점수에 v2 벡터를 붙이면 거짓말이 된다.
    $cvss = null; $vector = null;
    foreach (['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'] as $mk) {
        $d = $c['metrics'][$mk][0]['cvssData'] ?? null;
        if (!empty($d['baseScore'])) {
            $cvss   = (float) $d['baseScore'];
            $vector = !empty($d['vectorString']) ? (string) $d['vectorString'] : null;
            break;
        }
    }

    // CWE — NVD 는 여러 개를 줄 수 있지만 대표 하나만 쓴다(상세 화면에 유형 한 줄 띄우는 용도).
    //   'NVD-CWE-noinfo' 같은 자리표시자는 진짜 유형이 아니므로 거른다.
    $cwe = null;
    foreach ($c['weaknesses'] ?? [] as $w) {
        foreach ($w['description'] ?? [] as $d) {
            $v = (string) ($d['value'] ?? '');
            if (preg_match('/^CWE-\d+$/', $v)) { $cwe = $v; break 2; }
        }
    }

    $pub = !empty($c['published']) ? substr((string) $c['published'], 0, 10) : null;
    $refUrlsJson = vg_nvd_extract_ref_urls($c['references'] ?? []);
    vg_upsert_cve($pdo, $id, mb_substr($desc, 0, VG_TEXT_MAX), $cvss, $pub, $vector, $cwe, $refUrlsJson);
    return true;
}

/**
 * NVD references 배열 → [['url'=>..,'tags'=>[..]],...] 을 JSON 문자열로. 벤더 패치/공지 URL
 * 목록이다 — fixed_version 이 없는 CVE(NVD 는 구조화된 조치버전을 안 준다)라도 최소한 링크는
 * 보여줄 수 있게 저장한다. http(s) 스킴만 허용(그대로 href 로 출력되므로 방어적 검증 필수),
 * 중복 제거, 최대 10개로 자른다(CVE 하나에 수십 개가 붙는 경우가 있다). 'Patch'/
 * 'Vendor Advisory' 태그가 붙은 것을 앞으로 정렬한다 — 첫 항목이 화면 대표 링크로 쓰인다.
 */
function vg_nvd_extract_ref_urls(array $references): ?string {
    // 자르기 전에 먼저 정렬한다 — Patch 태그가 원본 배열 뒤쪽에 오는 경우가 흔해서,
    //   자르고 나서 정렬하면 앞 10개에 Patch 가 하나도 없어 벤더 패치 URL 이 통째로
    //   버려질 수 있다(그러면 화면의 대표 링크가 무관한 메일링리스트를 가리킨다).
    $seen = [];
    $list = [];
    foreach ($references as $ref) {
        $url = (string) ($ref['url'] ?? '');
        if (!vg_is_safe_http_url($url)) { continue; }
        // TEXT 컬럼(64KB) 저장 방어 — NVD 에는 쿼리스트링이 아주 긴 URL 이 섞인다. 비-strict
        //   모드에서 초과분이 조용히 잘리면 JSON 문자열이 깨져 cve.php 의 json_decode 가
        //   실패하고 카드가 통째로 사라진다(원인 추적도 어렵다). 넉넉히 512자로 자른다.
        if (strlen($url) > 512) { continue; }
        if (isset($seen[$url])) { continue; }
        $seen[$url] = true;
        $tags = [];
        foreach ($ref['tags'] ?? [] as $t) { $tags[] = (string) $t; }
        // NVD 가 죽은 링크라고 명시한 것 — 화면 대표 링크로 쓰이면 사용자가 클릭 후 헛수고한다.
        if (in_array('Broken Link', $tags, true)) { continue; }
        $list[] = ['url' => $url, 'tags' => $tags];
    }
    if (!$list) { return null; }

    usort($list, function ($a, $b) {
        $pref = fn($r) => (in_array('Patch', $r['tags'], true) || in_array('Vendor Advisory', $r['tags'], true)) ? 0 : 1;
        return $pref($a) <=> $pref($b);
    });
    $list = array_slice($list, 0, 10);

    $json = json_encode($list, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    return $json !== false ? $json : null;
}

/**
 * NVD 페이지 1건을 가져온다. 일시적 오류는 지수 백오프로 재시도한다.
 *
 * 실제로 겪은 실패(2026-07-09, 24워커 병렬 백필):
 *   "NVD fetch 실패 (HTTP 200) HTTP/2 stream 1 was not closed cleanly: INTERNAL_ERROR"
 *   → 응답이 중간에 끊겨 code=200 인데 JSON 이 없다. 그래서 code 만 보면 안 된다.
 *
 * 영구 오류(잘못된 API 키·잘못된 파라미터)는 재시도해도 같으므로 즉시 포기한다.
 * NVD 는 키가 틀리면 404 + "message: Invalid apiKey." 를, 범위가 120일을 넘으면 404 를 준다.
 */
function vg_nvd_fetch_page(string $url, array $headers, int $startIndex): array {
    $delay = 1;
    $last  = null;
    for ($try = 1; $try <= VG_NVD_MAX_RETRY; $try++) {
        $r = vg_http_json('GET', $url, null, $headers, VG_NVD_TIMEOUT);
        if ($r['code'] === 200 && isset($r['json']['vulnerabilities'])) {
            return $r;
        }
        $last = $r;
        if (in_array($r['code'], [400, 401, 403, 404], true)) {
            throw new RuntimeException("NVD fetch 실패 (HTTP {$r['code']}) startIndex=$startIndex {$r['error']} — 재시도 안 함(영구 오류)");
        }
        if ($try < VG_NVD_MAX_RETRY) {
            error_log("[nvd] startIndex=$startIndex 재시도 $try/" . VG_NVD_MAX_RETRY . " ({$delay}초 뒤): HTTP {$r['code']} {$r['error']}");
            sleep($delay);
            $delay *= 2;   // 1 → 2 → 4 → 8
        }
    }
    throw new RuntimeException(
        "NVD fetch 실패 (HTTP {$last['code']}) startIndex=$startIndex {$last['error']} — " . VG_NVD_MAX_RETRY . '회 재시도 후 포기'
    );
}

/**
 * NVD 2.0 페이지 순회 + upsert.
 *   $dateParams 가 비면 날짜 필터 없이 전체(36만건)를 훑는다 → 초기 백필.
 *   NVD 는 날짜가 없어도 startIndex 로 끝까지 페이징된다(실측: startIndex=360000 → HTTP 200).
 *   그래서 초기 백필에 120일 창을 순회할 필요가 없다.
 *   $onPage(startIndex, total, fetched) 로 진행 상황을 흘려보낸다(백필 로그용).
 * @return array{fetched:int,upserted:int,total:int}
 */
function vg_nvd_sync(PDO $pdo, array $conn, array $dateParams = [], int $startIndex = 0, ?callable $onPage = null): array {
    $base    = vg_conn_url($conn, VG_NVD_URL);
    $key     = trim((string) ($conn['api_key'] ?? ''));
    $headers = $key !== '' ? ['apiKey: ' . $key] : [];

    $total = 0; $fetched = 0; $up = 0;
    do {
        $qs = http_build_query($dateParams + [
            'resultsPerPage' => VG_NVD_PER_PAGE,
            'startIndex'     => $startIndex,
        ]);
        $r = vg_nvd_fetch_page("$base?$qs", $headers, $startIndex);
        $total = (int) ($r['json']['totalResults'] ?? 0);

        $pdo->beginTransaction();
        foreach ($r['json']['vulnerabilities'] as $item) {
            if (vg_nvd_upsert_item($pdo, $item)) { $up++; }
            $fetched++;
        }
        $pdo->commit();
        unset($r);   // 페이지(약 4MB)를 즉시 해제 → 36만건을 훑어도 메모리 사용량은 일정하다

        $startIndex += VG_NVD_PER_PAGE;
        // 콜백이 false 를 돌려주면 중단(백필의 --max-pages 시험용). 재개는 startIndex 로 한다.
        if ($onPage !== null && $onPage($startIndex, $total, $fetched) === false) { break; }
        if ($startIndex < $total) {
            sleep($key !== '' ? 1 : 6);   // rate limit (키 없으면 30초당 5요청)
        }
    } while ($startIndex < $total);

    return ['fetched' => $fetched, 'upserted' => $up, 'total' => $total];
}

final class VgNvdConnector implements VgFeedConnector {
    /**
     * 주기 수집·미리보기 공용 날짜창. **수정된 CVE(lastMod) 기준**이다.
     *   발행일(pubStartDate) 기준이면 예전에 발행됐다가 뒤늦게 CVSS·설명이 붙은 CVE 를
     *   영원히 놓친다. 실측(2026-07-09): 최근 7일 발행 1,311건 vs 수정 4,580건.
     *   NVD 는 lastModStartDate/lastModEndDate 를 둘 다 요구하고 범위는 120일까지만 허용한다.
     *   미리보기가 예전엔 발행일(pubStartDate)로 어긋나 있었다 — run 과 다른 걸 보여주는 버그였다.
     *   이제 run 과 preview 가 같은 이 창을 써 구조적으로 일치한다.
     */
    private function windowParams(int $days): array {
        $days = min(VG_NVD_MAX_WINDOW, max(1, $days));
        return [
            'lastModStartDate' => gmdate('Y-m-d\TH:i:s.000', time() - $days * 86400),
            'lastModEndDate'   => gmdate('Y-m-d\TH:i:s.000'),
        ];
    }

    /**
     * 주기 수집은 "수정된 CVE"(lastMod) 기준이다.
     * 전체 이력은 bin/backfill_nvd.php 로 1회 채운다(주기 수집이 할 일이 아니다).
     */
    public function run(PDO $pdo, array $conn): array {
        $res = vg_nvd_sync($pdo, $conn, $this->windowParams((int) ($conn['days'] ?? 7)));
        return ['fetched' => $res['fetched'], 'upserted' => $res['upserted']];
    }

    // 미리보기: run 과 같은 날짜창(lastMod)으로 앞 10건을 그대로 보여준다(저장 안 함).
    public function preview(PDO $pdo, array $conn): array {
        $base = vg_conn_url($conn, VG_NVD_URL);
        $qs   = http_build_query($this->windowParams((int) ($conn['days'] ?? 7)) + ['resultsPerPage' => 10]);
        $h    = !empty($conn['api_key']) ? ['apiKey: ' . $conn['api_key']] : [];
        $r = vg_http_json('GET', "$base?$qs", null, $h, 60);
        if ($r['code'] !== 200 || !isset($r['json']['vulnerabilities'])) {
            return ['ok' => false, 'error' => "HTTP {$r['code']} {$r['error']}"];
        }
        return ['ok' => true, 'count' => (int) ($r['json']['totalResults'] ?? 0), 'sample' => $r['json']['vulnerabilities']];
    }
}
