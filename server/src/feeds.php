<?php
declare(strict_types=1);

/**
 * feeds.php — CVE 피드 커넥터 (4단계).
 *   claude-pipeline 의 Connector/ConnectorCollectionLog 패턴을 PHP 로 옮긴 것.
 *   커넥터 타입: kev(CISA KEV) / osv(OSV.dev) / nvd(NVD 2.0).
 *   결과는 cves / kev_catalog / cve_affected_packages 로 upsert.
 */

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/audit.php';   // vg_log_activity
require_once __DIR__ . '/distro.php';  // vg_osv_ecosystem (매처와 공유)

/**
 * 긴 텍스트(설명·본문) 저장 상한(글자 수). 폭주한 응답으로부터 DB 를 지키는 안전장치일 뿐,
 * 정상 데이터를 자르기 위한 값이 아니다.
 *
 * 실제로 이 상한을 2000 으로 두는 바람에 NVD 설명 2,817건이 문장 중간에서 잘렸다.
 * 저장 컬럼은 MEDIUMTEXT(16MB) 이므로 6만 글자는 넉넉히 들어간다.
 * (TEXT 는 65,535 "바이트" 라 한글이 섞이면 글자 수가 훨씬 줄어든다 — 그래서 MEDIUMTEXT.)
 */
const VG_TEXT_MAX = 60000;

// 커넥터 기본 소스 URL. 커넥터 레코드의 url 이 비어 있으면 이 값을 쓴다(run/미리보기 공용).
const VG_KEV_URL  = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const VG_OSV_URL  = 'https://api.osv.dev/v1/querybatch';
const VG_NVD_URL  = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const VG_EPSS_URL = 'https://epss.cyentia.com/epss_scores-current.csv.gz';

/**
 * 커넥터 URL 을 고른다. 빈 값이면 기본 URL.
 *
 * `$conn['url'] ?? $default` 는 안 된다. connectors.php 의 저장 폼이 url 키를 항상 넣기
 * 때문에(빈 문자열 포함) `??` 가 절대 발동하지 않는다 — URL 을 비워둔 KISA/EPSS 커넥터가
 * 빈 문자열을 curl 에 넘겨 HTTP 0 으로 죽던 원인.
 */
function vg_conn_url(array $conn, string $default): string {
    $u = trim((string) ($conn['url'] ?? ''));
    return $u !== '' ? $u : $default;
}

// ─────────────────────────────────────────────────────────────────────────
// HTTP (curl)
// ─────────────────────────────────────────────────────────────────────────
// $maxBytes>0 이면 응답이 그 크기를 넘는 순간 전송을 중단한다(OSV 커널 등 거대 응답 OOM 방어).
function vg_http_json(string $method, string $url, $body = null, array $headers = [], int $timeout = 90, int $maxBytes = 0): array {
    $ch = curl_init($url);
    $hdr = array_merge(['Accept: application/json'], $headers);
    $opt = [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_TIMEOUT        => $timeout,
        CURLOPT_CONNECTTIMEOUT => 20,
        CURLOPT_CUSTOMREQUEST  => $method,
        CURLOPT_USERAGENT      => 'vuln-agent-feed/1.0',
        // SSRF/LFI 방어: http/https 만 허용(file://·gopher:// 등 차단), 리다이렉트도 동일 제한
        CURLOPT_PROTOCOLS       => CURLPROTO_HTTP | CURLPROTO_HTTPS,
        CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
    ];
    if ($body !== null) {
        $opt[CURLOPT_POSTFIELDS] = is_string($body) ? $body : json_encode($body);
        $hdr[] = 'Content-Type: application/json';
    }
    if ($maxBytes > 0) {
        $opt[CURLOPT_NOPROGRESS]       = false;
        $opt[CURLOPT_PROGRESSFUNCTION] = static function ($ch, $dltotal, $dlnow) use ($maxBytes) {
            return ($dlnow > $maxBytes || $dltotal > $maxBytes) ? 1 : 0; // 넘으면 중단
        };
    }
    $opt[CURLOPT_HTTPHEADER] = $hdr;
    curl_setopt_array($ch, $opt);
    $raw  = curl_exec($ch);
    $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err  = curl_error($ch);
    curl_close($ch);
    if ($raw === false && $maxBytes > 0 && $code === 0) {
        return ['code' => 0, 'json' => null, 'error' => "응답이 상한({$maxBytes}B) 초과로 건너뜀"];
    }
    $decoded = is_string($raw) ? json_decode($raw, true) : null;
    return ['code' => $code, 'json' => is_array($decoded) ? $decoded : null, 'error' => $err];
}

// raw 응답 (XML/RSS 등 non-JSON 소스용)
function vg_http_raw(string $method, string $url, array $headers = [], int $timeout = 60): array {
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_TIMEOUT        => $timeout,
        CURLOPT_CONNECTTIMEOUT => 20,
        CURLOPT_CUSTOMREQUEST  => $method,
        CURLOPT_USERAGENT      => 'vuln-agent-feed/1.0',
        // SSRF/LFI 방어: http/https 만 허용(file://·gopher:// 등 차단), 리다이렉트도 동일 제한
        CURLOPT_PROTOCOLS       => CURLPROTO_HTTP | CURLPROTO_HTTPS,
        CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
        CURLOPT_HTTPHEADER     => $headers,
    ]);
    $raw  = curl_exec($ch);
    $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err  = curl_error($ch);
    curl_close($ch);
    return ['code' => $code, 'body' => is_string($raw) ? $raw : '', 'error' => $err];
}

// ─────────────────────────────────────────────────────────────────────────
// upsert 헬퍼 (수집 결과 저장)
// ─────────────────────────────────────────────────────────────────────────
/**
 * CVE-ID 형식 검증. 공지 본문·제목에서 정규식으로 긁은 값에는 원문 오탈자가 섞인다
 * (실제로 CVE-0215-8451, CVE-2016-03246 이 tb_cves 에 들어갔다).
 *   - 연도는 1999 ~ 내년.
 *   - 일련번호는 4자리면 선행 0 허용(CVE-2014-0160 = Heartbleed), 5자리 이상이면 금지.
 */
function vg_is_cve_id(string $id): bool {
    if (!preg_match('/^CVE-([0-9]{4})-([0-9]{4}|[1-9][0-9]{4,6})$/', $id, $m)) {
        return false;
    }
    $year = (int) $m[1];
    return $year >= 1999 && $year <= (int) gmdate('Y') + 1;
}

/** 텍스트에서 유효한 CVE-ID 만 뽑는다(대문자·중복제거·정렬). 오탈자는 버린다. */
function vg_extract_cve_ids(string $text): array {
    preg_match_all('/CVE-[0-9]{4}-[0-9]{4,}/i', $text, $m);
    $ids = array_values(array_unique(array_filter(
        array_map('strtoupper', $m[0]),
        'vg_is_cve_id'
    )));
    sort($ids);
    return $ids;
}

// tb_cves 로 들어가는 유일한 통로. 여기서 막으면 모든 커넥터·백필이 함께 보호된다.
function vg_upsert_cve(PDO $pdo, string $id, ?string $summary, ?float $cvss, ?string $published): void {
    if (!vg_is_cve_id($id)) {
        error_log("[cve] 잘못된 CVE-ID 무시: $id");
        return;
    }
    $st = $pdo->prepare(
        'INSERT INTO tb_cves (cve_id, summary, cvss, published) VALUES (?,?,?,?)
         ON DUPLICATE KEY UPDATE
           summary   = COALESCE(VALUES(summary), summary),
           cvss      = COALESCE(VALUES(cvss), cvss),
           published = COALESCE(VALUES(published), published)'
    );
    $st->execute([$id, $summary, $cvss, $published]);
}

function vg_upsert_kev(PDO $pdo, string $id, ?string $dateAdded, ?string $note): void {
    $st = $pdo->prepare(
        'INSERT INTO tb_kev_catalog (cve_id, date_added, note) VALUES (?,?,?)
         ON DUPLICATE KEY UPDATE date_added = VALUES(date_added), note = VALUES(note)'
    );
    $st->execute([$id, $dateAdded ?: null, $note]);
}

// 보호나라 공지 URL 정규화. 같은 공지라도 유입 경로마다 쿼리스트링이 달라진다.
//   RSS  : view.do?searchCnd=&bbsId=..&searchWrd=&menuNo=..&pageIndex=1&categoryCode=&nttId=72127
//   목록N: view.do?searchCnd=&bbsId=..&searchWrd=&menuNo=..&pageIndex=5&categoryCode=&nttId=72127
// pageIndex 가 섞여 있으면 url 기준 dedup 이 깨져 같은 공지가 페이지 수만큼 중복된다.
// 실제 식별자는 nttId 뿐. 조회에 필요한 bbsId/menuNo 만 남기고 나머지는 버린다.
function vg_kisa_canon_url(string $url): string {
    $p = parse_url($url);
    if (!isset($p['host'], $p['path']) || stripos($p['host'], 'boho.or.kr') === false) {
        return $url;  // 보호나라 URL 이 아니면 손대지 않는다
    }
    parse_str($p['query'] ?? '', $q);
    if (empty($q['nttId'])) {
        return $url;  // nttId 없으면 정규화 불가(원본 유지)
    }
    $keep = [];
    foreach (['bbsId', 'menuNo', 'nttId'] as $k) {
        if (!empty($q[$k])) { $keep[$k] = $q[$k]; }
    }
    return 'https://' . $p['host'] . $p['path'] . '?' . http_build_query($keep);
}

// 국내 보안공지(KISA 등) upsert. 정규화한 url 기준 dedup.
//   KISA 는 수정일을 노출하지 않으므로(RSS·목록·상세 모두 등록일 하나뿐) 저장된 값과
//   비교해 실제로 달라졌을 때만 UPDATE 한다. 그래야 updated_at 이 "변경을 관측한 시각"이
//   되고, 백필을 몇 번 돌려도 멱등하다.
//   제목 정규화(엔티티 해제·공백 압축·길이 제한)를 여기서 한다. RSS 는 제목에 &#39; 같은
//   엔티티를 그대로 주고 목록 페이지는 해제된 문자를 준다. 경로마다 다르게 다듬으면
//   같은 공지가 수집 주기마다 '수정'으로 뒤집힌다.
//   반환: 'new' | 'updated' | 'unchanged'
/**
 * 두 cve_ids 문자열의 합집합(정렬·중복제거·형식검증).
 *   양쪽 모두 vg_extract_cve_ids 를 통과시키므로 예전에 잘려 저장된 조각("CVE-2")이나
 *   오탈자(CVE-0215-8451)는 여기서 함께 걸러진다.
 */
function vg_merge_cve_ids(?string $a, ?string $b): ?string {
    $ids = vg_extract_cve_ids((string) $a . "\n" . (string) $b);
    return $ids ? implode(',', $ids) : null;
}

function vg_upsert_advisory(PDO $pdo, string $source, string $title, string $url, ?string $published, ?string $cveIds): string {
    $url   = vg_kisa_canon_url($url);
    $title = html_entity_decode($title, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    $title = mb_substr(trim(preg_replace('/\s+/u', ' ', $title)), 0, 500);
    $chk = $pdo->prepare('SELECT id, title, published, cve_ids FROM tb_advisories WHERE url = ? LIMIT 1');
    $chk->execute([$url]);
    $cur = $chk->fetch(PDO::FETCH_ASSOC);
    if ($cur) {
        // cve_ids 는 덮어쓰지 않고 합친다.
        //   호출자(RSS 커넥터·목록 백필)는 "제목"만 보고 CVE 를 뽑는다. 본문에서 찾은 CVE 는
        //   DB 에만 있다(vg_advisory_fill_content 가 채운다). 덮어쓰면 본문 유래 CVE 가 날아가고,
        //   content_fetched_at 이 이미 찍혀 있어 fill_content 가 다시 채워주지도 않는다.
        //   실제로 백필 재실행이 공지 1,742건의 cve_ids 를 지웠다.
        //   전량 재계산(축소 포함)은 bin/rebuild_advisory_cveids.php 가 직접 UPDATE 로 한다.
        $cveIds = vg_merge_cve_ids($cur['cve_ids'] ?? null, $cveIds);
        $same = $cur['title'] === $title
             && (string) $cur['published'] === (string) $published
             && (string) $cur['cve_ids'] === (string) $cveIds;
        if ($same) {
            return 'unchanged';
        }
        $pdo->prepare('UPDATE tb_advisories SET title=?, published=?, cve_ids=? WHERE id=?')
            ->execute([$title, $published, $cveIds, (int) $cur['id']]);
        return 'updated';
    }
    $pdo->prepare('INSERT INTO tb_advisories (source, title, url, published, cve_ids) VALUES (?,?,?,?,?)')
        ->execute([$source, $title, $url, $published, $cveIds]);
    return 'new';
}

/**
 * KISA 상세페이지 HTML 에서 본문 평문을 뽑는다. 실패 시 null.
 * 외부 HTML 을 그대로 저장하면 XSS 표면이 되므로 태그를 걷어내고 평문만 남긴다.
 * 다만 블록 경계는 줄바꿈으로 보존해 개요/설명/해결방안 구분이 살아 있게 한다.
 */
function vg_kisa_parse_content(string $html): ?string {
    $doc = new DOMDocument();
    libxml_use_internal_errors(true);
    $ok = $doc->loadHTML('<?xml encoding="utf-8" ?>' . $html);
    libxml_clear_errors();
    if (!$ok) { return null; }

    $node = (new DOMXPath($doc))->query('//div[contains(@class,"content_html")]');
    if ($node === false || $node->length === 0) { return null; }

    $inner = '';
    foreach ($node->item(0)->childNodes as $child) {
        $inner .= $doc->saveHTML($child);
    }
    $inner = preg_replace('#<(br|/p|/div|/li|/tr|/h[1-6]|/table)\b[^>]*>#i', "\n", $inner);
    $text = html_entity_decode(strip_tags((string) $inner), ENT_QUOTES | ENT_HTML5, 'UTF-8');
    $text = preg_replace('/[ \t\x{00A0}]+/u', ' ', $text);
    $text = preg_replace('/ *\n */u', "\n", $text);
    $text = trim(preg_replace('/\n{3,}/', "\n\n", $text));

    return $text === '' ? null : mb_substr($text, 0, VG_TEXT_MAX);
}

/**
 * 공지 1건의 본문을 채운다. 이미 채워져 있으면 요청 없이 false.
 * 본문에만 등장하는 CVE 를 흡수해 cve_ids 를 보강한다(제목에 없는 경우가 흔하다).
 * @return bool 실제로 본문을 새로 저장했는지
 */
function vg_advisory_fill_content(PDO $pdo, string $url): bool {
    $url = vg_kisa_canon_url($url);
    $st = $pdo->prepare('SELECT id, cve_ids, content_fetched_at FROM tb_advisories WHERE url = ? AND is_deleted = 0 LIMIT 1');
    $st->execute([$url]);
    $row = $st->fetch(PDO::FETCH_ASSOC);
    // "이미 시도했는가"는 content 가 아니라 content_fetched_at 이 판단한다. 본문 텍스트가
    // 없는 공지도 있어서(아래) content='' 로 남는데, content 로 판단하면 매 수집마다 재시도한다.
    if (!$row || $row['content_fetched_at'] !== null) {
        return false;
    }

    $id = (int) $row['id'];

    // HTTP 실패는 일시적일 수 있다 → 표시를 남기지 않고 예외. 다음 수집 때 재시도한다.
    $r = vg_http_raw('GET', $url, [], 30);
    if ($r['code'] !== 200 || $r['body'] === '') {
        throw new RuntimeException("KISA 상세 fetch 실패 (HTTP {$r['code']}) $url");
    }

    $text = vg_kisa_parse_content($r['body']);
    if ($text === null) {
        // 본문 텍스트가 없는 공지가 실제로 있다(전체의 0.3%).
        //   - 보안공지 일부: content_html 안이 이미지뿐이라 추출 텍스트가 &nbsp; 한 글자
        //   - 경보단계: 게시글 본문 영역 자체가 없고 제목이 내용의 전부
        // 다시 긁어도 결과가 같으므로 시도 시각만 남겨 무한 재시도를 막는다.
        $pdo->prepare("UPDATE tb_advisories SET content='', content_fetched_at=NOW() WHERE id=?")
            ->execute([$id]);
        return false;
    }

    $pdo->prepare('UPDATE tb_advisories SET content=?, content_fetched_at=NOW() WHERE id=?')
        ->execute([$text, $id]);

    $found = vg_extract_cve_ids($text);
    if ($found) {
        // 기존 값에도 과거의 오탈자가 남아 있을 수 있으므로 함께 거른다.
        $cur    = array_filter(array_map('trim', explode(',', (string) $row['cve_ids'])), 'vg_is_cve_id');
        $merged = array_unique(array_merge($cur, $found));
        sort($merged);
        // 절단하지 않는다. 과거 varchar(512) 시절 mb_substr(...,500) 이 마지막 ID 를 한가운데서
        // 잘라 "CVE-2" 같은 조각을 남겼고(운영 114건), 패치데이 공지는 CVE 263개 중 36개만 남았다.
        // 컬럼은 TEXT 로 넓혀 두었다(db/06-advisories.sql).
        $joined = implode(',', $merged);
        if ($joined !== (string) $row['cve_ids']) {
            $pdo->prepare('UPDATE tb_advisories SET cve_ids=? WHERE id=?')->execute([$joined, $id]);
        }
        foreach ($merged as $cve) {
            vg_upsert_cve($pdo, $cve, null, null, null);
        }
    }
    return true;
}

function vg_upsert_affected(PDO $pdo, string $cve, ?string $eco, string $pkg, ?string $fixed): void {
    $chk = $pdo->prepare('SELECT id FROM tb_cve_affected_packages WHERE cve_id=? AND package_name=? LIMIT 1');
    $chk->execute([$cve, $pkg]);
    $id = $chk->fetchColumn();
    if ($id) {
        // 존재하면 fixed_version 을 채워 넣는다(이전 batch 수집엔 없었음)
        if ($fixed !== null && $fixed !== '') {
            $pdo->prepare('UPDATE tb_cve_affected_packages SET fixed_version=?, ecosystem=COALESCE(ecosystem,?) WHERE id=?')
                ->execute([$fixed, $eco, (int) $id]);
        }
        return;
    }
    $pdo->prepare('INSERT INTO tb_cve_affected_packages (cve_id, ecosystem, package_name, fixed_version) VALUES (?,?,?,?)')
        ->execute([$cve, $eco, $pkg, $fixed]);
}

// ─────────────────────────────────────────────────────────────────────────
// 커넥터: 각 타입은 run(PDO,$conn) → ['fetched'=>N,'upserted'=>N] 반환
// ─────────────────────────────────────────────────────────────────────────
interface VgFeedConnector {
    public function run(PDO $pdo, array $conn): array;
}

// CISA KEV — 실제 악용 취약점 카탈로그(JSON, 무인증). kev_catalog + cves.
final class VgKevConnector implements VgFeedConnector {
    public function run(PDO $pdo, array $conn): array {
        $url = vg_conn_url($conn, VG_KEV_URL);
        $r = vg_http_json('GET', $url);
        if ($r['code'] !== 200 || !isset($r['json']['vulnerabilities'])) {
            throw new RuntimeException("KEV fetch 실패 (HTTP {$r['code']}) {$r['error']}");
        }
        $vulns = $r['json']['vulnerabilities'];
        $up = 0;
        $pdo->beginTransaction();
        foreach ($vulns as $v) {
            $id = $v['cveID'] ?? '';
            if ($id === '') { continue; }
            $note = trim(($v['vendorProject'] ?? '') . ' ' . ($v['product'] ?? '') . ' — ' . ($v['vulnerabilityName'] ?? ''));
            vg_upsert_kev($pdo, $id, $v['dateAdded'] ?? null, mb_substr($note, 0, VG_TEXT_MAX));
            vg_upsert_cve($pdo, $id, mb_substr((string) ($v['shortDescription'] ?? ''), 0, VG_TEXT_MAX), null, null);
            $up++;
        }
        $pdo->commit();
        return ['fetched' => count($vulns), 'upserted' => $up];
    }
}

// vg_osv_ecosystem() 은 src/distro.php 로 옮겼다 — 매처도 같은 기준으로 읽어야 하기 때문.

// OSV vuln 에서 CVE ID 추출 (id → aliases 순)
function vg_osv_cve(array $vuln): ?string {
    if (preg_match('/CVE-\d{4}-\d+/i', (string) ($vuln['id'] ?? ''), $m)) { return strtoupper($m[0]); }
    foreach ($vuln['aliases'] ?? [] as $al) {
        if (preg_match('/CVE-\d{4}-\d+/i', (string) $al, $m)) { return strtoupper($m[0]); }
    }
    return null;
}

/**
 * OSV vuln 에서 해당 패키지의 "고쳐진 버전"(조치안) 추출 — 마지막 fixed 이벤트.
 *
 * $eco 를 주면 그 배포판의 affected 만 본다. 한 레코드가 여러 릴리스를 담기 때문이다
 * (USN-7786-1 은 14.04~24.04 의 openssl 을 한꺼번에 나열한다). 패키지명만으로 고르면
 * 24.04 호스트에 20.04 의 fixed 버전을 붙일 수 있다.
 * OSV 의 ecosystem 은 'Ubuntu:24.04:LTS' 처럼 접미사가 붙어 접두 일치로 비교한다.
 */
function vg_osv_fixed(array $vuln, string $key, ?string $eco = null): ?string {
    $fixed = null;
    foreach ($vuln['affected'] ?? [] as $aff) {
        if (($aff['package']['name'] ?? '') !== $key) { continue; }
        if ($eco !== null && strpos((string) ($aff['package']['ecosystem'] ?? ''), $eco) !== 0) { continue; }
        foreach ($aff['ranges'] ?? [] as $rng) {
            foreach ($rng['events'] ?? [] as $ev) {
                if (!empty($ev['fixed'])) { $fixed = (string) $ev['fixed']; }
            }
        }
    }
    return $fixed;
}

/**
 * 보안공지 레코드(USN-*, DSA-* …)가 묶고 있는 CVE 목록.
 *   querybatch 는 id 만 준다. USN 은 id 에 CVE 가 없어 그대로 버리면 취약점을 놓친다:
 *   실측(Ubuntu:24.04, 4개 패키지) CVE 105건 저장 → USN 을 펼치면 133건(+27%).
 *   OSV 의 per-CVE 레코드(UBUNTU-CVE-*)가 불완전한 탓이다. 예: CVE-2025-5745 는
 *   per-CVE 레코드에 Ubuntu:25.04 만 있는데, USN-7634-1 은 24.04 glibc 를 고친다.
 *
 *   USN 의 CVE 목록은 USN 전체 기준이라 일부는 다른 릴리스·다른 패키지 몫일 수 있다.
 *   그래도 조치는 동일하다(그 fixed 버전으로 올리면 전부 해결) → 커버리지를 택했다.
 * @return list<string> 대문자 CVE ID
 */
function vg_osv_advisory_cves(array $doc): array {
    $out = [];
    foreach (array_merge($doc['upstream'] ?? [], $doc['aliases'] ?? []) as $ref) {
        if (preg_match('/CVE-\d{4}-\d+/i', (string) $ref, $m)) { $out[strtoupper($m[0])] = true; }
    }
    return array_keys($out);
}

/** 단건 조회 URL(/v1/vulns/<id>). 커넥터 URL 이 무엇이든 같은 호스트를 쓴다. */
function vg_osv_vuln_url(string $id): string {
    return 'https://api.osv.dev/v1/vulns/' . rawurlencode($id);
}

/** 커넥터에 /v1/query 가 저장돼 있어도 batch 엔드포인트로 보정한다(run·미리보기 공용). */
function vg_osv_batch_url(array $conn): string {
    $url = vg_conn_url($conn, VG_OSV_URL);
    return substr($url, -6) === '/query' ? $url . 'batch' : $url;
}

/**
 * 스캔 1건의 패키지를 OSV querybatch 질의 목록으로 바꾼다(패키지·버전 중복 제거).
 * deb/ubuntu 는 바이너리 패키지가 아니라 source_pkg 로 조회해야 매칭된다.
 *
 * @return list<array{key:string,q:array}>
 */
function vg_osv_queries(PDO $pdo, int $scanId, string $eco): array {
    $isDeb = stripos($eco, 'Debian') === 0 || stripos($eco, 'Ubuntu') === 0;
    // OS 패키지만. 언어 패키지는 vg_osv_lang_queries 가 자기 생태계로 따로 조회한다.
    $pk = $pdo->prepare("SELECT name, source_pkg, version FROM tb_packages
                         WHERE scan_id = ? AND container_id = 0 AND manager IN ('rpm','dpkg')");
    $pk->execute([$scanId]);

    $out = []; $seen = [];
    foreach ($pk->fetchAll() as $p) {
        $key = $isDeb ? ($p['source_pkg'] ?: $p['name']) : $p['name'];
        $ver = (string) $p['version'];
        if ($key === '' || $ver === '' || isset($seen["$key|$ver"])) { continue; }
        $seen["$key|$ver"] = true;
        $out[] = ['key' => $key, 'eco' => $eco,
                  'q' => ['package' => ['ecosystem' => $eco, 'name' => $key], 'version' => $ver]];
    }
    return $out;
}

/**
 * 언어 패키지(pip/npm/gem/composer) → OSV 질의. 배포판과 무관하게 자기 생태계로 조회한다.
 * 에이전트는 예전부터 이걸 수집해 보냈는데 서버가 버려서 언어 패키지 CVE 가 전부 미탐이었다.
 *
 * @return list<array{key:string,eco:string,q:array}>
 */
function vg_osv_lang_queries(PDO $pdo, int $scanId): array {
    $pk = $pdo->prepare("SELECT manager, name, version FROM tb_packages
                         WHERE scan_id = ? AND container_id = 0 AND manager NOT IN ('rpm','dpkg')");
    $pk->execute([$scanId]);

    $out = []; $seen = [];
    foreach ($pk->fetchAll() as $p) {
        $eco = vg_pkg_ecosystem((string) $p['manager'], null);
        $key = (string) $p['name'];
        $ver = (string) $p['version'];
        if ($eco === null || $key === '' || $ver === '' || isset($seen["$eco|$key|$ver"])) { continue; }
        $seen["$eco|$key|$ver"] = true;
        $out[] = ['key' => $key, 'eco' => $eco,
                  'q' => ['package' => ['ecosystem' => $eco, 'name' => $key], 'version' => $ver]];
    }
    return $out;
}

/**
 * 컨테이너 **내부** 패키지 → OSV 질의. 생태계는 그 컨테이너의 배포판이다(호스트와 다를 수 있다).
 * deb 계열은 호스트와 마찬가지로 source_pkg 로 조회해야 매칭된다.
 *
 * @return list<array{key:string,eco:string,q:array}>
 */
function vg_osv_container_queries(PDO $pdo, int $scanId): array {
    $st = $pdo->prepare(
        'SELECT c.os_id, c.os_version, p.manager, p.name, p.source_pkg, p.version
           FROM tb_packages p JOIN tb_containers c ON c.id = p.container_id
          WHERE p.scan_id = ? AND p.container_id > 0'
    );
    $st->execute([$scanId]);

    $out = []; $seen = [];
    foreach ($st->fetchAll() as $p) {
        $eco = vg_osv_ecosystem($p['os_id'], $p['os_version']);
        if ($eco === null) { continue; }                     // OSV 미지원 배포판 → 조회 불가
        $isDeb = stripos($eco, 'Debian') === 0 || stripos($eco, 'Ubuntu') === 0;
        $key = $isDeb ? (($p['source_pkg'] ?: $p['name'])) : (string) $p['name'];
        $ver = (string) $p['version'];
        if ($key === '' || $ver === '' || isset($seen["$eco|$key|$ver"])) { continue; }
        $seen["$eco|$key|$ver"] = true;
        $out[] = ['key' => $key, 'eco' => $eco,
                  'q' => ['package' => ['ecosystem' => $eco, 'name' => $key], 'version' => $ver]];
    }
    return $out;
}

// OSV.dev — 최신 스캔의 실제 패키지를 단건 /v1/query 로 조회해 취약 패키지 발굴 + 조치안.
//   배포판별 ecosystem 자동, deb/ubuntu 는 source_pkg 로 조회, 설치버전으로 필터.
//   단건 응답엔 summary·aliases·affected.ranges(고쳐진 버전) 가 있어 조치안까지 확보.
final class VgOsvConnector implements VgFeedConnector {
    public function run(PDO $pdo, array $conn): array {
        // querybatch: 응답이 {results:[{vulns:[{id}]}]} 로 작아 수백~수천 패키지도 메모리 안전.
        // (단건 query 는 커널 등 거대한 응답에서 OOM. fixed_version 은 batch 미제공 → null)
        $url = vg_osv_batch_url($conn);
        $ecoOverride = trim((string) ($conn['ecosystem'] ?? ''));

        $scans = $pdo->query(
            'SELECT s.id, s.os_id, s.os_version
             FROM tb_scans s JOIN (SELECT host_id, MAX(id) mid FROM tb_scans GROUP BY host_id) t ON t.mid = s.id'
        )->fetchAll();

        $fetched = 0; $up = 0; $seen = [];
        foreach ($scans as $sc) {
            $eco = $ecoOverride !== '' ? $ecoOverride : vg_osv_ecosystem($sc['os_id'], $sc['os_version']);

            // OS 패키지(배포판 생태계) + 언어 패키지(PyPI/npm/RubyGems/Packagist).
            //   배포판이 미지원(eco=null)이어도 언어 패키지는 조회할 수 있다.
            $cand = array_merge(vg_osv_lang_queries($pdo, (int) $sc['id']),
                            vg_osv_container_queries($pdo, (int) $sc['id']));   // 컨테이너 내부 패키지도 자기 배포판으로 조회
            if ($eco !== null && $eco !== '') {
                $cand = array_merge(vg_osv_queries($pdo, (int) $sc['id'], $eco), $cand);
            }

            // 스캔 간 중복 조회 방지(호스트가 달라도 같은 생태계·패키지·버전이면 한 번만).
            $queries = [];
            foreach ($cand as $q) {
                $dk = $q['eco'] . '|' . $q['key'] . '|' . $q['q']['version'];
                if (isset($seen[$dk])) { continue; }
                $seen[$dk] = true;
                $queries[] = $q;
            }

            foreach (array_chunk($queries, 100) as $chunk) {
                $payload = ['queries' => array_map(static function ($x) { return $x['q']; }, $chunk)];
                $r = vg_http_json('POST', $url, $payload, [], 90);
                $fetched += count($chunk);
                if ($r['code'] === 200 && isset($r['json']['results'])) {
                    foreach ($r['json']['results'] as $i => $res) {
                        $key    = $chunk[$i]['key'] ?? '';
                        $qEco   = $chunk[$i]['eco'] ?? $eco;   // 질의마다 생태계가 다르다(배포판/PyPI/npm…)
                        foreach ($res['vulns'] ?? [] as $v) {
                            $id = (string) ($v['id'] ?? '');
                            if ($id === '') { continue; }
                            // batch 는 id 만 반환 → id 에서 CVE 추출(DEBIAN-CVE-…/UBUNTU-CVE-…/CVE-…)
                            if (preg_match('/CVE-\d{4}-\d+/i', $id, $m)) {
                                vg_upsert_cve($pdo, strtoupper($m[0]), null, null, null);
                                vg_upsert_affected($pdo, strtoupper($m[0]), $qEco, $key, null);
                                $up++;
                                continue;
                            }
                            // id 에 CVE 가 없는 보안공지(USN-*, DSA-*, GHSA-* …). 버리면 취약점을 놓친다
                            // (vg_osv_advisory_cves 주석 참고) → 단건 조회로 CVE 목록을 펼친다.
                            $up += $this->expandAdvisory($pdo, $id, (string) $qEco, $key);
                        }
                    }
                }
                unset($r); // 응답 메모리 즉시 해제
            }
        }
        return ['fetched' => $fetched, 'upserted' => $up];
    }

    /**
     * 보안공지 1건을 펼쳐 CVE 를 등록한다. 같은 공지가 여러 패키지에서 나오므로 문서를 캐시한다.
     * 공지 레코드엔 우리 배포판의 fixed 버전이 들어 있어 조치안까지 여기서 확보된다.
     * @return int upsert 한 CVE 수
     */
    private function expandAdvisory(PDO $pdo, string $id, string $eco, string $key): int {
        if (!array_key_exists($id, $this->advCache)) {
            $r = vg_http_json('GET', vg_osv_vuln_url($id), null, [], 30, 4 * 1024 * 1024);
            // 실패해도 수집 전체를 접지 않는다. 다음 실행에서 다시 시도한다.
            $this->advCache[$id] = ($r['code'] === 200 && is_array($r['json'] ?? null)) ? $r['json'] : null;
        }
        $doc = $this->advCache[$id];
        if ($doc === null) { return 0; }

        $fixed = vg_osv_fixed($doc, $key, $eco);
        $n = 0;
        foreach (vg_osv_advisory_cves($doc) as $cve) {
            vg_upsert_cve($pdo, $cve, null, null, null);
            vg_upsert_affected($pdo, $cve, $eco, $key, $fixed);
            $n++;
        }
        return $n;
    }

    /** @var array<string, array|null> 보안공지 문서 캐시(같은 USN 이 여러 패키지에 걸린다) */
    private array $advCache = [];
}

/**
 * OSV 조치안(fixed_version) 지연 보강.
 *   querybatch 응답엔 fixed 가 없다. 보안공지(USN)로 들어온 CVE 는 커넥터가 조치안까지 채우지만,
 *   per-CVE 레코드(UBUNTU-CVE-*)로 들어온 CVE 는 여전히 비어 있다. 여기서 "실제로 findings 에
 *   뜬 취약 패키지"(소수)만 골라 단건 /v1/query 로 조회해 채운다.
 *   커널 등 거대 응답은 바이트 상한으로 건너뛴다(OOM 방지).
 *
 *   findings 를 읽으므로 반드시 재매칭 뒤에 부른다.
 *   fixed 가 이미 있으면 대상에서 빠지므로 몇 번을 돌려도 멱등하다.
 *
 * @param callable|null $log 진행 로그(문자열 1줄). CLI 에서만 쓴다.
 * @return array{targets:int,queried:int,filled:int,skipped:int}
 */
function vg_osv_enrich_fixed(PDO $pdo, ?callable $log = null): array {
    $maxBytes = 6 * 1024 * 1024;
    $single   = 'https://api.osv.dev/v1/query';
    $stat     = ['targets' => 0, 'queried' => 0, 'filled' => 0, 'skipped' => 0];

    // 보강 대상: findings 에 실제로 뜬 패키지 중 조치 버전이 아직 빈 것.
    $needFix = [];
    foreach ($pdo->query(
        'SELECT DISTINCT a.package_name
           FROM tb_cve_affected_packages a
           JOIN tb_findings f ON f.package_name = a.package_name
          WHERE a.fixed_version IS NULL'
    )->fetchAll(PDO::FETCH_COLUMN) as $k) {
        $needFix[$k] = true;
    }
    $stat['targets'] = count($needFix);
    if (!$needFix) { return $stat; }

    $scans = $pdo->query(
        'SELECT s.id, s.os_id, s.os_version
           FROM tb_scans s JOIN (SELECT host_id, MAX(id) mid FROM tb_scans GROUP BY host_id) t ON t.mid = s.id'
    )->fetchAll();

    $seen = [];
    foreach ($scans as $sc) {
        $eco = vg_osv_ecosystem($sc['os_id'], $sc['os_version']);

        // OS 패키지 + 언어 패키지 둘 다 보강한다(생태계는 질의마다 다르다).
        $cand = array_merge(vg_osv_lang_queries($pdo, (int) $sc['id']),
                            vg_osv_container_queries($pdo, (int) $sc['id']));   // 컨테이너 내부 패키지도 자기 배포판으로 조회
        if ($eco !== null && $eco !== '') {
            $cand = array_merge(vg_osv_queries($pdo, (int) $sc['id'], $eco), $cand);
        }

        foreach ($cand as $q) {
            $key  = $q['key'];
            $qEco = (string) $q['eco'];
            $ver  = $q['q']['version'];
            if (!isset($needFix[$key])) { continue; }
            $dk = "$qEco|$key|$ver";
            if (isset($seen[$dk])) { continue; }
            $seen[$dk] = true;

            $r = vg_http_json('POST', $single, $q['q'], [], 90, $maxBytes);
            $stat['queried']++;
            if ($r['code'] !== 200 || !isset($r['json']['vulns'])) {
                $stat['skipped']++;
                if ($log) { $log("  - {$qEco} {$key}@{$ver}: 건너뜀 ({$r['error']})"); }
                unset($r);
                continue;
            }
            foreach ($r['json']['vulns'] as $v) {
                $cve   = vg_osv_cve($v);
                $fixed = vg_osv_fixed($v, $key, $qEco);
                if ($cve === null || $fixed === null) { continue; }
                vg_upsert_affected($pdo, $cve, $qEco, $key, $fixed);   // fixed 채움(기존 행 UPDATE)
                $stat['filled']++;
            }
            unset($r); // 응답 즉시 해제
        }
    }
    return $stat;
}

// NVD 2.0 — 최근 N일 공개 CVE → cves (CVSS 포함). 증분 수집(전체 미러 아님).
//   기간 내 결과를 startIndex 로 끝까지 페이지네이션(무음 절단 방지, rate limit 준수).
// ── NVD 2.0 공통 루틴 — 주기 수집(커넥터)과 전체 백필(bin/backfill_nvd.php)이 함께 쓴다 ──
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

/** NVD 응답 1건을 tb_cves 로 upsert. @return bool 실제로 처리했는지 */
function vg_nvd_upsert_item(PDO $pdo, array $item): bool {
    $c  = $item['cve'] ?? [];
    $id = $c['id'] ?? '';
    if ($id === '') { return false; }

    $desc = '';
    foreach ($c['descriptions'] ?? [] as $d) {
        if (($d['lang'] ?? '') === 'en') { $desc = (string) $d['value']; break; }
    }
    $cvss = null;
    foreach (['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'] as $mk) {
        if (!empty($c['metrics'][$mk][0]['cvssData']['baseScore'])) {
            $cvss = (float) $c['metrics'][$mk][0]['cvssData']['baseScore'];
            break;
        }
    }
    $pub = !empty($c['published']) ? substr((string) $c['published'], 0, 10) : null;
    vg_upsert_cve($pdo, $id, mb_substr($desc, 0, VG_TEXT_MAX), $cvss, $pub);
    return true;
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
     * 주기 수집은 "수정된 CVE"(lastMod) 기준이다.
     *   발행일(pubStartDate) 기준이면 예전에 발행됐다가 뒤늦게 CVSS·설명이 붙은 CVE 를
     *   영원히 놓친다. 실측(2026-07-09): 최근 7일 발행 1,311건 vs 수정 4,580건.
     *   NVD 는 lastModStartDate/lastModEndDate 를 둘 다 요구하고 범위는 120일까지만 허용한다.
     * 전체 이력은 bin/backfill_nvd.php 로 1회 채운다(주기 수집이 할 일이 아니다).
     */
    public function run(PDO $pdo, array $conn): array {
        $days = min(VG_NVD_MAX_WINDOW, max(1, (int) ($conn['days'] ?? 7)));
        $res  = vg_nvd_sync($pdo, $conn, [
            'lastModStartDate' => gmdate('Y-m-d\TH:i:s.000', time() - $days * 86400),
            'lastModEndDate'   => gmdate('Y-m-d\TH:i:s.000'),
        ]);
        return ['fetched' => $res['fetched'], 'upserted' => $res['upserted']];
    }
}

// KISA(보호나라) 국내 보안공지 RSS — 해외 도구가 안 하는 국내 특화.
//   RSS 는 title/link/pubDate 만 제공(CVE 없음) → 공지 자체를 advisories 로 수집.
//   제목에 CVE 가 있으면 best-effort 로 추출해 findings 에 국내공지 배지로 연계.
final class VgKisaConnector implements VgFeedConnector {
    // 보호나라(boho.or.kr) RSS 는 bbsId 별로 게시판이 나뉘고 카테고리당 최근 10건만 준다.
    // 취약점/보안공지 성격의 카테고리만 골라 순회하면 단일 피드보다 수집량이 늘어난다.
    // (보고서/가이드 B0000127, 공지사항 B0000132 등 일반 게시판은 취약점과 무관해 제외)
    public const DEFAULT_FEEDS = [
        'https://www.boho.or.kr/kr/rss.do?bbsId=B0000133' => 'KISA-보안공지',
        'https://www.boho.or.kr/kr/rss.do?bbsId=B0000302' => 'KISA-취약점정보',
        'https://www.boho.or.kr/kr/rss.do?bbsId=B0000342' => 'KISA-경보단계',
    ];

    public function run(PDO $pdo, array $conn): array {
        // 기존 커넥터 레코드(connection_json.url 단일값) 하위호환. 비었으면 기본 목록 순회.
        $url   = trim((string) ($conn['url'] ?? ''));
        $feeds = $url !== '' ? [$url => 'kisa'] : self::DEFAULT_FEEDS;

        $fetched = 0; $up = 0; $ok = 0;
        foreach ($feeds as $url => $source) {
            try {
                [$f, $u] = $this->fetchOne($pdo, $url, $source);
                $fetched += $f; $up += $u; $ok++;
            } catch (Throwable $e) {
                // 카테고리 하나가 죽어도 나머지는 계속 수집(SSRF 방어는 vg_http_raw 가 담당).
                error_log("[kisa_feed] $source ($url) 스킵: " . $e->getMessage());
            }
        }
        if ($ok === 0) {
            throw new RuntimeException('KISA RSS 전체 소스 수집 실패');
        }
        return ['fetched' => $fetched, 'upserted' => $up];
    }

    /** @return array{0:int,1:int} [fetched, upserted] */
    private function fetchOne(PDO $pdo, string $url, string $source): array {
        $r = vg_http_raw('GET', $url);
        if ($r['code'] !== 200 || $r['body'] === '') {
            throw new RuntimeException("KISA RSS fetch 실패 (HTTP {$r['code']}) {$r['error']}");
        }
        $xml = @simplexml_load_string($r['body'], 'SimpleXMLElement', LIBXML_NONET);
        if ($xml === false || !isset($xml->channel->item)) {
            throw new RuntimeException('KISA RSS 파싱 실패(형식 오류)');
        }
        $items = $xml->channel->item;
        $up = 0;
        foreach ($items as $it) {
            $title = trim((string) $it->title);
            $link  = trim((string) $it->link);
            if ($title === '' || $link === '') { continue; }
            $pub = null;
            if (!empty($it->pubDate)) {
                $ts = strtotime((string) $it->pubDate);
                if ($ts !== false) { $pub = date('Y-m-d', $ts); }
            }
            $titleCves = vg_extract_cve_ids($title);
            $cveIds    = $titleCves ? implode(',', $titleCves) : null;
            // 신규·수정만 upserted 로 집계(unchanged 는 제외). 제목 정규화는 upsert 가 담당.
            if (vg_upsert_advisory($pdo, $source, $title, $link, $pub, $cveIds) !== 'unchanged') {
                $up++;
            }
            // 제목에 CVE 가 있으면 cves 에도 등록(국내공지 근거 확보)
            foreach ($titleCves as $cve) {
                vg_upsert_cve($pdo, $cve, null, null, null);
            }
            // 본문 수집(미수집 건만 1회 요청). 상세 1건이 실패해도 목록 수집은 계속한다.
            try {
                vg_advisory_fill_content($pdo, $link);
            } catch (Throwable $e) {
                error_log('[kisa_feed] 본문 스킵: ' . $e->getMessage());
            }
        }
        return [count($items), $up];
    }
}

/** EPSS gzip CSV 를 받아 평문으로 돌려준다(run·미리보기 공용). */
function vg_epss_fetch(string $url): string {
    $r = vg_http_raw('GET', $url, [], 120);
    if ($r['code'] !== 200 || $r['body'] === '') {
        throw new RuntimeException("EPSS fetch 실패 (HTTP {$r['code']}) {$r['error']}");
    }
    $txt = @gzdecode($r['body']);
    if ($txt === false) {
        throw new RuntimeException('EPSS gzip 해제 실패');
    }
    return $txt;
}

// FIRST EPSS — CVE별 악용확률(0~1) + 백분위. gzip CSV 를 받아 보유 CVE 만 갱신.
final class VgEpssConnector implements VgFeedConnector {
    public function run(PDO $pdo, array $conn): array {
        $txt = vg_epss_fetch(vg_conn_url($conn, VG_EPSS_URL));
        // 우리가 보유한 CVE 만 갱신(전체 34만건 삽입 안 함)
        $have = [];
        foreach ($pdo->query('SELECT cve_id FROM tb_cves')->fetchAll(PDO::FETCH_COLUMN) as $c) {
            $have[strtoupper((string) $c)] = true;
        }
        if (!$have) {
            return ['fetched' => 0, 'upserted' => 0];
        }
        $upd = $pdo->prepare('UPDATE tb_cves SET epss = ?, epss_percentile = ? WHERE cve_id = ?');
        $fetched = 0; $up = 0;
        $pdo->beginTransaction();
        foreach (explode("\n", $txt) as $line) {
            if ($line === '' || $line[0] === '#') { continue; }
            if (strncmp($line, 'cve,', 4) === 0) { continue; } // 헤더
            $f = explode(',', $line);
            if (count($f) < 3) { continue; }
            $fetched++;
            $cve = strtoupper($f[0]);
            if (!isset($have[$cve])) { continue; }
            $upd->execute([(float) $f[1], (float) $f[2], $cve]);
            $up++;
        }
        $pdo->commit();
        return ['fetched' => $fetched, 'upserted' => $up];
    }
}

function vg_feed_make(string $type): VgFeedConnector {
    switch ($type) {
        case 'kev':  return new VgKevConnector();
        case 'osv':  return new VgOsvConnector();
        case 'nvd':  return new VgNvdConnector();
        case 'kisa': return new VgKisaConnector();
        case 'epss': return new VgEpssConnector();
        default: throw new InvalidArgumentException("알 수 없는 커넥터 타입: $type");
    }
}

// ─────────────────────────────────────────────────────────────────────────
// 실행 + 스케줄
// ─────────────────────────────────────────────────────────────────────────
// cron 필드 한 개 매칭 (*, 숫자, a-b 범위, */n 스텝, 콤마 목록 지원)
function vg_cron_field_match(string $field, int $val, int $min, int $max): bool {
    foreach (explode(',', $field) as $part) {
        $step = 1;
        if (strpos($part, '/') !== false) {
            [$part, $s] = explode('/', $part, 2);
            $step = max(1, (int) $s);
        }
        if ($part === '*' || $part === '') { $lo = $min; $hi = $max; }
        elseif (strpos($part, '-') !== false) { [$a, $b] = explode('-', $part, 2); $lo = (int) $a; $hi = (int) $b; }
        else { $lo = $hi = (int) $part; }
        for ($i = $lo; $i <= $hi; $i += $step) {
            if ($i === $val) { return true; }
        }
    }
    return false;
}

// 표준 5필드 cron(분 시 일 월 요일)이 주어진 시각과 일치하는가. 요일 0=일요일(7도 일요일).
function vg_cron_match(string $expr, int $ts): bool {
    $f = preg_split('/\s+/', trim($expr));
    if (count($f) !== 5) { return false; }
    $dow = (int) date('w', $ts);
    return vg_cron_field_match($f[0], (int) date('i', $ts), 0, 59)
        && vg_cron_field_match($f[1], (int) date('G', $ts), 0, 23)
        && vg_cron_field_match($f[2], (int) date('j', $ts), 1, 31)
        && vg_cron_field_match($f[3], (int) date('n', $ts), 1, 12)
        && (vg_cron_field_match($f[4], $dow, 0, 6) || ($dow === 0 && vg_cron_field_match($f[4], 7, 0, 7)));
}

// 지금 실행 대상인가 (스케줄러가 매 tick 마다 판정). last_run 기준 중복 방지.
function vg_schedule_due(array $schedule, ?string $lastRun, ?int $now = null): bool {
    $now = $now ?? time();
    $lastTs = $lastRun ? strtotime($lastRun) : null;
    switch ($schedule['mode'] ?? 'manual') {
        case 'interval':
            $min = max(1, (int) ($schedule['interval_minutes'] ?? 1440));
            return $lastTs === null || ($now - $lastTs) >= $min * 60;
        case 'daily':
            [$h, $m] = array_map('intval', array_pad(explode(':', (string) ($schedule['time'] ?? '03:00')), 2, 0));
            $sched = strtotime(date('Y-m-d', $now) . sprintf(' %02d:%02d:00', $h, $m));
            return $now >= $sched && ($lastTs === null || $lastTs < $sched);
        case 'cron':
            $expr = (string) ($schedule['expr'] ?? '');
            if ($expr === '' || !vg_cron_match($expr, $now)) { return false; }
            return $lastTs === null || $lastTs < $now - ($now % 60); // 같은 분 중복 방지
        default: // manual
            return false;
    }
}

// 다음 실행 예정 시각(표시용).
function vg_schedule_next(array $schedule, ?int $fromTs = null): ?string {
    $fromTs = $fromTs ?? time();
    switch ($schedule['mode'] ?? 'manual') {
        case 'interval':
            $min = max(1, (int) ($schedule['interval_minutes'] ?? 1440));
            return date('Y-m-d H:i:s', $fromTs + $min * 60);
        case 'daily':
            [$h, $m] = array_map('intval', array_pad(explode(':', (string) ($schedule['time'] ?? '03:00')), 2, 0));
            $next = strtotime(date('Y-m-d', $fromTs) . sprintf(' %02d:%02d:00', $h, $m));
            if ($next <= $fromTs) { $next += 86400; }
            return date('Y-m-d H:i:s', $next);
        case 'cron':
            $expr = (string) ($schedule['expr'] ?? '');
            if ($expr === '') { return null; }
            $t = $fromTs - ($fromTs % 60) + 60;
            for ($i = 0; $i < 527040; $i++) { // 최대 366일 앞으로 스캔
                if (vg_cron_match($expr, $t)) { return date('Y-m-d H:i:s', $t); }
                $t += 60;
            }
            return null;
        default: // manual
            return null;
    }
}

/** 주어진 커넥터 id 중에 해당 타입이 있는가. 수집 후 후처리를 걸지 결정할 때 쓴다. */
function vg_feed_has_type(PDO $pdo, array $ids, string $type): bool {
    if (!$ids) { return false; }
    $in = implode(',', array_fill(0, count($ids), '?'));
    $st = $pdo->prepare("SELECT 1 FROM tb_feed_connectors WHERE connector_type = ? AND id IN ($in) LIMIT 1");
    $st->execute(array_merge([$type], array_map('intval', $ids)));
    return (bool) $st->fetchColumn();
}

/** 커넥터 1건 실행: 로그(running→success/error) + 커넥터 상태/다음실행 갱신. */
function vg_feed_run(PDO $pdo, int $connectorId, string $triggerBy = 'schedule'): array {
    $st = $pdo->prepare('SELECT * FROM tb_feed_connectors WHERE id = ? AND is_deleted = 0');
    $st->execute([$connectorId]);
    $c = $st->fetch();
    if (!$c) {
        throw new RuntimeException("커넥터 없음: $connectorId");
    }
    // 스케줄러가 돌리면 SYSTEM, 사람이 누르면 USER 로 감사 기록.
    $actor = $triggerBy === 'schedule' ? 'SYSTEM' : 'USER';
    $conn     = json_decode((string) $c['connection_json'], true) ?: [];
    $schedule = json_decode((string) $c['schedule_json'], true) ?: [];

    $lg = $pdo->prepare('INSERT INTO tb_feed_collection_logs (connector_id, trigger_by, status) VALUES (?,?,?)');
    $lg->execute([$connectorId, $triggerBy, 'running']);
    $logId = (int) $pdo->lastInsertId();
    $pdo->prepare('UPDATE tb_feed_connectors SET last_status=?, last_run_at=NOW() WHERE id=?')->execute(['running', $connectorId]);

    try {
        $res = vg_feed_make((string) $c['connector_type'])->run($pdo, $conn);
        $msg = "fetched={$res['fetched']} upserted={$res['upserted']}";
        $pdo->prepare('UPDATE tb_feed_collection_logs SET status=?, finished_at=NOW(), items_fetched=?, items_upserted=?, message=? WHERE id=?')
            ->execute(['success', $res['fetched'], $res['upserted'], $msg, $logId]);
        $pdo->prepare('UPDATE tb_feed_connectors SET last_status=?, last_message=?, next_run_at=? WHERE id=?')
            ->execute(['success', $msg, vg_schedule_next($schedule), $connectorId]);
        vg_log_activity($pdo, 'CONNECTOR', $connectorId, 'feed_run', "수집 {$res['upserted']}건",
            ['fetched' => $res['fetched'], 'upserted' => $res['upserted'], 'status' => 'success'], null, $actor);
        return ['ok' => true] + $res;
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) { $pdo->rollBack(); }
        $msg = mb_substr($e->getMessage(), 0, 480);
        $pdo->prepare('UPDATE tb_feed_collection_logs SET status=?, finished_at=NOW(), message=? WHERE id=?')
            ->execute(['error', $msg, $logId]);
        $pdo->prepare('UPDATE tb_feed_connectors SET last_status=?, last_message=?, next_run_at=? WHERE id=?')
            ->execute(['error', $msg, vg_schedule_next($schedule), $connectorId]);
        vg_log_activity($pdo, 'CONNECTOR', $connectorId, 'feed_run', "수집 실패: $msg",
            ['status' => 'error'], null, $actor);
        return ['ok' => false, 'error' => $msg];
    }
}

/**
 * 미리보기: 소스에서 최대 10건을 가져와 그대로 보여준다(저장 안 함).
 *   커넥터 설정 전에 URL/응답 형태를 눈으로 확인하는 용도.
 */
function vg_feed_preview(string $type, array $conn, PDO $pdo): array {
    $limit = 10;
    switch ($type) {
        case 'kev':
            $r = vg_http_json('GET', vg_conn_url($conn, VG_KEV_URL));
            if ($r['code'] !== 200 || !isset($r['json']['vulnerabilities'])) {
                return ['ok' => false, 'error' => "HTTP {$r['code']} {$r['error']}"];
            }
            $all = $r['json']['vulnerabilities'];
            return ['ok' => true, 'count' => count($all), 'sample' => array_slice($all, 0, $limit)];

        case 'nvd':
            $base = vg_conn_url($conn, VG_NVD_URL);
            $days = max(1, (int) ($conn['days'] ?? 7));
            $qs = http_build_query([
                'pubStartDate'   => gmdate('Y-m-d\TH:i:s.000', time() - $days * 86400),
                'pubEndDate'     => gmdate('Y-m-d\TH:i:s.000'),
                'resultsPerPage' => $limit,
            ]);
            $h = !empty($conn['api_key']) ? ['apiKey: ' . $conn['api_key']] : [];
            $r = vg_http_json('GET', "$base?$qs", null, $h, 60);
            if ($r['code'] !== 200 || !isset($r['json']['vulnerabilities'])) {
                return ['ok' => false, 'error' => "HTTP {$r['code']} {$r['error']}"];
            }
            return ['ok' => true, 'count' => (int) ($r['json']['totalResults'] ?? 0), 'sample' => $r['json']['vulnerabilities']];

        case 'kisa':
            // URL 을 비워두면 run() 과 같은 기본 피드 목록의 첫 카테고리를 미리 본다.
            $url = vg_conn_url($conn, array_key_first(VgKisaConnector::DEFAULT_FEEDS));
            $r = vg_http_raw('GET', $url);
            $xml = $r['code'] === 200 ? @simplexml_load_string($r['body'], 'SimpleXMLElement', LIBXML_NONET) : false;
            if ($xml === false || !isset($xml->channel->item)) {
                return ['ok' => false, 'error' => "RSS 파싱 실패 (HTTP {$r['code']}) {$r['error']}"];
            }
            $out = []; $n = 0;
            foreach ($xml->channel->item as $it) {
                if ($n++ >= $limit) { break; }
                $out[] = ['title' => (string) $it->title, 'link' => (string) $it->link, 'pubDate' => (string) $it->pubDate];
            }
            return ['ok' => true, 'count' => count($xml->channel->item), 'note' => $url, 'sample' => $out];

        case 'osv':
            $sc = $pdo->query(
                'SELECT s.id, s.os_id, s.os_version FROM tb_scans s
                 JOIN (SELECT host_id, MAX(id) mid FROM tb_scans GROUP BY host_id) t ON t.mid = s.id
                 ORDER BY s.id DESC LIMIT 1'
            )->fetch();
            if (!$sc) {
                return ['ok' => false, 'error' => '수집된 스캔이 없어 미리보기 불가(에이전트 먼저 실행).'];
            }
            $eco = trim((string) ($conn['ecosystem'] ?? '')) ?: vg_osv_ecosystem($sc['os_id'], $sc['os_version']);
            if (!$eco) {
                return ['ok' => false, 'error' => "OSV ecosystem 판정 불가(os_id={$sc['os_id']}). 커넥터에 ecosystem 지정."];
            }
            // 패키지 1건만 단건 조회하면 대개 취약점이 없어 항상 "0건" 으로 보였다.
            // run() 과 같은 querybatch 로 최신 스캔의 앞쪽 100개를 실제로 조회한다.
            $queries = array_slice(vg_osv_queries($pdo, (int) $sc['id'], $eco), 0, 100);
            if (!$queries) {
                return ['ok' => false, 'error' => "최신 스캔(id={$sc['id']})에 패키지가 없어 미리보기 불가."];
            }
            $r = vg_http_json('POST', vg_osv_batch_url($conn),
                ['queries' => array_column($queries, 'q')], [], 90);
            if ($r['code'] !== 200 || !isset($r['json']['results'])) {
                return ['ok' => false, 'error' => "HTTP {$r['code']} {$r['error']}"];
            }
            $hits = [];
            foreach ($r['json']['results'] as $i => $res) {
                if (empty($res['vulns'])) { continue; }
                $hits[] = [
                    'package' => $queries[$i]['key'],
                    'version' => $queries[$i]['q']['version'],
                    'vulns'   => array_column($res['vulns'], 'id'),
                ];
            }
            $note = sprintf('ecosystem=%s, 패키지 %d개 조회 → 취약 %d개', $eco, count($queries), count($hits));
            return ['ok' => true, 'count' => count($hits), 'note' => $note, 'sample' => array_slice($hits, 0, $limit)];

        case 'epss':
            // 34만 행 CSV 라 앞쪽 10행만 보여준다(점수 내림차순 정렬본이라 상위권이 나온다).
            $txt = vg_epss_fetch(vg_conn_url($conn, VG_EPSS_URL));
            $out = []; $rows = 0;
            foreach (explode("\n", $txt) as $line) {
                if ($line === '' || $line[0] === '#' || strncmp($line, 'cve,', 4) === 0) { continue; }
                $f = explode(',', $line);
                if (count($f) < 3) { continue; }
                $rows++;
                if (count($out) < $limit) {
                    $out[] = ['cve' => strtoupper($f[0]), 'epss' => (float) $f[1], 'percentile' => (float) $f[2]];
                }
            }
            return ['ok' => true, 'count' => $rows, 'note' => '보유 중인 CVE 만 갱신된다(전체 삽입 안 함)', 'sample' => $out];

        default:
            return ['ok' => false, 'error' => "미리보기 미지원 타입: $type"];
    }
}

/**
 * 중단된 실행 정리. vg_feed_run 은 try/catch 로 성공·실패 모두 로그를 닫지만,
 * PHP 가 통째로 죽으면(치명적 오류·CPU 시간 초과·컨테이너 재기동) catch 가 돌지 않아
 * 로그가 'running' 으로 영구히 굳는다. 실측: OSV 로그 1건이 27시간째 running 이었다.
 *
 * 시작 후 $hours 시간이 지난 running 을 실패로 마감한다. 정상 수집은 길어야 10분대라
 * 기본 6시간이면 진행 중인 실행을 잘못 죽일 위험이 없다.
 *
 * @return int 정리한 로그 수
 */
function vg_feed_reap_stale(PDO $pdo, int $hours = 6): int {
    $hours = max(1, $hours);   // SQL 에 직접 넣으므로 정수로 못박는다
    $msg   = "중단된 실행으로 판단해 정리(시작 후 {$hours}시간 초과)";

    $st = $pdo->prepare(
        "UPDATE tb_feed_collection_logs
            SET status = 'error', finished_at = NOW(), message = ?
          WHERE status = 'running' AND started_at < NOW() - INTERVAL $hours HOUR"
    );
    $st->execute([$msg]);
    $n = $st->rowCount();

    if ($n > 0) {
        $pdo->prepare(
            "UPDATE tb_feed_connectors
                SET last_status = 'error', last_message = ?
              WHERE last_status = 'running' AND last_run_at < NOW() - INTERVAL $hours HOUR"
        )->execute([$msg]);
    }
    return $n;
}

/** 스케줄러가 돌릴 대상: enabled=1 이고 스케줄(interval/daily/cron) 상 지금이 due. */
function vg_feed_due(PDO $pdo): array {
    $rows = $pdo->query('SELECT id, schedule_json, last_run_at FROM tb_feed_connectors WHERE enabled = 1 AND is_deleted = 0')->fetchAll();
    $due = [];
    foreach ($rows as $r) {
        $sch = json_decode((string) $r['schedule_json'], true) ?: [];
        if (vg_schedule_due($sch, $r['last_run_at'])) {
            $due[] = (int) $r['id'];
        }
    }
    return $due;
}
