<?php
declare(strict_types=1);

/**
 * feeds/kisa.php — KISA(보호나라) 국내 보안공지 RSS 커넥터.
 *   RSS 는 title/link/pubDate 만 제공(CVE 없음) → 공지 자체를 tb_advisory 로 수집하고,
 *   상세 HTML 본문을 평문으로 뽑아 CVE 를 흡수한다. 제목·URL 정규화로 중복을 막는다.
 *   미리보기는 run 과 같은 기본 피드의 첫 카테고리를 본다.
 *
 *   공지(advisory) 저장/CVE 합치기/junction 동기화/본문 채우기 오케스트레이션은 도메인
 *   엔티티라 ../advisory.php 가 갖는다(SRP) — 이 파일은 KISA 응답 형식(URL·RSS·상세 HTML)
 *   전용 파싱만 담당한다.
 */

require_once __DIR__ . '/http.php';
require_once __DIR__ . '/upsert.php';
require_once __DIR__ . '/../advisory.php';

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
                // 카테고리 하나가 죽어도 나머지는 계속 수집한다(SSRF 방어는 vg_http_raw→vg_http_follow→vg_ssrf_guard_url 이 담당).
                error_log("[kisa_feed] $source ($url) 스킵: " . $e->getMessage());
            }
        }
        if ($ok === 0) {
            throw new RuntimeException('KISA RSS 전체 소스 수집 실패');
        }
        return ['fetched' => $fetched, 'upserted' => $up];
    }

    // 미리보기: URL 을 비워두면 run() 과 같은 기본 피드 목록의 첫 카테고리를 미리 본다.
    public function preview(PDO $pdo, array $conn): array {
        $url = vg_conn_url($conn, array_key_first(self::DEFAULT_FEEDS));
        $r = vg_http_raw('GET', $url);
        $xml = $r['code'] === 200 ? @simplexml_load_string($r['body'], 'SimpleXMLElement', LIBXML_NONET) : false;
        if ($xml === false || !isset($xml->channel->item)) {
            return ['ok' => false, 'error' => "RSS 파싱 실패 (HTTP {$r['code']}) {$r['error']}"];
        }
        $out = []; $n = 0;
        foreach ($xml->channel->item as $it) {
            if ($n++ >= 10) { break; }
            $out[] = ['title' => (string) $it->title, 'link' => (string) $it->link, 'pubDate' => (string) $it->pubDate];
        }
        return ['ok' => true, 'count' => count($xml->channel->item), 'note' => $url, 'sample' => $out];
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
            // 신규·수정만 upserted 로 집계(unchanged 는 제외). 제목 정규화는 upsert 가 담당.
            if (vg_upsert_advisory($pdo, $source, $title, $link, $pub, $titleCves) !== 'unchanged') {
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
