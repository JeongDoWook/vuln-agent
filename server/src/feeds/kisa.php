<?php
declare(strict_types=1);

/**
 * feeds/kisa.php — KISA(보호나라) 국내 보안공지 RSS 커넥터 + 공지 전용 저장/본문 처리.
 *   RSS 는 title/link/pubDate 만 제공(CVE 없음) → 공지 자체를 tb_advisories 로 수집하고,
 *   상세 HTML 본문을 평문으로 뽑아 CVE 를 흡수한다. 제목·URL 정규화로 중복을 막는다.
 *   미리보기는 run 과 같은 기본 피드의 첫 카테고리를 본다.
 */

require_once __DIR__ . '/http.php';
require_once __DIR__ . '/upsert.php';

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
 * 두 cve_ids 문자열의 합집합(정렬·중복제거·형식검증).
 *   양쪽 모두 vg_extract_cve_ids 를 통과시키므로 예전에 잘려 저장된 조각("CVE-2")이나
 *   오탈자(CVE-0215-8451)는 여기서 함께 걸러진다.
 */
function vg_merge_cve_ids(?string $a, ?string $b): ?string {
    $ids = vg_extract_cve_ids((string) $a . "\n" . (string) $b);
    return $ids ? implode(',', $ids) : null;
}

// 국내 보안공지(KISA 등) upsert. 정규화한 url 기준 dedup.
//   KISA 는 수정일을 노출하지 않으므로(RSS·목록·상세 모두 등록일 하나뿐) 저장된 값과
//   비교해 실제로 달라졌을 때만 UPDATE 한다. 그래야 updated_at 이 "변경을 관측한 시각"이
//   되고, 백필을 몇 번 돌려도 멱등하다.
//   제목 정규화(엔티티 해제·공백 압축·길이 제한)를 여기서 한다. RSS 는 제목에 &#39; 같은
//   엔티티를 그대로 주고 목록 페이지는 해제된 문자를 준다. 경로마다 다르게 다듬으면
//   같은 공지가 수집 주기마다 '수정'으로 뒤집힌다.
//   반환: 'new' | 'updated' | 'unchanged'
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
