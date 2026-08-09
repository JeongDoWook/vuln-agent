<?php
declare(strict_types=1);

/**
 * backfill_kisa.php — 보호나라(KISA) 국내 보안공지 과거 이력 1회성 백필.
 *
 *   RSS(rss.do)는 게시판당 최신 10건만 준다. 그래서 kisa 커넥터를 아무리 돌려도
 *   "커넥터를 처음 켠 시점 이후" 공지만 쌓인다(실측 30건). 과거 2천여 건은
 *   목록 페이지(list.do?pageIndex=N)를 순회해야 닿는다.
 *
 *   주기 수집(RSS)과 과거 백필(크롤링)은 성격이 다르므로 커넥터를 건드리지 않고
 *   여기서 분리한다. 매 주기 250페이지를 긁는 건 상대 서버에도 부담이다.
 *
 *   vg_upsert_advisory 가 정규화 url 기준 dedup + 변경분만 UPDATE 하므로 몇 번을
 *   돌려도 멱등하다. 중단 후 재실행도 안전.
 *
 *   사용:
 *     php bin/backfill_kisa.php              # 전 게시판 전 페이지
 *     php bin/backfill_kisa.php --pages=5    # 게시판당 앞 5페이지만(시험용)
 *     php bin/backfill_kisa.php --board=B0000133
 */

require __DIR__ . '/../src/feeds.php';

const KISA_BASE = 'https://www.boho.or.kr';

// 커넥터(VgKisaConnector::DEFAULT_FEEDS)와 동일한 게시판. menuNo 는 list.do 에 필수.
const KISA_BOARDS = [
    'B0000133' => ['menuNo' => '205020', 'source' => 'KISA-보안공지'],
    'B0000302' => ['menuNo' => '205023', 'source' => 'KISA-취약점정보'],
    'B0000342' => ['menuNo' => '205024', 'source' => 'KISA-경보단계'],
];

const REQ_DELAY_US = 300000;   // 요청 간 0.3초. 상대 서버 예의(250쪽 × 3게시판).
const MAX_PAGES    = 500;      // 폭주 방지 상한

// ─── 인자 파싱 ──────────────────────────────────────────────────────────
$maxPages   = MAX_PAGES;
$onlyBoard  = null;
foreach (array_slice($argv, 1) as $a) {
    if (preg_match('/^--pages=([0-9]+)$/', $a, $m)) {
        $maxPages = max(1, min(MAX_PAGES, (int) $m[1]));
    } elseif (preg_match('/^--board=(B[0-9]+)$/', $a, $m)) {
        $onlyBoard = $m[1];
    } else {
        fwrite(STDERR, "알 수 없는 인자: $a\n");
        exit(2);
    }
}
if ($onlyBoard !== null && !isset(KISA_BOARDS[$onlyBoard])) {
    fwrite(STDERR, "알 수 없는 게시판: $onlyBoard\n");
    exit(2);
}

/**
 * 목록 페이지 1장에서 공지 행을 뽑는다.
 *   보안공지 : <td class="date">2026-06-03</td>
 *   취약점정보: <td class="date" data-label="심각도 :">..</td> ... <td class="date" data-label="게시일 :">2026-02-27</td>
 * 게시판마다 class="date" td 가 여러 개이고 속성도 붙는다. 날짜 형태인 td 만 게시일로 본다.
 * @return list<array{title:string,url:string,published:string}>
 */
function kisa_parse_rows(string $html): array {
    $out = [];
    if (!preg_match_all('#<tr>(.*?)</tr>#s', $html, $rows)) {
        return $out;
    }
    foreach ($rows[1] as $row) {
        if (!preg_match('#<a\s+href="([^"]*view\.do[^"]*)"[^>]*>(.*?)</a>#s', $row, $a)) {
            continue;  // 헤더 행 등
        }
        if (!preg_match('#<td[^>]*class="date"[^>]*>\s*([0-9]{4}-[0-9]{2}-[0-9]{2})\s*</td>#', $row, $d)) {
            continue;  // 게시일 td 없음
        }
        // 제목 정규화(엔티티·공백·길이)는 vg_upsert_advisory 가 한다. 여기선 태그만 벗긴다.
        $title = trim(strip_tags($a[2]));
        if ($title === '') {
            continue;
        }
        // href 는 상대경로에 &amp; 가 섞여 있다. vg_kisa_canon_url 은 절대 URL 만 정규화한다.
        $href = html_entity_decode($a[1], ENT_QUOTES, 'UTF-8');
        $out[] = [
            'title'     => $title,
            'url'       => (strncmp($href, 'http', 4) === 0) ? $href : KISA_BASE . $href,
            'published' => $d[1],
        ];
    }
    return $out;
}

/** 총 페이지 수. 목록 페이지가 <em id="totalPage">249</em> 로 직접 알려준다. 못 읽으면 null. */
function kisa_total_pages(string $html): ?int {
    if (!preg_match('#id="totalPage"[^>]*>\s*([0-9]+)\s*<#', $html, $m)) {
        return null;
    }
    $pages = (int) $m[1];
    return $pages > 0 ? $pages : null;
}

// ─── 수집 ───────────────────────────────────────────────────────────────
$pdo    = vg_pdo();
$boards = $onlyBoard !== null ? [$onlyBoard => KISA_BOARDS[$onlyBoard]] : KISA_BOARDS;
$grand  = ['new' => 0, 'updated' => 0, 'unchanged' => 0, 'pages' => 0, 'failed' => 0];

foreach ($boards as $bbsId => $b) {
    $stat = ['new' => 0, 'updated' => 0, 'unchanged' => 0];
    $last = $maxPages;

    for ($page = 1; $page <= $last; $page++) {
        $url = KISA_BASE . '/kr/bbs/list.do?' . http_build_query([
            'menuNo'    => $b['menuNo'],
            'bbsId'     => $bbsId,
            'pageIndex' => $page,
        ]);
        $r = vg_http_raw('GET', $url, [], 30);
        if ($r['code'] !== 200 || $r['body'] === '') {
            fwrite(STDERR, "[$bbsId] {$page}쪽 실패 (HTTP {$r['code']}) {$r['error']}\n");
            $grand['failed']++;
            usleep(REQ_DELAY_US);
            continue;   // 한 쪽 실패로 전체를 접지 않는다
        }
        $grand['pages']++;

        if ($page === 1) {
            $tp = kisa_total_pages($r['body']);
            if ($tp !== null) {
                $last = min($maxPages, $tp);
                fwrite(STDOUT, "[$bbsId] {$b['source']} 총 {$tp}쪽 중 {$last}쪽 수집\n");
            }
        }

        $rows = kisa_parse_rows($r['body']);
        if (!$rows) {
            fwrite(STDERR, "[$bbsId] {$page}쪽 파싱 0건 — 마지막 쪽으로 보고 중단\n");
            break;
        }

        $pdo->beginTransaction();
        foreach ($rows as $row) {
            // 공용 헬퍼로 통일(정렬·중복제거·형식검증). 목록엔 제목뿐이라 본문 유래 CVE 는
            // 알 수 없지만, vg_upsert_advisory 가 기존 값과 합쳐주므로 지워지지 않는다.
            $ids = vg_extract_cve_ids($row['title']);
            $res = vg_upsert_advisory($pdo, $b['source'], $row['title'], $row['url'], $row['published'], $ids);
            $stat[$res]++;
            foreach ($ids as $cve) {
                vg_upsert_cve($pdo, $cve, null, null, null);
            }
        }
        $pdo->commit();

        if ($page % 20 === 0) {
            fwrite(STDOUT, "[$bbsId] {$page}/{$last}쪽 … 신규 {$stat['new']} 수정 {$stat['updated']}\n");
        }
        usleep(REQ_DELAY_US);
    }

    fwrite(STDOUT, sprintf(
        "[%s] %s 완료 — 신규 %d, 수정 %d, 변화없음 %d\n",
        $bbsId, $b['source'], $stat['new'], $stat['updated'], $stat['unchanged']
    ));
    foreach ($stat as $k => $v) { $grand[$k] += $v; }
}

fwrite(STDOUT, sprintf(
    "\n백필 완료 — %d쪽 조회(실패 %d), 신규 %d, 수정 %d, 변화없음 %d\n",
    $grand['pages'], $grand['failed'], $grand['new'], $grand['updated'], $grand['unchanged']
));
exit($grand['pages'] === 0 ? 1 : 0);
