<?php
declare(strict_types=1);

/**
 * advisory.php — 국내 보안공지(advisory) 도메인 영속화: 저장/CVE 합치기/junction 동기화/본문 채우기.
 *   advisory 는 KISA 전용이 아니라 도메인 엔티티다. KISA RSS 커넥터·목록 백필 스크립트가
 *   이 도메인을 쓰는 여러 주체 중 하나일 뿐이다. KISA 응답 형식 전용 파싱(HTML 본문 추출·
 *   URL 정규화)은 feeds/kisa.php 에 남아 있고, 아래 함수들이 그걸 호출한다.
 */

require_once __DIR__ . '/feeds/http.php';
require_once __DIR__ . '/feeds/upsert.php';

/**
 * 두 cve_ids 문자열의 합집합(정렬·중복제거·형식검증).
 *   양쪽 모두 vg_extract_cve_ids 를 통과시키므로 예전에 잘려 저장된 조각("CVE-2")이나
 *   오탈자(CVE-0215-8451)는 여기서 함께 걸러진다.
 */
function vg_merge_cve_ids(?string $a, ?string $b): ?string {
    $ids = vg_extract_cve_ids((string) $a . "\n" . (string) $b);
    return $ids ? implode(',', $ids) : null;
}

/**
 * tb_advisory.cve_ids(CSV, 정본)를 tb_advisory_cve 정션에 동기화한다(멱등).
 *   $cveIds 는 이미 검증된 배열(vg_extract_cve_ids 출력)이어야 한다.
 *   신규는 INSERT..ON DUPLICATE KEY 로 되살리고(과거 soft-delete 복구),
 *   목록에서 빠진 건 soft-delete 한다 — rebuild_advisory_cveids.php 가 오탈자를
 *   정리해 개수가 줄어드는 경우까지 junction 이 따라가야 하기 때문이다.
 */
function vg_sync_advisory_cves(PDO $pdo, int $advisoryId, array $cveIds): void {
    if ($cveIds) {
        $ins = $pdo->prepare(
            'INSERT INTO tb_advisory_cve (advisory_id, cve_id) VALUES (?,?)
             ON DUPLICATE KEY UPDATE is_deleted = 0, deleted_at = NULL'
        );
        foreach ($cveIds as $cve) {
            $ins->execute([$advisoryId, $cve]);
        }
    }
    $placeholders = $cveIds ? implode(',', array_fill(0, count($cveIds), '?')) : '';
    $sql = 'UPDATE tb_advisory_cve SET is_deleted = 1, deleted_at = NOW()
             WHERE advisory_id = ? AND is_deleted = 0'
         . ($placeholders !== '' ? " AND cve_id NOT IN ($placeholders)" : '');
    $pdo->prepare($sql)->execute($cveIds ? array_merge([$advisoryId], $cveIds) : [$advisoryId]);
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
    $chk = $pdo->prepare('SELECT advisory_id, title, published, cve_ids FROM tb_advisory WHERE url = ? LIMIT 1');
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
        $id = (int) $cur['advisory_id'];
        // junction 은 cve_ids 가 실제로 바뀌었는지와 무관하게 항상 최신 CSV 를 반영한다
        // (제목/발행일만 바뀐 경우에도 junction 이 CSV 와 어긋나지 않게).
        vg_sync_advisory_cves($pdo, $id, vg_extract_cve_ids((string) $cveIds));
        $same = $cur['title'] === $title
             && (string) $cur['published'] === (string) $published
             && (string) $cur['cve_ids'] === (string) $cveIds;
        if ($same) {
            return 'unchanged';
        }
        $pdo->prepare('UPDATE tb_advisory SET title=?, published=?, cve_ids=? WHERE advisory_id=?')
            ->execute([$title, $published, $cveIds, $id]);
        return 'updated';
    }
    $pdo->prepare('INSERT INTO tb_advisory (source, title, url, published, cve_ids) VALUES (?,?,?,?,?)')
        ->execute([$source, $title, $url, $published, $cveIds]);
    vg_sync_advisory_cves($pdo, (int) $pdo->lastInsertId(), vg_extract_cve_ids((string) $cveIds));
    return 'new';
}

/**
 * 공지 1건의 본문을 채운다. 이미 채워져 있으면 요청 없이 false.
 * 본문에만 등장하는 CVE 를 흡수해 cve_ids 를 보강한다(제목에 없는 경우가 흔하다).
 * HTML fetch·태그 제거는 KISA 응답 형식 전용이라 feeds/kisa.php(vg_kisa_parse_content)에
 * 위임하고, 여기서는 "채워야 하는가 → 가져와서 채운다 → CVE 를 흡수한다"는 도메인 흐름만 갖는다.
 * @return bool 실제로 본문을 새로 저장했는지
 */
function vg_advisory_fill_content(PDO $pdo, string $url): bool {
    $url = vg_kisa_canon_url($url);
    $st = $pdo->prepare('SELECT advisory_id, cve_ids, content_fetched_at FROM tb_advisory WHERE url = ? AND is_deleted = 0 LIMIT 1');
    $st->execute([$url]);
    $row = $st->fetch(PDO::FETCH_ASSOC);
    // "이미 시도했는가"는 content 가 아니라 content_fetched_at 이 판단한다. 본문 텍스트가
    // 없는 공지도 있어서(아래) content='' 로 남는데, content 로 판단하면 매 수집마다 재시도한다.
    if (!$row || $row['content_fetched_at'] !== null) {
        return false;
    }

    $id = (int) $row['advisory_id'];

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
        $pdo->prepare("UPDATE tb_advisory SET content='', content_fetched_at=NOW() WHERE advisory_id=?")
            ->execute([$id]);
        return false;
    }

    $pdo->prepare('UPDATE tb_advisory SET content=?, content_fetched_at=NOW() WHERE advisory_id=?')
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
            $pdo->prepare('UPDATE tb_advisory SET cve_ids=? WHERE advisory_id=?')->execute([$joined, $id]);
        }
        vg_sync_advisory_cves($pdo, $id, $merged);
        foreach ($merged as $cve) {
            vg_upsert_cve($pdo, $cve, null, null, null);
        }
    }
    return true;
}
