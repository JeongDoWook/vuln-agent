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
 * 공지 1건에 걸린 CVE 목록(정션 = 정본). 정렬·중복제거된 배열.
 */
function vg_advisory_cve_list(PDO $pdo, int $advisoryId): array {
    $st = $pdo->prepare(
        'SELECT cve_id FROM tb_advisory_cve
          WHERE advisory_id = ? AND is_deleted = 0 ORDER BY cve_id'
    );
    $st->execute([$advisoryId]);
    return $st->fetchAll(PDO::FETCH_COLUMN) ?: [];
}

/**
 * 공지 1건의 CVE 목록을 tb_advisory_cve 정션에 동기화한다(멱등).
 *   $cveIds 는 이미 검증된 배열(vg_extract_cve_ids 출력)이어야 한다.
 *   신규는 INSERT..ON DUPLICATE KEY 로 되살리고(과거 soft-delete 복구),
 *   목록에서 빠진 건 soft-delete 한다 — 오탈자가 정리돼 개수가 줄어드는 경우까지
 *   정션이 따라가야 하기 때문이다.
 * @return bool 실제로 목록이 달라졌는지(호출자의 '수정' 판정 근거)
 */
function vg_sync_advisory_cves(PDO $pdo, int $advisoryId, array $cveIds): bool {
    $cveIds = array_values(array_unique($cveIds));
    sort($cveIds);
    if (vg_advisory_cve_list($pdo, $advisoryId) === $cveIds) {
        return false;
    }
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
    return true;
}

// 국내 보안공지(KISA 등) upsert. 정규화한 url 기준 dedup.
//   KISA 는 수정일을 노출하지 않으므로(RSS·목록·상세 모두 등록일 하나뿐) 저장된 값과
//   비교해 실제로 달라졌을 때만 UPDATE 한다. 그래야 updated_at 이 "변경을 관측한 시각"이
//   되고, 백필을 몇 번 돌려도 멱등하다.
//   제목 정규화(엔티티 해제·공백 압축·길이 제한)를 여기서 한다. RSS 는 제목에 &#39; 같은
//   엔티티를 그대로 주고 목록 페이지는 해제된 문자를 준다. 경로마다 다르게 다듬으면
//   같은 공지가 수집 주기마다 '수정'으로 뒤집힌다.
//   반환: 'new' | 'updated' | 'unchanged'
function vg_upsert_advisory(PDO $pdo, string $source, string $title, string $url, ?string $published, array $cveIds): string {
    $url   = vg_kisa_canon_url($url);
    $title = html_entity_decode($title, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    $title = mb_substr(trim(preg_replace('/\s+/u', ' ', $title)), 0, 500);
    $chk = $pdo->prepare('SELECT advisory_id, title, published FROM tb_advisory WHERE url = ? LIMIT 1');
    $chk->execute([$url]);
    $cur = $chk->fetch(PDO::FETCH_ASSOC);
    if ($cur) {
        // CVE 는 덮어쓰지 않고 정션에 있는 기존 목록과 합친다.
        //   호출자(RSS 커넥터·목록 백필)는 "제목"만 보고 CVE 를 뽑는다. 본문에서 찾은 CVE 는
        //   DB 에만 있다(vg_advisory_fill_content 가 채운다). 덮어쓰면 본문 유래 CVE 가 날아가고,
        //   content_fetched_at 이 이미 찍혀 있어 fill_content 가 다시 채워주지도 않는다.
        //   실제로 백필 재실행이 공지 1,742건의 CVE 를 지웠다.
        $id = (int) $cur['advisory_id'];
        $merged = array_merge(vg_advisory_cve_list($pdo, $id), $cveIds);
        $cveChanged = vg_sync_advisory_cves($pdo, $id, $merged);
        if ($cur['title'] === $title
            && (string) $cur['published'] === (string) $published
            && !$cveChanged) {
            return 'unchanged';
        }
        // 값이 같아도 다시 쓴다 — CVE 만 늘어난 경우에도 updated_at 이
        // "변경을 관측한 시각" 으로 남아야 한다.
        $pdo->prepare('UPDATE tb_advisory SET title=?, published=? WHERE advisory_id=?')
            ->execute([$title, $published, $id]);
        return 'updated';
    }
    $pdo->prepare('INSERT INTO tb_advisory (source, title, url, published) VALUES (?,?,?,?)')
        ->execute([$source, $title, $url, $published]);
    vg_sync_advisory_cves($pdo, (int) $pdo->lastInsertId(), $cveIds);
    return 'new';
}

/**
 * 공지 1건의 본문을 채운다. 이미 채워져 있으면 요청 없이 false.
 * 본문에만 등장하는 CVE 를 흡수해 정션을 보강한다(제목에 없는 경우가 흔하다).
 * HTML fetch·태그 제거는 KISA 응답 형식 전용이라 feeds/kisa.php(vg_kisa_parse_content)에
 * 위임하고, 여기서는 "채워야 하는가 → 가져와서 채운다 → CVE 를 흡수한다"는 도메인 흐름만 갖는다.
 * @return bool 실제로 본문을 새로 저장했는지
 */
function vg_advisory_fill_content(PDO $pdo, string $url): bool {
    $url = vg_kisa_canon_url($url);
    $st = $pdo->prepare('SELECT advisory_id, content_fetched_at FROM tb_advisory WHERE url = ? AND is_deleted = 0 LIMIT 1');
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
        // 정션의 기존 목록과 합친다. 절단은 없다 — 정션은 CVE 한 건이 한 행이라
        // 패치데이 공지의 CVE 263개도 그대로 들어간다(옛 CSV 컬럼은 varchar(512)
        // 시절 마지막 ID 를 잘라 "CVE-2" 같은 조각을 남겼다).
        $merged = array_merge(vg_advisory_cve_list($pdo, $id), $found);
        vg_sync_advisory_cves($pdo, $id, $merged);
        foreach (array_unique($merged) as $cve) {
            vg_upsert_cve($pdo, $cve, null, null, null);
        }
    }
    return true;
}
