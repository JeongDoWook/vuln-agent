<?php
declare(strict_types=1);

/**
 * feeds/upsert.php — 수집 결과를 tb_cve / tb_kev_catalog / tb_cve_affected_package 로
 *   넣는 공용 write 프리미티브 + CVE-ID 형식검증. 여러 커넥터가 공유한다(KISA 공지 전용
 *   upsert 는 ../advisory.php 가 따로 갖는다).
 */

/**
 * 긴 텍스트(설명·본문) 저장 상한(글자 수). 폭주한 응답으로부터 DB 를 지키는 안전장치일 뿐,
 * 정상 데이터를 자르기 위한 값이 아니다.
 *
 * 실제로 이 상한을 2000 으로 두는 바람에 NVD 설명 2,817건이 문장 중간에서 잘렸다.
 * 저장 컬럼은 MEDIUMTEXT(16MB) 이므로 6만 글자는 넉넉히 들어간다.
 * (TEXT 는 65,535 "바이트" 라 한글이 섞이면 글자 수가 훨씬 줄어든다 — 그래서 MEDIUMTEXT.)
 */
const VG_TEXT_MAX = 60000;

/**
 * CVE-ID 형식 검증. 공지 본문·제목에서 정규식으로 긁은 값에는 원문 오탈자가 섞인다
 * (실제로 CVE-0215-8451, CVE-2016-03246 이 tb_cve 에 들어갔다).
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

// tb_cve 로 들어가는 유일한 통로. 여기서 막으면 모든 커넥터·백필이 함께 보호된다.
/**
 * $vector·$cwe 는 NVD 만 준다(KEV·OSV·KISA 는 null 을 넘긴다). COALESCE 라 null 은
 * 기존 값을 덮지 않는다 — 어느 피드가 먼저/나중에 돌든 채워진 값이 지워지지 않는다.
 */
function vg_upsert_cve(
    PDO $pdo, string $id, ?string $summary, ?float $cvss, ?string $published,
    ?string $vector = null, ?string $cwe = null, ?string $refUrlsJson = null
): void {
    if (!vg_is_cve_id($id)) {
        error_log("[cve] 잘못된 CVE-ID 무시: $id");
        return;
    }
    $st = $pdo->prepare(
        'INSERT INTO tb_cve (cve_id, summary, cvss, published, cvss_vector, cwe, ref_urls_json) VALUES (?,?,?,?,?,?,?)
         ON DUPLICATE KEY UPDATE
           summary        = COALESCE(VALUES(summary), summary),
           cvss           = COALESCE(VALUES(cvss), cvss),
           published      = COALESCE(VALUES(published), published),
           cvss_vector    = COALESCE(VALUES(cvss_vector), cvss_vector),
           cwe            = COALESCE(VALUES(cwe), cwe),
           -- ref_urls_json 은 지금은 NVD 만 채운다 — 다른 피드가 vg_upsert_cve 를 부를 때
           -- 넘기는 null 이 기존 링크를 지우면 안 되므로 COALESCE. 대가: NVD 가 재수집에서
           -- 링크를 뺐거나(죽은 링크 정리 등) extract 가 전부 걸러 null 이 돼도 옛 URL 이
           -- DB 에 남는다. 출력 시점(vg_cve_first_ref/cve.php)의 스킴 재검증이 최소한의
           -- 방어선이다 — 완전한 해는 아니다.
           ref_urls_json  = COALESCE(VALUES(ref_urls_json), ref_urls_json)'
    );
    $st->execute([$id, $summary, $cvss, $published, $vector, $cwe, $refUrlsJson]);
}

/**
 * $dueDate 는 CISA 가 정한 연방기관 패치 기한, $ransomware 는 랜섬웨어 악용 확인 여부.
 * 둘 다 KEV 피드에 원래 들어있는데 그동안 버리고 있었다 — "언제까지 고쳐야 하나" 를
 * 말해주는 유일한 신호라 CVSS 점수보다 실용적이다.
 */
function vg_upsert_kev(
    PDO $pdo, string $id, ?string $dateAdded, ?string $note,
    ?string $dueDate = null, bool $ransomware = false
): void {
    $st = $pdo->prepare(
        'INSERT INTO tb_kev_catalog (cve_id, date_added, note, due_date, ransomware) VALUES (?,?,?,?,?)
         ON DUPLICATE KEY UPDATE
           date_added = COALESCE(VALUES(date_added), date_added),
           note       = COALESCE(VALUES(note), note),
           due_date   = COALESCE(VALUES(due_date), due_date),
           ransomware = VALUES(ransomware)'
    );
    $st->execute([$id, $dateAdded ?: null, $note, $dueDate ?: null, $ransomware ? 1 : 0]);
}

function vg_upsert_affected(PDO $pdo, string $cve, ?string $eco, string $pkg, ?string $fixed): void {
    // 자연키는 (cve_id, package_name, ecosystem) — UNIQUE uq_cap. 같은 패키지라도 배포판마다
    //   조치버전이 달라 ecosystem 을 키에 포함해야 서로 덮어쓰지 않는다(예: nginx 가 Rocky 와
    //   Debian 에서 각기 다른 fixed_version). ecosystem NULL 은 키에서 '' 로 정규화한다.
    // fixed_version 은 새 값이 있을 때만 갱신한다(빈 값이면 기존 조치버전을 지우지 않는다).
    $ecoKey = (string) ($eco ?? '');
    $fixedVal = ($fixed !== null && $fixed !== '') ? $fixed : null;
    $pdo->prepare(
        'INSERT INTO tb_cve_affected_package (cve_id, ecosystem, package_name, fixed_version)
         VALUES (?,?,?,?)
         ON DUPLICATE KEY UPDATE fixed_version = COALESCE(VALUES(fixed_version), fixed_version)'
    )->execute([$cve, $ecoKey, $pkg, $fixedVal]);
}
