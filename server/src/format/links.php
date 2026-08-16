<?php
declare(strict_types=1);

/**
 * format/links.php — 바깥으로 나가는 링크와 그 안전성.
 *   참조 URL 검증 · CVE 대표 참조 · 조치 열 · 벤더 공식 페이지 URL.
 *   href 로 나가는 값은 **여기 한 곳에서만** 스킴을 검증한다(vg_is_safe_http_url) —
 *   검증식이 두 곳에 있으면 한쪽만 고쳤을 때 다른 쪽에 구멍이 남는다.
 */

/**
 * href 로 그대로 출력해도 안전한 URL 인가(http/https 스킴만). 저장 시점(vg_nvd_extract_ref_urls)과
 * 출력 시점(vg_cve_first_ref·cve.php 참조 목록)이 각자 정규식을 들고 있으면 한쪽만 고쳤을 때
 * 다른 쪽에 구멍이 남는다 — 검증을 여기 한 곳으로 모은다.
 */
function vg_is_safe_http_url(?string $url): bool {
    return $url !== null && preg_match('#^https?://#i', $url) === 1;
}

/**
 * tb_cve.ref_urls_json(첫 항목)에서 url·tags 를 꺼낸다. findings.php/host.php 는 대표 링크
 * 1개만 보여주면 되므로(전체 표는 cve.php 개요 탭) 파싱 실패·빈 배열·안전하지 않은 스킴이면 null.
 * tags 를 함께 돌려주는 건 호출부가 "이게 실제로 패치 링크인지"를 판단해야 하기 때문 —
 * vg_nvd_extract_ref_urls 의 정렬은 Patch/Vendor Advisory 가 있을 때만 앞으로 올리므로,
 * 태그가 없거나 Mailing List/Broken Link 뿐인 CVE 는 첫 항목이 패치 링크가 아닐 수 있다.
 */
function vg_cve_first_ref(?string $json): ?array {
    if ($json === null || $json === '') { return null; }
    $list = json_decode($json, true);
    if (!is_array($list) || !isset($list[0]['url'])) { return null; }
    $url = (string) $list[0]['url'];
    if (!vg_is_safe_http_url($url)) { return null; }
    $tags = [];
    foreach ((array) ($list[0]['tags'] ?? []) as $t) { $tags[] = (string) $t; }
    return ['url' => $url, 'tags' => $tags];
}

/**
 * 조치 열 공통 표시 규칙 — findings.php/host.php 가 각자 들고 있던 같은 삼항 로직을 통일.
 *   조치버전이 있으면 "현재버전 → 조치버전 이상", 없고 NVD 대표 참조링크가 있으면 링크,
 *   둘 다 없으면 평문 — 두 경우 모두 현재 버전을 곁들여 패키지 열과 오가지 않아도 되게 한다.
 *   링크 문구는 태그로 갈린다 — Patch/Vendor Advisory 가 아니면 "패치 확인"이라고 단정하지
 *   않는다(무관한 메일링리스트·죽은 링크를 패치인 줄 알고 클릭하게 만들 수 있다).
 */
function vg_fix_cell(?string $fixedVersion, ?string $refUrlsJson, ?string $installedVersion = null): string {
    $installed = ($installedVersion !== null && $installedVersion !== '') ? vg_h($installedVersion) : null;
    if ($fixedVersion !== null && $fixedVersion !== '') {
        $ver = $installed !== null ? $installed . ' → ' . vg_h($fixedVersion) : vg_h($fixedVersion);
        // 조치 버전은 rhel 모듈처럼 아주 긴 것이 있다(1:1.22.1-3.module+el9.2.0+15280+45c505d6.1).
        //   좁은 칸에서 세 줄로 부풀어 행 높이를 혼자 결정하므로 두 줄까지만 보이게 하고(clamp-2)
        //   전체 값은 title 로 남긴다 — 목록에서 훑고, 정확한 버전은 상세·툴팁에서 본다.
        $plain = ($installedVersion !== null && $installedVersion !== '' ? $installedVersion . ' → ' : '')
               . $fixedVersion . ' 이상';
        return '<span class="pill clamp-2" title="' . vg_h($plain) . '">' . $ver . ' 이상</span>';
    }
    $currentLine = $installed !== null ? '<div class="why">현재 ' . $installed . '</div>' : '';
    $ref = vg_cve_first_ref($refUrlsJson);
    if ($ref === null) {
        return '<span class="why">패치 확인</span>' . $currentLine;
    }
    $isPatch = in_array('Patch', $ref['tags'], true) || in_array('Vendor Advisory', $ref['tags'], true);
    return '<a class="why" href="' . vg_h($ref['url']) . '" target="_blank" rel="noopener noreferrer">'
        . ($isPatch ? '패치 확인 →' : '참고 링크 →') . '</a>' . $currentLine;
}

/**
 * 벤더 판정 advisory → 벤더 공식 권고 URL. 확신 가능한 두 벤더만(레드햇·알마리눅스) — vendor.php·
 *   cve.php 가 공유한다(원본 지침: 한쪽만 링크되면 사용자가 헷갈린다).
 *   AlmaLinux 는 OVAL 자체엔 ALSA 참조도 있지만 커넥터(feeds/rhoval.php)가 RHSA/ELSA 참조만
 *   골라 저장한다 — 그래서 vendor='almalinux' 행도 advisory 값은 "RHSA-YYYY:NNNN" 이다.
 *   실물 OVAL(org.almalinux.alsa-9.xml) 대조 결과 같은 정의 안에서 RHSA·ALSA 번호(연도:일련번호)는
 *   1610건 전수 동일했다(AlmaLinux 가 RHEL 권고를 그대로 재빌드하며 번호를 유지) — 그래서 접두만
 *   RHSA→ALSA 로 바꿔 재구성해도 안전하다. 확신 없는 패턴(Oracle ELSA 등)은 null.
 */
function vg_vendor_advisory_url(string $vendor, ?string $advisory, string $releaseMajor = ''): ?string {
    $advisory = trim((string) $advisory);
    if ($advisory === '') { return null; }
    if ($vendor === 'redhat' && preg_match('/^RHSA-\d+:\d+$/i', $advisory)) {
        return 'https://access.redhat.com/errata/' . rawurlencode($advisory);
    }
    if ($vendor === 'almalinux' && $releaseMajor !== '' && preg_match('/^RHSA-(\d+:\d+)$/i', $advisory, $m)) {
        return 'https://errata.almalinux.org/' . rawurlencode($releaseMajor) . '/ALSA-' . str_replace(':', '-', $m[1]) . '.html';
    }
    return null;
}

/**
 * 벤더 판정 소스 cve_id → 벤더 공식 CVE 페이지 URL. advisory 가 없는 소스(rhunfixed)이거나
 *   패키지가 아니라 CVE 단위로 원문을 보여주는 소스(debtracker·ubuntuoval)만 해당.
 *   kcve 는 마땅한 벤더 페이지가 없어 null(호출부가 링크 없이 텍스트만 보여준다).
 */
function vg_vendor_cve_url(string $src, string $cveId): ?string {
    $cveId = trim($cveId);
    if ($cveId === '' || !preg_match('/^CVE-\d{4}-\d+$/i', $cveId)) { return null; }
    switch ($src) {
        case 'rhunfixed':  return 'https://access.redhat.com/security/cve/' . rawurlencode($cveId);
        case 'debtracker': return 'https://security-tracker.debian.org/tracker/' . rawurlencode($cveId);
        case 'ubuntuoval': return 'https://ubuntu.com/security/' . rawurlencode($cveId);
        default: return null;
    }
}
