<?php
declare(strict_types=1);

/**
 * components/prop.php — 소품: 출력 캡처·내부 링크 검증·복사 버튼·SBOM 줄·수집 안내 CTA.
 *   다른 컴포넌트가 부품으로 쓰는 것들이라 이 층에서 가장 아래에 둔다
 *   (vg_local_href 는 signal.php 의 KPI·판단 순서가, vg_capture 는 화면들이 쓴다).
 */

require_once __DIR__ . '/../../format.php';

/** 출력형 공통 컴포넌트를 문자열 슬롯(actions 등)에 안전하게 담는다. */
function vg_capture(callable $render): string {
    ob_start();
    try {
        $render();
        return (string) ob_get_clean();
    } catch (Throwable $e) {
        ob_end_clean();
        throw $e;
    }
}

/** 앱 내부 이동만 허용한다. 외부·스킴 상대·제어문자 URL은 링크로 만들지 않는다. */
function vg_local_href($href): ?string {
    if (!is_string($href) || $href === '' || str_contains($href, '\\')
        || preg_match('/[\x00-\x20\x7f]/', $href) === 1) {
        return null;
    }
    if ($href[0] === '?' || $href[0] === '#') { return $href; }
    return str_starts_with($href, '/') && !str_starts_with($href, '//') ? $href : null;
}

/**
 * 클립보드 복사 버튼. JS 가 죽어도 값 자체는 화면에 그대로 있으므로(선택해서 복사 가능)
 * 이 버튼은 편의일 뿐 필수 경로가 아니다 — 그래서 <button type=button>.
 */
function vg_copy_btn(string $text, string $label = '복사'): void {
    echo '<button type="button" class="btn btn--sm btn--ghost copy" data-copy="' . vg_h($text) . '">'
        . vg_h($label) . '</button>';
}

/**
 * "아직 수집된 데이터 없음" 빈 상태의 CTA — 피드 커넥터 화면으로 안내한다.
 *   connectors 메뉴 권한이 없는 역할(기본 'user')에겐 눌러도 403 인 링크를 주지 않도록
 *   null 을 돌려준다(vg_empty 는 'cta' 가 없으면 버튼을 그리지 않는다).
 *   cves.php/advisories.php/compliance_rules.php/packages.php/vendor.php 가 공유한다.
 */
function vg_connectors_empty_cta(): ?array {
    return vg_can('connectors') ? ['href' => '/connectors.php', 'label' => '데이터 수집으로 이동'] : null;
}

/**
 * SBOM 다운로드 줄 — CycloneDX / SPDX 두 형식.
 *   자산 상세(호스트)와 컨테이너 상세가 같은 줄을 쓴다. 링크 형태·범위 규약(cid 를 주면
 *   그 컨테이너 하나, 안 주면 호스트 자신)이 두 화면에서 어긋나지 않게 여기 한 곳에 둔다.
 *   sbom.php 는 자산(assets) 권한이라 그 권한이 없는 사용자에겐 아예 그리지 않는다 —
 *   눌러보면 403 인 버튼을 보여주지 않는다(인가 자체는 sbom.php 가 서버측에서 확정한다).
 *   $scanId 는 sbom.php 의 시각화 보기(view=html)가 지금 보고 있는 스캔을 그대로 넘길 때만
 *   쓴다(> 0). 과거 스캔을 보면서 다운로드는 최신 스캔 것을 받는 어긋남을 막는다 — 호스트·
 *   컨테이너 상세는 항상 최신을 보므로 안 넘겨도(0) 기존과 동일하게 "최신" 그대로다.
 */
function vg_sbom_links(string $fqdn, string $cid = '', int $scanId = 0): void {
    if (!vg_can('assets')) { return; }
    $base = '/sbom.php?host=' . urlencode($fqdn) . ($cid !== '' ? '&cid=' . urlencode($cid) : '')
        . ($scanId > 0 ? '&scan_id=' . $scanId : '');
    // 사람이 보는 주 화면(view=html)은 눈에 띄는 버튼으로, 표준 포맷 다운로드(외부 도구·감사
    //   제출용 — route-query-contract.json 의 sbom_client/browser_bookmark)는 있다는 것만
    //   알면 되는 보조 링크로 낮춘다. URL·쿼리는 그대로다.
    echo '<div class="card"><strong>SBOM</strong>'
        . '<div class="card__body">'
        . '<div class="actions"><a class="btn btn--sm btn--primary" href="' . vg_h($base . '&view=html') . '">부품표 보기</a></div>'
        . '<div class="links">'
        . '<a href="' . vg_h($base . '&format=cyclonedx') . '">CycloneDX 1.5 다운로드</a>'
        . '<a href="' . vg_h($base . '&format=spdx') . '">SPDX 2.3 다운로드</a>'
        . '</div></div></div>';
}
