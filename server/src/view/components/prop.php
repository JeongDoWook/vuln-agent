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
 *   $withView 는 호출부가 "진입점"인지 "도착지"인지를 가른다 — 컨테이너 탭
 *   (container/overview.php)은 sbom.php 로 넘어가는 진입점이라 true(기본값)로 "부품표 보기"를
 *   주 버튼으로 보여준다. 반면 sbom.php 자기 자신(view=html 화면)은 도착지라 그 버튼을 누르면
 *   지금 보고 있는 페이지로 재이동하는 no-op 이 된다 — false 로 넘겨 숨기고, 그 화면에서 실제로
 *   필요한 다운로드 링크를 주 버튼으로 승격한다.
 *   호스트의 설치 패키지 탭은 이 카드를 안 쓴다 — 버튼 하나에 카드 하나가 아까워 아래
 *   vg_sbom_view_button() 으로 그 탭의 액션 줄에 흡수했다.
 */
function vg_sbom_links(string $fqdn, string $cid = '', int $scanId = 0, bool $withView = true): void {
    if (!vg_can('assets')) { return; }
    $base = vg_sbom_url($fqdn, $cid, $scanId);
    $cycloneHref = vg_h($base . '&format=cyclonedx');
    $spdxHref = vg_h($base . '&format=spdx');
    if ($withView) {
        // 사람이 보는 주 화면(view=html)은 눈에 띄는 버튼으로, 표준 포맷 다운로드(외부 도구·
        //   감사 제출용 — route-query-contract.json 의 sbom_client/browser_bookmark)는 있다는
        //   것만 알면 되는 보조 링크로 낮춘다. URL·쿼리는 그대로다.
        echo '<div class="card"><strong>SBOM</strong>'
            . '<div class="card__body">'
            . '<div class="actions"><a class="btn btn--sm btn--primary" href="' . vg_h($base . '&view=html') . '">부품표 보기</a></div>'
            . '<div class="links">'
            . '<a href="' . $cycloneHref . '">CycloneDX 1.5 다운로드</a>'
            . '<a href="' . $spdxHref . '">SPDX 2.3 다운로드</a>'
            . '</div></div></div>';
        return;
    }
    /* 도착지(sbom.php 자신)에선 "부품표 보기"가 no-op 이라 빼고, 다운로드 링크를 주 버튼으로.
     *   카드로 감싸지 않는다 — 버튼 둘뿐인데 카드를 두면 본문 폭 1611px 중 17% 만 쓰는
     *   92px 짜리 띠가 페이지 끝에 하나 더 생긴다(실측). 호출부가 제목 줄의 액션 자리에 놓는다. */
    echo '<a class="btn btn--sm btn--primary" href="' . $cycloneHref . '">CycloneDX 1.5 다운로드</a>'
        . '<a class="btn btn--sm btn--ghost" href="' . $spdxHref . '">SPDX 2.3 다운로드</a>';
}

/** sbom.php 링크의 범위 규약(host·cid·scan_id)을 한 곳에 둔다 — 위 카드와 아래 버튼이 공유한다. */
function vg_sbom_url(string $fqdn, string $cid = '', int $scanId = 0): string {
    return '/sbom.php?host=' . urlencode($fqdn) . ($cid !== '' ? '&cid=' . urlencode($cid) : '')
        . ($scanId > 0 ? '&scan_id=' . $scanId : '');
}

/**
 * "부품표 보기" 버튼 하나만 — SBOM 카드를 따로 세우지 않고 남의 액션 줄에 얹을 때 쓴다.
 *   설치 패키지 탭(host/tabs/packages.php)이 그렇다: 카드 하나가 버튼 하나 때문에 자리를
 *   차지하던 것을 그 탭의 액션 줄로 흡수했다. 표준 포맷 다운로드는 감사 제출 같은 실제
 *   요구가 없어 화면에서 내렸다 — 엔드포인트(sbom.php?format=…)는 그대로 살아 있다.
 *   인가 게이트(assets)는 vg_sbom_links() 와 같다.
 */
function vg_sbom_view_button(string $fqdn, string $cid = '', int $scanId = 0): void {
    if (!vg_can('assets')) { return; }
    echo '<a class="btn btn--sm btn--ghost" href="' . vg_h(vg_sbom_url($fqdn, $cid, $scanId) . '&view=html')
        . '" title="이 자산의 부품표(SBOM)를 표로 보기">' . vg_icon('package') . '부품표 보기</a>';
}
