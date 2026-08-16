<?php
declare(strict_types=1);

/**
 * cve.php — CVE 상세페이지. 로그인 필요.
 *   ?cve=CVE-XXXX-XXXXX  ·  ?page=N/?per_page=N (발견 위치) ·  ?vpage=N/?vper_page=N (벤더 판정) ·
 *   ?apage=N/?aper_page=N (영향 패키지)
 *
 * 구성: 히어로(식별 + 등급) → 통계 그리드(핵심 지표 한눈에) → 앵커 내비(sticky) →
 *   요약 → 공격 벡터 → (있으면) 벤더 판정 → 영향 패키지 → 발견 위치 → 참조 자료.
 *   예전엔 탭 3개(개요/영향 패키지/발견 위치) 뒤에 숨기고 지표를 사이드바에 따로 뒀는데,
 *   "한눈에 안 들어온다" 는 사용자 피드백의 핵심 원인이었다 — 탭 전환 없이 스크롤 한 번으로
 *   전부 보이는 단일 페이지로 바꾼다. 세 섹션(벤더 판정·영향 패키지·발견 위치) 모두 같은 화면에
 *   동시에 존재해 건수가 많을 수 있으므로 각각 독립된 쿼리 파라미터로 페이지네이션한다
 *   (vg_page_nav 의 파라미터명을 섹션마다 다르게 줘서 서로의 페이지 이동이 섞이지 않게 한다).
 *
 * cvss_vector·cwe·due_date·ransomware 는 커넥터가 이제야 받아오기 시작한 필드라
 * 예전에 수집된 행은 NULL 이다. 전부 "없으면 그 줄을 생략" 으로 처리한다.
 *
 * 이 파일은 **무엇을 어떤 순서로 그리나**만 갖는다. SQL 은 src/cve/queries.php,
 *   섹션별 HTML 은 src/cve/sections/*.php 다. 페이저 파라미터 이름(page/vpage/apage …)은
 *   여기서만 정해 아래로 값만 넘긴다 — 이름이 두 곳에서 정해지면 세 페이저가 서로를 민다(#278).
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require_once __DIR__ . '/../src/distro.php'; // vg_is_kernel_code_pkg — 재시작/재부팅 안내 구분
require_once __DIR__ . '/../src/audit.php';   // vg_log_activity
require_once __DIR__ . '/../src/cve/queries.php';   // VG_CVE_VENDOR_SRC · vg_cve_load_* — 섹션별 조회
require_once __DIR__ . '/../src/cve/sections.php';  // vg_cve_render_section — 섹션 파일 하나를 그린다
vg_require_menu_any('findings', 'catalog', 'advisories');   // CVE 상세: 탐지 결과·CVE 카탈로그·보안 공지에서 함께 열린다

$err = null; $cveId = ''; $cve = null; $kev = null; $affected = []; $locations = []; $vendorRows = [];
$locTotal = 0; $assetTotal = 0; $page = vg_page(); $perPage = vg_perpage();
$vendorTotal = 0; $vPage = vg_page('vpage'); $vPerPage = vg_perpage(null, 'vper_page');
$affectedTotal = 0; $aPage = vg_page('apage'); $aPerPage = vg_perpage(null, 'aper_page');

try {
    $raw = (string) ($_GET['cve'] ?? '');
    // 이 정규식은 vendor.php 의 CVE 컬럼 렌더러(cell[3], 링크 여부 판정)와 동기화되어야 한다 —
    //   거기서도 같은 식을 그대로 복제해 쓴다(의도적 중복, 공유 상수로 안 뽑음 — 최초 작업 지침의
    //   YAGNI). 둘 중 하나만 고치면 "링크는 걸리는데 여긴 튕긴다" 가 조용히 생기니 같이 바꿀 것.
    if (!preg_match('/^CVE-\d{4}-\d+$/i', $raw)) {
        $err = '잘못된 CVE 형식입니다.';
    } else {
        $cveId = strtoupper($raw);
        $pdo = vg_pdo();

        $cve = vg_cve_load_cve($pdo, $cveId);

        if ($cve) {
            // CVE 상세 열람 감사로그. CVE ID 는 정수 PK 가 아니라 message 에 담는다(host.php 의 fqdn 과 동일한 방식).
            vg_log_activity($pdo, 'CVE', null, 'view_cve', $cveId, subject: $cveId, action: 'READ');
        }

        $kev = vg_cve_load_kev($pdo, $cveId);

        ['total' => $vendorTotal, 'rows' => $vendorRows]
            = vg_cve_load_vendor($pdo, $cveId, $vPage, $vPerPage);

        ['total' => $affectedTotal, 'rows' => $affected]
            = vg_cve_load_affected($pdo, $cveId, $aPage, $aPerPage);

        ['total' => $locTotal, 'assetTotal' => $assetTotal, 'rows' => $locations]
            = vg_cve_load_locations($pdo, $cveId, $page, $perPage);
    }
} catch (Throwable $e) {
    error_log('[cve] ' . $e->getMessage());
    $err = '처리 중 오류가 발생했습니다.';
}

vg_header($cveId !== '' ? $cveId : 'CVE', 'findings');

if ($err !== null) {
    vg_alert('오류 · ' . $err);
    vg_footer();
    return;
}

// 등급은 CVSS 점수에서 파생한다 — tb_cve 엔 등급 컬럼이 없다(cves.php 목록과 같은 구간).
$cvss    = $cve['cvss'] ?? null;
$sevName = vg_cvss_sev($cvss === null ? null : (string) $cvss);
$sevUp   = $sevName !== '' ? strtoupper($sevName) : null;
$tone    = $sevUp !== null ? vg_sev_tone($sevUp) : 'muted';

// KEV 패치 기한 — "언제까지 고쳐야 하나" 를 말해주는 유일한 신호. 지났으면 붉게.
//   통계 그리드·사이드 카드가 둘 다 이 값을 쓰므로 히어로보다 먼저 계산해 둔다.
$due = $kev['due_date'] ?? null;
$dLeft = null; $overdue = false;
if ($due) {
    $dLeft   = (int) (new DateTimeImmutable('today'))->diff(new DateTimeImmutable((string) $due))->format('%r%a');
    $overdue = $dLeft < 0;
}

// 히어로 제목 — KEV·랜섬웨어는 다른 무엇보다 먼저 보여야 할 신호라 제목 옆에 붙인다.
$title = vg_h($cveId);
if ($kev) {
    $title .= ' ' . vg_badge('KEV', 'crit', '악용이 확인된 취약점 — CISA KEV 등재');
    if (!empty($kev['ransomware'])) {
        $title .= ' ' . vg_badge('랜섬웨어', 'crit', '랜섬웨어 캠페인에 실제로 사용된 취약점');
    }
}

vg_hero($title, ['<a href="/findings.php?q=' . urlencode($cveId) . '">취약점 현황에서 보기</a>'], $sevUp ?? '등급 미상', $tone, 'CVSS 등급', 'CVE DETAIL');
?>

<?php
/* 판단 신호 네 축 — 노출→악용→등급→조치. 순서는 vg_signal_slots() 가 고정한다.
 *   값은 이 화면이 이미 들고 있는 것만 쓴다: 없는 축을 추정해 만들지 않는다.
 *     노출 = 내 자산에 이 CVE 가 걸린 범위(발견 위치 집계) · 악용 = KEV 등재 여부와 EPSS ·
 *     등급 = CVSS 파생 등급 · 조치 = KEV 조치 기한(연방기관 기준일). KEV 가 아니면 이 제품이
 *     제시할 기한이 없으므로 unknown 으로 남긴다 — "기한 없음"이라고 단정하지 않는다.
 *   이 화면은 이미 vg_decision_flow() 를 갖고 있어 vg_explain_flow() 는 두지 않는다
 *   (docs/dev/ui-design-system.md — 두 도식을 한 화면에 겹치지 않는다). */
$epssPct = ($cve['epss'] ?? null) !== null && $cve['epss'] !== ''
    ? number_format((float) $cve['epss'] * 100, 1) . '%' : null;
// 아직 수집되지 않은 CVE 면 네 칸이 전부 '미제공' 이라 그리지 않는다 — 빈 슬롯은 잡음이다.
if ($cve !== null) {
vg_signal_slots([
    'exposure' => $locTotal > 0
        ? ['value' => '내 자산 ' . number_format($assetTotal) . '대', 'tone' => 'crit']
        : ['value' => '해당 자산 없음', 'tone' => 'ok'],
    'exploit'  => $kev
        ? ['value' => 'KEV 등재', 'tone' => 'crit']
        : ($epssPct !== null
            ? ['value' => 'EPSS ' . $epssPct, 'tone' => vg_epss_tone((float) $cve['epss'])]
            : ['state' => 'unknown']),
    'severity' => $sevUp !== null
        ? ['value' => $sevUp, 'tone' => $tone]
        : ['state' => 'unknown'],
    'action'   => $kev && $due
        ? ['value' => $overdue ? abs($dLeft) . '일 초과' : 'D-' . $dLeft, 'tone' => $overdue ? 'crit' : 'med']
        : ['state' => 'unknown'],
]);
}

/* 섹션 렌더 — 각 파일이 쓰는 값만 열거해 넘긴다(전역을 주워 쓰지 않는다).
 *   세 섹션의 페이저는 여기서 정한 값만 받는다: 발견 위치 page/per_page, 벤더 판정
 *   vpage/vper_page, 영향 패키지 apage/aper_page(#278). */
vg_cve_render_section('stats', [
    'cve' => $cve, 'kev' => $kev, 'cvss' => $cvss, 'tone' => $tone,
    'due' => $due, 'dLeft' => $dLeft, 'overdue' => $overdue,
    'assetTotal' => $assetTotal, 'locTotal' => $locTotal,
]);

vg_decision_flow([
    ['label' => '위험·근거', 'hint' => 'CVSS·EPSS·KEV와 원본', 'href' => '#summary'],
    ['label' => '영향 대상', 'hint' => number_format($assetTotal) . '대 · ' . number_format($locTotal) . '건', 'href' => '#locations'],
    ['label' => '조치', 'hint' => '자산별 현재 → 권장 조치', 'href' => '#locations'],
    ['label' => '재검증', 'hint' => '다음 자산 스캔 결과 확인', 'href' => '/findings.php?q=' . urlencode($cveId)],
]); ?>

<nav class="subtabs subtabs--sticky">
  <a href="#summary">요약</a>
  <a href="#vector">공격 벡터</a>
  <?php if ($vendorTotal > 0): ?><a href="#vendor">벤더 판정<span class="n"><?= number_format($vendorTotal) ?></span></a><?php endif; ?>
  <a href="#affected">영향 패키지<span class="n"><?= number_format($affectedTotal) ?></span></a>
  <a href="#locations">발견 위치<span class="n"><?= number_format($locTotal) ?></span></a>
  <a href="#references">참조 자료</a>
</nav>

<?php
vg_cve_render_section('summary', [
    'cve' => $cve, 'cveId' => $cveId, 'kev' => $kev,
    'due' => $due, 'dLeft' => $dLeft, 'overdue' => $overdue,
    'vendorTotal' => $vendorTotal, 'affectedTotal' => $affectedTotal,
    'locTotal' => $locTotal, 'assetTotal' => $assetTotal,
]);

vg_cve_render_section('vector', ['cve' => $cve]);

vg_cve_render_section('vendor', [
    'cveId' => $cveId, 'vendorRows' => $vendorRows, 'vendorTotal' => $vendorTotal,
    'vPage' => $vPage, 'vPerPage' => $vPerPage,
]);

vg_cve_render_section('affected', [
    'affected' => $affected, 'affectedTotal' => $affectedTotal,
    'aPage' => $aPage, 'aPerPage' => $aPerPage,
]);

vg_cve_render_section('locations', [
    'cve' => $cve, 'locations' => $locations, 'locTotal' => $locTotal,
    'page' => $page, 'perPage' => $perPage,
]);

vg_cve_render_section('references', ['cve' => $cve, 'cveId' => $cveId]);

vg_footer();
