<?php
declare(strict_types=1);

/**
 * components/paging.php — 목록의 URL 상태: 쿼리스트링 병합·페이지/페이지당 개수 파싱·페이저.
 *   표를 그리지 않는다. 한 화면에 페이저가 여럿인 경우(cve.php 3섹션)를 위해 파라미터
 *   이름을 인자로 받되 **기본값은 'page'/'per_page' 다** — 20여 곳의 호출부가 이 기본값에
 *   기대고 있다(#278).
 */

require_once __DIR__ . '/../../format.php';
require_once __DIR__ . '/../../ui_config.php';

// 현재 $_GET 에 $overrides 를 병합한 쿼리스트링(?a=1&b=2). 값이 null/빈문자면 해당 키 제거.
function vg_qs(array $overrides = []): string {
    $params = $_GET;
    foreach ($overrides as $k => $v) {
        if ($v === null || $v === '') {
            unset($params[$k]);
        } else {
            $params[$k] = $v;
        }
    }
    $parts = [];
    foreach ($params as $k => $v) {
        if ($v === null || $v === '' || is_array($v)) { // 배열값(?a[]=)은 무시
            continue;
        }
        $parts[] = urlencode((string) $k) . '=' . urlencode((string) $v);
    }
    return '?' . implode('&', $parts);
}

// 페이지당 표시 개수. ?per_page= 를 화이트리스트로 검증해 반환. 잘못된 값이면 $default.
//   $param 은 한 화면에 페이지네이션 섹션이 여러 개일 때 서로 다른 쿼리 파라미터를 쓰기 위함
//   (예: cve.php 의 벤더 판정=vper_page, 영향 패키지=aper_page, 발견 위치=per_page).
function vg_perpage(?int $default = null, string $param = 'per_page'): int {
    $default ??= vg_ui_per_page_default();
    $v = (int) ($_GET[$param] ?? $default);
    return in_array($v, vg_ui_per_page_options(), true) ? $v : $default;
}

// 현재 페이지 번호. ?page= 를 정수로 파싱해 1 미만이면 1로 올린다.
//   상한도 여기서 함께 건다 — 호출부는 대개 (page-1)*perPage 로 OFFSET 을 바로 계산해
//   SQL 문자열에 보간한다(PDO::ATTR_EMULATE_PREPARES=false 라 LIMIT/OFFSET 은 바인딩이 아닌
//   보간을 쓴다). page 가 PHP_INT_MAX 근처면 그 곱셈이 float 로 오버플로해 "LIMIT 100 OFFSET
//   9.2E+20" 같은 깨진 SQL 리터럴이 나간다(실측). 실사용 규모를 크게 넘는 상한이라 정상
//   페이지네이션엔 영향이 없다.
const VG_PAGE_MAX = 10_000_000;
function vg_page(string $param = 'page'): int {
    return min(max(1, (int) ($_GET[$param] ?? 1)), VG_PAGE_MAX);
}

// "페이지당 N개" 셀렉트. onchange 시 현재 쿼리스트링 유지한 채 per_page 변경 + page=1 로 이동.
//   data-nav 는 app.js 가 이동 시작을 알아채 상단 진행바를 띄우는 표식이다.
function vg_perpage_select(string $pageParam = 'page', string $perPageParam = 'per_page'): void {
    $current = vg_perpage(null, $perPageParam);
    echo '<select data-nav onchange="location.href=this.value" aria-label="페이지당 표시 개수">';
    foreach (vg_ui_per_page_options() as $n) {
        $url = vg_qs([$perPageParam => $n, $pageParam => 1]);
        echo '<option value="' . vg_h($url) . '"' . ($current === $n ? ' selected' : '') . '>' . $n . '개씩 보기</option>';
    }
    echo '</select>';
}

/**
 * 페이지네이션 출력. 한 페이지에 다 들어가도 "N개씩 보기" 셀렉트는 남긴다
 * (큰 값을 고른 뒤 되돌릴 UI가 사라지지 않게). 최소 선택지 이하면 아예 생략.
 *   $pageParam·$perPageParam 은 한 화면에 페이지네이션 섹션이 여러 개일 때(cve.php) 서로
 *   다른 쿼리 파라미터를 써서 페이지 이동이 섞이지 않게 하기 위함. 기본값은 기존 'page'/'per_page'.
 */
function vg_page_nav(int $total, int $perPage, int $page, string $pageParam = 'page', string $perPageParam = 'per_page'): void {
    $totalPages = max(1, (int) ceil($total / $perPage));
    $options = vg_ui_per_page_options();
    if ($totalPages === 1 && $total <= $options[0]) {
        return;
    }
    if ($page < 1) { $page = 1; }
    if ($page > $totalPages) { $page = $totalPages; }

    if ($totalPages === 1) {   // 페이지 링크는 필요없고 개수 셀렉트만
        echo '<nav class="pager" aria-label="페이지 탐색"><span class="muted">· 총 ' . number_format($total) . '건</span>';
        vg_perpage_select($pageParam, $perPageParam);
        echo '</nav>';
        return;
    }

    // 표시할 페이지 번호: 처음, 현재 ±2, 끝
    $show = [1, $totalPages];
    for ($p = $page - 2; $p <= $page + 2; $p++) {
        if ($p >= 1 && $p <= $totalPages) { $show[] = $p; }
    }
    $show = array_values(array_unique($show));
    sort($show);

    echo '<nav class="pager" aria-label="페이지 탐색">';
    if ($page > 1) {
        echo '<a href="' . vg_h(vg_qs([$pageParam => $page - 1])) . '">‹ 이전</a>';
    } else {
        echo '<span class="muted">‹ 이전</span>';
    }
    $prev = 0;
    foreach ($show as $p) {
        if ($prev !== 0 && $p - $prev > 1) {
            echo '<span class="muted">…</span>';
        }
        if ($p === $page) {
            echo '<span class="cur" aria-current="page"><span class="sr-only">현재 페이지 </span>' . $p . '</span>';
        } else {
            echo '<a href="' . vg_h(vg_qs([$pageParam => $p])) . '">' . $p . '</a>';
        }
        $prev = $p;
    }
    if ($page < $totalPages) {
        echo '<a href="' . vg_h(vg_qs([$pageParam => $page + 1])) . '">다음 ›</a>';
    } else {
        echo '<span class="muted">다음 ›</span>';
    }
    echo '<span class="muted">· 총 ' . number_format($total) . '건 · ' . $page . '/' . $totalPages . '페이지</span>';
    vg_perpage_select($pageParam, $perPageParam);
    echo '</nav>';
}
