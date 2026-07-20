<?php
declare(strict_types=1);

/**
 * components.php — 페이지가 공유하는 위젯 컴포넌트: 복사버튼·모달·히어로·서브탭·빈상태·알림,
 *   그리고 목록 화면 공통부(쿼리스트링·페이지네이션·테이블·툴바)까지.
 */

require_once __DIR__ . '/../format.php';

/**
 * 클립보드 복사 버튼. JS 가 죽어도 값 자체는 화면에 그대로 있으므로(선택해서 복사 가능)
 * 이 버튼은 편의일 뿐 필수 경로가 아니다 — 그래서 <button type=button>.
 */
function vg_copy_btn(string $text, string $label = '복사'): void {
    echo '<button type="button" class="btn btn--sm btn--ghost copy" data-copy="' . vg_h($text) . '">'
        . vg_h($label) . '</button>';
}

/**
 * 모달 — 자주 안 쓰는 폼(추가·발급·설치안내)을 화면에 펼쳐두지 않고 버튼 뒤에 숨긴다.
 *
 * 네이티브 <dialog> 를 쓴다. showModal() 이 포커스 가둠·ESC 닫기·backdrop 을 다 해주므로
 * 라이브러리도, 직접 만든 포커스 트랩도 필요 없다(KISS).
 *   vg_modal_btn('addUser', '+ 사용자 추가');      ← 여는 버튼
 *   vg_modal_open('addUser', '사용자 추가');       ← <dialog> 시작
 *     … 폼 내용 …
 *   vg_modal_close();                              ← </dialog>
 *
 * 주의: 모달 안의 폼은 서버로 POST 하는 평범한 폼이다. JS 가 죽어도 내용은 DOM 에 있고,
 *       열기 버튼만 안 먹는다 — 그래서 열기 버튼은 <button> 이지 <a> 가 아니다.
 */
function vg_modal_btn(string $target, string $label, string $class = 'btn btn--sm btn--primary'): void {
    echo '<button type="button" class="' . vg_h($class) . '" data-modal="' . vg_h($target) . '">'
        . vg_h($label) . '</button>';
}

/**
 * $open=true 면 페이지가 뜨자마자 이 모달을 연다. 모달 안의 폼이 서버 검증에 걸리면
 * 페이지가 다시 그려지며 모달이 닫혀 버린다 — 사용자는 뭐가 틀렸는지 못 보고 입력도 잃는다.
 *
 * <dialog open> 속성을 쓰지 않는 건, 그건 backdrop 없는 인라인 표시라서 "모달" 이 아니기 때문이다.
 * data-modal-autoopen 을 달아 app.js 가 showModal() 을 부르게 한다.
 */
function vg_modal_open(string $id, string $title, string $class = '', bool $open = false): void {
    echo '<dialog class="modal ' . vg_h($class) . '" id="' . vg_h($id) . '"'
        . ($open ? ' data-modal-autoopen' : '') . '>'
        . '<div class="modal__head">'
        . '<strong>' . vg_h($title) . '</strong>'
        . '<button type="button" class="modal__x" data-modal-close aria-label="닫기">✕</button>'
        . '</div>'
        . '<div class="modal__body">';
}

/**
 * 모달 푸터 — 주작업/닫기를 **오른쪽 아래**에 모은다(모든 모달 통일). 폼 모달은 폼 안
 * 맨 끝에서 부른다(제출 버튼이 그 폼에 속해야 하므로). 정보 모달은 $submit=null 로 닫기만.
 *   $submit : 주작업 라벨(저장·추가·발급…). null 이면 닫기 버튼만.
 *   $opts   : tone(주작업 톤, 기본 primary) · loading(제출 중 문구) · cancel(닫기 라벨) ·
 *             extra(왼쪽에 붙일 보조 버튼 HTML — 이미 이스케이프됨, 예: 미리보기)
 * 버튼 크기는 손대지 않는다 → 기본 .btn(중간) 하나로 모든 모달이 같은 크기·정렬을 갖는다.
 */
function vg_modal_foot(?string $submit = '저장', array $opts = []): void {
    echo '<div class="modal__foot">';
    if (!empty($opts['extra'])) {
        echo '<div class="modal__foot__extra">' . $opts['extra'] . '</div>';
    }
    echo '<button type="button" class="btn btn--ghost" data-modal-close>' . vg_h((string) ($opts['cancel'] ?? '닫기')) . '</button>';
    if ($submit !== null) {
        $tone = (string) ($opts['tone'] ?? 'primary');
        $ld   = !empty($opts['loading']) ? ' data-loading="' . vg_h((string) $opts['loading']) . '"' : '';
        echo '<button type="submit" class="btn btn--' . vg_h($tone) . '"' . $ld . '>' . vg_h($submit) . '</button>';
    }
    echo '</div>';
}

function vg_modal_close(): void {
    echo '</div></dialog>';
}

/**
 * POST 처리 결과를 세션에 담고 같은 URL 로 303 리다이렉트한다(PRG).
 *   POST 응답을 그대로 그리면 새로고침이 POST 를 재전송한다 — 토큰 발급 화면에선
 *   새로고침 한 번이 방금 받은 토큰을 폐기하고 또 발급해 버렸다.
 *   출력 전에 부른다. 되돌아오지 않는다.
 */
function vg_redirect_flash(array $flash): void {
    $_SESSION['vg_flash'] = $flash;
    // REQUEST_URI 는 raw(미디코딩)라 개행이 들어올 수 없지만, 헤더 분리는 값싸게 막는다.
    $uri = preg_replace('/[\r\n].*$/s', '', (string) ($_SERVER['REQUEST_URI'] ?? '/'));
    header('Location: ' . ($uri === '' ? '/' : $uri), true, 303);
    exit;
}

/** 직전 POST 가 남긴 결과를 꺼내며 지운다(1회용). 없으면 빈 배열. */
function vg_flash_take(): array {
    $f = $_SESSION['vg_flash'] ?? null;
    unset($_SESSION['vg_flash']);
    return is_array($f) ? $f : [];
}

/** 성공/오류 알림. $msg 가 null·빈문자면 아무것도 출력하지 않는다. */
function vg_alert(?string $msg, string $type = 'err'): void {
    if ($msg === null || $msg === '') {
        return;
    }
    echo '<div class="alert alert--' . ($type === 'ok' ? 'ok' : 'err') . '">' . vg_h($msg) . '</div>';
}

/**
 * 빈 상태. "데이터가 없습니다" 한 줄은 막다른 길이라, 왜 비었는지와 다음 행동을 준다.
 *   문자열을 주면 기존처럼 한 줄만 출력(하위호환 — 대부분의 vg_table 호출이 이 형태).
 *   배열을 주면 아이콘·제목·힌트·행동버튼까지: ['icon'=>'🔍','title'=>…,'hint'=>…,'cta'=>['href'=>…,'label'=>…]]
 */
function vg_empty($spec): void {
    if (!is_array($spec)) {
        echo '<div class="empty">' . vg_h((string) $spec) . '</div>';
        return;
    }
    echo '<div class="empty">';
    if (!empty($spec['icon'])) {
        echo '<span class="empty__icon" aria-hidden="true">' . vg_h((string) $spec['icon']) . '</span>';
    }
    echo '<span class="empty__title">' . vg_h((string) ($spec['title'] ?? '데이터가 없습니다.')) . '</span>';
    if (!empty($spec['hint'])) {
        echo '<span class="empty__hint">' . vg_h((string) $spec['hint']) . '</span>';
    }
    if (!empty($spec['cta']['href'])) {
        echo '<a class="btn btn--sm btn--primary" href="' . vg_h((string) $spec['cta']['href']) . '">'
            . vg_h((string) ($spec['cta']['label'] ?? '이동')) . '</a>';
    }
    echo '</div>';
}

/**
 * 상세 페이지 히어로 — "무엇을 보고 있나(좌) + 얼마나 위험한가(우)".
 * 왼쪽 띠 색이 위험도다. host.php 가 인라인으로 갖고 있던 것을 공용으로 뺐다.
 *   $title·$meta 는 이미 이스케이프된 HTML (호출부가 vg_h 책임 — 링크·뱃지를 섞어 넣어야 해서).
 *   $riskLabel 이 null 이면 위험도 칸 없이 식별부만.
 *   $riskTone 은 톤 어휘(crit/high/med/low/ok/muted). 라벨과 톤을 분리한 건 "양호" 처럼
 *   심각도 어휘에 없는 라벨을 써야 할 때가 있기 때문이다(vg_sev_tone 은 그걸 muted 로 떨군다).
 */
function vg_hero(string $title, array $meta = [], ?string $riskLabel = null, string $riskTone = 'ok', string $riskCap = '최고 위험도'): void {
    echo '<div class="hero hero--' . vg_h($riskLabel !== null ? $riskTone : 'ok') . '">';
    echo '<div class="hero__id"><h1>' . $title . '</h1>';
    if ($meta) {
        echo '<div class="hero__meta">' . implode(' <span class="why">·</span> ', $meta) . '</div>';
    }
    echo '</div>';
    if ($riskLabel !== null) {
        echo '<div class="hero__risk"><span class="badge tone-' . vg_h($riskTone) . ' badge--lg">' . vg_h($riskLabel) . '</span>'
            . '<span class="cap">' . vg_h($riskCap) . '</span></div>';
    }
    echo '</div>';
}

/**
 * 섹션 탭(밑줄형). 첫 화면에 다 쏟지 않고 갈래로 나눠 담는 자리.
 *   $tabs: ['vuln' => ['label'=>'취약점', 'n'=>12], 'runtime' => ['label'=>'런타임', 'n'=>null], …]
 *   'n' 이 null 이 아니면 라벨 옆에 건수를 붙인다. 탭 전환은 ?tab= + page 초기화.
 */
function vg_subtabs(array $tabs, string $active): void {
    echo '<nav class="subtabs">';
    foreach ($tabs as $key => $def) {
        $cls = $active === (string) $key ? ' class="on"' : '';
        echo '<a' . $cls . ' href="' . vg_h(vg_qs(['tab' => $key, 'page' => null])) . '">'
            . vg_h((string) ($def['label'] ?? $key));
        if (($def['n'] ?? null) !== null) {
            echo '<span class="n">' . number_format((int) $def['n']) . '</span>';
        }
        echo '</a>';
    }
    echo '</nav>';
}

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

// 페이지당 표시 개수 선택지(SSOT). vg_perpage / vg_perpage_select 가 공유한다.
const VG_PERPAGE_OPTIONS = [10, 20, 40, 60, 100];
const VG_PERPAGE_DEFAULT = 10;

// 페이지당 표시 개수. ?per_page= 를 화이트리스트로 검증해 반환. 잘못된 값이면 $default.
//   $param 은 한 화면에 페이지네이션 섹션이 여러 개일 때 서로 다른 쿼리 파라미터를 쓰기 위함
//   (예: cve.php 의 벤더 판정=vper_page, 영향 패키지=aper_page, 발견 위치=per_page).
function vg_perpage(int $default = VG_PERPAGE_DEFAULT, string $param = 'per_page'): int {
    $v = (int) ($_GET[$param] ?? $default);
    return in_array($v, VG_PERPAGE_OPTIONS, true) ? $v : $default;
}

// 현재 페이지 번호. ?page= 를 정수로 파싱해 1 미만이면 1로 올린다.
function vg_page(string $param = 'page'): int {
    return max(1, (int) ($_GET[$param] ?? 1));
}

// "페이지당 N개" 셀렉트. onchange 시 현재 쿼리스트링 유지한 채 per_page 변경 + page=1 로 이동.
//   data-nav 는 app.js 가 이동 시작을 알아채 상단 진행바를 띄우는 표식이다.
function vg_perpage_select(string $pageParam = 'page', string $perPageParam = 'per_page'): void {
    $current = vg_perpage(VG_PERPAGE_DEFAULT, $perPageParam);
    echo '<select data-nav onchange="location.href=this.value" aria-label="페이지당 표시 개수">';
    foreach (VG_PERPAGE_OPTIONS as $n) {
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
    if ($totalPages === 1 && $total <= VG_PERPAGE_OPTIONS[0]) {
        return;
    }
    if ($page < 1) { $page = 1; }
    if ($page > $totalPages) { $page = $totalPages; }

    if ($totalPages === 1) {   // 페이지 링크는 필요없고 개수 셀렉트만
        echo '<div class="pager"><span class="muted">· 총 ' . number_format($total) . '건</span>';
        vg_perpage_select($pageParam, $perPageParam);
        echo '</div>';
        return;
    }

    // 표시할 페이지 번호: 처음, 현재 ±2, 끝
    $show = [1, $totalPages];
    for ($p = $page - 2; $p <= $page + 2; $p++) {
        if ($p >= 1 && $p <= $totalPages) { $show[] = $p; }
    }
    $show = array_values(array_unique($show));
    sort($show);

    echo '<div class="pager">';
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
            echo '<span class="cur">' . $p . '</span>';
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
    echo '</div>';
}

/**
 * 카드+테이블 렌더 (DRY — 각 페이지가 반복하던 <div class="card"><table>… 마크업 통합).
 *   $headers: [['label'=>'등급','align'=>'left'|'right'|'center','width'=>'80px','key'=>'severity'], ...]
 *     'key' 는 콜백이 없을 때 $row[key] 를 자동 이스케이프해서 출력하는 데 쓰인다(없으면 빈칸).
 *   $opts['cell']: 컬럼 인덱스(0,1,2…) 또는 header 의 'key' → function($row): string.
 *     콜백 반환값은 이미 이스케이프된 HTML 이라는 규약(콜백 안에서 vg_h 책임).
 *   $opts['empty']: 빈 목록 메시지(문자열) 또는 vg_empty() 의 배열 스펙.
 *   $opts['row_class']: function($row): string — <tr> 에 붙일 클래스.
 *     심각도 행 강조는 vg_sev_row() 를 그대로 넘기면 된다: 'row_class' => 'vg_sev_row'.
 *   $opts['card']: 카드 래핑 여부(기본 true). $opts['class']: <table> 에 추가할 클래스.
 */
function vg_table(array $headers, array $rows, array $opts = []): void {
    $card     = $opts['card'] ?? true;
    $class    = $opts['class'] ?? '';
    $cell     = $opts['cell'] ?? [];
    $empty    = $opts['empty'] ?? '데이터가 없습니다.';
    $rowClass = $opts['row_class'] ?? null;

    if ($card) { echo '<div class="card">'; }

    if (!$rows) {
        vg_empty($empty);
        if ($card) { echo '</div>'; }
        return;
    }

    echo '<table' . ($class !== '' ? ' class="' . vg_h($class) . '"' : '') . '>';
    echo '<thead><tr>';
    foreach ($headers as $h) {
        $label = is_array($h) ? (string) ($h['label'] ?? '') : (string) $h;
        $align = is_array($h) ? ($h['align'] ?? null) : null;
        $width = is_array($h) ? ($h['width'] ?? null) : null;
        $style = $width ? ' style="width:' . vg_h($width) . ';"' : '';
        $thClass = ($align === 'right') ? ' class="right"' : (($align === 'center') ? ' class="center"' : '');
        echo '<th' . $thClass . $style . '>' . vg_h($label) . '</th>';
    }
    echo '</tr></thead><tbody>';
    foreach ($rows as $row) {
        $rc = $rowClass !== null ? (string) $rowClass($row) : '';
        echo $rc !== '' ? '<tr class="' . vg_h($rc) . '">' : '<tr>';
        foreach (array_values($headers) as $i => $h) {
            $key   = is_array($h) ? ($h['key'] ?? null) : null;
            $align = is_array($h) ? ($h['align'] ?? null) : null;
            $cb    = $cell[$i] ?? ($key !== null ? ($cell[$key] ?? null) : null);
            if ($cb) {
                $html = $cb($row);
            } elseif ($key !== null) {
                $html = vg_h((string) ($row[$key] ?? ''));
            } else {
                $html = '';
            }
            $nowrap = is_array($h) && !empty($h['nowrap']);
            $tdClasses = [];
            if ($nowrap) { $tdClasses[] = 'nowrap'; }
            if ($align === 'right') { $tdClasses[] = 'right'; }
            elseif ($align === 'center') { $tdClasses[] = 'center'; }
            $tdClass = $tdClasses ? ' class="' . vg_h(implode(' ', $tdClasses)) . '"' : '';
            echo '<td' . $tdClass . '>' . $html . '</td>';
        }
        echo '</tr>';
    }
    echo '</tbody></table>';
    if ($card) { echo '</div>'; }
}

/**
 * GET 검색/필터 툴바(class="toolbar"). 값이 있으면 제출버튼 옆에 초기화 링크 자동 표시.
 *   $fields 각 항목: ['type'=>'search'|'select'|'hidden', 'name'=>, 'value'=>, 'placeholder'=>,
 *                     'options'=>['값'=>'라벨'], 'selected'=>, 'empty_label'=>'전체']
 *   per_page 는 이 폼의 입력이 아니므로 hidden 으로 실어 보낸다 —
 *   안 그러면 "100개씩 보기" 상태에서 검색할 때마다 기본값으로 돌아간다.
 */
function vg_toolbar(array $fields): void {
    $resetOverrides = ['page' => null];
    $hasValue = false;

    echo '<form class="toolbar" method="get">';

    $perPage = vg_perpage();
    if ($perPage !== VG_PERPAGE_DEFAULT) {
        echo '<input type="hidden" name="per_page" value="' . $perPage . '">';
    }

    foreach ($fields as $f) {
        $type = $f['type'] ?? 'search';
        $name = (string) ($f['name'] ?? '');
        $value = (string) ($f['value'] ?? '');

        if ($type === 'hidden') {
            echo '<input type="hidden" name="' . vg_h($name) . '" value="' . vg_h($value) . '">';
            continue;
        }

        if ($type === 'search') {
            $ph = (string) ($f['placeholder'] ?? '');
            echo '<input type="search" name="' . vg_h($name) . '" placeholder="' . vg_h($ph) . '" value="' . vg_h($value) . '">';
            if ($value !== '') { $hasValue = true; }
            $resetOverrides[$name] = null;
        } elseif ($type === 'select') {
            $options  = $f['options'] ?? [];
            $selected = (string) ($f['selected'] ?? '');
            $emptyLabel = (string) ($f['empty_label'] ?? '전체');
            // data-autosubmit: 고르는 즉시 폼 제출(app.js). JS 가 없으면 검색 버튼이 그대로 동작한다.
            echo '<select name="' . vg_h($name) . '" data-autosubmit>';
            echo '<option value="">' . vg_h($emptyLabel) . '</option>';
            foreach ($options as $val => $label) {
                $val = (string) $val;
                echo '<option value="' . vg_h($val) . '"' . ($selected === $val ? ' selected' : '') . '>' . vg_h((string) $label) . '</option>';
            }
            echo '</select>';
            if ($selected !== '') { $hasValue = true; }
            $resetOverrides[$name] = null;
        }
    }
    echo '<button type="submit" class="btn btn--sm btn--primary" data-loading="검색 중…">검색</button>';
    if ($hasValue) {
        echo '<a class="btn btn--sm btn--ghost" href="' . vg_h(vg_qs($resetOverrides)) . '">초기화</a>';
    }
    echo '</form>';
}
