<?php
declare(strict_types=1);

/**
 * view.php — 공통 레이아웃(헤더/네비/푸터) + 테이블/툴바/페이지네이션 등 렌더 헬퍼.
 *   vg_h() 이스케이프, vg_header($title,$active) 로 시작, vg_footer() 로 끝.
 *   스타일·스크립트는 public/assets/app.{css,js} 가 소유한다. 여기에 색상을 하드코딩하지 않는다.
 *   순수 포맷 함수(뱃지·EPSS/리소스 셀·vg_trunc 등, side-effect 없음)는 format.php 에 있다.
 */

require __DIR__ . '/format.php';

/** 정적 파일 URL + 캐시버스팅(mtime). 파일이 없으면 경로만 돌려준다. */
function vg_asset(string $path): string {
    $file = __DIR__ . '/../public' . $path;
    $v = is_file($file) ? (string) filemtime($file) : '';
    return vg_h($path . ($v !== '' ? '?v=' . $v : ''));
}

/**
 * 심각도 도넛 (순수 SVG — 차트 라이브러리를 들이지 않는다).
 *   $counts: ['CRITICAL'=>3, 'HIGH'=>7, …]. 합이 0이면 회색 빈 링 + "0" 을 그린다.
 *
 * stroke-dasharray 로 원호를 그린다: 둘레를 100 으로 잡으면 dasharray 가 곧 퍼센트다.
 * 조각마다 dashoffset 을 누적해 이어 붙인다. 색은 CSS 변수(--crit 등)를 그대로 참조하므로
 * 팔레트를 바꾸면 도넛도 같이 바뀐다.
 */
function vg_sev_donut(array $counts, int $size = 132): void {
    $total = 0;
    foreach (VG_TONE_SEV as $sev => $tone) { $total += (int) ($counts[$sev] ?? 0); }

    $r = 15.9155;   // 둘레가 정확히 100 이 되는 반지름 (2πr = 100)
    echo '<div class="donut">';
    echo '<svg viewBox="0 0 42 42" width="' . $size . '" height="' . $size . '" role="img" aria-label="심각도 분포">';
    echo '<circle class="donut__track" cx="21" cy="21" r="' . $r . '" fill="none" stroke-width="4.5"></circle>';

    if ($total > 0) {
        $offset = 25;   // 12시 방향에서 시작(기본은 3시 방향)
        foreach (VG_TONE_SEV as $sev => $tone) {
            $n = (int) ($counts[$sev] ?? 0);
            if ($n === 0) { continue; }
            $pct = $n / $total * 100;
            echo '<circle class="donut__arc tone-' . $tone . '" cx="21" cy="21" r="' . $r . '"'
                . ' fill="none" stroke-width="4.5"'
                . ' stroke-dasharray="' . round($pct, 2) . ' ' . round(100 - $pct, 2) . '"'
                . ' stroke-dashoffset="' . round($offset, 2) . '">'
                . '<title>' . vg_h($sev . ' ' . $n . '건') . '</title></circle>';
            $offset -= $pct;   // 시계방향으로 이어 붙인다
        }
    }
    echo '</svg>';
    echo '<div class="donut__mid"><b>' . number_format($total) . '</b><span>전체</span></div>';
    echo '</div>';
}

/**
 * 심각도 추세 (누적 막대 — 순수 SVG. 도넛과 같은 톤 토큰을 쓴다).
 *   $days: [['d'=>'2026-07-14', 'counts'=>['CRITICAL'=>3,…]], …] — 날짜 오름차순.
 *   $sevs: 그릴 등급. 기본은 조치 대상 3종.
 *
 * 왜 누적 막대인가: 답해야 할 질문이 "나아지고 있나"라서 날짜별 총량과 그 안의 등급 구성이
 * 동시에 보여야 한다. CRITICAL 을 **바닥에** 깐다 — 기준선에 붙은 조각이 가장 읽기 쉽고,
 * 제일 급한 등급의 추세를 눈이 먼저 잡아야 하기 때문이다.
 * 조각 사이는 2px 를 띄워 배경색이 비치게 한다(등급 경계가 색만으로 구분되지 않게).
 *
 * LOW 는 기본에서 뺀다. 실측에서 LOW 2,198건 : CRITICAL 2건이라, 한 축에 같이 쌓으면
 * 정작 봐야 할 CRITICAL·HIGH 가 1px 실선이 된다(스케일이 다른 계열을 한 축에 쌓지 않는다).
 * 전체 구성은 옆의 도넛이 그대로 보여준다.
 */
function vg_sev_trend(array $days, array $sevs = ['CRITICAL', 'HIGH', 'MEDIUM']): void {
    $tones = array_intersect_key(VG_TONE_SEV, array_flip($sevs));
    $tot = static fn(array $c): int => array_sum(array_map(
        static fn($s) => (int) ($c[$s] ?? 0), array_keys($tones)
    ));
    $max = 0;
    foreach ($days as $d) { $max = max($max, $tot($d['counts'])); }

    if (!$days || $max === 0) {
        vg_empty(['icon' => '📈', 'title' => '추세를 그릴 스캔이 없습니다.',
                  'hint'  => '에이전트가 두 번 이상 수집하면 여기에 변화가 쌓입니다.']);
        return;
    }

    // 논리 좌표(px). CSS 가 width:100% 로 늘려도 비율은 유지된다.
    $W = 720; $H = 190;
    $padL = 36; $padR = 8; $padT = 12; $padB = 26;
    $plotW = $W - $padL - $padR;
    $plotH = $H - $padT - $padB;
    $n = count($days);
    $colW = $plotW / $n;
    $barW = min(30.0, $colW * 0.62);   // 얇은 마크 — 열을 꽉 채우지 않는다
    $gap  = 2;                          // 조각 사이 배경이 비치는 틈

    // 눈금은 3줄(0·중간·최대)이면 충분하다. 최대는 보기 좋은 수로 올림.
    $step = (int) max(1, 10 ** max(0, (int) floor(log10(max(1, $max))) - 1));
    $top  = (int) (ceil($max / $step) * $step);

    echo '<div class="chart">';
    echo '<svg viewBox="0 0 ' . $W . ' ' . $H . '" role="img" aria-label="최근 ' . $n . '일 심각도 추세">';

    // 눈금선·눈금값 — 뒤로 물러나 있어야 한다(데이터가 주인공).
    foreach ([0, 0.5, 1] as $f) {
        $y = $padT + $plotH * (1 - $f);
        echo '<line class="chart__grid" x1="' . $padL . '" y1="' . round($y, 1) . '"'
            . ' x2="' . ($W - $padR) . '" y2="' . round($y, 1) . '"></line>';
        echo '<text class="chart__tick" x="' . ($padL - 6) . '" y="' . round($y + 3.5, 1) . '">'
            . number_format((int) round($top * $f)) . '</text>';
    }

    foreach ($days as $i => $day) {
        $x = $padL + $colW * $i + ($colW - $barW) / 2;
        $y = $padT + $plotH;   // 바닥에서 위로 쌓는다
        foreach ($tones as $sev => $tone) {   // CRITICAL 부터: 급한 게 바닥
            $v = (int) ($day['counts'][$sev] ?? 0);
            if ($v === 0) { continue; }
            $h = $v / $top * $plotH;
            $y -= $h;
            $drawH = max(1.5, $h - $gap);          // 틈만큼 줄여 그린다(조각이 붙지 않게)
            echo '<rect class="chart__seg tone-' . $tone . '" rx="2"'
                . ' x="' . round($x, 1) . '" y="' . round($y, 1) . '"'
                . ' width="' . round($barW, 1) . '" height="' . round($drawH, 1) . '">'
                . '<title>' . vg_h($day['d'] . ' · ' . $sev . ' ' . number_format($v) . '건') . '</title>'
                . '</rect>';
        }
        // 날짜는 하나 걸러 하나만 — 14개를 다 쓰면 글자가 겹친다. 마지막 날은 항상 쓴다.
        if ($i % 2 === 1 || $i === $n - 1) {
            echo '<text class="chart__lbl" x="' . round($x + $barW / 2, 1) . '" y="' . ($H - 8) . '">'
                . vg_h(date('n/j', strtotime($day['d']))) . '</text>';
        }
    }
    echo '</svg></div>';
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
function vg_perpage(int $default = VG_PERPAGE_DEFAULT): int {
    $v = (int) ($_GET['per_page'] ?? $default);
    return in_array($v, VG_PERPAGE_OPTIONS, true) ? $v : $default;
}

// "페이지당 N개" 셀렉트. onchange 시 현재 쿼리스트링 유지한 채 per_page 변경 + page=1 로 이동.
//   data-nav 는 app.js 가 이동 시작을 알아채 상단 진행바를 띄우는 표식이다.
function vg_perpage_select(): void {
    $current = vg_perpage();
    echo '<select data-nav onchange="location.href=this.value" aria-label="페이지당 표시 개수">';
    foreach (VG_PERPAGE_OPTIONS as $n) {
        $url = vg_qs(['per_page' => $n, 'page' => 1]);
        echo '<option value="' . vg_h($url) . '"' . ($current === $n ? ' selected' : '') . '>' . $n . '개씩 보기</option>';
    }
    echo '</select>';
}

/**
 * 페이지네이션 출력. 한 페이지에 다 들어가도 "N개씩 보기" 셀렉트는 남긴다
 * (큰 값을 고른 뒤 되돌릴 UI가 사라지지 않게). 최소 선택지 이하면 아예 생략.
 */
function vg_page_nav(int $total, int $perPage, int $page): void {
    $totalPages = max(1, (int) ceil($total / $perPage));
    if ($totalPages === 1 && $total <= VG_PERPAGE_OPTIONS[0]) {
        return;
    }
    if ($page < 1) { $page = 1; }
    if ($page > $totalPages) { $page = $totalPages; }

    if ($totalPages === 1) {   // 페이지 링크는 필요없고 개수 셀렉트만
        echo '<div class="pager"><span class="muted">· 총 ' . number_format($total) . '건</span>';
        vg_perpage_select();
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
        echo '<a href="' . vg_h(vg_qs(['page' => $page - 1])) . '">‹ 이전</a>';
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
            echo '<a href="' . vg_h(vg_qs(['page' => $p])) . '">' . $p . '</a>';
        }
        $prev = $p;
    }
    if ($page < $totalPages) {
        echo '<a href="' . vg_h(vg_qs(['page' => $page + 1])) . '">다음 ›</a>';
    } else {
        echo '<span class="muted">다음 ›</span>';
    }
    echo '<span class="muted">· 총 ' . number_format($total) . '건 · ' . $page . '/' . $totalPages . '페이지</span>';
    vg_perpage_select();
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
        $style = '';
        if ($align && $align !== 'left') { $style .= 'text-align:' . $align . ';'; }
        if ($width) { $style .= 'width:' . $width . ';'; }
        echo '<th' . ($style !== '' ? ' style="' . vg_h($style) . '"' : '') . '>' . vg_h($label) . '</th>';
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
            $style = ($align && $align !== 'left') ? ' style="text-align:' . vg_h($align) . ';"' : '';
            echo '<td' . ($nowrap ? ' class="nowrap"' : '') . $style . '>' . $html . '</td>';
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

/**
 * 사이드바 메뉴(라벨 SSOT). 대분류(섹션 라벨) → 중분류(링크) 2단.
 *   섹션 라벨이 '' 이면 라벨 없이 링크만 렌더한다(대시보드처럼 단독 항목).
 *   각 링크의 'perm' 은 vg_can() 메뉴코드, 'key' 는 vg_header($active) 와 맞춘다.
 *   'perm' 은 vg_menus() 의 코드와 반드시 일치해야 한다 — 어긋나면 사이드바에 보이는데
 *   눌러보면 403 나는 링크가 생긴다. 단, findings 처럼 코드 하나가 링크 둘을 열 수 있다.
 */
function vg_nav_sections(): array {
    return [
        '' => [
            ['perm' => 'dashboard', 'href' => '/', 'label' => '대시보드', 'key' => 'dashboard'],
        ],
        '취약점' => [
            ['perm' => 'findings',   'href' => '/findings.php',   'label' => '취약점 현황',   'key' => 'findings'],
            ['perm' => 'findings',   'href' => '/changes.php',    'label' => '변화 추적',     'key' => 'changes'],
            ['perm' => 'findings',   'href' => '/cves.php',       'label' => 'CVE 목록',      'key' => 'cves'],
            ['perm' => 'findings',   'href' => '/packages.php',   'label' => '영향 패키지',   'key' => 'packages'],
            ['perm' => 'advisories', 'href' => '/advisories.php', 'label' => '국내 보안공지', 'key' => 'advisories'],
        ],
        '자산' => [
            ['perm' => 'assets', 'href' => '/assets.php', 'label' => '자산 관리', 'key' => 'assets'],
        ],
        '수집' => [
            ['perm' => 'connectors', 'href' => '/connectors.php', 'label' => '피드 커넥터', 'key' => 'connectors'],
        ],
        '시스템' => [
            ['perm' => 'users',       'href' => '/users.php',        'label' => '사용자',      'key' => 'users'],
            ['perm' => 'permissions', 'href' => '/permissions.php',  'label' => '권한 설정',   'key' => 'permissions'],
            ['perm' => 'agenttokens', 'href' => '/agent-tokens.php', 'label' => '에이전트 토큰', 'key' => 'agenttokens'],
            ['perm' => 'apitokens',   'href' => '/api-tokens.php',   'label' => 'API 토큰',    'key' => 'apitokens'],
            ['perm' => 'activity',    'href' => '/activity.php',     'label' => '감사 로그',   'key' => 'activity'],
        ],
    ];
}

/**
 * 사이드바 메뉴 아이콘 — 단색 라인 SVG. stroke=currentColor 라 링크 색을 그대로
 * 상속한다(테마·활성 상태에 자동으로 따라간다). key 는 vg_nav_sections() 의 것과 맞춘다.
 * 이미 이스케이프가 필요 없는 정적 마크업이라 그대로 돌려준다.
 */
function vg_nav_icon(string $key): string {
    static $paths = [
        'dashboard'   => '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/>',
        'findings'    => '<path d="m10.29 3.86-8.4 14.55A2 2 0 0 0 3.62 21h16.76a2 2 0 0 0 1.73-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
        'changes'     => '<polyline points="22 7 13.5 15.5 8.5 10.5 2 17"/><polyline points="16 7 22 7 22 13"/>',
        'cves'        => '<line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/>',
        'packages'    => '<path d="M21 8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22" x2="12" y2="12"/>',
        'advisories'  => '<path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10.3 21a1.94 1.94 0 0 0 3.4 0"/>',
        'assets'      => '<rect x="2" y="3" width="20" height="8" rx="2"/><rect x="2" y="13" width="20" height="8" rx="2"/><line x1="6" y1="7" x2="6.01" y2="7"/><line x1="6" y1="17" x2="6.01" y2="17"/>',
        'connectors'  => '<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>',
        'users'       => '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>',
        'permissions' => '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
        'agenttokens' => '<path d="M2 9a3 3 0 0 1 0 6v2a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-2a3 3 0 0 1 0-6V7a2 2 0 0 0-2-2H4a2 2 0 0 0-2 2z"/><line x1="13" y1="5" x2="13" y2="19"/>',
        'apitokens'   => '<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>',
        'activity'    => '<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>',
    ];
    $p = $paths[$key] ?? '<circle cx="12" cy="12" r="9"/>';
    return '<svg class="ico" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor"'
        . ' stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' . $p . '</svg>';
}

// 사이드바 렌더. 권한 없는 링크는 빼고, 링크가 하나도 안 남은 섹션은 라벨째 숨긴다.
function vg_nav(string $active): void {
    foreach (vg_nav_sections() as $section => $links) {
        $visible = array_filter($links, fn($l) => vg_can($l['perm']));
        if (!$visible) {
            continue;
        }
        if ($section !== '') {
            echo '<div class="grp">' . vg_h($section) . '</div>';
        }
        foreach ($visible as $l) {
            $cls = 'link' . ($active === $l['key'] ? ' active' : '');
            echo '<a class="' . $cls . '" href="' . vg_h($l['href']) . '">'
                . vg_nav_icon($l['key']) . '<span>' . vg_h($l['label']) . '</span></a>';
        }
    }
}

/**
 * 상단바 브레드크럼 — "지금 어디" 를 사이드바 밖에서 한 줄로. 홈 › 섹션 › 현재.
 *   active 키로 vg_nav_sections() 에서 소속 섹션·라벨을 찾는다. 네비에 없는 상세
 *   페이지(cve·advisory·host 등)는 섹션을 못 찾으니 제목($title)을 잎으로 쓴다.
 */
function vg_breadcrumb(string $active, string $title): void {
    $section = null;
    $label = null;
    foreach (vg_nav_sections() as $sec => $links) {
        foreach ($links as $l) {
            if ($l['key'] === $active) { $section = $sec; $label = $l['label']; break 2; }
        }
    }
    $leaf = $label ?? $title;
    echo '<nav class="crumbs" aria-label="위치">';
    echo '<a href="/">홈</a>';
    if ($section !== null && $section !== '') {
        echo '<span class="sep">›</span><span>' . vg_h($section) . '</span>';
    }
    echo '<span class="sep">›</span><span class="cur">' . vg_h($leaf) . '</span>';
    echo '</nav>';
}

function vg_header(string $title, string $active = ''): void {
    $user = function_exists('vg_current_user') ? vg_current_user() : null;
    ?>
<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= vg_h($title) ?> · vuln-agent</title>
<?php // 테마 초기화 — 저장된 선택(없으면 OS 설정)을 첫 페인트 전에 적용해 깜빡임을 막는다.
      //   defer 되는 app.js 로는 늦다(스타일이 먼저 그려진다). 그래서 인라인·즉시 실행. ?>
<script>(function(){try{var t=localStorage.getItem('vg-theme');if(t!=='dark'&&t!=='light'){t=window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light';}document.documentElement.setAttribute('data-theme',t);}catch(e){}})();</script>
<link rel="stylesheet" href="<?= vg_asset('/assets/app.css') ?>">
<script src="<?= vg_asset('/assets/app.js') ?>" defer></script>
<?php
// 페이지 전용 JS: 공용 app.js 뒤에, 이 페이지와 같은 이름의 assets/js/<페이지>.js 가 있으면
//   자동으로 붙는다(예: connectors.php → assets/js/connectors.js). 없으면 아무것도 안 붙는다.
//   공용 동작은 app.js 가, 한 화면에서만 쓰는 동작은 동일명 파일이 갖는다.
$pageJs = basename((string) ($_SERVER['SCRIPT_NAME'] ?? ''), '.php');
if ($pageJs !== '' && is_file(__DIR__ . "/../public/assets/js/{$pageJs}.js")): ?>
<script src="<?= vg_asset("/assets/js/{$pageJs}.js") ?>" defer></script>
<?php endif; ?>
</head>
<body>
<?php if ($user !== null): ?>
  <aside class="side">
    <?php if (vg_can('dashboard')): ?>
      <a class="brand" href="/" title="대시보드로 이동">🛡️ vuln-agent</a>
    <?php else: ?>
      <span class="brand">🛡️ vuln-agent</span>
    <?php endif; ?>
    <nav class="menu"><?php vg_nav($active); ?></nav>
    <div class="foot">
      <span class="who"><?= vg_h($user['username']) ?> (<?= vg_h(vg_role_label(vg_role())) ?>)</span>
      <a href="/profile.php"<?= $active === 'profile' ? ' class="active"' : '' ?>>내 프로필</a>
      <a href="/logout.php">로그아웃</a>
    </div>
  </aside>
<?php endif; ?>
<div class="app">
<?php if ($user !== null): ?>
  <header class="topbar">
    <?php vg_breadcrumb($active, $title); ?>
    <div class="topbar__right">
      <div class="seg" role="group" aria-label="테마 전환">
        <button type="button" class="seg__btn" data-theme-set="light" aria-label="밝은 테마">☀ Light</button>
        <button type="button" class="seg__btn" data-theme-set="dark" aria-label="어두운 테마">☾ Dark</button>
      </div>
      <?php // 사용자 칩 — 아바타(아이디 첫 글자) + 이름·역할. 누르면 내 프로필로. ?>
      <a class="topbar__user" href="/profile.php" title="내 프로필">
        <span class="avatar"><?= vg_h(mb_strtoupper(mb_substr($user['username'], 0, 1))) ?></span>
        <span class="topbar__who"><?= vg_h($user['username']) ?><i><?= vg_h(vg_role_label(vg_role())) ?></i></span>
      </a>
    </div>
  </header>
<?php endif; ?>
<main>
<?php
}

function vg_footer(): void {
    ?>
</main>
</div>
</body>
</html>
<?php
}
