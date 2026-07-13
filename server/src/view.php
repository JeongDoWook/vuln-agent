<?php
declare(strict_types=1);

/**
 * view.php — 공통 레이아웃(헤더/네비/푸터) + 렌더 헬퍼.
 *   vg_h() 이스케이프, vg_header($title,$active) 로 시작, vg_footer() 로 끝.
 *   스타일·스크립트는 public/assets/app.{css,js} 가 소유한다. 여기에 색상을 하드코딩하지 않는다.
 */

function vg_h(?string $s): string {
    return htmlspecialchars((string) $s, ENT_QUOTES, 'UTF-8');
}

/** 정적 파일 URL + 캐시버스팅(mtime). 파일이 없으면 경로만 돌려준다. */
function vg_asset(string $path): string {
    $file = __DIR__ . '/../public' . $path;
    $v = is_file($file) ? (string) filemtime($file) : '';
    return vg_h($path . ($v !== '' ? '?v=' . $v : ''));
}

/* --- 톤 어휘 --------------------------------------------------------------
 * 색은 CSS 의 .tone-* 이 정한다. PHP 는 "어떤 톤인가" 만 고른다.
 * 뱃지를 쓰는 모든 화면(심각도·런타임상태·피드상태·노출범위·자산상태)이 이 어휘를 공유한다. */

const VG_TONE_SEV = ['CRITICAL' => 'crit', 'HIGH' => 'high', 'MEDIUM' => 'med', 'LOW' => 'low'];

/** 임의의 라벨을 톤 뱃지로. $label 은 여기서 이스케이프한다. */
function vg_badge(string $label, string $tone = 'muted', string $title = ''): string {
    return '<span class="badge tone-' . vg_h($tone) . '"'
        . ($title !== '' ? ' title="' . vg_h($title) . '"' : '')
        . '>' . vg_h($label) . '</span>';
}

/** 심각도(CRITICAL/HIGH/MEDIUM/LOW) 뱃지. */
function vg_sev_badge(string $sev): string {
    return vg_badge($sev, vg_sev_tone($sev));
}

/** 심각도 → 톤 클래스명. KPI 카드도 같은 톤을 쓴다. */
function vg_sev_tone(string $sev): string {
    return VG_TONE_SEV[$sev] ?? 'muted';
}

/* CVSS 기본점수 → 심각도 구간(NVD v3 기준). cves.php 에만 있었는데 cve.php 도 쓰게 돼 공용으로. */
const VG_SEV_RANGES = [
    'critical' => [9.0, 10.0],
    'high'     => [7.0, 8.9],
    'medium'   => [4.0, 6.9],
    'low'      => [0.1, 3.9],
];

/** CVSS 점수 → 심각도 라벨(소문자). 점수가 없으면 빈 문자열. */
function vg_cvss_sev(?string $cvss): string {
    if ($cvss === null || $cvss === '') { return ''; }
    $v = (float) $cvss;
    foreach (VG_SEV_RANGES as $name => [$lo, $hi]) {
        if ($v >= $lo && $v <= $hi) { return $name; }
    }
    return '';
}

/* CVSS v3 벡터 해독표. 점수 하나로는 "원격인지 로컬인지, 인증이 필요한지" 를 알 수 없다.
 * 벡터가 그걸 말한다 — 같은 9.8 이라도 AV:N/PR:N 이면 인터넷에서 무인증 공격이 가능하다는 뜻.
 * 축약키만 담는다(v2 벡터는 키가 달라 해독 안 되고, 그대로 원문만 보여준다). */
const VG_CVSS_METRICS = [
    'AV' => ['label' => '공격 경로',   'v' => ['N' => '네트워크', 'A' => '인접 네트워크', 'L' => '로컬', 'P' => '물리']],
    'AC' => ['label' => '공격 복잡도', 'v' => ['L' => '낮음', 'H' => '높음']],
    'PR' => ['label' => '필요 권한',   'v' => ['N' => '불필요', 'L' => '일반 사용자', 'H' => '관리자']],
    'UI' => ['label' => '사용자 개입', 'v' => ['N' => '불필요', 'R' => '필요']],
    'S'  => ['label' => '범위 변경',   'v' => ['U' => '없음', 'C' => '있음']],
    'C'  => ['label' => '기밀성 영향', 'v' => ['H' => '높음', 'L' => '낮음', 'N' => '없음']],
    'I'  => ['label' => '무결성 영향', 'v' => ['H' => '높음', 'L' => '낮음', 'N' => '없음']],
    'A'  => ['label' => '가용성 영향', 'v' => ['H' => '높음', 'L' => '낮음', 'N' => '없음']],
];

/**
 * CVSS 벡터 문자열 → [['label'=>'공격 경로','value'=>'네트워크','danger'=>true], …]
 * 해독 못하는 키(v2 벡터 등)는 건너뛴다 — 빈 배열이면 호출부가 원문만 보여준다.
 * 'danger' 는 "공격자에게 유리한 값"(원격·무인증·개입불필요·영향높음) — UI 가 붉게 강조한다.
 */
function vg_cvss_vector_parts(?string $vector): array {
    if ($vector === null || $vector === '') { return []; }
    $worst = ['AV' => 'N', 'AC' => 'L', 'PR' => 'N', 'UI' => 'N', 'S' => 'C', 'C' => 'H', 'I' => 'H', 'A' => 'H'];
    $out = [];
    foreach (explode('/', $vector) as $part) {
        $kv = explode(':', $part, 2);
        if (count($kv) !== 2) { continue; }
        [$k, $v] = $kv;
        if (!isset(VG_CVSS_METRICS[$k]['v'][$v])) { continue; }   // CVSS:3.1 접두나 v2 키는 여기서 걸러진다
        $out[] = [
            'label'  => VG_CVSS_METRICS[$k]['label'],
            'value'  => VG_CVSS_METRICS[$k]['v'][$v],
            'danger' => ($worst[$k] ?? null) === $v,
        ];
    }
    return $out;
}

/**
 * 표의 <tr> 심각도 클래스. CSS 가 왼쪽 띠(+상위 등급은 옅은 배경)로 칠한다.
 * vg_table 의 'row_class' 에 심각도를 뽑아 넘긴다:
 *     'row_class' => fn($r) => vg_sev_row((string) $r['severity'])
 * 심각도가 어느 컬럼에 있는지는 표마다 다르고(base_severity), CVSS 에서 파생시키는
 * 표(cves.php)도 있어서, 컬럼명을 추측하지 않고 호출부가 문자열로 건네게 한다.
 * 어휘에 없는 값이면 빈 문자열 — 클래스 없는 평범한 행이 된다.
 */
function vg_sev_row(?string $sev): string {
    return isset(VG_TONE_SEV[(string) $sev]) ? 'sev-' . VG_TONE_SEV[(string) $sev] : '';
}

/**
 * 심각도별 건수 뱃지 묶음. 0건인 등급은 생략하고, 전부 0이면 '–'.
 *   $href 를 주면 각 뱃지를 링크로 만든다(자산관리: 등급별 취약점 목록으로).
 *   대시보드 · 자산관리 · 호스트 스캔이력이 공유한다.
 */
function vg_sev_counts(array $counts, ?callable $href = null): string {
    $out = [];
    foreach (VG_TONE_SEV as $sev => $tone) {
        $n = (int) ($counts[$sev] ?? 0);
        if ($n === 0) {
            continue;
        }
        $attr = 'class="badge tone-' . $tone . '" title="' . vg_h($sev) . '"';
        $out[] = $href !== null
            ? '<a ' . $attr . ' href="' . vg_h($href($sev)) . '">' . $n . '</a>'
            : '<span ' . $attr . '>' . $n . '</span>';
    }
    return $out ? implode(' ', $out) : '<span class="why">–</span>';
}

// 런타임 상태(EXTERNAL/LISTENING/RUNNING/LOADED/INSTALLED)
function vg_status_label(?string $s): string {
    $m = ['EXTERNAL' => '외부노출', 'LISTENING' => '로컬리스닝', 'RUNNING' => '실행중', 'LOADED' => '사용중', 'INSTALLED' => '설치만'];
    return $m[$s ?? ''] ?? (string) $s;
}
function vg_status_badge(?string $s): string {
    $tone = ['EXTERNAL' => 'crit', 'LISTENING' => 'high', 'RUNNING' => 'med', 'LOADED' => 'purple', 'INSTALLED' => 'muted'];
    return vg_badge(vg_status_label($s), $tone[$s ?? ''] ?? 'muted');
}

/* 수집 상태 판정 기준(분). 에이전트 기본 스케줄이 매시간이라 3시간까지는 정상으로 본다.
 *   자산관리 목록(assets.php)과 호스트 상세(host.php) 히어로가 공유한다. */
const VG_STALE_MIN   = 180;        // 3시간 초과 → 지연
const VG_OFFLINE_MIN = 10080;      // 7일 초과 → 오프라인

/** 최신 수집 경과시간(분)으로 수집 상태 뱃지. 스캔이 없으면(null) '수집없음'. */
function vg_asset_state($ageMin): string {
    if ($ageMin === null) { return vg_badge('수집없음', 'muted'); }
    $m = (int) $ageMin;
    if ($m > VG_OFFLINE_MIN) { return vg_badge('오프라인', 'crit'); }
    if ($m > VG_STALE_MIN)   { return vg_badge('지연', 'high'); }
    return vg_badge('정상', 'ok');
}

/**
 * 에이전트 자기계측 셀 — 실행당 리소스 발자국(담당자 안심용).
 *   피크 메모리는 프로세스 트리 전체 최댓값, CPU 는 자식 포함 실제 점유(벽시계 아님).
 *   값이 없으면(구버전 에이전트·측정 불가) 대시. 옛 스캔은 컬럼이 비어 있는 게 정상이다.
 */
function vg_resource_mem($mb): string {
    if ($mb === null || $mb === '') { return '<span class="why">–</span>'; }
    return number_format((float) $mb, 0) . '<span class="why">MB</span>';
}
function vg_resource_cpu($sec): string {
    if ($sec === null || $sec === '') { return '<span class="why">–</span>'; }
    return vg_h(number_format((float) $sec, 1)) . '<span class="why">s</span>';
}

/**
 * EPSS 셀 — 악용확률과 백분위를 함께.
 *
 * 확률만 보면 크기 감이 안 온다. EPSS 는 절대다수가 1% 미만이라 "2.7%" 도 실은 상위권이다.
 * FIRST 가 같이 주는 백분위(epss_percentile)를 "상위 N%" 로 뒤집어 붙여 맥락을 준다.
 *   epss=0.02719, percentile=0.97281  →  "2.7% 상위 2.7%"
 * 값이 없으면(1999년대 CVE 등 FIRST 가 점수를 안 매기는 건) 대시.
 */
function vg_epss_cell($epss, $percentile = null): string {
    if ($epss === null || $epss === '') {
        return '<span class="why">–</span>';
    }
    $out = vg_h(number_format((float) $epss * 100, 1)) . '%';
    if ($percentile !== null && $percentile !== '') {
        $top = (1.0 - (float) $percentile) * 100;
        if ($top < 0.01) { $top = 0.01; }   // percentile=1.0 이 "상위 0%" 로 보이지 않게
        $dec = $top < 1 ? 2 : ($top < 10 ? 1 : 0);
        $out .= ' <span class="why">상위 ' . vg_h(number_format($top, $dec)) . '%</span>';
    }
    return $out;
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
function vg_modal_btn(string $target, string $label, string $class = 'btn btn--primary'): void {
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

function vg_modal_close(): void {
    echo '</div></dialog>';
}

/**
 * 도움말 툴팁. 본문에 늘어놓으면 화면이 무거워지는 부연설명을 아이콘 뒤로 보낸다.
 * 네이티브 title 을 쓴다 — 스크린리더도 읽고, JS 도 필요 없다.
 */
function vg_help(string $text): string {
    return '<span class="help" title="' . vg_h($text) . '" tabindex="0" role="note">?</span>';
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

// 긴 텍스트 말줄임 + 툴팁(title 에 원문). 안 잘리면 그냥 이스케이프만.
function vg_trunc(?string $text, int $len = 72): string {
    $text = (string) $text;
    $cut = mb_strimwidth($text, 0, $len, '…');
    if ($cut === $text) {
        return vg_h($text);
    }
    return '<span class="trunc" title="' . vg_h($text) . '">' . vg_h($cut) . '</span>';
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
            ['perm' => 'users',       'href' => '/users.php',       'label' => '사용자',    'key' => 'users'],
            ['perm' => 'permissions', 'href' => '/permissions.php', 'label' => '권한 설정', 'key' => 'permissions'],
            ['perm' => 'apitokens',   'href' => '/api-tokens.php',  'label' => 'API 토큰',  'key' => 'apitokens'],
            ['perm' => 'activity',    'href' => '/activity.php',    'label' => '감사 로그', 'key' => 'activity'],
        ],
    ];
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
            echo '<a class="' . $cls . '" href="' . vg_h($l['href']) . '">' . vg_h($l['label']) . '</a>';
        }
    }
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
<link rel="stylesheet" href="<?= vg_asset('/assets/app.css') ?>">
<script src="<?= vg_asset('/assets/app.js') ?>" defer></script>
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
