<?php
declare(strict_types=1);

/**
 * components/page.php — 페이지 뼈대: 제목 줄·상세 히어로·섹션 탭·카드.
 *   "지금 무엇을 보고 있나" 만 화면 위쪽에 세운다. 화면을 해설하는 부제·결론 문장은 두지 않는다.
 */

require_once __DIR__ . '/../../format.php';   // vg_card() 의 'badge' 가 vg_badge() 를 쓴다.
require_once __DIR__ . '/paging.php';   // vg_subtabs() 의 기본 href 가 vg_qs() 를 쓴다.
require_once __DIR__ . '/../icons.php'; // vg_subtabs() 가 탭 정의의 선택적 'icon' 키를 vg_icon() 으로 그린다.

/**
 * 화면 제목 — **카드가 아니라 얇은 헤더 줄이다.** 예전엔 흰 카드로 세로 150px 를 먹었는데
 * 담긴 건 제목 + 설명 한 줄뿐이라, 1440×675 첫 화면에서 정작 표가 두 행밖에 안 보였다.
 * 부제 인자($description)는 없앴다 — 화면을 해설하는 줄은 두지 않는다는 규약이 생겨
 * 호출부 전부가 빈 문자열을 넘기게 됐고, 인자가 남아 있으면 다시 문장이 자란다.
 * 두 번째 인자 $eyebrow('OVERVIEW' 등)는 예전에도 화면에 안 그렸고 지금도 안 그린다.
 * 자리만 지키는 인자다.
 */
function vg_page_title(string $title, string $eyebrow, array $opts = []): void {
    $class = trim('page-title ' . (!empty($opts['actions']) ? 'page-title--actions ' : '') . (string) ($opts['class'] ?? ''));
    echo '<header class="' . vg_h($class) . '"><div class="page-title__text"><h1>' . vg_h($title);
    if (array_key_exists('count', $opts)) { echo ' <span class="hint">(' . number_format((int) $opts['count']) . vg_h((string) ($opts['count_label'] ?? '건')) . ')</span>'; }
    if (!empty($opts['hint'])) { echo ' <span class="hint">' . vg_h((string) $opts['hint']) . '</span>'; }
    if (!empty($opts['suffix_html'])) { echo ' ' . (string) $opts['suffix_html']; }
    echo '</h1>';
    echo '</div>';
    if (!empty($opts['actions'])) { echo '<div class="page-title__actions">' . $opts['actions'] . '</div>'; }
    echo '</header>';
}

/* 화면 결론 배너(vg_verdict)는 없앴다 — 한 문장으로 결론을 말하고 숫자를 붙이던 자리인데,
 *   그 문장은 바로 아래 표·KPI 가 이미 가진 값을 되풀이하는 해설이었다. 목록 화면은 값만
 *   세우고 판단은 상세에서 한다. `.verdict*` 규칙도 app.css 에서 같이 걷었다. */

/**
 * 상세 페이지 히어로 — "무엇을 보고 있나(좌) + 얼마나 위험한가(우)".
 * 왼쪽 띠 색이 위험도다. host.php 가 인라인으로 갖고 있던 것을 공용으로 뺐다.
 *   $title·$meta·$actions 는 이미 이스케이프된 HTML (호출부가 vg_h 책임 — 링크·뱃지·폼을
 *   섞어 넣어야 해서). $actions 는 그대로 echo 되므로 호출부가 안전한 HTML 을 만들어
 *   넘겨야 한다 — 사용자 입력을 그대로 흘리면 안 되고, 반드시 vg_h() 로 이스케이프한 뒤
 *   조립한 문자열이어야 한다.
 *   $riskLabel 이 null 이면 위험도 칸 없이 식별부만.
 *   $riskTone 은 톤 어휘(crit/high/med/low/ok/muted). 라벨과 톤을 분리한 건 "양호" 처럼
 *   심각도 어휘에 없는 라벨을 써야 할 때가 있기 때문이다(vg_sev_tone 은 그걸 muted 로 떨군다).
 */
function vg_hero(string $title, array $meta = [], ?string $riskLabel = null, string $riskTone = 'ok', string $riskCap = '최고 위험도', ?string $actions = null): void {
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
    if ($actions !== null) {
        echo '<div class="hero__actions">' . $actions . '</div>';
    }
    echo '</div>';
}

/**
 * 섹션 탭(밑줄형). 첫 화면에 다 쏟지 않고 갈래로 나눠 담는 자리.
 *   $tabs: ['vuln' => ['label'=>'취약점'], 'runtime' => ['label'=>'런타임'], …]
 *   탭 줄은 "어디로 갈 수 있나" 만 말한다 — **라벨 옆 건수 배지는 그리지 않는다.**
 *   건수는 각 탭 안의 카드·페이지네이션('총 N건')이 이미 갖고 있어 두 번 말하는 것이었다
 *   (사용자 지적 — "글자·숫자가 너무 많다"). href 를 주면 별도 페이지로 이동하고,
 *   없으면 같은 페이지의 ?tab= 값을 바꾼다.
 *   'icon' (선택) — icons.php 의 아이콘 이름. 없으면 지금까지처럼 아이콘 없이 그린다.
 *   'group' (선택) — 인접한 두 탭의 group 이 서로 다르면 그 경계에 옅은 구분선을 넣는다
 *   (host.php 의 "위협/자산 구성/이력" 묶음처럼 탭이 많은 화면에서만 쓴다 — 안 주면 지금까지의
 *   화면(packages.php 등)은 구분선 없이 그대로다).
 */
function vg_subtabs(array $tabs, string $active): void {
    echo '<nav class="subtabs">';
    $prevGroup = null;
    foreach ($tabs as $key => $def) {
        $group = $def['group'] ?? null;
        $classes = [];
        if ($active === (string) $key) { $classes[] = 'on'; }
        if ($group !== null && $prevGroup !== null && $group !== $prevGroup) { $classes[] = 'subtabs__sep'; }
        if ($group !== null) { $prevGroup = $group; }
        $cls = $classes ? ' class="' . vg_h(implode(' ', $classes)) . '"' : '';
        $href = (string) ($def['href'] ?? vg_qs(['tab' => $key, 'page' => null]));
        echo '<a' . $cls . ' href="' . vg_h($href) . '">';
        if (!empty($def['icon'])) { echo vg_icon((string) $def['icon']); }
        echo vg_h((string) ($def['label'] ?? $key));
        echo '</a>';
    }
    echo '</nav>';
}

/**
 * 카드 하나 — 이 저장소의 **카드 문법**을 코드로 못박는다.
 *   화면마다 `<div class="card"><strong>…` 를 손으로 쓰던 것이 갈라짐의 원인이었다:
 *   같은 성격의 덩어리인데 어떤 화면은 카드 안 `<strong>`, 어떤 화면은 카드 밖 `<h2>`,
 *   어떤 화면은 제목이 아예 없었다(도넛 둘이 제목 없이 한 카드에 붙어 있던 탐지 결과 CVE 탭).
 *
 *   규약 — 새로 만드는 카드와 손대는 카드는 이 셋을 지킨다:
 *     1. **한 카드 = 한 이야기.** 성격이 다른 덩어리(등급 구성 / 노출 상태 / 조치 성격)는
 *        카드를 따로 세운다. 여러 카드를 한 줄에 놓을 때는 `.card-row` 로 감싼다.
 *     2. **카드에는 제목이 있다.** 제목을 못 붙일 덩어리는 애초에 카드가 아니다 —
 *        다른 카드 안의 요소이거나, 지워야 할 것이다.
 *     3. 제목 오른쪽에는 **보조 수치(배지)나 조작부**를 둘 수 있다(총계·생성 버튼).
 *
 *   예외는 하나다 — **화면의 주 목록 표**(vg_table() 이 스스로 감싸는 카드). 그 카드의 제목은
 *     화면 제목(h1)과 탭 줄이 이미 갖고 있어서, 카드에 또 적으면 같은 말이 두 줄이 된다
 *     (이 저장소가 결론 배너·탭 배지를 걷어낸 것과 같은 기준). 다만 **한 화면에 표가 둘 이상**
 *     이면 h1 하나로는 어느 표가 무엇인지 못 가리므로 그때는 전부 제목을 단다
 *     (컴플라이언스의 통제별 판정/판정 추이, 자산 상세 탭들이 그렇게 서 있다).
 *
 *   $title : 카드 제목. 빈 문자열은 규약 위반이라 받지 않는다(2번).
 *   $body  : 출력하는 콜러블(권장 — PHP 블록을 그대로 쓴다) 또는 이미 이스케이프된 HTML 문자열.
 *            버퍼를 끼지 않고 그 자리에서 바로 그린다 — 카드 본문이 큰 표일 때 문자열로 한 번
 *            더 들고 있을 이유가 없다.
 *   $opts  :
 *     'badge'      — 제목 오른쪽 보조 수치. 문자열이면 muted 뱃지로 감싼다(참고 화면의 '취약점: 4,704건').
 *     'aside'      — 제목 오른쪽에 그대로 넣을 HTML(버튼·링크). 이미 이스케이프된 HTML 이라는 규약.
 *     'title_attr' — 제목 툴팁 한 문장(왜 이렇게 세는지 같은 것).
 *     'class'      — .card 에 붙일 추가 클래스.
 *     'body_class' — .card__body 에 붙일 추가 클래스(center 등).
 *     'id'         — 카드 태그의 id(앵커).
 *     'attrs'      — 카드 태그의 추가 속성 ['data-action-queue' => true]. true 면 값 없는 속성.
 */
function vg_card(string $title, $body, array $opts = []): void {
    static $seq = 0;
    $seq++;
    $titleId = 'card-title-' . $seq;

    $cls = trim('card ' . (string) ($opts['class'] ?? ''));
    echo '<section class="' . vg_h($cls) . '" aria-labelledby="' . vg_h($titleId) . '"';
    if (!empty($opts['id'])) { echo ' id="' . vg_h((string) $opts['id']) . '"'; }
    // 속성 이름은 화이트리스트가 아니라 형식으로 거른다(vg_table 의 row_attrs 와 같은 규약).
    foreach ((array) ($opts['attrs'] ?? []) as $name => $value) {
        $name = (string) $name;
        if ($value === null || $value === false || preg_match('/^[a-zA-Z_:][a-zA-Z0-9:._-]*$/', $name) !== 1) { continue; }
        echo $value === true ? ' ' . $name : ' ' . $name . '="' . vg_h((string) $value) . '"';
    }
    echo '>';

    $tip = (string) ($opts['title_attr'] ?? '');
    echo '<div class="card__head"><strong id="' . vg_h($titleId) . '"'
        . ($tip !== '' ? ' title="' . vg_h($tip) . '"' : '') . '>' . vg_h($title) . '</strong>';
    $aside = (string) ($opts['aside'] ?? '');
    if ($aside === '' && isset($opts['badge'])) {
        $aside = vg_badge((string) $opts['badge'], 'muted');
    }
    if ($aside !== '') { echo '<span class="card__head-aside">' . $aside . '</span>'; }
    echo '</div>';

    $bodyCls = trim('card__body ' . (string) ($opts['body_class'] ?? ''));
    echo '<div class="' . vg_h($bodyCls) . '">';
    // 문자열은 언제나 HTML 로 본다 — 함수명과 같은 문자열('vg_footer')이 우연히 호출되지 않게
    //   is_callable 보다 타입 판정을 먼저 세운다.
    if (!is_string($body) && is_callable($body)) { $body(); } else { echo (string) $body; }
    echo '</div></section>';
}
