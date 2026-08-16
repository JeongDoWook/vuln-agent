<?php
declare(strict_types=1);

/**
 * components/notice.php — 알림·플래시·빈 상태: PRG 리다이렉트와 1회용 결과, 알림 배너, 빈 목록.
 *   "지금 무슨 일이 있었나 / 왜 비었나" 를 말하는 자리다.
 */

require_once __DIR__ . '/../../format.php';
require_once __DIR__ . '/../icons.php';   // vg_empty() 의 아이콘

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

/**
 * 성공/오류/경고 알림. $msg 가 null·빈문자면 아무것도 출력하지 않는다.
 *   문자열을 주면 기존처럼 한 줄만 출력(하위호환): vg_alert($msg, 'err'|'ok'|'warn')
 *   배열을 주면 제목+힌트 목록까지: vg_alert(['title'=>…, 'hints'=>[…], 'type'=>'warn'])
 *
 *   'details' => ['summary'=>…, 'items'=>[…]] 를 주면 그 목록을 **접어서** 붙인다(JS 없이 <details>).
 *   경고에 딸린 대상 목록이 길 때 쓴다 — findings.php 의 "판정 불가" 경고가 미지원 배포판 호스트
 *   199개를 전부 펴 놓아 배너 혼자 화면 6줄을 먹고 KPI·필터·표를 아래로 밀어냈다. 목록을 지우는
 *   대신 접는다: 닫혀 있어도 HTML 에는 그대로 있어 검색(Ctrl+F)·스모크 단언이 같이 산다.
 */
function vg_alert($msg, string $type = 'err'): void {
    if ($msg === null || $msg === '' || $msg === []) {
        return;
    }
    if (is_array($msg)) {
        $type = (string) ($msg['type'] ?? $type);
        $title = (string) ($msg['title'] ?? '');
        $hints = is_array($msg['hints'] ?? null) ? $msg['hints'] : [];
        echo '<div class="alert alert--' . (in_array($type, ['ok', 'warn'], true) ? $type : 'err') . '" role="' . ($type === 'ok' ? 'status' : 'alert') . '">';
        if ($title !== '') {
            echo '<strong>' . vg_h($title) . '</strong>';
        }
        if ($hints) {
            echo '<ul class="hint-list">';
            foreach ($hints as $hint) {
                echo '<li>' . vg_h((string) $hint) . '</li>';
            }
            echo '</ul>';
        }
        $det   = is_array($msg['details'] ?? null) ? $msg['details'] : [];
        $items = is_array($det['items'] ?? null) ? $det['items'] : [];
        if ($items) {
            echo '<details><summary>' . vg_h((string) ($det['summary'] ?? '전체 보기')) . '</summary>'
               . '<ul class="hint-list">';
            foreach ($items as $item) {
                echo '<li>' . vg_h((string) $item) . '</li>';
            }
            echo '</ul></details>';
        }
        echo '</div>';
        return;
    }
    echo '<div class="alert alert--' . (in_array($type, ['ok', 'warn'], true) ? $type : 'err') . '" role="' . ($type === 'ok' ? 'status' : 'alert') . '">' . vg_h((string) $msg) . '</div>';
}

/**
 * 빈 상태. "데이터가 없습니다" 한 줄은 막다른 길이라, 왜 비었는지와 다음 행동을 준다.
 *   문자열을 주면 기존처럼 한 줄만 출력(하위호환 — 대부분의 vg_table 호출이 이 형태).
 *   배열을 주면 아이콘·제목·힌트·행동버튼까지: ['icon'=>'search','title'=>…,'hint'=>…,'cta'=>['href'=>…,'label'=>…]]
 *   'icon' 은 icons.php 의 아이콘 이름이다 — 이모지·기호 문자를 넣지 않는다. 그것들은 환경에
 *   따라 컬러 이모지 폰트로 렌더돼 currentColor 를 안 따라가고(#584), 폰트에 없으면 두부(□)가
 *   된다. 이름이 아닌 값이 오면 예전처럼 글자 그대로 두어 화면이 깨지지는 않게 한다.
 */
function vg_empty($spec): void {
    if (!is_array($spec)) {
        echo '<div class="empty">' . vg_h((string) $spec) . '</div>';
        return;
    }
    echo '<div class="empty">';
    if (!empty($spec['icon'])) {
        $icon = (string) $spec['icon'];
        echo '<span class="empty__icon" aria-hidden="true">'
            . (isset(VG_ICON_PATHS[$icon]) ? vg_icon($icon) : vg_h($icon)) . '</span>';
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
