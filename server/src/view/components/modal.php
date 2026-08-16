<?php
declare(strict_types=1);

/**
 * components/modal.php — 모달: 여는 버튼·<dialog> 열기/푸터/닫기·공용 확인창.
 *   네이티브 <dialog> 한 벌을 모든 화면이 공유한다.
 */

require_once __DIR__ . '/../../format.php';

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
    $titleId = $id . 'Title';
    echo '<dialog class="modal ' . vg_h($class) . '" id="' . vg_h($id) . '" aria-labelledby="' . vg_h($titleId) . '"'
        . ($open ? ' data-modal-autoopen' : '') . '>'
        . '<div class="modal__head">'
        . '<strong id="' . vg_h($titleId) . '">' . vg_h($title) . '</strong>'
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
 * 삭제·폐기처럼 되돌리기 어려운 작업이 공유하는 확인창.
 * 페이지마다 같은 dialog 골격을 만들지 않고 레이아웃에 한 번만 렌더한 뒤 app.js 가
 * 문구와 주작업 라벨만 바꿔 쓴다. JS 가 없으면 기존처럼 폼 자체는 그대로 제출된다.
 */
function vg_confirm_dialog(): void {
    // 폭은 모달 프리셋 --sm(440) 이 준다 — .confirm-modal 이 따로 440 을 들고 있지 않게 합쳤다.
    vg_modal_open('vgConfirmDialog', '작업을 진행할까요?', 'confirm-modal modal--sm');
    echo '<p class="confirm-modal__message" data-confirm-message></p>'
        . '<div class="modal__foot">'
        . '<button type="button" class="btn btn--ghost" data-confirm-cancel>취소</button>'
        . '<button type="button" class="btn btn--danger" data-confirm-ok>계속</button>'
        . '</div>';
    vg_modal_close();
}
