<?php
declare(strict_types=1);

/**
 * connectors/vocab.php — 데이터 수집 화면의 **어휘**(DB 값 → 사람이 읽는 말)만 갖는다.
 *   목록 표와 이력 표가 같은 상태 뱃지를 써야 하므로 한 곳에 둔다 — 두 벌이면 같은
 *   'success' 가 화면마다 다른 글자·다른 색으로 뜬다.
 */

// 범용 API 커넥터(generic_api)의 역할 라벨 — 단일 소스. <select id="gRole"> 옵션과
//   connectors.js 가 각자 하드코딩해 두 곳이 따로 놀던 것을 여기로 합친다. $roleGroups
//   (connectors/list_view.php) 카드 타이틀과 뜻은 겹치지만 "취약점 정체 — 무엇인가" 처럼
//   부가설명이 붙어 있어 옵션 라벨(설명 없는 짧은 형태)로 그대로 못 쓴다 — 억지로 문자열을
//   자르지 않고 새 상수로 둔다.
const VG_GENERIC_ROLE_LABELS = [
    'identity' => '취약점 정체', 'priority' => '우선순위 신호',
    'vendor' => '벤더 패치 판정',
];

/* 수집 상태 → 한글 라벨 + 뱃지 톤(색은 CSS 가 결정).
 * 라벨과 톤을 한 표에 둔다 — 전엔 톤만 있고 뱃지 글자는 DB 값(success/never)이 그대로 나갔다. */
const VG_COLLECT_STATUS = [
    'success' => ['성공', 'ok'], 'error' => ['실패', 'danger'],
    'running' => ['수집 중', 'warn'], 'never' => ['미실행', 'muted'],
];

// 실행 계기 — DB 값(manual/schedule)을 그대로 보여주지 않는다.
const VG_COLLECT_TRIGGER = ['manual' => '직접 실행', 'schedule' => '예약'];

/** 수집 상태 뱃지. 목록 표와 이력 표가 같은 것을 쓴다(예전엔 두 표가 한 클로저를 돌려썼다). */
function vg_connector_status_badge(?string $s): string
{
    $s = (string) ($s ?: 'never');
    [$label, $tone] = VG_COLLECT_STATUS[$s] ?? [$s, 'muted'];
    return vg_badge($label, $tone);
}
