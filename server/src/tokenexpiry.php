<?php
declare(strict_types=1);

/**
 * tokenexpiry.php — API 토큰·에이전트 토큰이 공유하는 유효기간 어휘.
 *   발급 화면(api-tokens.php / agent-tokens.php)과 검증 헬퍼(apitoken.php / agenttoken.php)가
 *   같은 선택지·같은 판정을 쓰도록 한 곳에 모은다(둘로 흩어지면 조용히 어긋난다).
 *   자동 갱신·자동 재발급은 두지 않는다 — 만료되면 사람이 새로 발급한다.
 */

require_once __DIR__ . '/format.php';   // vg_badge

// 발급 UI 선택지: 값(일수) → 라벨. 0 = 무기한(expires_at NULL).
//   설정 이관 예정(tb_setting) — 다른 워커가 만드는 중이라 지금은 상수로 둔다.
const VG_TOKEN_EXPIRY_OPTIONS = [0 => '무기한', 30 => '30일', 90 => '90일', 365 => '1년'];

// 만료 임박으로 표시할 잔여 일수. 설정 이관 예정(tb_setting).
const VG_TOKEN_EXPIRY_SOON_DAYS = 7;

/**
 * 발급 폼이 보낸 유효기간(일)을 검증해 정규화한다.
 *   선택지에 없는 값은 거부한다 — 임의 일수를 허용할 이유가 없다(YAGNI).
 * @return int 0(무기한) 또는 선택지의 일수
 */
function vg_token_expiry_days_input($raw): int {
    $days = filter_var((string) $raw, FILTER_VALIDATE_INT);
    if ($days === false || !array_key_exists((int) $days, VG_TOKEN_EXPIRY_OPTIONS)) {
        throw new RuntimeException('유효기간 선택값이 올바르지 않습니다.');
    }
    return (int) $days;
}

/** 유효기간(일) → DB 에 넣을 만료시각. 0 이면 null(무기한). */
function vg_token_expires_at(int $days): ?string {
    return $days > 0 ? date('Y-m-d H:i:s', time() + $days * 86400) : null;
}

/** 만료시각이 지났는가. NULL(무기한)은 언제나 false. */
function vg_token_is_expired(?string $expiresAt): bool {
    if ($expiresAt === null || $expiresAt === '') { return false; }
    $ts = strtotime($expiresAt);
    return $ts !== false && $ts <= time();
}

/** 목록 표시용 상태: 'none'(무기한) | 'expired' | 'soon' | 'active'. */
function vg_token_expiry_state(?string $expiresAt): string {
    if ($expiresAt === null || $expiresAt === '') { return 'none'; }
    $ts = strtotime($expiresAt);
    if ($ts === false) { return 'none'; }
    if ($ts <= time()) { return 'expired'; }
    return ($ts - time()) <= VG_TOKEN_EXPIRY_SOON_DAYS * 86400 ? 'soon' : 'active';
}

/** 목록 셀에 넣는 만료 뱃지. 만료·임박은 눈에 띄게, 무기한은 조용하게. */
function vg_token_expiry_badge(?string $expiresAt): string {
    $state = vg_token_expiry_state($expiresAt);
    if ($state === 'none') {
        return vg_badge('무기한', 'muted', '만료되지 않는 토큰입니다.');
    }
    $date = substr((string) $expiresAt, 0, 16);
    if ($state === 'expired') {
        return vg_badge($date . ' 만료됨', 'danger', '이미 만료되어 인증이 거부됩니다. 새로 발급하세요.');
    }
    if ($state === 'soon') {
        return vg_badge($date . ' 만료 임박', 'warn', VG_TOKEN_EXPIRY_SOON_DAYS . '일 이내에 만료됩니다.');
    }
    return vg_badge($date, 'ok');
}

/** 발급 폼의 유효기간 select. 두 발급 화면이 같은 선택지를 쓰도록 여기서 그린다. */
function vg_token_expiry_select(int $selected = 0): string {
    $out = '<select name="expires_days">';
    foreach (VG_TOKEN_EXPIRY_OPTIONS as $days => $label) {
        $out .= '<option value="' . (int) $days . '"'
              . ($days === $selected ? ' selected' : '') . '>' . vg_h($label) . '</option>';
    }
    return $out . '</select>';
}
