<?php
declare(strict_types=1);

/**
 * UI??? ?? ??? ?? ???.
 * ?? ?? ????? ??? ? ??? ??? ????.
 */

require_once __DIR__ . '/config.php';

function vg_ui_int(string $key, int $default, int $min, int $max): int {
    $raw = vg_env($key);
    if ($raw === null || filter_var($raw, FILTER_VALIDATE_INT) === false) {
        return $default;
    }
    return max($min, min($max, (int) $raw));
}

/** @return int[] */
function vg_ui_per_page_options(): array {
    $raw = (string) vg_env('UI_PER_PAGE_OPTIONS', '10,20,40,60,100');
    $values = [];
    foreach (explode(',', $raw) as $item) {
        $value = filter_var(trim($item), FILTER_VALIDATE_INT);
        if ($value !== false && $value >= 5 && $value <= 200) {
            $values[] = (int) $value;
        }
    }
    $values = array_values(array_unique($values));
    sort($values);
    return $values ?: [10, 20, 40, 60, 100];
}

function vg_ui_per_page_default(): int {
    $options = vg_ui_per_page_options();
    $configured = vg_ui_int('UI_PER_PAGE_DEFAULT', 10, 5, 200);
    return in_array($configured, $options, true) ? $configured : $options[0];
}

function vg_ui_dashboard_urgent_limit(): int {
    return vg_ui_int('UI_DASHBOARD_URGENT_LIMIT', 6, 3, 30);
}

/** @return string[] 실제 사용 중인 KEV만 긴급 목록에 올린다. */
function vg_ui_dashboard_actionable_statuses(): array {
    $allowed = ['EXTERNAL', 'LAN', 'LISTENING', 'RUNNING', 'LOADED'];
    $raw = strtoupper((string) vg_env('UI_DASHBOARD_ACTIONABLE_STATUSES', implode(',', $allowed)));
    $values = [];
    foreach (explode(',', $raw) as $item) {
        $status = trim($item);
        if (in_array($status, $allowed, true)) { $values[] = $status; }
    }
    return array_values(array_unique($values)) ?: $allowed;
}

/**
 * 상세 화면(자산 상세 등)의 기본 페이지 크기. 목록 화면 기본값보다 크다 —
 *   자산 상세는 "이 자산 한 대의 전량"을 훑는 자리라 10개씩 13페이지로 넘기면 실측이 안 된다.
 *   선택지(vg_ui_per_page_options)에 없는 값이 설정되면 그보다 크지 않은 가장 큰 선택지로 접는다
 *   — 셀렉트에 없는 값이 현재값이면 "N개씩 보기" 가 아무것도 선택되지 않은 채로 뜬다.
 */
function vg_ui_detail_per_page_default(): int {
    $options = vg_ui_per_page_options();
    $configured = vg_ui_int('UI_DETAIL_PER_PAGE_DEFAULT', 40, 5, 200);
    if (in_array($configured, $options, true)) { return $configured; }
    $fallback = $options[0];
    foreach ($options as $n) { if ($n <= $configured) { $fallback = $n; } }
    return $fallback;
}

function vg_ui_detail_preview_limit(): int {
    return vg_ui_int('UI_DETAIL_PREVIEW_LIMIT', 10, 5, 100);
}

function vg_ui_trend_limit(): int {
    return vg_ui_int('UI_TREND_LIMIT', 50, 10, 500);
}

function vg_audit_page_views_enabled(): bool {
    return filter_var(vg_env('AUDIT_PAGE_VIEWS', '1'), FILTER_VALIDATE_BOOLEAN);
}

function vg_ui_filter_option_limit(): int {
    return vg_ui_int('UI_FILTER_OPTION_LIMIT', 300, 50, 2000);
}

/** advisories.php 영향 자산 모달에 담는 상세 행 상한(초과분은 "외 N건"). */
function vg_ui_advisory_asset_limit(): int {
    return vg_ui_int('UI_ADVISORY_ASSET_LIMIT', 200, 20, 2000);
}
