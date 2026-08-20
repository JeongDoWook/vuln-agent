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

/**
 * 대시보드 '주요 취약점 신호' 표시 건수. **지금은 부르는 곳이 없다** — 그 카드가 상위 N건
 * 나열에서 구성(도넛 KPI)으로 바뀌면서 자를 목록 자체가 없어졌다. 설정과 테스트는 남긴다:
 * 값의 범위 계약을 tests/ui_config_test.php 가 검증하고 있고, 목록형 카드가 다시 서면
 * 그때 이 값을 그대로 쓴다. 정리할 거면 문서(docs/ui-configuration.md)·테스트와 함께 뺀다.
 */
function vg_ui_dashboard_urgent_limit(): int {
    return vg_ui_int('UI_DASHBOARD_URGENT_LIMIT', 6, 3, 30);
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
