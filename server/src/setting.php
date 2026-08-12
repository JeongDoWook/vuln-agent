<?php
declare(strict_types=1);

/**
 * setting.php — 운영 중 바꿀 수 있는 전역 설정값(tb_setting) 읽기.
 *   조직마다 다른 판정 기준(SLA 기준일·컷라인)을 코드 상수에서 뺀 것이라, 값이 없거나
 *   테이블이 아직 없을 때는 **호출부의 상수를 그대로 폴백**한다 — 설정을 도입했다고
 *   기존 동작이 달라지면 안 된다.
 *
 *   읽기는 요청당 1회 전체 로드 후 정적 캐시. 설정은 몇 줄짜리 표라 통째로 읽는 게
 *   키마다 쿼리를 날리는 것보다 싸고, 한 요청 안에서 값이 바뀌지 않아 일관성도 얻는다.
 *   쓰기는 settings.php(관리자 전용 화면)만 한다 — 여기엔 읽기와 정의만 둔다(SRP).
 */

require_once __DIR__ . '/db.php';

/**
 * 설정 항목 정의(SSOT) — 설정 화면의 행 목록이자 저장 시 검증 규칙.
 *   **기본값은 여기 두지 않는다.** 호출부가 자기 상수를 폴백으로 넘긴다
 *   (예: compliance.php 의 VG_COMPLIANCE_SLA_KEV_DAYS) — 같은 숫자를 두 곳에 두면 갈라진다.
 * @return array<string, array{label:string, desc:string, type:string, min:int, max:int}>
 */
function vg_setting_defs(): array {
    return [
        'compliance.sla_kev_days' => [
            'label' => 'KEV 조치 기한(일)', 'type' => 'int', 'min' => 1, 'max' => 365,
            'desc'  => 'KEV(실제 악용 확인) 등재 취약점을 조치해야 하는 기준 일수.',
        ],
        'compliance.sla_crit_days' => [
            'label' => 'CRITICAL 조치 기한(일)', 'type' => 'int', 'min' => 1, 'max' => 365,
            'desc'  => 'CRITICAL 등급 취약점 조치 기준 일수.',
        ],
        'compliance.sla_high_days' => [
            'label' => 'HIGH 조치 기한(일)', 'type' => 'int', 'min' => 1, 'max' => 365,
            'desc'  => 'HIGH 등급 취약점 조치 기준 일수.',
        ],
        'compliance.partial_max' => [
            'label' => '부분준수 상한(건)', 'type' => 'int', 'min' => 1, 'max' => 1000,
            'desc'  => '위반 1~이 값이면 부분준수, 초과하면 미준수로 판정합니다.',
        ],
        'compliance.history_lookback_margin_days' => [
            'label' => '이력 역산 여유일', 'type' => 'int', 'min' => 0, 'max' => 365,
            'desc'  => '최초 발견 시각을 되짚는 구간 = 가장 긴 조치 기한 + 이 여유일.',
        ],
        // 세션 만료는 **보안 통제**다. 단위를 분으로 둔 것은 관리자가 다루는 단위라서고,
        //   min 은 "설정으로 통제를 무력화할 수 없게" 하는 하한이다 — 0·1초 만료(로그인 불가)나
        //   무한 세션(만료 없음)을 저장할 수 있으면 그 자체가 장애·보안사고다.
        'session.idle_minutes' => [
            'label' => '세션 유휴 만료(분)', 'type' => 'int', 'min' => 5, 'max' => 720,
            'desc'  => '마지막 활동 이후 이 시간이 지나면 자동 로그아웃합니다(ISMS-P 2.6.3).',
        ],
        'session.absolute_minutes' => [
            'label' => '세션 절대 만료(분)', 'type' => 'int', 'min' => 30, 'max' => 1440,
            'desc'  => '유휴와 무관하게 로그인 시점부터 이 시간이 지나면 자동 로그아웃합니다.',
        ],
        'account.stale_login_days' => [
            'label' => '계정 미사용 판정(일)', 'type' => 'int', 'min' => 7, 'max' => 1095,
            'desc'  => '이 일수 이상 로그인하지 않은 대화형 계정을 미사용으로 판정합니다(ISMS-P 2.5.1·2.5.6).',
        ],
    ];
}

/**
 * tb_setting 전체를 [key => value] 로. 요청당 1회만 조회하고 정적 캐시한다.
 *   테이블이 아직 없거나(마이그레이션 미적용) DB 오류면 빈 배열 — 호출부가 폴백을 쓴다.
 * @return array<string, string>
 */
function vg_settings_all(): array {
    static $cache = null;
    if ($cache !== null) {
        return $cache;
    }
    $cache = [];
    try {
        $rows = vg_pdo()->query('SELECT setting_key, setting_value FROM tb_setting WHERE is_deleted = 0')->fetchAll();
        foreach ($rows as $r) {
            $cache[(string) $r['setting_key']] = (string) $r['setting_value'];
        }
    } catch (Throwable $e) {
        // 설정을 못 읽는다고 화면이 죽으면 안 된다 — 로그만 남기고 전부 폴백으로 간다.
        error_log('[setting] ' . $e->getMessage());
    }
    return $cache;
}

/**
 * 정수 설정값. 숫자가 아니면 $default, 정의된 min/max 를 벗어나면 그 범위로 클램프한다
 * (화면에서 이미 검증하지만, DB 를 직접 고친 값이 판정을 망가뜨리지 않게 읽을 때도 막는다).
 */
function vg_setting_int(string $key, int $default): int {
    $raw = vg_settings_all()[$key] ?? null;
    $v = ($raw !== null && filter_var($raw, FILTER_VALIDATE_INT) !== false) ? (int) $raw : $default;
    $def = vg_setting_defs()[$key] ?? null;
    if ($def !== null) {
        $v = max((int) $def['min'], min((int) $def['max'], $v));
    }
    return $v;
}

/**
 * 정의상 이 키가 가질 수 있는 최댓값. 정의가 없으면 $default.
 *   "설정이 어떤 값이든 안전하도록" 여유를 잡아야 하는 곳이 쓴다 — 예: auth.php 의
 *   session.gc_maxlifetime 은 DB 를 읽지 않고도 절대 만료 상한보다 길어야 한다.
 */
function vg_setting_max(string $key, int $default): int {
    $def = vg_setting_defs()[$key] ?? null;
    return $def !== null ? (int) $def['max'] : $default;
}
