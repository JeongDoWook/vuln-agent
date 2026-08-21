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
 * 설정 항목의 묶음(SSOT) — 설정 화면이 이 순서대로 카드 하나씩 그린다.
 *   성격이 다른 값(조치 기한 · 준수 판정 · 세션 · 계정)이 한 표에 섞여 있으면 무엇을
 *   만지는지 안 보인다. 분류표를 화면에 하드코딩하지 않도록 라벨을 여기 둔다.
 *
 *   note 는 **카드 제목 옆 한 줄**이다(줄을 새로 쓰지 않는다). 항목마다 달려 있던 해설을
 *   걷으면서 그룹당 한 줄로 모은 것 — '부분준수 상한'·'이력 역산 여유일'처럼 이름만으로는
 *   어디에 쓰이는 값인지 모르는 항목이 있어서, 설명을 아주 없애면 무엇을 넣는 칸인지
 *   알 수 없다. 항목마다 한 줄씩 다는 것만 피하면 된다.
 *   **ISMS-P 근거는 여기 있다** — 이 제품이 왜 이 기본값인지의 근거라 지우지 않는다.
 * @return array<string, array{label:string, note:string}>
 */
function vg_setting_groups(): array {
    return [
        'sla'      => ['label' => '조치 기한(SLA)',
                       'note'  => '컴플라이언스 판정이 "기한 초과"를 가르는 일수'],
        'judgment' => ['label' => '준수 판정 기준',
                       'note'  => '위반 건수로 준수/부분준수/미준수를 가른다 · 이력은 (최장 기한 + 여유일) 만큼 역산'],
        'session'  => ['label' => '세션 정책',
                       'note'  => 'ISMS-P 2.6.3 — 기준 시간이 지나면 자동 로그아웃'],
        'account'  => ['label' => '계정 정책',
                       'note'  => 'ISMS-P 2.5.1·2.5.6 — 로그인이 없는 대화형 계정을 미사용으로 판정'],
        'report'   => ['label' => 'AI 보고서',
                       'note'  => '보고서 작업큐 API 연동 — 주소는 경로 없이 호스트[:포트]까지'],
        'source'   => ['label' => '소스코드 공개',
                       'note'  => 'AGPL-3.0 제13조 — 화면 하단에 이 주소를 링크로 노출한다'],
    ];
}

/**
 * 설정 항목 정의(SSOT) — 설정 화면의 항목 목록이자 저장 시 검증 규칙.
 *   **기본값 숫자는 여기 두지 않는다.** 호출부가 자기 상수를 폴백으로 넘긴다
 *   (예: compliance.php 의 VG_COMPLIANCE_SLA_KEV_DAYS) — 같은 숫자를 두 곳에 두면 갈라진다.
 *   화면이 "기본값 N" 을 보여줄 수 있게 **상수의 이름만** 적어 둔다(값은 vg_setting_default()가
 *   그 상수에서 읽는다). default_div 는 상수 단위가 설정 단위와 다를 때의 나눗수다(초→분).
 *   group 은 vg_setting_groups() 의 키다.
 * @return array<string, array{label:string, desc:string, type:string, min:int, max:int, group:string, default_const:string, default_div?:int}>
 */
function vg_setting_defs(): array {
    return [
        'compliance.sla_kev_days' => [
            'label' => 'KEV 조치 기한(일)', 'type' => 'int', 'min' => 1, 'max' => 365,
            'group' => 'sla', 'default_const' => 'VG_COMPLIANCE_SLA_KEV_DAYS',
            'desc'  => 'KEV(실제 악용 확인) 등재 취약점을 조치해야 하는 기준 일수.',
        ],
        'compliance.sla_crit_days' => [
            'label' => 'CRITICAL 조치 기한(일)', 'type' => 'int', 'min' => 1, 'max' => 365,
            'group' => 'sla', 'default_const' => 'VG_COMPLIANCE_SLA_CRIT_DAYS',
            'desc'  => 'CRITICAL 등급 취약점 조치 기준 일수.',
        ],
        'compliance.sla_high_days' => [
            'label' => 'HIGH 조치 기한(일)', 'type' => 'int', 'min' => 1, 'max' => 365,
            'group' => 'sla', 'default_const' => 'VG_COMPLIANCE_SLA_HIGH_DAYS',
            'desc'  => 'HIGH 등급 취약점 조치 기준 일수.',
        ],
        'compliance.partial_max' => [
            'label' => '부분준수 상한(건)', 'type' => 'int', 'min' => 1, 'max' => 1000,
            'group' => 'judgment', 'default_const' => 'VG_COMPLIANCE_PARTIAL_MAX',
            'desc'  => '위반 1~이 값이면 부분준수, 초과하면 미준수로 판정합니다.',
        ],
        'compliance.history_lookback_margin_days' => [
            'label' => '이력 역산 여유일', 'type' => 'int', 'min' => 0, 'max' => 365,
            'group' => 'judgment', 'default_const' => 'VG_COMPLIANCE_HISTORY_MARGIN_DAYS',
            'desc'  => '최초 발견 시각을 되짚는 구간 = 가장 긴 조치 기한 + 이 여유일.',
        ],
        // 세션 만료는 **보안 통제**다. 단위를 분으로 둔 것은 관리자가 다루는 단위라서고,
        //   min 은 "설정으로 통제를 무력화할 수 없게" 하는 하한이다 — 0·1초 만료(로그인 불가)나
        //   무한 세션(만료 없음)을 저장할 수 있으면 그 자체가 장애·보안사고다.
        'session.idle_minutes' => [
            'label' => '세션 유휴 만료(분)', 'type' => 'int', 'min' => 5, 'max' => 720,
            'group' => 'session', 'default_const' => 'VG_SESSION_IDLE_SECONDS', 'default_div' => 60,
            'desc'  => '마지막 활동 이후 이 시간이 지나면 자동 로그아웃합니다(ISMS-P 2.6.3).',
        ],
        'session.absolute_minutes' => [
            'label' => '세션 절대 만료(분)', 'type' => 'int', 'min' => 30, 'max' => 1440,
            'group' => 'session', 'default_const' => 'VG_SESSION_ABSOLUTE_SECONDS', 'default_div' => 60,
            'desc'  => '유휴와 무관하게 로그인 시점부터 이 시간이 지나면 자동 로그아웃합니다.',
        ],
        'account.stale_login_days' => [
            'label' => '계정 미사용 판정(일)', 'type' => 'int', 'min' => 7, 'max' => 1095,
            'group' => 'account', 'default_const' => 'VG_ACCOUNT_STALE_LOGIN_DAYS',
            'desc'  => '이 일수 이상 로그인하지 않은 대화형 계정을 미사용으로 판정합니다(ISMS-P 2.5.1·2.5.6).',
        ],
        // AI 보고서 — 외부 작업큐 API 주소와 그 상태를 화면이 되묻는 방식. 기본값 상수는
        //   server/src/report_job.php 가 갖는다(값을 여기 다시 적으면 폴백과 화면이 갈라진다).
        'report.api_base_url' => [
            'label' => '보고서 API 주소', 'type' => 'url', 'min' => 1, 'max' => 255,
            'group' => 'report', 'default_const' => 'VG_REPORT_API_BASE_URL',
            'desc'  => '보고서 작업큐 API 의 base URL(http:// 또는 https://). 경로는 붙이지 않습니다.',
        ],
        'report.poll_interval_seconds' => [
            'label' => '진행 확인 간격(초)', 'type' => 'int', 'min' => 1, 'max' => 60,
            'group' => 'report', 'default_const' => 'VG_REPORT_POLL_INTERVAL_SECONDS',
            'desc'  => '보고서 생성 중일 때 화면이 상태를 다시 물어보는 간격.',
        ],
        'report.poll_max_attempts' => [
            'label' => '진행 확인 최대 횟수', 'type' => 'int', 'min' => 1, 'max' => 2000,
            'group' => 'report', 'default_const' => 'VG_REPORT_POLL_MAX_ATTEMPTS',
            'desc'  => '이 횟수를 넘으면 확인을 멈춥니다(작업은 서버에 남아 나중에 다시 볼 수 있습니다).',
        ],
        // 소스코드 주소 — AGPL 제13조(네트워크로 서비스를 받는 이용자에게도 소스를 준다)를
        //   화면에서 실효화하는 값이다. 포크해 배포하는 쪽은 자기 저장소를 가리켜야 하므로
        //   코드 상수가 아니라 설정이어야 한다. 기본값 상수는 server/src/view/layout.php 가 갖는다.
        //   type=link 인 이유: 저장소 주소에는 경로(/사용자/저장소)가 붙어서 type=url(경로 금지,
        //   base URL 자리)로는 저장 자체가 안 된다.
        'app.source_url' => [
            'label' => '소스코드 저장소 주소', 'type' => 'link', 'min' => 1, 'max' => 255,
            'group' => 'source', 'default_const' => 'VG_SOURCE_URL',
            'desc'  => '화면 하단 "소스코드 (AGPL-3.0)" 링크가 가리키는 주소. 포크해 배포한다면 자기 저장소 주소로 바꾸세요.',
        ],
    ];
}

/**
 * 이 키의 기본값(= 설정 행이 없을 때 실제로 쓰이는 폴백). 정의의 default_const 가 가리키는
 *   상수에서 읽는다 — 숫자를 여기 다시 적으면 폴백과 화면이 갈라진다.
 *   **상수를 가진 파일이 로드돼 있어야 한다**(compliance.php·account_inventory.php·auth.php).
 *   여기서 그 파일들을 require 하지는 않는다 — 이 파일은 모든 요청이 include 하는 경로에
 *   걸려 있어서, 판정 로직 전체를 끌어오면 값 하나 읽자고 요청마다 비용을 문다. 로드돼 있지
 *   않으면 null(= 기본값을 모른다)을 돌려주고 화면이 표시를 생략한다.
 */
function vg_setting_default(string $key): ?int {
    $def = vg_setting_defs()[$key] ?? null;
    $const = (string) ($def['default_const'] ?? '');
    if ($const === '' || !defined($const)) {
        return null;
    }
    return intdiv((int) constant($const), max(1, (int) ($def['default_div'] ?? 1)));
}

/**
 * 같은 기본값을 **표시용 문자열**로. 정수 항목은 vg_setting_default() 그대로고, 문자열 항목
 *   (type=url 등)은 상수를 문자열로 읽는다 — 설정 화면은 어차피 <input value> 로 그리므로
 *   타입마다 분기를 두지 않게 여기서 한 번만 좁힌다.
 */
function vg_setting_default_str(string $key): ?string {
    $def = vg_setting_defs()[$key] ?? null;
    $const = (string) ($def['default_const'] ?? '');
    if ($const === '' || !defined($const)) {
        return null;
    }
    if (vg_setting_is_int($key)) {
        return (string) vg_setting_default($key);
    }
    return (string) constant($const);
}

/** 이 항목이 정수인가. 정의가 없으면 정수로 본다(기존 항목이 전부 정수였다). */
function vg_setting_is_int(string $key): bool {
    return (string) (vg_setting_defs()[$key]['type'] ?? 'int') === 'int';
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
 * 주소 항목(type=url·link)의 검증. 통과하면 null, 아니면 그 입력 아래에 붙일 한글 문구.
 *   설정 화면이 저장 전에 부른다 — 여기서 통과한 값이 그대로 서버측 HTTP 호출의 목적지가
 *   되므로, 스킴을 http/https 로 못박고 base URL 이 아닌 것(경로·질의·조각)을 거른다.
 *   $allowPath 는 type=link 용이다 — 저장소 주소(/사용자/저장소)처럼 경로가 있어야 하는
 *   항목이 있다. 그때도 질의문자열·조각은 여전히 거른다(링크 자리지 API 호출 자리가 아니다).
 */
function vg_setting_url_error(string $raw, int $maxLen, bool $allowPath = false): ?string {
    if ($raw === '') {
        return '주소를 입력하세요.';
    }
    if (mb_strlen($raw) > $maxLen) {
        return sprintf('%d자 이내로 입력하세요.', $maxLen);
    }
    $p = parse_url($raw);
    if ($p === false || !isset($p['scheme'], $p['host'])
        || !in_array(strtolower((string) $p['scheme']), ['http', 'https'], true)
        || (string) $p['host'] === '') {
        return 'http:// 또는 https:// 로 시작하는 주소만 가능합니다.';
    }
    if (isset($p['query']) || isset($p['fragment'])) {
        return '질의문자열(?)·조각(#) 없이 주소만 입력하세요.';
    }
    if (!$allowPath && trim((string) ($p['path'] ?? ''), '/') !== '') {
        return '경로·질의문자열 없이 주소(호스트[:포트])까지만 입력하세요.';
    }
    return null;
}

/**
 * 문자열 설정값. 비어 있으면 $default — 저장된 값이 빈 문자열이어도 호출부가 빈 주소로
 *   나가지 않는다. 조회는 vg_settings_all() 의 요청당 캐시를 그대로 쓴다.
 */
function vg_setting_str(string $key, string $default): string {
    $raw = trim((string) (vg_settings_all()[$key] ?? ''));
    return $raw !== '' ? $raw : $default;
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
