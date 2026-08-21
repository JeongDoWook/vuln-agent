<?php
declare(strict_types=1);

/** UI 운영 설정·감사 로그 마스킹 단위 테스트. */
require_once __DIR__ . '/../server/src/ui_config.php';
require_once __DIR__ . '/../server/src/audit.php';
require_once __DIR__ . '/../server/src/distro.php';
require_once __DIR__ . '/../server/src/setting.php';

$fail = 0;
$eq = static function (string $label, $got, $want) use (&$fail): void {
    if ($got !== $want) {
        printf("  ✗ [%s] 기대 %s, 실제 %s\n", $label, var_export($want, true), var_export($got, true));
        $fail++;
    }
};

putenv('UI_PER_PAGE_OPTIONS=5,20,20,50,999,bad');
putenv('UI_PER_PAGE_DEFAULT=50');
$eq('페이지 선택지 검증·중복 제거', vg_ui_per_page_options(), [5, 20, 50]);
$eq('설정된 기본 페이지 크기', vg_ui_per_page_default(), 50);
putenv('UI_PER_PAGE_DEFAULT=30');
$eq('선택지 밖 기본값은 첫 선택지', vg_ui_per_page_default(), 5);
putenv('UI_DASHBOARD_URGENT_LIMIT=999');
$eq('대시보드 한도 상한', vg_ui_dashboard_urgent_limit(), 30);
putenv('UI_TREND_LIMIT=-1');
$eq('추이 한도 하한', vg_ui_trend_limit(), 10);
putenv('UI_FILTER_OPTION_LIMIT=99999');
$eq('필터 선택지 한도 상한', vg_ui_filter_option_limit(), 2000);
$eq('Wolfi OSV 생태계', vg_osv_ecosystem('wolfi', '20230201'), 'Wolfi');
$eq('Wolfi는 판정 가능', vg_distro_unsupported('wolfi', '20230201'), null);

$clean = vg_audit_sanitize([
    'username' => 'alice',
    'password' => 'plain',
    'nested' => ['api_token' => 'secret-token', 'role' => 'user'],
    'csrf_value' => 'csrf-secret',
]);
$eq('일반 감사값 유지', $clean['username'], 'alice');
$eq('비밀번호 마스킹', $clean['password'], '[REDACTED]');
$eq('중첩 토큰 마스킹', $clean['nested']['api_token'], '[REDACTED]');
$eq('중첩 일반값 유지', $clean['nested']['role'], 'user');
$eq('CSRF 마스킹', $clean['csrf_value'], '[REDACTED]');

// 접속기록 5요소 — subject/action 이 마스킹을 우회하지 않는지, 수행업무 정규화가 맞는지.
$eq('대상 자원은 그대로', vg_audit_subject('web01.example.com'), 'web01.example.com');
$eq('대상에 섞인 비밀번호 마스킹', vg_audit_subject('user=alice password=plain'), 'user=alice password=[REDACTED]');
$eq('대상에 섞인 토큰 마스킹', vg_audit_subject('token: abc123'), 'token=[REDACTED]');
$eq('빈 대상은 NULL', vg_audit_subject('   '), null);
$eq('자유 텍스트 길이 제한', vg_audit_redact_text(str_repeat('a', 600), 500), str_repeat('a', 500));
$eq('열람은 READ', vg_activity_action('view_host'), 'READ');
$eq('로그인은 LOGIN', vg_activity_action('login_fail'), 'LOGIN');
$eq('폐기는 DELETE', vg_activity_action('token_revoke'), 'DELETE');
$eq('발급은 CREATE', vg_activity_action('agent_token_issue'), 'CREATE');
$eq('내보내기는 EXPORT', vg_activity_action('export_data'), 'EXPORT');
$eq('모르는 코드는 OTHER', vg_activity_action('무슨_이벤트'), 'OTHER');
$eq('자산 등급 확정은 UPDATE', vg_activity_action('host_set_grade'), 'UPDATE');
$eq('자산 검토 저장은 UPDATE', vg_activity_action('host_grade_review_save'), 'UPDATE');
$eq('자산 검토 삭제는 DELETE', vg_activity_action('host_grade_review_clear'), 'DELETE');

// ── 운영 설정(tb_setting) ─────────────────────────────────────────────────
//   이 테스트는 DB 없는 컨테이너에서 돈다 → vg_settings_all() 이 빈 배열이라
//   "설정을 저장하지 않은 상태"를 그대로 재현한다. 가장 중요한 회귀는 이것이다:
//   **설정이 비어 있으면 호출부 상수(폴백)가 그대로 나와야 한다.**
$eq('설정 없으면 유휴 만료 폴백(30분)', vg_setting_int('session.idle_minutes', 30), 30);
$eq('설정 없으면 절대 만료 폴백(720분)', vg_setting_int('session.absolute_minutes', 720), 720);
$eq('설정 없으면 미사용 판정 폴백(90일)', vg_setting_int('account.stale_login_days', 90), 90);

// 만료를 0·무한으로 만들 수 없어야 한다 — 읽을 때도 정의 범위로 자른다.
$eq('유휴 만료 하한 클램프', vg_setting_int('session.idle_minutes', 0), 5);
$eq('절대 만료 상한 클램프', vg_setting_int('session.absolute_minutes', 999999), 1440);
$eq('미사용 판정 하한 클램프', vg_setting_int('account.stale_login_days', 1), 7);
$eq('정의 없는 키는 클램프 대상 아님', vg_setting_int('없는.키', 999999), 999999);
$eq('상한 조회', vg_setting_max('session.absolute_minutes', 0), 1440);
$eq('정의 없는 키의 상한은 기본값', vg_setting_max('없는.키', 42), 42);

// 정의 자체의 무결성 — min>max 나 빈 라벨이면 설정 화면이 조용히 망가진다.
//   타입은 설정 화면이 아는 세 가지뿐이다(int=숫자 입력, url=주소 입력, link=화면에 거는 링크
//   — 저장소 주소처럼 경로가 붙는다). 모르는 타입이 들어오면 화면이 어떤 입력을 그릴지 못
//   정하므로 여기서 막는다.
foreach (vg_setting_defs() as $key => $def) {
    $eq("정의 min<max ($key)", $def['min'] < $def['max'], true);
    $eq("정의 라벨 있음 ($key)", $def['label'] !== '', true);
    $eq("정의 설명 있음 ($key)", $def['desc'] !== '', true);
    $eq("정의 타입 허용값 ($key)", in_array($def['type'], ['int', 'url', 'link'], true), true);
}

// 주소 항목(type=url) — 여기서 통과한 값이 그대로 서버측 HTTP 호출의 목적지가 되므로,
//   스킴·경로 검증이 무너지면 안 된다.
$eq('빈 주소는 거절', vg_setting_url_error('', 255) !== null, true);
$eq('http 주소 허용', vg_setting_url_error('http://172.17.0.1:8000', 255), null);
$eq('https 주소 허용', vg_setting_url_error('https://reports.example.com', 255), null);
$eq('끝 슬래시만 있는 것은 경로 아님', vg_setting_url_error('http://10.0.0.5:8000/', 255), null);
$eq('다른 스킴은 거절', vg_setting_url_error('ftp://example.com', 255) !== null, true);
$eq('스킴 없는 값은 거절', vg_setting_url_error('172.17.0.1:8000', 255) !== null, true);
$eq('경로가 붙으면 거절', vg_setting_url_error('http://example.com/jobs', 255) !== null, true);
$eq('질의문자열이 붙으면 거절', vg_setting_url_error('http://example.com?a=1', 255) !== null, true);
$eq('길이 초과는 거절', vg_setting_url_error('http://' . str_repeat('a', 300), 255) !== null, true);

// type=link(화면에 거는 링크 — 저장소 주소)는 경로를 허용한다. 그래도 스킴은 http/https 로
//   묶이고 질의·조각은 여전히 거절한다 — 링크 자리에 javascript: 가 들어오면 그대로 XSS 다.
$eq('link 은 경로 허용', vg_setting_url_error('https://github.com/사용자/저장소', 255, true), null);
$eq('link 도 다른 스킴은 거절', vg_setting_url_error('javascript:alert(1)', 255, true) !== null, true);
$eq('link 도 질의문자열은 거절', vg_setting_url_error('https://example.com/a?b=1', 255, true) !== null, true);

// 문자열 설정 리더 — 저장된 값이 없으면 호출부 기본값이 그대로 나와야 한다(정수와 같은 규약).
$eq('설정 없으면 문자열 폴백', vg_setting_str('report.api_base_url', 'http://fallback:1'), 'http://fallback:1');
$eq('정수 항목 판별', vg_setting_is_int('report.poll_interval_seconds'), true);
$eq('주소 항목 판별', vg_setting_is_int('report.api_base_url'), false);

putenv('UI_PER_PAGE_OPTIONS');
putenv('UI_PER_PAGE_DEFAULT');
putenv('UI_DASHBOARD_URGENT_LIMIT');
putenv('UI_TREND_LIMIT');
putenv('UI_FILTER_OPTION_LIMIT');

if ($fail > 0) {
    printf("ui_config_test: %d건 실패\n", $fail);
    exit(1);
}
printf("ui_config_test: 전부 통과\n");
