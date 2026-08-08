<?php
declare(strict_types=1);

/** UI 운영 설정·감사 로그 마스킹 단위 테스트. */
require_once __DIR__ . '/../server/src/ui_config.php';
require_once __DIR__ . '/../server/src/audit.php';
require_once __DIR__ . '/../server/src/distro.php';

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
putenv('UI_DASHBOARD_ACTIONABLE_STATUSES=external,loaded,installed,bad');
$eq('긴급 상태 화이트리스트', vg_ui_dashboard_actionable_statuses(), ['EXTERNAL', 'LOADED']);
$eq('긴급 상태 SQL도 검증된 값만 사용', vg_ui_dashboard_actionable_statuses_sql(), "'EXTERNAL','LOADED'");
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

putenv('UI_PER_PAGE_OPTIONS');
putenv('UI_PER_PAGE_DEFAULT');
putenv('UI_DASHBOARD_URGENT_LIMIT');
putenv('UI_DASHBOARD_ACTIONABLE_STATUSES');
putenv('UI_TREND_LIMIT');
putenv('UI_FILTER_OPTION_LIMIT');

if ($fail > 0) {
    printf("ui_config_test: %d건 실패\n", $fail);
    exit(1);
}
printf("ui_config_test: 전부 통과\n");