<?php
declare(strict_types=1);

/** UI 운영 설정·감사 로그 마스킹 단위 테스트. */
require_once __DIR__ . '/../server/src/ui_config.php';
require_once __DIR__ . '/../server/src/audit.php';

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

putenv('UI_PER_PAGE_OPTIONS');
putenv('UI_PER_PAGE_DEFAULT');
putenv('UI_DASHBOARD_URGENT_LIMIT');
putenv('UI_TREND_LIMIT');

if ($fail > 0) {
    printf("ui_config_test: %d건 실패\n", $fail);
    exit(1);
}
printf("ui_config_test: 전부 통과\n");