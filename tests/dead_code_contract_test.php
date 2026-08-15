<?php
declare(strict_types=1);

/** #599 W4에서 제거한 내부 계약이 조용히 되살아나지 않는지 검사한다. */
$root = dirname(__DIR__);
$fail = 0;
$check = static function (bool $ok, string $label) use (&$fail): void {
    if (!$ok) {
        fwrite(STDERR, "  ✗ {$label}\n");
        $fail++;
    }
};
$read = static function (string $path) use ($root): string {
    return (string) file_get_contents($root . '/' . $path);
};

$server = '';
$it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root . '/server'));
foreach ($it as $file) {
    if ($file->isFile() && preg_match('/\.(?:php|js|css)$/', $file->getFilename())) {
        $server .= (string) file_get_contents($file->getPathname());
    }
}
foreach (['vg_info_icon', 'vg_stacked_bar', 'vg_gauge', 'vg_sparkline',
          'vg_ui_dashboard_actionable_statuses', 'UI_DASHBOARD_ACTIONABLE_STATUSES'] as $dead) {
    $check(strpos($server, $dead) === false, "폐기 식별자 없음: {$dead}");
}

$css = $read('server/public/assets/app.css');
foreach (['.info-icon', '.riskbar--lg', '.gauge', '.spark', '.page--api-tokens'] as $selector) {
    $check(strpos($css, $selector) === false, "폐기 CSS 없음: {$selector}");
}
$check(strpos($css, '.help {') !== false, '공용 도움말 CSS 유지');
$check(strpos($css, '.legend--inline') !== false, 'host.php가 쓰는 인라인 범례 CSS 유지');

$appJs = $read('server/public/assets/app.js');
$check(!preg_match('/function\s+refresh\s*\(\s*schedule\s*\)/', $appJs), 'refresh 미사용 인자 없음');
$check(strpos($appJs, 'refresh(true)') === false, 'refresh 불필요 인자 호출 없음');

$connectorsJs = $read('server/public/assets/js/connectors.js');
$check(!preg_match('/function\s+vgGenericCollect\s*\(\)\s*\{\s*var\s+form\s*=/', $connectorsJs),
    'vgGenericCollect 미사용 form 변수 없음');

$host = $read('server/public/host.php');
$check(strpos($host, '재시작·재부팅 표에 보여줄 최대 건수') === false, '사라진 상수 설명 주석 없음');
$check(strpos($host, '리소스 추이 차트에 그릴 최대 스캔 건수') === false, '사라진 상수 설명 주석 없음');

if ($fail > 0) {
    fwrite(STDERR, "dead_code_contract_test: {$fail}건 실패\n");
    exit(1);
}
echo "dead_code_contract_test: 전부 통과\n";
