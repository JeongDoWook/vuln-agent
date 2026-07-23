<?php
declare(strict_types=1);

/** UI 공통 구조 회귀 테스트 — 서버나 DB 없이 소스 구조만 검사한다. */
$root = dirname(__DIR__);
$public = $root . '/server/public';
$fail = 0;
$check = static function (bool $ok, string $label) use (&$fail): void {
    if (!$ok) { printf("  ✗ %s\n", $label); $fail++; }
};

$phpFiles = glob($public . '/*.php') ?: [];
foreach ($phpFiles as $file) {
    $source = (string) file_get_contents($file);
    $name = basename($file);
    $check(!preg_match('/<(?:table|dialog)\b/i', $source), "$name 직접 table/dialog 금지");
    $check(!preg_match('/\s(?:onclick|onsubmit)\s*=/i', $source), "$name 인라인 이벤트 금지");
    $check(!str_contains($source, 'confirm('), "$name 브라우저 confirm 금지");
    $check(!preg_match('/\sstyle="/i', $source), "$name 인라인 style 금지");
}

$titlePages = [
    'activity.php', 'advisories.php', 'agent-tokens.php', 'api-tokens.php', 'assets.php',
    'changes.php', 'compliance_rules.php', 'connectors.php', 'cves.php', 'index.php',
    'packages.php', 'permissions.php', 'profile.php', 'users.php', 'vendor.php',
];
foreach ($titlePages as $name) {
    $source = (string) file_get_contents($public . '/' . $name);
    $check(str_contains($source, 'vg_page_title('), "$name 공통 페이지 제목 사용");
}

foreach (['agent-tokens.php', 'api-tokens.php', 'users.php'] as $name) {
    $source = (string) file_get_contents($public . '/' . $name);
    $check(str_contains($source, 'vg_toolbar('), "$name 검색 툴바 제공");
    $check(str_contains($source, 'prepare('), "$name 검색 SQL 바인딩");
}

$connectorPhp = (string) file_get_contents($public . '/connectors.php');
$connectorJs = (string) file_get_contents($public . '/assets/js/connectors.js');
$check(str_contains($connectorPhp, 'data-feed-preview'), '커넥터 미리보기 data 속성');
$check(str_contains($connectorJs, "closest('[data-feed-preview]')"), '커넥터 미리보기 이벤트 위임');

if ($fail > 0) { printf("ui_structure_test: %d건 실패\n", $fail); exit(1); }
printf("ui_structure_test: 전부 통과\n");