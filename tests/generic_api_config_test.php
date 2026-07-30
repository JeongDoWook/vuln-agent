<?php
declare(strict_types=1);

/** 범용 API 커넥터가 실행 가능한 역할만 받아들이는지 검증한다. */
interface VgFeedConnector {
    public function run(PDO $pdo, array $conn): array;
    public function preview(PDO $pdo, array $conn): array;
}
require_once dirname(__DIR__) . '/server/src/feeds/generic_api.php';

$fail = 0;
$check = static function (bool $ok, string $label) use (&$fail): void {
    if (!$ok) {
        printf("  ✗ %s\n", $label);
        $fail++;
    }
};

$base = [
    'url_template' => 'https://example.test/vulnerabilities',
    'response' => ['field_mapping' => ['cve_id' => 'cve']],
];

foreach (['identity', 'priority'] as $role) {
    $parsed = vg_generic_parse_config(['role' => $role] + $base);
    $check($parsed['role'] === $role, "$role 역할 허용");
}

$vendor = $base;
$vendor['role'] = 'vendor';
$vendor['response']['field_mapping'] += [
    'vendor' => 'vendor',
    'release_major' => 'release',
    'pkg_name' => 'package',
    'fixed_evr' => 'fixed',
];
$check(vg_generic_parse_config($vendor)['role'] === 'vendor', 'vendor 역할 허용');

$legacy = $base;
$legacy['role'] = 'compliance';
try {
    vg_generic_parse_config($legacy);
    $check(false, '기존 compliance 설정 거절');
} catch (RuntimeException $e) {
    $check(
        str_contains($e->getMessage(), '지원하지 않는 role (compliance)')
        && str_contains($e->getMessage(), 'identity, priority, vendor'),
        '기존 compliance 설정을 지원 역할 안내와 함께 거절'
    );
}

if ($fail > 0) {
    printf("generic_api_config_test: %d건 실패\n", $fail);
    exit(1);
}
printf("generic_api_config_test: 전부 통과\n");
