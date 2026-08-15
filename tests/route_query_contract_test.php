<?php
declare(strict_types=1);

/** Public route/query/redirect contract snapshot. Runs without a server or DB. */
$root = dirname(__DIR__);
$fixturePath = $root . '/tests/fixtures/route-query-contract.json';
$contract = json_decode((string) file_get_contents($fixturePath), true);
if (!is_array($contract)) { throw new RuntimeException('invalid route contract JSON'); }
if (!function_exists('str_contains')) {
    function str_contains(string $haystack, string $needle): bool { return $needle === '' || strpos($haystack, $needle) !== false; }
}
if (!function_exists('str_starts_with')) {
    function str_starts_with(string $haystack, string $needle): bool { return strncmp($haystack, $needle, strlen($needle)) === 0; }
}
$failures = [];
$check = static function (bool $ok, string $message) use (&$failures): void {
    if (!$ok) { $failures[] = $message; }
};

$registered = array_keys($contract['routes'] ?? []);
sort($registered);
$actual = array_map(static function (string $path): string { return '/' . basename($path); },
    glob($root . '/server/public/*.php') ?: []);
sort($actual);
$check($registered === $actual, 'registry must match every server/public/*.php entrypoint exactly');

$extractQueryKeys = static function (string $source): array {
    $keys = [];
    preg_match_all('/\$_GET\s*\[\s*[\'\"]([^\'\"]+)[\'\"]\s*\]/', $source, $literal);
    $keys = array_merge($keys, $literal[1] ?? []);
    preg_match_all('/filter_input\(\s*INPUT_GET\s*,\s*[\'\"]([^\'\"]+)[\'\"]/', $source, $filtered);
    $keys = array_merge($keys, $filtered[1] ?? []);
    preg_match_all('/vg_page\(\s*(?:[\'\"]([^\'\"]+)[\'\"])?\s*\)/', $source, $pages, PREG_SET_ORDER);
    foreach ($pages as $match) { $keys[] = ($match[1] ?? '') !== '' ? $match[1] : 'page'; }
    preg_match_all('/vg_perpage\(([^;]*)\)/', $source, $perPages, PREG_SET_ORDER);
    foreach ($perPages as $match) {
        $keys[] = preg_match('/,\s*[\'\"]([^\'\"]+)[\'\"]/', $match[1], $named) ? $named[1] : 'per_page';
    }
    $keys = array_values(array_unique($keys));
    sort($keys);
    return $keys;
};

$extractMethods = static function (string $source): array {
    if (str_contains($source, "['GET', 'HEAD']")) { return ['GET', 'HEAD']; }
    if (preg_match('/REQUEST_METHOD[^\n]+!==\s*[\'\"]POST[\'\"]/', $source)) { return ['POST']; }
    if (preg_match('/REQUEST_METHOD[^\n]+!==\s*[\'\"]GET[\'\"]/', $source)) { return ['GET']; }
    $methods = ['GET'];
    if (str_contains($source, '$_POST') || str_contains($source, 'INPUT_POST')
        || preg_match('/REQUEST_METHOD[^\n]+===\s*[\'\"]POST[\'\"]/', $source)) {
        $methods[] = 'POST';
    }
    return $methods;
};

foreach (($contract['routes'] ?? []) as $route => $entry) {
    $path = $root . '/server/public/' . ltrim($route, '/');
    $source = is_file($path) ? (string) file_get_contents($path) : '';
    $check($source !== '', "$route source exists");
    $check(($entry['methods'] ?? []) === $extractMethods($source), "$route method contract drifted");
    if (($entry['query_policy'] ?? '') !== 'passthrough_all') {
        $expected = $entry['query_keys'] ?? [];
        sort($expected);
        $check($expected === $extractQueryKeys($source), "$route accepted query keys drifted");
    } else {
        $check(str_contains($source, '$qs = $_GET;'), "$route must preserve all legacy query parameters");
    }

    $auth = (string) ($entry['auth'] ?? '');
    if (str_starts_with($auth, 'menu:')) {
        $menu = substr($auth, 5);
        $check(str_contains($source, "vg_require_menu('$menu')"), "$route auth guard drifted");
    } elseif (str_starts_with($auth, 'menu_any:')) {
        $menus = explode(',', substr($auth, 9));
        $check(str_contains($source, 'vg_require_menu_any('), "$route menu_any guard missing");
        foreach ($menus as $menu) { $check(str_contains($source, "'$menu'"), "$route auth menu $menu missing"); }
    } elseif ($auth === 'login') {
        $check(str_contains($source, 'vg_require_login()'), "$route login guard missing");
    } elseif ($auth === 'agent_token') {
        $check(str_contains($source, "vg_auth_token('X-Agent-Token')"), "$route agent-token guard missing");
    }

    $response = (string) ($entry['response'] ?? '');
    if ($response === 'json') { $check(str_contains($source, 'application/json'), "$route JSON response marker missing"); }
    if ($response === 'html') { $check(str_contains($source, 'vg_header(') || $route === '/login.php', "$route HTML response marker missing"); }
    foreach (($entry['redirects'] ?? []) as $redirect) {
        $targetPath = explode('?', (string) $redirect['target'], 2)[0];
        $check(str_contains($source, "Location: $targetPath"), "$route redirect target drifted: $targetPath");
        $check(str_contains($source, (string) $redirect['status']) || ($redirect['status'] === 302 && str_contains($source, 'Location:')),
            "$route redirect status drifted");
    }
    $check(array_key_exists('in_repo_callers', $entry), "$route caller classification missing");
    $check(!empty($entry['external_consumers']), "$route external consumer class missing (use unknown when unverified)");
}

$language = (string) file_get_contents($root . '/server/public/language-packages.php');
$check(str_contains($language, '$qs[\'tab\'] = \'lang\';') && str_contains($language, 'http_build_query($qs)')
    && str_contains($language, 'true, 302'), 'language-packages legacy query/302 compatibility drifted');
$control = (string) file_get_contents($root . '/server/public/control_mapping.php');
$check(str_contains($control, '$_GET[\'control\']') && str_contains($control, '/control.php?fw=')
    && str_contains($control, '&control=') && str_contains($control, 'true, 302'),
    'control_mapping legacy control query/302 compatibility drifted');

if ($failures !== []) {
    foreach ($failures as $failure) { fwrite(STDERR, "route contract: {$failure}\n"); }
    exit(1);
}
echo 'route contract: ok (' . count($registered) . " routes)\n";
