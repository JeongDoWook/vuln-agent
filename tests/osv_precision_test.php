<?php
declare(strict_types=1);
require_once __DIR__ . '/../server/src/feeds/osv.php';
$fail = 0;
$check = static function (string $label, $got, $want) use (&$fail): void {
    if ($got !== $want) { fwrite(STDERR, "FAIL {$label}: got=" . var_export($got, true) . " want=" . var_export($want, true) . "\n"); $fail++; }
};
$multi = ['id' => 'CVE-2099-0001', 'affected' => [[
    'package' => ['ecosystem' => 'Go', 'name' => 'example.org/lib'],
    'ranges' => [['type' => 'SEMVER', 'events' => [
        ['introduced' => '1.0.0'], ['fixed' => '1.2.0'],
        ['introduced' => '3.0.0'], ['fixed' => '3.4.0'],
    ]]],
]]];
$check('first vulnerable interval', vg_osv_fixed($multi, 'example.org/lib', 'Go', 'v1.1.0'), '1.2.0');
$check('gap is unaffected', vg_osv_fixed($multi, 'example.org/lib', 'Go', 'v2.0.0'), null);
$check('second vulnerable interval', vg_osv_fixed($multi, 'example.org/lib', 'Go', 'v3.2.0'), '3.4.0');
$check('fixed version is unaffected', vg_osv_fixed($multi, 'example.org/lib', 'Go', 'v3.4.0'), null);
$check('multi-range is not flattened globally', vg_osv_global_fixed($multi, 'example.org/lib', 'Go', 'v1.1.0'), null);
$ceiling = ['type' => 'ECOSYSTEM', 'events' => [['introduced' => '0'], ['last_affected' => '2.1.214']]];
$check('last_affected is not a fix', vg_osv_range_fixed($ceiling, '2.1.200', 'npm'), null);
$limit = ['type' => 'ECOSYSTEM', 'events' => [['introduced' => '1.0.0'], ['limit' => '2.0.0']]];
$check('limit is not a fix', vg_osv_range_fixed($limit, '1.5.0', 'npm'), null);
$git = ['type' => 'GIT', 'events' => [['introduced' => 'aaa'], ['fixed' => 'bbb']]];
$check('git hashes are not ordered as versions', vg_osv_range_fixed($git, 'aab', 'upstream'), null);
$q = vg_osv_package_query([
    'name' => 'libcurl4', 'version' => '7.88.1-10+deb12u5+b1',
    'source_pkg' => 'curl', 'source_version' => '7.88.1-10+deb12u5',
], 'Debian:12');
$check('Debian source package name', $q['key'] ?? null, 'curl');
$check('Debian source version', $q['q']['version'] ?? null, '7.88.1-10+deb12u5');
$q2 = vg_osv_package_query(['name' => 'requests', 'version' => '2.31.0'], 'PyPI');
$check('language package keeps installed version', $q2['q']['version'] ?? null, '2.31.0');
if ($fail > 0) { exit(1); }
echo "osv precision tests: ok\n";