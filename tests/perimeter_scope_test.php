<?php
declare(strict_types=1);

require __DIR__ . '/../server/src/matcher.php';

$allow = ['tcp/22' => true, 'tcp/443' => true, 'tcp/8080' => true];
$cases = [
    ['EXTERNAL', 0, 'tcp', 3306, true,  'FILTERED'],
    ['EXTERNAL', 0, 'tcp', 6443, true,  'FILTERED'],
    ['EXTERNAL', 0, 'tcp', 10250, true, 'FILTERED'],
    ['EXTERNAL', 0, 'tcp', 111, true,   'FILTERED'],
    ['EXTERNAL', 0, 'tcp', 22, true,    'EXTERNAL'],
    ['EXTERNAL', 0, 'TCP', 443, true,   'EXTERNAL'],
    ['EXTERNAL', 0, 'tcp', 8080, true,  'EXTERNAL'],
    ['EXTERNAL', 1, 'tcp', 3306, true,  'EXTERNAL'],
    ['EXTERNAL', 0, 'tcp', 3306, false, 'EXTERNAL'],
    ['LOCAL',    0, 'tcp', 3306, true,  'LOCAL'],
];

foreach ($cases as $i => [$scope, $containerId, $proto, $port, $enabled, $expected]) {
    $actual = vg_apply_host_perimeter_scope($scope, $containerId, $proto, $port, $enabled, $allow);
    if ($actual !== $expected) {
        fwrite(STDERR, 'case ' . $i . ': expected ' . $expected . ', got ' . $actual . PHP_EOL);
        exit(1);
    }
}

echo 'perimeter scope tests passed' . PHP_EOL;
