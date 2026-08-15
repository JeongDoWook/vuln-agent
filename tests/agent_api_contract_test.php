<?php
declare(strict_types=1);

/** Installed-agent poll/progress/ingest compatibility contract. Runs without a server or DB. */
$root = dirname(__DIR__);
$decoded = json_decode((string) file_get_contents($root . '/tests/fixtures/route-query-contract.json'), true);
if (!is_array($decoded) || !isset($decoded['agent_api'])) { throw new RuntimeException('invalid agent API contract JSON'); }
$contract = $decoded['agent_api'];
if (!function_exists('str_contains')) {
    function str_contains(string $haystack, string $needle): bool { return $needle === '' || strpos($haystack, $needle) !== false; }
}
$sources = [
    'install' => (string) file_get_contents($root . '/agent/install-agent.sh'),
    'agent' => (string) file_get_contents($root . '/agent/vuln-inventory-agent.sh'),
    'poll' => (string) file_get_contents($root . '/server/public/agent-poll.php'),
    'progress' => (string) file_get_contents($root . '/server/public/agent-progress.php'),
    'ingest' => (string) file_get_contents($root . '/server/public/ingest.php'),
    'config' => (string) file_get_contents($root . '/server/src/config.php'),
];
$failures = [];
$check = static function (bool $ok, string $message) use (&$failures): void {
    if (!$ok) { $failures[] = $message; }
};

foreach ($contract['install']['required_options'] as $option) {
    $check(str_contains($sources['install'], $option . ')'), "installer option removed: $option");
}
$check(str_contains($sources['install'], '*/ingest.php)') && str_contains($sources['install'], 'SERVER="$SERVER/ingest.php"'),
    'installer must continue normalizing --server to /ingest.php');
$check(str_contains($sources['install'], 'POLL_URL="\${SEND_URL%ingest.php}agent-poll.php"'),
    'installer poll endpoint derivation drifted');

foreach (['poll', 'progress', 'ingest'] as $name) {
    $api = $contract[$name];
    $endpoint = $sources[$name];
    $check(str_contains($endpoint, "REQUEST_METHOD") && str_contains($endpoint, "'{$api['method']}'"), "$name method guard removed");
    foreach ($api['auth_headers'] as $header) {
        $haystacks = [$endpoint, $sources['config'], $sources[$api['consumer'] === 'agent/install-agent.sh' ? 'install' : 'agent']];
        $check(str_contains(implode("\n", $haystacks), $header), "$name auth header removed: $header");
    }
    foreach ($api['error_statuses'] as $status) {
        $check(str_contains($endpoint, (string) $status), "$name status removed: $status");
    }
    foreach ($api['response_fields'] as $field) {
        $check(str_contains($endpoint, "'$field'") || str_contains($endpoint, "\"$field\""), "$name response field removed: $field");
    }
}

$pollConsumer = $sources['install'];
foreach ($contract['poll']['response_fields'] as $field) {
    $check(str_contains($pollConsumer, ".$field") && str_contains($pollConsumer, "\"$field\""),
        "installer no longer consumes poll field: $field");
}

foreach ($contract['progress']['request_fields'] as $field) {
    $check(str_contains($sources['progress'], "'$field'") && str_contains($sources['agent'], "$field="),
        "progress request field removed: $field");
}
foreach ($contract['progress']['states'] as $state) {
    $check(str_contains($sources['progress'], "'$state'"), "progress state removed: $state");
}
$check(str_contains($sources['agent'], '"cancel_requested":true'), 'agent cancellation response handling removed');

foreach ($contract['ingest']['request_fields'] as $field) {
    $check(str_contains($sources['ingest'], "['$field']") || str_contains($sources['ingest'], "'$field'"),
        "ingest request field removed: $field");
}
$check(str_contains($sources['agent'], "-H 'Content-Type: application/json'")
    && str_contains($sources['agent'], '--data-binary @"$OUT"'), 'agent JSON ingest upload contract drifted');
$check(str_contains($sources['agent'], 'X-Agent-Timestamp:') && str_contains($sources['agent'], 'X-Agent-Nonce:'),
    'agent ingest replay-protection headers removed');
$check(str_contains($sources['agent'], 'if (cid != "") sub('), 'agent command_id payload injection removed');

if ($failures !== []) {
    foreach ($failures as $failure) { fwrite(STDERR, "agent API contract: {$failure}\n"); }
    exit(1);
}
echo "agent API contract: ok\n";
