<?php
declare(strict_types=1);

require_once __DIR__ . '/../server/src/assetgrade.php';

function fail_test(string $message): never { fwrite(STDERR, "FAIL: $message\n"); exit(1); }
function same(mixed $expected, mixed $actual, string $message): void {
    if ($expected !== $actual) { fail_test($message . ' expected=' . var_export($expected, true) . ' actual=' . var_export($actual, true)); }
}
function truth(bool $value, string $message): void { if (!$value) { fail_test($message); } }

$pdo = new PDO('sqlite::memory:');
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$pdo->exec('CREATE TABLE tb_exposure (scan_id INTEGER, proc TEXT, proto TEXT, bind_addr TEXT, port INTEGER, scope TEXT)');
$pdo->exec('CREATE TABLE tb_process (scan_id INTEGER, comm TEXT)');
$pdo->exec('CREATE TABLE tb_host (host_id INTEGER PRIMARY KEY, fqdn TEXT, is_deleted INTEGER DEFAULT 0, grade TEXT, grade_reason TEXT, approved_by INTEGER, approved_at TEXT, grade_suggested TEXT, grade_suggested_reason TEXT)');

function add_exposure(PDO $pdo, int $scan, string $proc, int $port, ?string $scope, string $bind = '10.0.0.1'): void {
    $st = $pdo->prepare('INSERT INTO tb_exposure VALUES (?, ?, ?, ?, ?, ?)');
    $st->execute([$scan, $proc, 'tcp', $bind, $port, $scope]);
}
function add_process(PDO $pdo, int $scan, string $comm): void {
    $st = $pdo->prepare('INSERT INTO tb_process VALUES (?, ?)');
    $st->execute([$scan, $comm]);
}

foreach (['LOCAL', 'FILTERED', '-', 'UNKNOWN'] as $i => $scope) {
    add_exposure($pdo, 10 + $i, 'rsyslogd', 514, $scope);
    same(null, vg_asset_grade_suggest($pdo, 10 + $i), "$scope listener must not be remote evidence");
}
add_exposure($pdo, 20, 'rsyslogd', 514, null);
same(null, vg_asset_grade_suggest($pdo, 20), 'null scope must not be remote evidence');
add_exposure($pdo, 21, 'rsyslogd', 514, 'BOUND', '127.0.0.2');
same(null, vg_asset_grade_suggest($pdo, 21), 'loopback inside BOUND must not be remote evidence');
add_exposure($pdo, 22, 'rsyslogd', 514, 'LAN');
add_exposure($pdo, 22, 'rsyslogd', 514, 'LAN');
$deduped = vg_asset_grade_suggest($pdo, 22);
truth(strpos($deduped['reason'], '원격 로그 수신 1건') !== false, 'duplicate socket evidence is counted once');

foreach (['LAN', 'BOUND', 'EXTERNAL'] as $i => $scope) {
    add_exposure($pdo, 30 + $i, 'rsyslogd', 514 + $i, $scope);
    $s = vg_asset_grade_suggest($pdo, 30 + $i);
    same('S', $s['grade'] ?? null, "$scope listener suggests S");
    truth(strpos($s['reason'], $scope) !== false, "$scope is retained in reason");
}

foreach ([40 => ['logstash', '서버·저장소'], 41 => ['Filebeat', '전달자·클라이언트'], 42 => ['restic', '일회성 도구']] as $scan => [$proc, $label]) {
    add_process($pdo, $scan, $proc);
    $s = vg_asset_grade_suggest($pdo, $scan);
    same('S', $s['grade'] ?? null, "$proc suggests S review");
    truth(strpos($s['reason'], $label) !== false, "$proc role is explicit");
}

add_exposure($pdo, 50, 'syslog-ng', 601, 'BOUND');
add_exposure($pdo, 50, 'rsyslogd', 514, 'LAN');
add_exposure($pdo, 50, 'nginx', 443, 'EXTERNAL');
add_process($pdo, 50, 'restic');
add_process($pdo, 50, 'logstash');
add_process($pdo, 50, 'filebeat');
$both = vg_asset_grade_suggest($pdo, 50);
same('S', $both['grade'] ?? null, 'S outranks O');
foreach (['원격 로그 수신 2건', 'rsyslogd:514/tcp@10.0.0.1/LAN', '서버·저장소', '전달자·클라이언트', '일회성 도구', 'O 외부노출 1개'] as $needle) {
    truth(strpos($both['reason'], $needle) !== false, "multiple evidence retains $needle");
}
truth(mb_strwidth($both['reason']) <= 255, 'reason is bounded');
same($both, vg_asset_grade_suggest($pdo, 50), 'reason is deterministic');

for ($port = 700; $port < 800; $port++) {
    add_exposure($pdo, 51, 'rsyslogd', $port, 'BOUND', $port === 700 ? str_repeat('a', 200) : '10.0.0.1');
}
add_exposure($pdo, 51, 'nginx', 443, 'EXTERNAL');
foreach (['logstash', 'bacula-sd', 'filebeat', 'promtail', 'restic', 'borg'] as $proc) { add_process($pdo, 51, $proc); }
$crowded = vg_asset_grade_suggest($pdo, 51);
foreach (['원격 로그 수신 100건', 'O 외부노출 1개', '서버·저장소', '전달자·클라이언트', '일회성 도구', '사람 확인 전'] as $needle) {
    truth(strpos($crowded['reason'], $needle) !== false, "bounded reason retains category $needle");
}
truth(mb_strwidth($crowded['reason']) <= 255, 'crowded reason is bounded');

add_exposure($pdo, 60, 'nginx', 443, 'EXTERNAL');
$o = vg_asset_grade_suggest($pdo, 60);
same('O', $o['grade'] ?? null, 'external-only suggests O');
same(null, vg_asset_grade_suggest($pdo, 61), 'no evidence means no suggestion');

$pdo->exec("INSERT INTO tb_host (host_id, fqdn, grade, grade_reason, approved_by, approved_at) VALUES (1, 'fixed.example', 'C', 'human decision', 7, '2026-08-09')");
vg_asset_grade_refresh($pdo, 1, 60);
$host = $pdo->query('SELECT grade, grade_reason, approved_by, approved_at, grade_suggested FROM tb_host WHERE host_id = 1')->fetch(PDO::FETCH_ASSOC);
same('C', $host['grade'], 'refresh preserves confirmed grade');
same('human decision', $host['grade_reason'], 'refresh preserves confirmed reason');
same(7, (int) $host['approved_by'], 'refresh preserves approver');
same('2026-08-09', $host['approved_at'], 'refresh preserves approval time');
same('O', $host['grade_suggested'], 'refresh writes only suggestion');

echo "assetgrade tests: ok\n";
