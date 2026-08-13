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
// 보조 신호(등급을 만들지 않는 검토 재료)가 읽는 표들. 비어 있으면 신호도 안 생긴다.
$pdo->exec('CREATE TABLE tb_host_account (scan_id INTEGER, username TEXT, is_sudoer INTEGER, is_system INTEGER DEFAULT 0, is_deleted INTEGER DEFAULT 0)');
$pdo->exec('CREATE TABLE tb_cce_finding (scan_id INTEGER, code TEXT, result TEXT)');
$pdo->exec('CREATE TABLE tb_container (scan_id INTEGER, cid TEXT, is_deleted INTEGER DEFAULT 0)');

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

same('external_exposure', $o['source'] ?? null, 'external-only suggestion reports its source');
same('log_listener', vg_asset_grade_suggest($pdo, 50)['source'] ?? null, 'listener outranks process as source');
same('process', vg_asset_grade_suggest($pdo, 42)['source'] ?? null, 'process-only suggestion reports its source');

// --- 넓힌 신호: 데이터 저장소·인증/비밀 프로세스도 S 초안을 만든다 --------------
add_process($pdo, 70, 'mysqld');
$db = vg_asset_grade_suggest($pdo, 70);
same('S', $db['grade'] ?? null, 'datastore process suggests S');
same('process', $db['source'] ?? null, 'datastore evidence is process-stage evidence');
truth(strpos($db['reason'], '업무 데이터 저장소') !== false, 'datastore role is explicit');

add_process($pdo, 71, 'slapd');
$id = vg_asset_grade_suggest($pdo, 71);
same('S', $id['grade'] ?? null, 'identity process suggests S, never C');
truth(strpos($id['reason'], '인증·비밀 관리') !== false, 'identity role is explicit');
foreach (vg_asset_grade_signals($pdo, 71) as $sig) {
    truth($sig['grade'] !== 'C', 'no signal may auto-suggest C');
}
truth(in_array('mysqld', vg_asset_grade_watch_procs(), true), 'watch list feeds the scan-identity snapshot');
truth(count(vg_asset_grade_relevant_process_rows([['1', 'mysqld', 'root', '', '']])) === 1,
      'new signal processes change the scan identity');

// --- 보조 신호: 등급을 만들지 않는다(근거 없이 등급을 찍지 않는다) --------------
$pdo->prepare('INSERT INTO tb_container (scan_id, cid, is_deleted) VALUES (?,?,0)')->execute([72, 'abc123']);
$pdo->prepare("INSERT INTO tb_cce_finding (scan_id, code, result) VALUES (?,?,'FAIL')")->execute([72, 'CCE-CRYPTO-DISK']);
for ($i = 0; $i < 6; $i++) {
    $pdo->prepare('INSERT INTO tb_host_account (scan_id, username, is_sudoer, is_system, is_deleted) VALUES (?,?,1,0,0)')
        ->execute([72, 'user' . $i]);
}
$reviewSignals = vg_asset_grade_signals($pdo, 72);
same(3, count($reviewSignals), 'review signals are collected');
foreach ($reviewSignals as $sig) {
    same('review', $sig['kind'], 'account/cce/container signals are review-only');
    same(null, $sig['grade'], 'review signals carry no grade');
    same(null, $sig['source'], 'review signals never claim a collection stage');
}
same(null, vg_asset_grade_suggest($pdo, 72), 'review-only evidence still suggests nothing');

// 보조 신호는 등급 근거 뒤에 붙는다 — 잘리더라도 등급을 만든 근거가 먼저 남는다.
add_process($pdo, 73, 'mysqld');
$pdo->prepare('INSERT INTO tb_container (scan_id, cid, is_deleted) VALUES (?,?,0)')->execute([73, 'ctr1']);
$mixed = vg_asset_grade_suggest($pdo, 73);
truth(strpos($mixed['reason'], '컨테이너 1개') !== false, 'review evidence rides along when a grade exists');
truth(strpos($mixed['reason'], '업무 데이터 저장소') < strpos($mixed['reason'], '컨테이너 1개'),
      'grade evidence precedes review evidence');

// 제안값 반영은 vg_asset_grade_observe()(assetgrade_history.php)가 맡는다 — 확정값을 건드리지
//   않는다는 불변식은 tests/assetgrade_history_test.php 가 그쪽에서 검증한다.
truth(!function_exists('vg_asset_grade_refresh'), 'suggestion write lives only in the history observer');

echo "assetgrade tests: ok\n";
