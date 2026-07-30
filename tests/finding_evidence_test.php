<?php
declare(strict_types=1);

require dirname(__DIR__) . '/server/src/finding_evidence.php';

$fail = 0;
$check = static function (bool $ok, string $label) use (&$fail): void {
    if (!$ok) {
        fwrite(STDERR, "FAIL: {$label}\n");
        $fail++;
    }
};

$check(vg_match_source(['os_id' => 'ubuntu'], 'dpkg', null) === 'ubuntu_oval', 'Ubuntu OVAL source');
$check(vg_match_source(['os_id' => 'debian'], 'dpkg', null) === 'debian_tracker', 'Debian tracker source');
$check(vg_match_source(['os_id' => 'ubuntu'], 'go', ['os_id' => 'wolfi']) === 'osv', 'Wolfi/Go OSV source');

if ($fail) {
    exit(1);
}
echo "finding evidence tests: ok\n";
