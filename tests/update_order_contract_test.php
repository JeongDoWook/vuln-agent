<?php
declare(strict_types=1);

/** 운영 배포가 새 PHP를 backup/migration보다 먼저 노출하지 않는 순서 계약. */
$root = dirname(__DIR__);
$source = (string) file_get_contents($root . '/deploy/update.sh');
$failures = [];
$check = static function (bool $ok, string $message) use (&$failures): void {
    if (!$ok) { $failures[] = $message; }
};

$flow = substr($source, (int) strpos($source, 'say "[2/6]'));
$ordered = [
    'git fetch --prune origin' => 'remote commit fetch',
    'NEW=$(git rev-parse origin/main)' => 'fetched commit pin',
    'git merge-base --is-ancestor "$OLD" "$NEW"' => 'fast-forward preflight',
    'prepare_staged_release "$NEW"' => 'isolated release checkout',
    'migrate_with_verified_backup "$RELEASE_ROOT"' => 'verified backup and migration',
    'git merge --ff-only "$NEW"' => 'live source fast-forward',
];
$previous = -1;
foreach ($ordered as $needle => $label) {
    $position = strpos($flow, $needle);
    $check($position !== false, "배포 단계 없음: {$label}");
    if ($position !== false) {
        $check($position > $previous, "배포 순서 위반: {$label}");
        $previous = $position;
    }
}

$check(strpos($source, 'git merge --ff-only origin/main') === false,
    '검증 전 origin/main 직접 merge가 다시 생김');
$check(strpos($source, 'bash "$release_root/deploy/backup_db.sh"') !== false
    && strpos($source, 'bash "$release_root/deploy/migrate.sh"') !== false,
    'staged release의 backup/migration 도구를 실행해야 함');
$check(strpos($source, 'trap cleanup_staged_release EXIT') !== false
    && strpos($source, 'git worktree remove --force "$STAGED_ROOT"') !== false,
    '실패 경로에서도 staged worktree를 정리해야 함');

if ($failures !== []) {
    foreach ($failures as $failure) { fwrite(STDERR, "update order contract: {$failure}\n"); }
    exit(1);
}
echo "update order contract: ok\n";
