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
    // 미적용분이 있을 때만 백업·검증·마이그레이션을 도는 단계. 판정과 실행이 한 함수로 묶여 있다.
    'run_migration_stage "$RELEASE_ROOT"' => 'verified backup and migration',
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
// 백업을 건너뛸지 말지는 migrate.sh 의 --pending 판정 하나로만 정한다. update.sh 가 자체 기준
// (예: git diff 에 db/migrations 가 있나)을 들면 두 벌이 되어 갈라진다 — 앞선 배포가 중단돼
// 미적용분이 남은 경우 파일 변경이 없다는 이유로 영영 안 걸리게 된다.
$check(strpos($source, 'deploy/migrate.sh" vulnagent-db --pending') !== false,
    '미적용 판정은 migrate.sh --pending 으로만 해야 함');
$check(strpos($source, 'MIGRATION_PROBE_RC" != 0') !== false,
    '판정 실패 시 백업하는 쪽으로 기우는 분기가 있어야 함');
$check(strpos($source, 'trap cleanup_staged_release EXIT') !== false
    && strpos($source, 'git worktree remove --force "$STAGED_ROOT"') !== false,
    '실패 경로에서도 staged worktree를 정리해야 함');

if ($failures !== []) {
    foreach ($failures as $failure) { fwrite(STDERR, "update order contract: {$failure}\n"); }
    exit(1);
}
echo "update order contract: ok\n";
