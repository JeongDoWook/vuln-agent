<?php
declare(strict_types=1);

/**
 * 운영 배포가 새 PHP를 migration보다 먼저 노출하지 않는 순서 계약.
 *
 * 배포는 백업을 만들지 않는다(정기 백업은 매일 04:00 cron 의 deploy/backup_db.sh).
 * 그래서 이 계약은 "백업이 migration 보다 먼저인가"가 아니라 **"배포 경로에 백업이 다시
 * 끼어들지 않았는가"** 를 단언한다 — 20분 넘던 배포의 원인이 그것이었다.
 */
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
    // 백업 없이 마이그레이션만 도는 단계(staged release 의 migrate.sh 를 쓴다).
    'run_migration_stage "$RELEASE_ROOT"' => 'migration stage',
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
$check(strpos($source, 'bash "$release_root/deploy/migrate.sh"') !== false,
    'staged release의 migration 도구를 실행해야 함');
// 배포 경로에는 백업이 없다. backup_db.sh 는 cron 전용이고, 여기서 다시 부르면 배포가 다시
// 덤프+복원 대조를 기다리게 된다(#638 이전의 20분 배포). 주석은 그 사실을 설명하느라 파일명을
// 언급하므로, 단언은 **주석을 뺀 실행 코드**만 본다.
$code = preg_replace('/^\s*#.*$/m', '', $source);
$check(strpos($code, 'backup_db') === false,
    '배포 경로에 백업 호출이 다시 생김(백업은 04:00 cron 전용)');
$check(strpos($code, 'MIGRATION_REQUIRE_BACKUP') === false,
    '배포 경로가 다시 백업 증거를 요구함');
// 미적용 판정을 update.sh 가 자체 기준(예: git diff 에 db/migrations 가 있나)으로 하면 안 된다 —
// 앞선 배포가 중단돼 미적용분이 남은 경우 파일 변경이 없다는 이유로 영영 안 걸린다.
// 지금은 판정 자체를 하지 않고 migrate.sh 를 무조건 돌린다(멱등) — 실제로 그렇게 도는지는
// tests/update_sh_scenarios.sh 5~8 이 update.sh 를 통째로 돌려 확인한다.
$check(strpos($source, 'bash "$release_root/deploy/migrate.sh" vulnagent-db') !== false,
    '마이그레이션은 조건 없이 migrate.sh 로 실행돼야 함');
$check(strpos($source, 'trap cleanup_staged_release EXIT') !== false
    && strpos($source, 'git worktree remove --force "$STAGED_ROOT"') !== false,
    '실패 경로에서도 staged worktree를 정리해야 함');

if ($failures !== []) {
    foreach ($failures as $failure) { fwrite(STDERR, "update order contract: {$failure}\n"); }
    exit(1);
}
echo "update order contract: ok\n";
