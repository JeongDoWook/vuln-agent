<?php
declare(strict_types=1);

/** DB 없이 제안 관찰의 replay/change/null/확정값 격리를 검증한다. */
require_once __DIR__ . '/../server/src/assetgrade_history.php';

$fail = 0;
$eq = static function (string $label, $got, $want) use (&$fail): void {
    if ($got !== $want) {
        printf("  ✗ [%s] 기대 %s, 실제 %s\n", $label, var_export($want, true), var_export($got, true));
        $fail++;
    }
};

final class VgAssetGradeHistoryFakePdo extends PDO
{
    public bool $inTx = true;
    public ?string $suggestion = 'S';
    public bool $logListener = false;
    public ?string $latestGrade = null;
    public ?string $latestReason = null;
    public ?string $confirmedGrade = 'C';
    /** @var array<string,array<string,mixed>> */
    public array $history = [];

    public function __construct() {}
    public function inTransaction(): bool { return $this->inTx; }
    public function prepare(string $query, array $options = []): PDOStatement|false
    {
        return new VgAssetGradeHistoryFakeStatement($this, $query);
    }
}

final class VgAssetGradeHistoryFakeStatement extends PDOStatement
{
    private VgAssetGradeHistoryFakePdo $pdo;
    private string $sql;
    private array $params = [];

    public function __construct(VgAssetGradeHistoryFakePdo $pdo, string $sql)
    {
        $this->pdo = $pdo;
        $this->sql = $sql;
    }
    public function execute(?array $params = null): bool
    {
        $this->params = $params ?? [];
        if (str_starts_with(trim($this->sql), 'UPDATE tb_host')) {
            $sourceAt = (string) ($this->params[6] ?? '');
            foreach ($this->pdo->history as $row) {
                if ((string) ($row['observed_at'] ?? '') > $sourceAt) { return true; }
            }
            $this->pdo->latestGrade = $this->params[0];
            $this->pdo->latestReason = $this->params[1];
        } elseif (str_starts_with(trim($this->sql), 'INSERT INTO tb_asset_grade_suggestion_history')) {
            $key = $this->params[0] . '|' . $this->params[1] . '|' . bin2hex($this->params[6]);
            $this->pdo->history[$key] ??= [
                'host_id' => $this->params[0], 'scan_id' => $this->params[1],
                'grade' => $this->params[2], 'reason' => $this->params[3],
                'status' => $this->params[4], 'evidence' => $this->params[5],
                'observed_at' => $this->params[7],
            ];
        }
        return true;
    }
    public function fetch(int $mode = PDO::FETCH_DEFAULT, int $cursorOrientation = PDO::FETCH_ORI_NEXT, int $cursorOffset = 0): mixed
    {
        if (str_contains($this->sql, 'FROM tb_exposure') && str_contains($this->sql, 'proc IN')) {
            return $this->pdo->logListener ? ['proc' => 'rsyslogd', 'port' => 514] : false;
        }
        return false;
    }
    public function fetchColumn(int $column = 0): mixed
    {
        if (str_contains($this->sql, 'FROM tb_process')) {
            return $this->pdo->suggestion === 'S' ? 'restic' : false;
        }
        if (str_contains($this->sql, "scope = 'EXTERNAL'")) {
            return $this->pdo->suggestion === 'O' ? 1 : 0;
        }
        return false;
    }
}

$complete = [
    ['runtime_processes', 'COMPLETE', 1],
    ['network_exposure', 'EMPTY', 0],
];
$pdo = new VgAssetGradeHistoryFakePdo();

vg_asset_grade_observe($pdo, 7, 11, '2026-08-09 10:00:00', $complete);
$eq('첫 S 제안 기록', count($pdo->history), 1);
$eq('최신 호환 컬럼 S', $pdo->latestGrade, 'S');

vg_asset_grade_observe($pdo, 7, 11, '2026-08-09 10:00:00', $complete);
$eq('동일 replay 중복 없음', count($pdo->history), 1);

$pdo->suggestion = 'O';
vg_asset_grade_observe($pdo, 7, 11, '2026-08-09 10:05:00', $complete);
$eq('같은 scan 재평가 결과 변화 보존', count($pdo->history), 2);
$eq('최신 호환 컬럼 O', $pdo->latestGrade, 'O');

$externalOnly = new VgAssetGradeHistoryFakePdo();
$externalOnly->suggestion = 'O';
vg_asset_grade_observe($externalOnly, 8, 20, '2026-08-09 10:06:00', [
    ['runtime_processes', 'MISSING', 0], ['network_exposure', 'COMPLETE', 1],
]);
$eq('외부노출 O는 프로세스 수집 누락과 무관하게 제안', array_values($externalOnly->history)[0]['status'], 'SUGGESTED');

$pdo->suggestion = null;
vg_asset_grade_observe($pdo, 7, 12, '2026-08-09 10:10:00', $complete);
$eq('null/no-suggestion 관찰도 기록', count($pdo->history), 3);
$eq('최신 제안은 null로 전환', $pdo->latestGrade, null);
$eq('no-suggestion 상태', array_values($pdo->history)[2]['status'], 'NO_MATCH');

vg_asset_grade_observe($pdo, 7, 13, '2026-08-09 10:15:00', [['runtime_processes', 'MISSING', 0]]);
$eq('수집 부족 null은 판정 안 함으로 분리', array_values($pdo->history)[3]['status'], 'NOT_EVALUATED');
$eq('수집 부족은 기존 최신 제안을 지우지 않음', $pdo->latestGrade, null);
$eq('사람이 확정한 grade는 전혀 건드리지 않음', $pdo->confirmedGrade, 'C');

$pdo->suggestion = 'S';
vg_asset_grade_observe($pdo, 7, 14, '2026-08-09 09:00:00', $complete);
$eq('지연 도착한 과거 관찰은 최신 제안을 되돌리지 않음', $pdo->latestGrade, null);

$source = file_get_contents(__DIR__ . '/../server/src/assetgrade_history.php');
$eq('지연 replay가 최신값을 되돌리지 않는 guard', str_contains($source, 'newer.effective_at'), true);
$eq('중복 외 DB 오류를 숨기지 않음', str_contains($source, 'ON DUPLICATE KEY UPDATE'), true);
$eq('동일 스캔·결과 replay 식별키', str_contains(file_get_contents(__DIR__ . '/../db/migrations/20260809184905_asset_grade_suggestion_history.sql'), '(host_id, scan_id, result_fingerprint)'), true);

$pdo->inTx = false;
$thrown = false;
try { vg_asset_grade_observe($pdo, 7, 15, null, $complete); } catch (LogicException $e) { $thrown = true; }
$eq('트랜잭션 밖 기록 거부', $thrown, true);

$coveragePdo = new VgAssetGradeHistoryFakePdo();
$coveragePdo->logListener = true;
vg_asset_grade_observe($coveragePdo, 8, 21, '2026-08-09 11:00:00', [
    ['runtime_processes', 'MISSING', 0], ['network_exposure', 'COMPLETE', 1],
]);
$eq('입증된 로그 리스너 S는 별도 프로세스 누락에도 유지', array_values($coveragePdo->history)[0]['status'], 'SUGGESTED');

$coveragePdo = new VgAssetGradeHistoryFakePdo();
$coveragePdo->suggestion = 'O';
vg_asset_grade_observe($coveragePdo, 8, 22, '2026-08-09 11:05:00', [
    ['runtime_processes', 'MISSING', 0], ['network_exposure', 'COMPLETE', 1],
]);
$eq('외부노출 O는 프로세스 누락과 무관하게 유지', array_values($coveragePdo->history)[0]['status'], 'SUGGESTED');

if ($fail > 0) { printf("assetgrade_history_test: %d건 실패\n", $fail); exit(1); }
echo "assetgrade_history_test: 전부 통과\n";
