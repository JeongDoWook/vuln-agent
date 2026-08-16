<?php
declare(strict_types=1);

require_once __DIR__ . '/../server/src/asset_grade_review.php';

$fail = 0;
$ok = static function (bool $condition, string $label) use (&$fail): void {
    if (!$condition) { echo "  ✗ {$label}\n"; $fail++; }
};
$throws = static function (callable $fn, string $label) use ($ok): void {
    try { $fn(); $ok(false, $label); } catch (RuntimeException) { $ok(true, $label); }
};

$valid = vg_asset_grade_review_validate([
    'article9_item' => '6',
    'article9_reference' => '제9조 제1항 제6호',
    'business_category' => '취약점 관리',
    'data_category' => '시스템 구성정보',
    'owning_department' => '정보보호팀',
    'external_publication_state' => 'NOT_PUBLIC',
    'review_reference' => 'SEC-2026-541',
    'next_review_date' => (new DateTimeImmutable('today'))->modify('+1 year')->format('Y-m-d'),
]);
$ok($valid['article9_item'] === '6' && $valid['next_review_date'] !== null, '유효한 검토 정보 정규화');
$ok(vg_asset_grade_review_validate([])['article9_item'] === null, '빈 값은 NULL');
$throws(fn() => vg_asset_grade_review_validate(['article9_item' => '9']), '제9조 호 enum 검증');
$throws(fn() => vg_asset_grade_review_validate(['external_publication_state' => 'UNKNOWN']), '공개 상태 enum 검증');
$throws(fn() => vg_asset_grade_review_validate(['next_review_date' => '2027-02-29']), '달력 날짜 검증');
$throws(fn() => vg_asset_grade_review_validate(['next_review_date' => '2000-01-01']), '지난 재검토일 거부');
$throws(fn() => vg_asset_grade_review_validate(['next_review_date' => '2099-01-01']), '재검토일 상한 검증');
$throws(fn() => vg_asset_grade_review_validate(['owning_department' => str_repeat('가', 121)]), '문자열 길이 검증');
$throws(fn() => vg_asset_grade_review_validate(['owning_department' => ['정보보호팀']]), '배열 형태 POST 거부');
$ok(count(vg_asset_grade_review_missing([])) === 8, '누락 검토 항목 안내');
$ok(vg_asset_grade_review_overdue(['next_review_date' => '2026-01-01'], new DateTimeImmutable('2026-08-09')), '재검토 기한 경과 안내');
$articleKeys = array_map('strval', array_keys(VG_ASSET_REVIEW_ARTICLE9_ITEMS));
$ok(in_array('6', $articleKeys, true), '숫자 제9조 호 키를 문자열 폼 값으로 변환 가능');

final class AssetReviewFakeStatement extends PDOStatement {
    public function __construct(private AssetReviewFakePdo $pdo, private string $sql) {}
    public function execute(?array $params = null): bool {
        $this->pdo->executions[] = ['sql' => $this->sql, 'params' => $params ?? []];
        if ($this->pdo->failAudit && str_contains($this->sql, 'INSERT INTO tb_activity_log')) {
            throw new PDOException('audit unavailable');
        }
        if (str_contains($this->sql, 'UPDATE tb_host SET')) {
            $this->pdo->gradeVersion++;
        } elseif (str_contains($this->sql, 'ON DUPLICATE KEY UPDATE')) {
            $names = ['host_id', 'article9_item', 'article9_reference', 'business_category', 'data_category',
                'owning_department', 'review_reference', 'external_publication_state', 'next_review_date', 'reviewed_by'];
            $row = array_combine($names, $params ?? []);
            $row['is_stale'] = 0;
            $row['review_version'] = (int) ($this->pdo->reviewRow['review_version'] ?? 0) + 1;
            $this->pdo->reviewRow = $row;
        } elseif (str_contains($this->sql, 'SET is_stale = 1')) {
            if ($this->pdo->reviewRow !== null) {
                $this->pdo->reviewRow['is_stale'] = 1;
                $this->pdo->reviewRow['review_version']++;
            }
        } elseif (str_contains($this->sql, 'DELETE FROM tb_asset_grade_review')) {
            $this->pdo->reviewRow = null;
        }
        return true;
    }
    public function fetchColumn(int $column = 0): mixed {
        if (str_contains($this->sql, 'SELECT fqdn')) { return 'host01.example'; }
        if (str_contains($this->sql, 'SELECT grade_version')) { return $this->pdo->gradeVersion; }
        return false;
    }
    public function fetch(int $mode = PDO::FETCH_DEFAULT, int $cursorOrientation = PDO::FETCH_ORI_NEXT, int $cursorOffset = 0): mixed {
        return str_contains($this->sql, 'SELECT * FROM tb_asset_grade_review')
            ? ($this->pdo->reviewRow ?? false) : false;
    }
}

final class AssetReviewFakePdo extends PDO {
    /** @var list<array{sql:string,params:array}> */
    public array $executions = [];
    /** @var list<string> */
    public array $tx = [];
    public ?array $reviewRow = null;
    public int $gradeVersion = 0;
    public bool $failAudit = false;
    private bool $in = false;
    public function __construct() {}
    public function prepare(string $query, array $options = []): PDOStatement|false { return new AssetReviewFakeStatement($this, $query); }
    public function beginTransaction(): bool { $this->in = true; $this->tx[] = 'begin'; return true; }
    public function commit(): bool { $this->in = false; $this->tx[] = 'commit'; return true; }
    public function rollBack(): bool { $this->in = false; $this->tx[] = 'rollback'; return true; }
    public function inTransaction(): bool { return $this->in; }
}

$pdo = new AssetReviewFakePdo();
vg_asset_grade_review_confirm($pdo, 11, 'S', 'HIGH', '사람이 작성한 기존 근거', $valid + ['review_version' => '0', 'grade_version' => '0'], 7);
$ok($pdo->tx === ['begin', 'commit'], '등급과 검토 정보 원자적 저장');
$upserts = array_values(array_filter($pdo->executions, static fn(array $e): bool => str_contains($e['sql'], 'tb_asset_grade_review') && str_contains($e['sql'], 'ON DUPLICATE KEY')));
$ok(count($upserts) === 1 && $pdo->reviewRow['review_version'] === 1, '신규 저장은 version 1 upsert');

vg_asset_grade_review_confirm($pdo, 11, 'C', 'HIGH', '갱신 근거', $valid + ['review_version' => '1', 'grade_version' => '1'], 7);
$upserts = array_values(array_filter($pdo->executions, static fn(array $e): bool => str_contains($e['sql'], 'ON DUPLICATE KEY')));
$ok(count($upserts) === 2 && $pdo->reviewRow['review_version'] === 2, '기존 검토 정보 version 갱신');

vg_asset_grade_confirm($pdo, 11, 'O', null, '일괄 변경', 7);
$ok($pdo->reviewRow['is_stale'] === 1 && $pdo->reviewRow['review_version'] === 3, '일괄 확정은 기존 검토를 stale 처리');
$throws(
    fn() => vg_asset_grade_review_confirm($pdo, 11, 'S', 'HIGH', '오래된 화면', $valid + ['review_version' => '2', 'grade_version' => '2'], 7),
    '오래된 검토 버전 저장 거부'
);
$ok($pdo->tx[count($pdo->tx) - 1] === 'rollback', '동시 수정 충돌 시 롤백');

vg_asset_grade_review_confirm($pdo, 11, '', '', '화면에 남은 기존 근거', ['review_version' => '3', 'grade_version' => '3', 'next_review_date' => '2000-01-01'], 7);
$deletes = array_values(array_filter($pdo->executions, static fn(array $e): bool => str_contains($e['sql'], 'DELETE FROM tb_asset_grade_review')));
$ok(count($deletes) === 1, '등급 해제 시 구조화 검토 정보 삭제');
$ok($pdo->reviewRow === null && $pdo->tx[count($pdo->tx) - 1] === 'commit', '지난 재검토일이어도 확정 해제 가능');

$auditFailPdo = new AssetReviewFakePdo();
$auditFailPdo->failAudit = true;
$throws(
    fn() => vg_asset_grade_review_confirm($auditFailPdo, 12, 'S', 'LOW', '근거', $valid + ['review_version' => '0', 'grade_version' => '0'], 7),
    '필수 감사로그 실패를 호출자에게 전파'
);
$ok($auditFailPdo->tx === ['begin', 'rollback'], '감사로그 실패 시 등급·검토 트랜잭션 롤백');

$auditRows = array_values(array_filter($pdo->executions, static fn(array $e): bool => str_contains($e['sql'], 'INSERT INTO tb_activity_log')));
$auditText = json_encode($auditRows, JSON_UNESCAPED_UNICODE);
$ok(!str_contains((string) $auditText, 'SEC-2026-541'), '감사 payload에 검토 문서 참조 미포함');
$ok(!str_contains((string) $auditText, '제9조 제1항 제6호'), '감사 payload에 자유 참조 미포함');
$ok(!str_contains((string) $auditText, '사람이 작성한 기존 근거'), '감사 payload에 기존 확정 근거 원문 미포함');
$ok(!str_contains((string) $auditText, '화면에 남은 기존 근거'), '등급 해제 감사 payload에 지워진 근거 원문 미포함');
$ok(str_contains((string) $auditText, 'cleared_fields'), '등급 해제 감사 payload에 삭제 필드명 포함');

/* 호스트 상세는 파일 하나가 아니다 — 수집 제어 POST·등급 카드는 server/src/host/** 에 있다.
 *   "상세 화면의 소스" 는 그 묶음 전체다(코드가 옮겨졌을 뿐인데 계약이 깨지면 안 된다). */
$hostSource = implode("\n", array_map(
    static fn(string $f): string => (string) file_get_contents($f),
    array_merge(
        [__DIR__ . '/../server/public/host.php'],
        glob(__DIR__ . '/../server/src/host/*.php') ?: [],
        glob(__DIR__ . '/../server/src/host/tabs/*.php') ?: []
    )
));
$assetsSource = file_get_contents(__DIR__ . '/../server/public/assets.php');
$guardPos = strpos((string) $hostSource, "if (!vg_has_role('admin'))");
$confirmPos = strpos((string) $hostSource, 'vg_asset_grade_review_confirm(');
$ok($guardPos !== false && $confirmPos !== false && $guardPos < $confirmPos
    && str_contains(substr((string) $hostSource, $guardPos, $confirmPos - $guardPos), "throw new RuntimeException('자산 등급을 확정할 권한이 없습니다.')"),
    '단일 확정은 명시적 관리자 거부 뒤에만 실행');
$ok(str_contains((string) $hostSource, '=== (string) $v'), '저장된 숫자 제9조 호를 strict 비교 전에 문자열화');
$ok(!str_contains((string) $assetsSource, 'vg_asset_grade_review_confirm('), '일괄 확정은 호스트별 구조화 정보 미복제');
$ok(str_contains((string) $assetsSource, '기존 정보는 재검토 필요 상태'), '일괄 확정 뒤 기존 검토의 stale 한계 표시');

if ($fail > 0) { exit(1); }
echo "  ✓ 자산 등급 구조화 검토 단위 테스트\n";
