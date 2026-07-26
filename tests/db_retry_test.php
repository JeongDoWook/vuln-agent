<?php
declare(strict_types=1);

/**
 * db_retry 단위 테스트 — server/src/db.php 의 재시도 판정과 vg_with_tx 재시도 흐름.
 *
 * DB 없이 돈다. 판정은 순수 함수(vg_db_driver_errno·vg_db_is_retryable_*)라 예외를 손으로 만들어
 * 확인하고, vg_with_tx 는 네이티브 메서드를 전부 가로챈 가짜 PDO(VgFakePdo)를 넘겨 확인한다.
 * 실제 교착은 DB 두 세션이 필요해 여기서 재현하지 않는다 — 회귀 지점은 "무엇을 재시도로 보는가"와
 * "몇 번·어떤 순서로 begin/rollback 하는가" 이고 그 둘이 여기서 다 잡힌다.
 *
 * 실행:
 *   docker run --rm -v "$PWD:/w" -w /w php:8.3-cli php tests/db_retry_test.php
 */

require_once __DIR__ . '/../server/src/db.php';

$fail = 0;
$eq = static function (string $label, $got, $want) use (&$fail): void {
    if ($got !== $want) {
        printf("  ✗ [%s] 기대 %s, 실제 %s\n", $label, var_export($want, true), var_export($got, true));
        $fail++;
    }
};

/** PDO 가 던지는 것과 같은 모양의 예외를 만든다(errorInfo = [SQLSTATE, 드라이버번호, 메시지]). */
function vg_t_ex(string $msg, ?string $sqlstate = null, ?int $errno = null, int $code = 0): PDOException {
    $e = new PDOException($msg, $code);
    if ($sqlstate !== null) { $e->errorInfo = [$sqlstate, $errno, $msg]; }
    return $e;
}

// ── vg_db_driver_errno — 어디서 번호를 뽑는가 ────────────────────────────────
$eq('errorInfo[1] 에서 뽑는다', vg_db_driver_errno(vg_t_ex('Deadlock found', '40001', 1213)), 1213);
$eq('errorInfo 없으면 getCode() 에서', vg_db_driver_errno(vg_t_ex('Connection refused', null, null, 2002)), 2002);
// 최후수단: errorInfo·code 둘 다 비었을 때만 메시지 파싱. 접속 단계 예외가 실제로 이 모양이다.
$eq('둘 다 없으면 메시지 파싱',
    vg_db_driver_errno(vg_t_ex('SQLSTATE[HY000] [2002] Connection refused')), 2002);
$eq('SQLSTATE 의 문자코드는 번호로 오해하지 않는다',
    vg_db_driver_errno(vg_t_ex('SQLSTATE[HY000] [2003] Can\'t connect to MySQL server')), 2003);
$eq('번호가 없으면 null', vg_db_driver_errno(vg_t_ex('알 수 없는 오류')), null);
$eq('PDOException 이 아니면 null', vg_db_driver_errno(new RuntimeException('SQLSTATE[HY000] [2002] x')), null);

// ── vg_db_is_retryable_connect — 기다려서 될 접속 실패만 ────────────────────
$eq('2002 접속 거부는 재시도', vg_db_is_retryable_connect(vg_t_ex('SQLSTATE[HY000] [2002] Connection refused')), true);
$eq('2003 접속 불가는 재시도', vg_db_is_retryable_connect(vg_t_ex('SQLSTATE[HY000] [2003] Can\'t connect')), true);
$eq('2013 핸드셰이크 끊김은 재시도',
    vg_db_is_retryable_connect(vg_t_ex('SQLSTATE[HY000] [2013] Lost connection during greeting')), true);
// 기다려도 안 되는 것들 — 무의미한 지연이 배포를 늦춘다.
$eq('1045 인증 실패는 즉시 던진다',
    vg_db_is_retryable_connect(vg_t_ex('Access denied for user', '28000', 1045)), false);
$eq('1049 DB 없음은 즉시 던진다',
    vg_db_is_retryable_connect(vg_t_ex('Unknown database', '42000', 1049)), false);
$eq('교착은 접속 재시도 대상이 아니다',
    vg_db_is_retryable_connect(vg_t_ex('Deadlock found', '40001', 1213)), false);

// ── vg_db_is_retryable_deadlock — 교착/락대기만 ─────────────────────────────
$eq('errorInfo 1213 은 재시도', vg_db_is_retryable_deadlock(vg_t_ex('Deadlock found', '40001', 1213)), true);
$eq('SQLSTATE 40001 만 있어도 재시도', vg_db_is_retryable_deadlock(vg_t_ex('Serialization failure', '40001')), true);
$eq('getCode() 40001 도 재시도', vg_db_is_retryable_deadlock(vg_t_ex('Serialization failure', null, null, 40001)), true);
// 1205 는 SQLSTATE 가 HY000 이라 번호를 봐야 잡힌다.
$eq('1205 락 대기 초과는 재시도',
    vg_db_is_retryable_deadlock(vg_t_ex('Lock wait timeout exceeded', 'HY000', 1205)), true);
$eq('23000 중복키는 재시도 안 함', vg_db_is_retryable_deadlock(vg_t_ex('Duplicate entry', '23000', 1062)), false);
$eq('접속 실패는 트랜잭션 재시도 대상이 아니다',
    vg_db_is_retryable_deadlock(vg_t_ex('SQLSTATE[HY000] [2002] Connection refused')), false);
$eq('PDOException 이 아니면 재시도 안 함', vg_db_is_retryable_deadlock(new RuntimeException('Deadlock found')), false);

// ── vg_with_tx — 가짜 PDO 로 재시도 흐름 ────────────────────────────────────
/**
 * 부모 생성자를 부르지 않는다 — vg_with_tx 가 쓰는 네이티브 메서드 5개를 전부 여기서 가로채므로
 * 실제 접속이 필요 없다. 호출 순서를 $calls 에 남겨 begin/rollback/commit 흐름을 검증한다.
 */
final class VgFakePdo extends PDO {
    /** @var list<string> */
    public array $calls = [];
    private bool $in;
    public function __construct(bool $inTx = false) { $this->in = $inTx; }
    public function beginTransaction(): bool { $this->calls[] = 'begin';    $this->in = true;  return true; }
    public function commit(): bool          { $this->calls[] = 'commit';   $this->in = false; return true; }
    public function rollBack(): bool        { $this->calls[] = 'rollback'; $this->in = false; return true; }
    public function inTransaction(): bool   { return $this->in; }
    public function exec(string $statement): int|false { $this->calls[] = 'exec:' . $statement; return 0; }
}

// 성공 1회 — 예전 동작 그대로.
$pdo = new VgFakePdo();
$eq('성공 시 콜백 반환값을 그대로', vg_with_tx($pdo, static fn() => 'ok'), 'ok');
$eq('성공 시 begin→commit', $pdo->calls, ['begin', 'commit']);

// 격리수준은 재시도마다 다시 걸어야 한다(SET TRANSACTION 은 다음 트랜잭션 하나에만 걸린다).
$pdo = new VgFakePdo();
$n = 0;
$got = vg_with_tx($pdo, static function () use (&$n) {
    if (++$n < 3) { throw vg_t_ex('Deadlock found when trying to get lock', '40001', 1213); }
    return $n;
}, 'READ COMMITTED');
$eq('3번째 시도에서 성공', $got, 3);
$eq('교착마다 롤백 후 재시도, 격리수준 재적용', $pdo->calls, [
    'exec:SET TRANSACTION ISOLATION LEVEL READ COMMITTED', 'begin', 'rollback',
    'exec:SET TRANSACTION ISOLATION LEVEL READ COMMITTED', 'begin', 'rollback',
    'exec:SET TRANSACTION ISOLATION LEVEL READ COMMITTED', 'begin', 'commit',
]);

// 계속 교착이면 상한(VG_TX_DEADLOCK_TRIES)에서 포기하고 원본 예외를 던진다 — 무한루프 금지.
$pdo = new VgFakePdo();
$n = 0;
$caught = null;
try {
    vg_with_tx($pdo, static function () use (&$n) {
        $n++;
        throw vg_t_ex('Deadlock found when trying to get lock', '40001', 1213);
    });
} catch (Throwable $e) { $caught = $e; }
$eq('상한만큼만 시도', $n, VG_TX_DEADLOCK_TRIES);
$eq('포기 시 원본 예외를 던진다', $caught instanceof PDOException, true);
$eq('마지막 시도도 롤백은 한다', array_count_values($pdo->calls), ['begin' => 3, 'rollback' => 3]);

// 교착이 아닌 오류는 재시도하지 않는다.
$pdo = new VgFakePdo();
$n = 0;
try {
    vg_with_tx($pdo, static function () use (&$n) {
        $n++;
        throw vg_t_ex('Duplicate entry', '23000', 1062);
    });
} catch (Throwable $e) { /* 기대된 전파 */ }
$eq('중복키는 1회만 실행', $n, 1);
$eq('중복키는 begin→rollback 한 벌', $pdo->calls, ['begin', 'rollback']);

// ★ 이 작업의 핵심 안전조건: 남의 트랜잭션에 참여 중이면 재시도하지 않는다.
//   롤백 범위가 호출자 것이므로 여기서 다시 돌리면 반쪽짜리로 실행된다.
$pdo = new VgFakePdo(true);
$n = 0;
try {
    vg_with_tx($pdo, static function () use (&$n) {
        $n++;
        throw vg_t_ex('Deadlock found when trying to get lock', '40001', 1213);
    });
} catch (Throwable $e) { /* 기대된 전파 */ }
$eq('참여 중이면 교착도 재시도 안 함', $n, 1);
$eq('참여 중이면 begin/commit/rollback 을 건드리지 않는다', $pdo->calls, []);

$pdo = new VgFakePdo(true);
$eq('참여 중 성공도 커밋하지 않는다(호출자 몫)', vg_with_tx($pdo, static fn() => 'nested'), 'nested');
$eq('참여 중 성공 시 호출 없음', $pdo->calls, []);

// 참여 중일 때는 격리수준도 건드리지 않는다(호출자 트랜잭션엔 이미 못 건다).
$pdo = new VgFakePdo(true);
vg_with_tx($pdo, static fn() => null, 'READ COMMITTED');
$eq('참여 중이면 SET TRANSACTION 도 안 건다', $pdo->calls, []);

if ($fail === 0) {
    echo "db_retry: 모든 테스트 통과\n";
    exit(0);
}
printf("db_retry: %d건 실패\n", $fail);
exit(1);
