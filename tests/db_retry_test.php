<?php
declare(strict_types=1);

/**
 * db_retry 단위 테스트 — server/src/db.php 의 재시도 판정.
 *
 * DB 없이 돈다. 판정은 순수 함수(vg_db_driver_errno·vg_db_is_retryable_connect)라 PDO 가 던지는
 * 것과 같은 모양의 예외를 손으로 만들어 확인한다. 실제 접속 실패는 DB 를 내려야 재현되므로
 * 여기서 다루지 않는다 — 회귀 지점은 "무엇을 재시도로 보는가" 이고 그게 여기서 잡힌다.
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

if ($fail === 0) {
    echo "db_retry: 모든 테스트 통과\n";
    exit(0);
}
printf("db_retry: %d건 실패\n", $fail);
exit(1);
