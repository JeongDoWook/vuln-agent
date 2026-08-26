<?php
declare(strict_types=1);

// 접속 재시도 파라미터. 짧게 잡는다 — 웹 요청도 vg_pdo() 를 쓰므로 길면 사용자 응답이 멈춘다
//   (최악 대기 = (TRIES-1) × WAIT_US).
const VG_DB_CONNECT_TRIES   = 3;        // 총 시도 횟수(첫 시도 포함)
const VG_DB_CONNECT_WAIT_US = 1000000;  // 재시도 간 대기(마이크로초 = 1초)

/**
 * 기다리면 풀릴 접속 실패의 MySQL 오류번호. DB 컨테이너 재시작 중에 나는 것들만 담는다.
 *   2002 소켓/호스트 접속 실패(운영 로그의 `[2002] Connection refused` 11회)
 *   2003 TCP 접속 거부
 *   2013 핸드셰이크 중 끊김(서버가 떴지만 아직 초기화 중일 때)
 * 인증 실패(1045)·DB 없음(1049)·호스트 차단(1129) 은 기다려도 안 되므로 여기 없다 → 즉시 던진다.
 */
const VG_DB_CONNECT_RETRY_ERRNOS = [2002, 2003, 2013];

/**
 * PDOException 에서 MySQL 드라이버 오류번호를 뽑는다. 못 뽑으면 null.
 *   errorInfo[1] 이 정석이고, 접속 단계 예외는 errorInfo 가 비어 있을 수 있어 getCode() 를 본다.
 *   메시지의 `[2002]` 파싱은 **최후수단**(둘 다 비었을 때만).
 */
if (!function_exists('vg_db_driver_errno')) {
    function vg_db_driver_errno(Throwable $e): ?int {
        if (!$e instanceof PDOException) { return null; }
        $info = $e->errorInfo;
        if (is_array($info) && isset($info[1]) && is_numeric($info[1])) { return (int) $info[1]; }
        $code = $e->getCode();
        if (is_numeric($code) && (int) $code > 0) { return (int) $code; }
        if (preg_match('/\[(\d{4})\]/', $e->getMessage(), $m)) { return (int) $m[1]; }
        return null;
    }
}

/** 이 예외가 "잠시 기다렸다 다시 붙으면 통할" 접속 실패인가. */
if (!function_exists('vg_db_is_retryable_connect')) {
    function vg_db_is_retryable_connect(Throwable $e): bool {
        $errno = vg_db_driver_errno($e);
        return $errno !== null && in_array($errno, VG_DB_CONNECT_RETRY_ERRNOS, true);
    }
}

// PDO 싱글턴. 예외 모드 + 진짜 prepared statement.
//   접속은 짧게 재시도한다 — compose 의 `depends_on: condition: service_healthy` 는 **최초 기동에만**
//   걸려서 운영 중 DB 재시작을 못 막는다. 스케줄러는 60초 뒤마다 새 프로세스로 재실행되니 결국 회복하지만
//   그 사이 실행이 통째로 유실됐다(운영 실측 2026-07-26).
if (!function_exists('vg_pdo')) {
    function vg_pdo(): PDO {
        static $pdo = null;
        if ($pdo instanceof PDO) {
            return $pdo;
        }
        $cfg = require __DIR__ . '/config.php';
        $dsn = sprintf(
            'mysql:host=%s;port=%s;dbname=%s;charset=utf8mb4',
            $cfg['db_host'], $cfg['db_port'], $cfg['db_name']
        );
        $opts = [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ];
        for ($try = 1; ; $try++) {
            try {
                // 성공한 PDO 만 static 에 담는다 — 실패한 값이 캐시되면 이후 호출이 전부 깨진다.
                $pdo = new PDO($dsn, $cfg['db_user'], $cfg['db_pass'], $opts);
                if ($try > 1) { error_log(sprintf('[db] 접속 재시도 %d회 후 성공', $try - 1)); }
                return $pdo;
            } catch (PDOException $e) {
                if ($try >= VG_DB_CONNECT_TRIES || !vg_db_is_retryable_connect($e)) {
                    // 상세(호스트·SQLSTATE·자격증명 힌트)는 서버 로그로만. 사용자에겐 일반 메시지.
                    //   previous 로 원본을 달지 않는다 — 미처리 예외는 PHP 가 체인을 전부 출력해
                    //   display_errors 켜진 환경에서 상세가 화면으로 새어 나간다.
                    error_log(sprintf('[db] 접속 실패(%d회 시도): %s', $try, $e->getMessage()));
                    throw new RuntimeException('데이터베이스에 연결할 수 없습니다.');
                }
                error_log(sprintf('[db] 접속 실패 재시도 %d/%d: %s', $try, VG_DB_CONNECT_TRIES, $e->getMessage()));
                usleep(VG_DB_CONNECT_WAIT_US);
            }
        }
    }
}

/**
 * 호스트별 "최신(비삭제) 스캔" 파생 테이블. 별칭 뒤 컬럼은 host_id, mid(=scan_id).
 *   'JOIN ' . vg_latest_scan_subq() . ' t ON t.mid = s.scan_id'  (LEFT JOIN 도 가능 — assets.php)
 * is_deleted=1 스캔은 최신 후보에서 제외한다(소프트삭제된 스캔은 최신이 아니다).
 * 예전엔 화면마다 이 조건 유무가 갈려 있어(export.php 만 있었다) 삭제된 스캔이 최신으로
 * 잡히는 화면과 안 잡히는 화면이 공존했다 — 여기 하나로 모아 통일한다.
 */
if (!function_exists('vg_latest_scan_subq')) {
    function vg_latest_scan_subq(): string {
        return '(SELECT host_id, MAX(scan_id) AS mid FROM tb_scan WHERE is_deleted = 0 GROUP BY host_id)';
    }
}

/**
 * finding 의 조치 버전 하나(있으면). 상관 서브쿼리라 바깥 쿼리에 tb_finding 별칭 f 가 있어야 한다.
 * findings.php·host.php·export.php 가 각자 같은 서브쿼리를 들고 있던 걸 통일.
 */
const VG_FIXED_VERSION_SUBQ =
    "(SELECT a.fixed_version FROM tb_cve_affected_package a
        WHERE a.cve_id = f.cve_id AND a.package_name = f.package_name
          AND a.fixed_version IS NOT NULL LIMIT 1) AS fixed_version";

/**
 * 여러 scan_id 의 심각도별 건수를 [scan_id => [severity => count]] 로. 빈 배열이면 빈 배열.
 * assets.php·host.php(스캔이력 탭)·index.php 가 각자 같은 조회+누적 루프를 들고 있던 걸 통일.
 */
if (!function_exists('vg_sev_by_scan_ids')) {
    function vg_sev_by_scan_ids(PDO $pdo, array $scanIds): array {
        if (!$scanIds) { return []; }
        $in = implode(',', array_fill(0, count($scanIds), '?'));
        $st = $pdo->prepare("SELECT scan_id, severity, COUNT(*) c FROM tb_finding WHERE scan_id IN ($in) GROUP BY scan_id, severity");
        $st->execute($scanIds);
        $out = [];
        foreach ($st->fetchAll() as $f) { $out[(int) $f['scan_id']][$f['severity']] = (int) $f['c']; }
        return $out;
    }
}

// 교착 재시도 파라미터. 대기는 지수 백오프 + 지터(같은 두 트랜잭션이 같은 간격으로 재충돌하는 것을 피한다).
//   최악 대기 = 50+100ms 에 지터를 더한 수준 — 웹 요청 경로도 이 함수를 쓰므로 짧게 잡는다.
const VG_TX_DEADLOCK_TRIES   = 3;      // 총 시도 횟수(첫 시도 포함)
const VG_TX_DEADLOCK_WAIT_US = 50000;  // 첫 재시도 기본 대기(마이크로초). 시도마다 2배 + 0~같은 값의 지터.

/**
 * 이 예외가 교착(1213)·락 대기 초과(1205) 인가 — 재시도하면 통할 실패.
 *   1213 은 원인을 제거해도 동시성 상황에 따라 나므로(matcher.php 는 이미 READ COMMITTED 로
 *   갭락 원인을 없앴는데도 운영에서 2건 났다) 재시도가 정석이다.
 *   1205 는 SQLSTATE 가 HY000 이라 드라이버 번호를 함께 봐야 잡힌다.
 */
if (!function_exists('vg_db_is_retryable_deadlock')) {
    function vg_db_is_retryable_deadlock(Throwable $e): bool {
        if (!$e instanceof PDOException) { return false; }
        if ((string) $e->getCode() === '40001') { return true; }
        $info = $e->errorInfo;
        if (is_array($info) && (string) ($info[0] ?? '') === '40001') { return true; }
        $errno = vg_db_driver_errno($e);
        return $errno === 1213 || $errno === 1205;
    }
}

/**
 * 콜백을 트랜잭션 안에서 실행한다. 이미 트랜잭션 중이면 새로 시작하지 않고 그대로
 * 참여한다(중첩 호출 안전). $isolation 이 있으면 새 트랜잭션을 시작할 때만 적용한다.
 *
 * 교착(1213)·락 대기 초과(1205)는 **자기가 트랜잭션을 소유할 때만** 롤백 후 재시도한다.
 *   남의 트랜잭션에 참여 중이면 롤백 범위가 호출자 것이라 여기서 되돌릴 게 없고, 콜백만 다시
 *   돌리면 이미 죽은 트랜잭션 위에서 반쪽으로 실행된다 → 그대로 던져 호출자가 결정하게 한다.
 * 전제(호출부 확인 완료): 소유 경로의 콜백은 전부 `DELETE ... WHERE <키>` 뒤 `INSERT` 로
 *   통째 재작성하므로 재실행이 안전하다 — matcher.php(tb_finding·tb_suppressed_finding),
 *   cce.php(tb_cce_finding), package_summary.php(tb_package_summary).
 */
if (!function_exists('vg_with_tx')) {
    function vg_with_tx(PDO $pdo, callable $fn, ?string $isolation = null)
    {
        // 참여만 하는 경로는 예전 그대로 — 트랜잭션을 열지도 닫지도 않고 재시도도 하지 않는다.
        if ($pdo->inTransaction()) {
            return $fn();
        }
        for ($try = 1; ; $try++) {
            // SET TRANSACTION(SESSION/GLOBAL 없이)은 **다음 트랜잭션 하나에만** 걸리므로
            //   재시도마다 다시 걸어야 한다.
            if ($isolation !== null) {
                $pdo->exec("SET TRANSACTION ISOLATION LEVEL {$isolation}");
            }
            $pdo->beginTransaction();
            try {
                $result = $fn();
                $pdo->commit();
                if ($try > 1) { error_log(sprintf('[db] 트랜잭션 재시도 %d회 후 성공', $try - 1)); }
                return $result;
            } catch (Throwable $e) {
                if ($pdo->inTransaction()) { $pdo->rollBack(); }
                if ($try >= VG_TX_DEADLOCK_TRIES || !vg_db_is_retryable_deadlock($e)) { throw $e; }
                // 조용히 삼키지 않는다 — 로그가 없으면 교착 빈도가 안 보인다.
                error_log(sprintf('[db] 교착 재시도 %d/%d: %s', $try, VG_TX_DEADLOCK_TRIES, $e->getMessage()));
                // 롤백 **뒤에** 기다린다(락을 쥔 채 자면 상대도 못 풀린다).
                $wait = VG_TX_DEADLOCK_WAIT_US << ($try - 1);
                usleep($wait + random_int(0, $wait));
            }
        }
    }
}

/** JSON 컬럼(문자열) 을 배열로. NULL·빈 문자열·파싱 실패는 전부 빈 배열. */
if (!function_exists('vg_json_col')) {
    function vg_json_col($val): array {
        return json_decode((string) $val, true) ?: [];
    }
}
