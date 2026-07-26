<?php
declare(strict_types=1);

// PDO 싱글턴. 예외 모드 + 진짜 prepared statement.
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
        $pdo = new PDO($dsn, $cfg['db_user'], $cfg['db_pass'], [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ]);
        return $pdo;
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

/**
 * 콜백을 트랜잭션 안에서 실행한다. 이미 트랜잭션 중이면 새로 시작하지 않고 그대로
 * 참여한다(중첩 호출 안전). $isolation 이 있으면 새 트랜잭션을 시작할 때만 적용한다.
 */
if (!function_exists('vg_with_tx')) {
    function vg_with_tx(PDO $pdo, callable $fn, ?string $isolation = null)
    {
        $ownTx = !$pdo->inTransaction();
        if ($ownTx) {
            if ($isolation !== null) {
                $pdo->exec("SET TRANSACTION ISOLATION LEVEL {$isolation}");
            }
            $pdo->beginTransaction();
        }
        try {
            $result = $fn();
            if ($ownTx) { $pdo->commit(); }
            return $result;
        } catch (Throwable $e) {
            if ($ownTx && $pdo->inTransaction()) { $pdo->rollBack(); }
            throw $e;
        }
    }
}

/** JSON 컬럼(문자열) 을 배열로. NULL·빈 문자열·파싱 실패는 전부 빈 배열. */
if (!function_exists('vg_json_col')) {
    function vg_json_col($val): array {
        return json_decode((string) $val, true) ?: [];
    }
}
