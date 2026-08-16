<?php
declare(strict_types=1);

/**
 * ingest/store/runtime.php — 호스트의 런타임 관측 저장: 네트워크 노출 · 실행 프로세스.
 *   매처가 "외부노출/로드됨" 등급을 매기는 근거다. 컨테이너 쪽 같은 값은 container_id 매핑이
 *   필요해 store/containers.php 가 갖는다.
 */

/** 노출 벌크(호스트, container_id 기본값 0). */
function vg_ingest_store_exposures(PDO $pdo, int $scanId, array $expRows): void
{
    $ins = $pdo->prepare(
        'INSERT INTO tb_exposure
                (scan_id, pid, proc, proto, bind_addr, port, scope, exe_pkg, loaded_pkgs)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
    );
    foreach ($expRows as $f) {
        $ins->execute([
            $scanId,
            ($f[0] !== '' ? (int) $f[0] : null),
            $f[1], $f[2], $f[3],
            ($f[4] !== '' ? (int) $f[4] : null),
            $f[5], $f[6], $f[7],
        ]);
    }
}

/** 실행 프로세스 벌크(호스트). */
function vg_ingest_store_processes(PDO $pdo, int $scanId, array $procRows): void
{
    $ins = $pdo->prepare(
        'INSERT INTO tb_process (scan_id, pid, comm, username, exe_pkg, loaded_pkgs)
             VALUES (?, ?, ?, ?, ?, ?)'
    );
    foreach ($procRows as $f) {
        $ins->execute([
            $scanId,
            ($f[0] !== '' ? (int) $f[0] : null),
            $f[1], $f[2], $f[3], $f[4],
        ]);
    }
}
