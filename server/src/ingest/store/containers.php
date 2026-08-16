<?php
declare(strict_types=1);

/**
 * ingest/store/containers.php — 컨테이너 스트림 저장.
 *
 *   ⚠ 실행 순서: 컨테이너 목록이 **먼저** 들어가야 한다. vg_ingest_store_containers 가 돌려주는
 *   cid → container_id 지도가 없으면 그 아래(패키지·프로세스·노출·SBOM 엣지)가 붙을 곳을
 *   못 찾는다. 지도에 없는 cid 의 행은 원래부터 버린다 — 그 규칙도 그대로 옮겼다.
 */

/**
 * 컨테이너 자체 메타. 안의 패키지(license 포함)는 tb_package 벌크에 들어간다.
 *   컨테이너는 호스트와 OS 가 다를 수 있어(호스트 Rocky + 컨테이너 Debian) os 를 따로 갖는다.
 *   반환: cid => tb_container.container_id
 */
function vg_ingest_store_containers(PDO $pdo, int $scanId, array $ctrRows): array
{
    $ctrIds = [];
    $insC = $pdo->prepare(
        'INSERT INTO tb_container (scan_id,cid,name,image,image_digest,k8s_namespace,k8s_pod,k8s_container,workload_ref,runtime_state,sbom_format,sbom_hash,os_id,os_version,manager,pkg_count)
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'
    );
    foreach ($ctrRows as $cid => $f) {
        $insC->execute([
            $scanId, $cid,
            ($f[1] !== '' ? $f[1] : null), ($f[2] !== '' ? $f[2] : null),
            (($f[7] ?? '') !== '' ? $f[7] : null), (($f[8] ?? '') !== '' ? $f[8] : null),
            (($f[9] ?? '') !== '' ? $f[9] : null), (($f[10] ?? '') !== '' ? $f[10] : null),
            (($f[11] ?? '') !== '' ? $f[11] : null), (($f[12] ?? '') !== '' ? $f[12] : 'running'),
            (($f[13] ?? '') !== '' ? $f[13] : null), (($f[14] ?? '') !== '' ? $f[14] : null),
            ($f[3] !== '' ? $f[3] : null), ($f[4] !== '' ? $f[4] : null),
            ($f[5] !== '' ? $f[5] : null), (int) $f[6],
        ]);
        $ctrIds[$cid] = (int) $pdo->lastInsertId();
    }
    return $ctrIds;
}

/** 컨테이너 안의 패키지 — 같은 tb_package 에 container_id 를 달아 넣는다(0 = 호스트). */
function vg_ingest_store_container_packages(PDO $pdo, int $scanId, array $ctrPkgRows, array $ctrIds): void
{
    // license(6번째 필드)는 SBOM 경로(vg_ingest_parse_sbom)만 채운다 — rpm/apk 목록·rpmdb
    //   경로는 이 자리가 비어 null 로 저장된다(OS 패키지 라이선스는 이번 라운드 scope_out).
    $ins = $pdo->prepare(
        'INSERT INTO tb_package (scan_id, container_id, manager, name, version, source_pkg, license)
             VALUES (?, ?, ?, ?, ?, ?, ?)'
    );
    $storedCtrPkgCounts = [];
    foreach ($ctrPkgRows as $r) {
        $cidKey = $r[0];
        if (!isset($ctrIds[$cidKey])) { continue; }   // 목록에 없는 컨테이너의 패키지는 버린다
        $ins->execute([
            $scanId, $ctrIds[$cidKey], $r[1], $r[2], $r[3],
            (($r[4] ?? '') !== '' ? $r[4] : null),
            (($r[5] ?? '') !== '' ? $r[5] : null),
        ]);
        $storedCtrPkgCounts[$cidKey] = ($storedCtrPkgCounts[$cidKey] ?? 0) + 1;
    }

    // 에이전트가 컨테이너 안에서 rpm 명령을 실행하지 못하면 목록의 pkg_count는 0이다.
    // 이 경우에도 중앙이 업로드된 RPM DB를 파싱해 패키지를 저장하므로, 실제 저장 건수로
    // 컨테이너 요약을 보정해야 UI가 이를 "패키지 없음/판정 불가"로 오인하지 않는다.
    if ($storedCtrPkgCounts) {
        $updCtrPkgCount = $pdo->prepare('UPDATE tb_container SET pkg_count = ? WHERE container_id = ?');
        foreach ($storedCtrPkgCounts as $cidKey => $storedCount) {
            $updCtrPkgCount->execute([$storedCount, $ctrIds[$cidKey]]);
        }
    }
}

/**
 * 컨테이너 런타임 프로세스 — 호스트와 같은 테이블에 container_id 를 달아 넣는다(0 = 호스트).
 *   이게 있어야 매처가 컨테이너 패키지에도 "로드됨/외부노출" 을 적용해 등급을 매길 수 있다.
 */
function vg_ingest_store_container_processes(PDO $pdo, int $scanId, array $ctrProcRows, array $ctrIds): void
{
    $ins = $pdo->prepare(
        'INSERT INTO tb_process (scan_id, container_id, pid, comm, username, exe_pkg, loaded_pkgs)
             VALUES (?, ?, ?, ?, ?, ?, ?)'
    );
    foreach ($ctrProcRows as $f) {
        if (!isset($ctrIds[$f[0]])) { continue; }   // 목록에 없는 컨테이너 것은 버린다
        $ins->execute([
            $scanId, $ctrIds[$f[0]],
            ($f[1] !== '' ? (int) $f[1] : null),
            $f[2], $f[3], $f[4], $f[5],
        ]);
    }
}

/** 컨테이너 네트워크 노출 — 호스트 노출과 같은 tb_exposure 에 container_id 를 달아 넣는다. */
function vg_ingest_store_container_exposures(PDO $pdo, int $scanId, array $ctrExpRows, array $ctrIds): void
{
    $ins = $pdo->prepare(
        'INSERT INTO tb_exposure
                (scan_id, container_id, pid, proc, proto, bind_addr, port, scope, exe_pkg, loaded_pkgs)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
    );
    foreach ($ctrExpRows as $f) {
        if (!isset($ctrIds[$f[0]])) { continue; }
        $ins->execute([
            $scanId, $ctrIds[$f[0]],
            ($f[1] !== '' ? (int) $f[1] : null),
            $f[2], $f[3], $f[4],
            ($f[5] !== '' ? (int) $f[5] : null),
            $f[6], $f[7], $f[8],
        ]);
    }
}
