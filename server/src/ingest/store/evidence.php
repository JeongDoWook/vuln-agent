<?php
declare(strict_types=1);

/**
 * ingest/store/evidence.php — 매처의 억제·비억제 **근거**가 되는 관측물 저장.
 *   changelog CVE·errata·debsecan 은 "이미 고쳐졌다"는 근거이고, 재시작 필요(stale lib)는
 *   반대로 "아직 고쳐지지 않았다"는 근거다. 판정 자체는 matcher 가 한다 — 여기는 저장만.
 */

/** changelog CVE 벌크 (백포트 근거 — 매처가 억제 판정에 사용) */
function vg_ingest_store_changelog_cves(PDO $pdo, int $scanId, array $clogRows): void
{
    $ins = $pdo->prepare(
        'INSERT INTO tb_pkg_changelog_cve (scan_id, package_name, cve_id, evidence)
             VALUES (?, ?, ?, ?)'
    );
    foreach ($clogRows as $r) {
        $ins->execute([$scanId, $r[0], $r[1], $r[2]]);
    }
}

/** 재시작 필요 벌크 (옛 라이브러리 상주 — 매처가 억제를 막는 근거로 사용) */
function vg_ingest_store_stale_libs(PDO $pdo, int $scanId, array $staleRows): void
{
    $ins = $pdo->prepare(
        'INSERT INTO tb_stale_lib (scan_id, pid, comm, package_name, lib_path)
             VALUES (?, ?, ?, ?, ?)'
    );
    foreach ($staleRows as $r) {
        $ins->execute([$scanId, (int) $r[0], $r[1], $r[2], mb_strimwidth((string) $r[3], 0, 512, '')]);
    }
}

/** debsecan 벌크 (데비안 트래커가 "아직 취약"이라 본 CVE — 매처가 나머지를 억제하는 근거) */
function vg_ingest_store_debsecan(PDO $pdo, int $scanId, array $debsecanRows): void
{
    $ins = $pdo->prepare(
        'INSERT INTO tb_debsecan (scan_id, cve_id, package_name) VALUES (?, ?, ?)'
    );
    foreach ($debsecanRows as $r) {
        $ins->execute([$scanId, $r[0], $r[1]]);
    }
}

/** errata CVE 벌크 (벤더가 "이 빌드에서 고쳤다"고 확인한 CVE — 매처가 억제 판정에 사용) */
function vg_ingest_store_errata(PDO $pdo, int $scanId, array $errataRows): void
{
    $ins = $pdo->prepare(
        'INSERT INTO tb_applied_errata (scan_id, package_name, cve_id, evidence)
             VALUES (?, ?, ?, ?)'
    );
    foreach ($errataRows as $r) {
        $ins->execute([$scanId, $r[0], $r[1], $r[2]]);
    }
}
