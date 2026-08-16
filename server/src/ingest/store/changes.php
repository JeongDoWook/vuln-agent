<?php
declare(strict_types=1);

/**
 * ingest/store/changes.php — 패키지 변경 이력(tb_pkg_change).
 *   직전 스냅샷과 무엇이 달라졌나(설치/제거/업그레이드/다운그레이드).
 *   첫 수집(직전 스냅샷 없음)은 전부 "설치"로 기록하지 않는다 — 의미 없는 폭증만 만든다.
 *   그래서 호출부가 $prev !== null 일 때만 부른다.
 *
 *   비교 재료는 vg_ingest_build_pkg_map/vg_ingest_diff_packages(ingest/snapshot.php)가 만들고,
 *   버전 승강 판정은 vg_ver_cmp(vercmp.php)가 한다 — 둘 다 ingest.php 가 이미 require 해 둔다.
 */

/** 반환: 이번에 기록한 패키지 변경 건수. */
function vg_ingest_store_pkg_changes(
    PDO $pdo,
    int $hostId,
    int $scanId,
    int $prevScanId,
    string $manager,
    array $pkgRows,
    array $langRows
): int {
    $chgCount = 0;

    // 호스트 패키지만 비교한다(container_id=0). 컨테이너 것까지 섞으면 컨테이너 패키지가
    // 전부 "제거됨"으로 잘못 기록된다 — $curPkgs 에는 호스트·언어 패키지만 담기기 때문이다.
    $q = $pdo->prepare('SELECT manager, name, version FROM tb_package WHERE scan_id = ? AND container_id = 0');
    $q->execute([$prevScanId]);
    $prevPkgs = [];
    foreach ($q->fetchAll() as $r) {
        $prevPkgs[$r['manager'] . '|' . $r['name']] = (string) $r['version'];
    }
    $curPkgs = vg_ingest_build_pkg_map($manager, $pkgRows, $langRows);
    // 배포판 규칙으로 비교해야 승강을 정확히 가른다(1:1.1 > 2.0 같은 epoch 사례).
    $pkgChanges = vg_ingest_diff_packages($prevPkgs, $curPkgs, 'vg_ver_cmp');

    $insChg = $pdo->prepare(
        'INSERT INTO tb_pkg_change (host_id, scan_id, manager, package_name, change_type, old_version, new_version)
             VALUES (?, ?, ?, ?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE change_type=VALUES(change_type),
               old_version=VALUES(old_version), new_version=VALUES(new_version)'
    );
    foreach ($pkgChanges as [$key, $type, $old, $new]) {
        [$mgr, $name] = explode('|', $key, 2);
        $insChg->execute([$hostId, $scanId, $mgr, $name, $type, $old, $new]);
        $chgCount++;
    }

    return $chgCount;
}
