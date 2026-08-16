<?php
declare(strict_types=1);

/**
 * ingest/store/packages.php — 패키지 스트림 저장: 호스트 패키지 · 언어 패키지 · 의존 그래프.
 *   전부 tb_package(그래프만 tb_package_dependency)로 들어간다. 컨테이너 안의 패키지는
 *   container_id 매핑이 필요해 store/containers.php 가 따로 갖는다.
 *   저장 전 문자셋 검증·dedup·상한은 파싱 단계에서 이미 끝났다.
 */

/** 설치 패키지 벌크(호스트, container_id=0). */
function vg_ingest_store_packages(PDO $pdo, int $scanId, string $manager, array $pkgRows, $originMap): void
{
    $ins = $pdo->prepare(
        'INSERT INTO tb_package (scan_id, manager, name, version, arch, source_pkg, source_version, vendor, origin)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
    );
    foreach ($pkgRows as $r) {
        // 출처: dpkg 는 apt Origin 라벨, rpm 은 VENDOR($r[5]).
        $origin = $manager === 'rpm'
            ? (($r[5] ?? '') !== '' ? $r[5] : null)
            : ($originMap[$r[0]] ?? null);
        $ins->execute([$scanId, $manager, $r[0], $r[1], $r[2], $r[3], $r[4], $r[5], $origin]);
    }
}

/**
 * 언어 패키지 벌크 — 같은 tb_package 에 manager=pip|npm|gem|composer 로 넣는다.
 *   매처가 manager 로 생태계(PyPI/npm/…)를 정해 OS 패키지와 섞이지 않게 매칭한다.
 */
function vg_ingest_store_lang_packages(PDO $pdo, int $scanId, array $langRows): void
{
    // license(4번째 필드)는 SBOM/METADATA/composer 유래일 때만 채워진다(vg_ingest_attach_pkg_license).
    $ins = $pdo->prepare(
        'INSERT INTO tb_package (scan_id, manager, name, version, license) VALUES (?, ?, ?, ?, ?)'
    );
    foreach ($langRows as $r) {
        $ins->execute([$scanId, $r[0], $r[1], $r[2], (($r[3] ?? '') !== '' ? $r[3] : null)]);
    }
}

/**
 * 패키지 의존성 그래프 벌크 — pom.xml 직접 선언(호스트, container_id=0) + SBOM 의존성 엣지.
 *   저장 전 문자셋 검증·dedup·상한은 파싱 단계(vg_ingest_parse_pom_deps/vg_ingest_parse_sbom)에서
 *   이미 끝났다 — 여기서는 SBOM 엣지의 cid → container_id 매핑만 한다.
 */
function vg_ingest_store_package_deps(PDO $pdo, int $scanId, array $pomDepRows, array $sbomDepRows, array $ctrIds): void
{
    $insDep = $pdo->prepare(
        'INSERT IGNORE INTO tb_package_dependency
                (scan_id, container_id, source, parent_manager, parent_name, parent_version,
                 child_manager, child_name, child_version)
             VALUES (?, 0, ?, ?, ?, ?, ?, ?, ?)'
    );
    foreach ($pomDepRows as $r) {
        $insDep->execute([$scanId, 'pom', null, null, null, $r[0], $r[1], $r[2]]);
    }
    $insSbomDep = $pdo->prepare(
        'INSERT IGNORE INTO tb_package_dependency
                (scan_id, container_id, source, parent_manager, parent_name, parent_version,
                 child_manager, child_name, child_version)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
    );
    foreach ($sbomDepRows as $r) {
        $cidKey = $r[0];
        if (!isset($ctrIds[$cidKey])) { continue; }   // 목록에 없는 컨테이너의 엣지는 버린다
        $insSbomDep->execute([
            $scanId, $ctrIds[$cidKey], 'sbom',
            $r[1], $r[2], $r[3],
            $r[4], $r[5], $r[6],
        ]);
    }
}
