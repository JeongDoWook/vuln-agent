<?php
declare(strict_types=1);

/**
 * cve/queries.php — CVE 상세(cve.php)의 조회층.
 *   각 vg_cve_load_*() 는 섹션 하나가 쓸 데이터만 읽어 돌려준다. 렌더는 이 파일의 책임이
 *   아니다 — 섹션별 HTML 은 cve/sections/*.php 가 갖는다.
 *
 *   **페이저 파라미터 이름은 여기서 정하지 않는다.** 세 섹션(벤더 판정·영향 패키지·발견 위치)이
 *   한 화면에 동시에 존재해 page/per_page 가 충돌하므로 cve.php 가 섹션마다 다른 이름으로
 *   읽어 이 함수들엔 **이미 정해진 페이지 번호·크기만** 넘긴다(#278). 이 파일이 이름을
 *   다시 정하면 그 규약이 두 곳으로 갈라진다.
 */

/**
 * 벤더 판정 5종 — vendor.php 의 VG_VENDOR_SRC 를 이 CVE 하나로 좁혀 최소 재현한다
 * (의도적 중복 — vendor.php 는 필터·페이지네이션까지 갖춘 별도 화면이라 그대로 재사용할 수
 * 없고, 여긴 "한 CVE 분량" 이라 COUNT·LIMIT 도 필요 없다. vendor.php 자체는 건드리지 않는다).
 * cols 는 UNION 컬럼을 (src, vendor, rel, pkg, fixed, state) 로 고정 — 다섯 갈래가 같아야 한다.
 */
const VG_CVE_VENDOR_SRC = [
    'debtracker' => [
        'label' => '데비안 보안 트래커',
        'from'  => 'tb_debian_tracker',
        'cve'   => 'cve_id',
        'soft'  => true,
        'cols'  => "'debtracker' AS src, 'debian' AS vendor, release_codename AS rel, pkg_name AS pkg,"
                 . " fixed_version AS fixed, IF(has_fix = 1, '수정본 있음', '수정본 없음') AS state,"
                 . " other_versions AS extra1, is_binary AS extra2",
    ],
    'rhoval' => [
        'label' => 'RHEL 계열 벤더 권고(OVAL)',
        'from'  => 'tb_vendor_errata',
        'cve'   => 'cve_id',
        'soft'  => true,
        'cols'  => "'rhoval' AS src, vendor, release_major AS rel, pkg_name AS pkg,"
                 . " fixed_evr AS fixed, severity AS state, advisory AS extra1, NULL AS extra2",
    ],
    'rhunfixed' => [
        'label' => 'Red Hat 미수정 CVE(조치 불가)',
        'from'  => 'tb_vendor_unfixed',
        'cve'   => 'cve_id',
        'soft'  => true,
        'cols'  => "'rhunfixed' AS src, vendor, release_major AS rel, component AS pkg,"
                 . " NULL AS fixed, fix_state AS state, cvss AS extra1, checked_at AS extra2",
    ],
    'ubuntuoval' => [
        'label' => '우분투 보안 OVAL',
        'from'  => 'tb_ubuntu_oval',
        'cve'   => 'cve_id',
        'soft'  => true,
        'cols'  => "'ubuntuoval' AS src, 'ubuntu' AS vendor, release_codename AS rel, pkg_name AS pkg,"
                 . " fixed_evr AS fixed, severity AS state, NULL AS extra1, NULL AS extra2",
    ],
    'kcve' => [
        'label' => '리눅스 커널 CNA(kernel.org)',
        'from'  => 'tb_kernel_cve_fix f JOIN tb_kernel_cve k ON k.cve_id = f.cve_id',
        'cve'   => 'f.cve_id',
        'soft'  => false,   // 커널 두 테이블엔 소프트삭제 컬럼이 없다(vendor.php 와 같은 확인 사항).
        'cols'  => "'kcve' AS src, 'kernel' AS vendor, f.stream AS rel, 'linux' AS pkg,"
                 . " f.fixed_version AS fixed, k.mainline_fixed AS state, NULL AS extra1, NULL AS extra2",
    ],
];

/** CVE 본체. 없으면 null — "아직 수집되지 않은 CVE" 화면으로 갈린다. */
function vg_cve_load_cve(PDO $pdo, string $cveId): ?array {
    $stmt = $pdo->prepare('SELECT * FROM tb_cve WHERE cve_id = ?');
    $stmt->execute([$cveId]);
    return $stmt->fetch() ?: null;
}

/** CISA KEV 등재 여부. 없으면 null. */
function vg_cve_load_kev(PDO $pdo, string $cveId): ?array {
    $stmt = $pdo->prepare('SELECT * FROM tb_kev_catalog WHERE cve_id = ?');
    $stmt->execute([$cveId]);
    return $stmt->fetch() ?: null;
}

/**
 * 벤더 판정 5종 UNION — 커널/RHEL/우분투는 릴리스·패키지별로 행이 쪼개져 CVE 하나가
 *   수백~수천 건도 나올 수 있다(CVE-2023-44487 실측 373건). 정확한 총 건수를 COUNT 로
 *   구하고, 목록은 페이지 단위(vpage/vper_page)만 가져온다.
 */
function vg_cve_load_vendor(PDO $pdo, string $cveId, int $vPage, int $vPerPage): array {
    $vParts = []; $vParams = [];
    foreach (VG_CVE_VENDOR_SRC as $def) {
        $w = ($def['soft'] ? 'is_deleted = 0 AND ' : '') . $def['cve'] . ' = ?';
        $vParts[] = "SELECT {$def['cols']} FROM {$def['from']} WHERE $w";
        $vParams[] = $cveId;
    }
    $vUnion = implode(' UNION ALL ', $vParts);

    $stmt = $pdo->prepare("SELECT COUNT(*) FROM ($vUnion) t");
    $stmt->execute($vParams);
    $vendorTotal = (int) $stmt->fetchColumn();

    $vOffset = ($vPage - 1) * $vPerPage;
    $stmt = $pdo->prepare("$vUnion ORDER BY src, vendor, rel LIMIT $vPerPage OFFSET $vOffset");
    $stmt->execute($vParams);

    return ['total' => $vendorTotal, 'rows' => $stmt->fetchAll()];
}

/** 영향 패키지 — 이 CVE 의 전역 영향 범위(설치 여부 무관). */
function vg_cve_load_affected(PDO $pdo, string $cveId, int $aPage, int $aPerPage): array {
    $stmt = $pdo->prepare('SELECT COUNT(*) FROM tb_cve_affected_package WHERE cve_id = ?');
    $stmt->execute([$cveId]);
    $affectedTotal = (int) $stmt->fetchColumn();

    $aOffset = ($aPage - 1) * $aPerPage;
    $stmt = $pdo->prepare(
        "SELECT ecosystem, package_name, fixed_version FROM tb_cve_affected_package WHERE cve_id = ?
         ORDER BY ecosystem, package_name LIMIT $aPerPage OFFSET $aOffset"
    );
    $stmt->execute([$cveId]);

    return ['total' => $affectedTotal, 'rows' => $stmt->fetchAll()];
}

/**
 * 호스트별 최신 스캔 기준으로 이 CVE 가 발견된 위치.
 *   한 자산에서 여러 건이 나온다: 같은 CVE 가 여러 패키지에 걸리고(curl·libcurl4t64 처럼
 *   같은 소스의 바이너리들), 컨테이너 안에서도 따로 잡힌다.
 *   {total(발견 건수), assetTotal(호스트 수), rows} 를 돌려준다.
 */
function vg_cve_load_locations(PDO $pdo, string $cveId, int $page, int $perPage): array {
    $locSql =
        "FROM tb_finding f
         JOIN tb_scan s ON s.scan_id = f.scan_id
         JOIN tb_host h ON h.host_id = s.host_id
         LEFT JOIN tb_container c ON c.container_id = f.container_id
         LEFT JOIN tb_finding_evidence fe ON fe.finding_id = f.finding_id
         JOIN " . vg_latest_scan_subq() . " latest
           ON latest.host_id = s.host_id AND latest.mid = s.scan_id
         WHERE f.cve_id = ?";
    $stmt = $pdo->prepare("SELECT COUNT(*) $locSql");
    $stmt->execute([$cveId]);
    $locTotal = (int) $stmt->fetchColumn();

    // **영향 자산은 발견 건수가 아니라 호스트 수다.** COUNT(*) 를 "N대"로 찍으면
    //   서버 1대인데 "4대"가 된다(패키지 2종 × CVE 2건 = 4행이었을 뿐 — 실측).
    //   위험 범위를 부풀려 보여주는 셈이라, 중복 없는 호스트로 센다.
    $stmt = $pdo->prepare("SELECT COUNT(DISTINCT h.host_id) $locSql");
    $stmt->execute([$cveId]);
    $assetTotal = (int) $stmt->fetchColumn();

    $offset = ($page - 1) * $perPage;
    $stmt = $pdo->prepare(
        "SELECT h.host_id, h.fqdn, IFNULL(c.cid, '') AS ctr,
                f.severity, f.runtime_status, f.package_name, f.installed_version,
                f.needs_restart, f.no_fix, fe.fixed_version, s.collected_at
         $locSql
         ORDER BY FIELD(f.severity,'CRITICAL','HIGH','MEDIUM','LOW'), h.fqdn, c.cid
         LIMIT $perPage OFFSET $offset"
    );
    $stmt->execute([$cveId]);

    return ['total' => $locTotal, 'assetTotal' => $assetTotal, 'rows' => $stmt->fetchAll()];
}
