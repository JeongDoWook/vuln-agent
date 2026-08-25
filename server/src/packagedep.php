<?php
declare(strict_types=1);

/**
 * packagedep.php — tb_package_dependency(패키지 의존성 엣지) 조회 전용 헬퍼.
 *   적재는 server/src/ingest_store.php 가 소유하고, 여기는 **읽기만** 한다.
 *   화면(server/public/depgraph.php)이 쓰는 것: 컨테이너 목록 → 엣지 한 번에 적재 →
 *   메모리에서 그래프 조립 → 정방향 트리 / 역방향 경로.
 *
 * ── 왜 "한 번에 긁고 메모리에서 조립" 인가 ─────────────────────────────────
 *   재귀 전개를 SQL 로 한 단계씩 풀면 깊이만큼 쿼리가 늘어난다(N+1). 엣지는
 *   (scan_id, container_id) 로 이미 좁혀지고 유니크 키 uk_pkg_dep_edge 의 좌측 접두가
 *   정확히 그 둘이라 인덱스 레인지 스캔 한 번으로 그 스캔·컨테이너의 엣지 전부가 나온다.
 *   한 SBOM 의 엣지 수는 수천 단위라 메모리 조립이 더 싸고 단순하다(KISS).
 *   그래도 비정상 데이터가 화면을 죽이지 못하게 VG_PKGDEP_EDGE_MAX 로 상한을 두고,
 *   상한에 걸리면 화면이 **잘렸다는 사실을 밝힌다**(조용히 자르지 않는다).
 */

require_once __DIR__ . '/format.php';   // VG_TONE_SEV — 심각도 표기·정렬 순서의 정본
require_once __DIR__ . '/vercmp.php';   // vg_ver_cmp — 수정버전 중 가장 높은 것을 고를 때만 쓴다
require_once __DIR__ . '/db.php';       // VG_FIXED_VERSION_SUBQ — 조치 버전 서브쿼리의 정본

// 한 화면이 메모리에 올리는 엣지 상한. 넘으면 잘린 사실을 화면에 표시한다.
const VG_PKGDEP_EDGE_MAX = 20000;
// 트리 전개 깊이 상한(루트=0). 넘는 가지는 "더 깊은 의존성 있음"으로 접어 둔다.
const VG_PKGDEP_DEPTH_MAX = 6;
// 한 화면에 그리는 노드 상한. 폭이 넓은 그래프가 한 페이지를 통째로 먹지 않게.
const VG_PKGDEP_NODE_MAX = 400;
// 역추적("상위 의존성")에서 보여주는 경로 개수 상한.
const VG_PKGDEP_PATH_MAX = 20;
// 부모별 묶음 집계가 읽는 취약점 행 상한. 넘으면 잘린 사실을 화면에 밝힌다(조용한 절단 금지).
const VG_PKGDEP_ROLLUP_FINDING_MAX = 20000;
// 화면에 보여주는 손댈 대상(부모) 개수 상한.
const VG_PKGDEP_ROLLUP_TOP = 5;
// 부모 하나의 하위 취약 패키지를 몇 개까지 이름으로 보여줄지.
const VG_PKGDEP_ROLLUP_PKG_TOP = 4;

/** 노드 키 — manager|name|version. 세 값 모두 적재 전 vg_pkg_ident_valid() 로 검증돼 '|' 가 없다. */
function vg_pkgdep_key(string $manager, string $name, string $version): string
{
    return $manager . '|' . $name . '|' . $version;
}

/** 키 → ['manager','name','version']. */
function vg_pkgdep_parts(string $key): array
{
    $f = explode('|', $key, 3);
    return ['manager' => $f[0] ?? '', 'name' => $f[1] ?? '', 'version' => $f[2] ?? ''];
}

/**
 * 이 스캔에서 의존성 엣지를 가진 컨테이너 단위 목록.
 *   반환: [container_id => ['edges' => 엣지수, 'label' => 표시명]]  (0 = 호스트 자신)
 *   컨테이너 이름은 tb_container 에서 한 번에 읽는다(컨테이너마다 조회하지 않는다).
 */
function vg_pkgdep_containers(PDO $pdo, int $scanId): array
{
    $st = $pdo->prepare(
        'SELECT container_id, COUNT(*) AS n
           FROM tb_package_dependency WHERE scan_id = ?
          GROUP BY container_id ORDER BY container_id'
    );
    $st->execute([$scanId]);
    $groups = [];
    foreach ($st->fetchAll() as $r) {
        $groups[(int) $r['container_id']] = ['edges' => (int) $r['n'], 'label' => ''];
    }
    if (!$groups) { return []; }

    $names = [];
    $st = $pdo->prepare('SELECT container_id, name, cid FROM tb_container WHERE scan_id = ?');
    $st->execute([$scanId]);
    foreach ($st->fetchAll() as $r) {
        $names[(int) $r['container_id']] = (string) ($r['name'] !== '' ? $r['name'] : $r['cid']);
    }
    foreach ($groups as $cid => $g) {
        $groups[$cid]['label'] = $cid === 0
            ? '호스트'
            : ($names[$cid] ?? ('컨테이너 #' . $cid));
    }
    return $groups;
}

/**
 * 그 스캔·컨테이너의 엣지를 **한 번에** 읽는다.
 *   반환: ['edges' => 원본행, 'loaded' => 읽은 수, 'truncated' => 상한에 걸렸나]
 */
function vg_pkgdep_load(PDO $pdo, int $scanId, int $containerId): array
{
    $st = $pdo->prepare(
        'SELECT source, parent_manager, parent_name, parent_version,
                child_manager, child_name, child_version
           FROM tb_package_dependency
          WHERE scan_id = ? AND container_id = ?
          ORDER BY package_dependency_id
          LIMIT ' . VG_PKGDEP_EDGE_MAX
    );
    $st->execute([$scanId, $containerId]);
    $edges = $st->fetchAll();
    return [
        'edges'     => $edges,
        'loaded'    => count($edges),
        'truncated' => count($edges) >= VG_PKGDEP_EDGE_MAX,
    ];
}

/**
 * 그 스캔·컨테이너의 취약점 행을 **한 번에** 읽는다.
 *   노드 색칠(vg_deptree_severity)과 조치 묶음(vg_pkgdep_rollup_unit)이 같은 한 벌을 봐야
 *   화면 안에서 "색은 칠했는데 조치 목록엔 없다" 는 어긋남이 안 생긴다 — 그래서 조회를
 *   여기 한곳에 둔다(DRY). 조회 범위는 엣지와 같다: uq_find 좌측 접두가 (scan_id, container_id)다.
 */
function vg_pkgdep_unit_findings(PDO $pdo, int $scanId, int $containerId): array
{
    // 조치 버전은 tb_finding 의 컬럼이 아니다 — CVE×패키지의 영향 범위 표에서 온다.
    //   서브쿼리는 화면마다 베끼지 않고 db.php 의 VG_FIXED_VERSION_SUBQ 하나를 쓴다(별칭 f 필요).
    //   uq_cap 좌측 접두가 (cve_id, package_name)이라 행마다 점 조회 한 번이다.
    $st = $pdo->prepare(
        'SELECT f.package_name, f.installed_version, f.severity, ' . VG_FIXED_VERSION_SUBQ . '
           FROM tb_finding f
          WHERE f.scan_id = ? AND f.container_id = ? AND f.is_deleted = 0
          LIMIT ' . VG_PKGDEP_ROLLUP_FINDING_MAX
    );
    $st->execute([$scanId, $containerId]);
    return $st->fetchAll();
}

/**
 * 취약 패키지별 **필요한 최소 버전**.
 *   반환: ['by_label' => ['이름 버전' => '수정버전'], 'by_key' => ['노드키' => '수정버전']]
 *   by_label 의 키는 vg_pkgdep_rollup_unit() 의 packages 항목과 **같은 형식**이라 부모별
 *   묶음의 패키지 목록에 그대로 붙는다. by_key 는 트리 노드 하나를 집어 볼 때 쓴다 —
 *   취약점 행의 설치버전 표기(rpm 의 epoch 등)와 그래프 노드의 버전이 글자로는 다를 수 있어
 *   라벨로는 못 찾는 경우가 있다.
 *
 *   ── 우리가 아는 것과 모르는 것 ──────────────────────────────────────────────
 *   자식의 수정버전은 피드가 준 사실이다(tb_finding.fixed_version). 반면 **그 하위 의존성을 가진
 *   상위 의존성의 버전**은 수집된 데이터에 없다 — tb_package_dependency 는 *설치된 스냅샷 한 벌*이지
 *   업스트림의 *버전별 의존 관계표*가 아니다. 그래서 조치 문장은 "부모를 올려라 + 자식은 X
 *   이상이어야 한다" 까지만 간다. 부모의 목표 버전은 **지어내지 않는다.**
 *   한 패키지에 CVE 가 여럿이면 그중 **가장 높은 수정버전**이 필요조건이다(vg_ver_cmp 로 고른다 —
 *   문자열 비교로는 1.2.10 이 1.2.9 보다 낮게 잡힌다).
 *   비교 규칙(rpm/dpkg/semver)은 그래프 노드의 manager 로 정한다 — 취약점 행에는 그 컬럼이 없다.
 */
function vg_pkgdep_fix_floor(array $idx, array $findings): array
{
    $best = [];   // 라벨 => 수정버전
    $keys = [];   // 라벨 => [노드키…]
    foreach ($findings as $f) {
        $fixed = trim((string) ($f['fixed_version'] ?? ''));
        if ($fixed === '') { continue; }
        $name = (string) ($f['package_name'] ?? '');
        $ver  = (string) ($f['installed_version'] ?? '');
        $cands = $idx['by_name_ver'][$name . '|' . $ver]
            ?? ($idx['by_name_norm'][$name . '|' . vg_pkgdep_version_norm($ver)] ?? []);
        if (!$cands) { continue; }   // 그래프에 없는 패키지 — 이 화면이 그리지도 않는다
        $label = $name . ' ' . $ver;
        $mgr   = vg_pkgdep_parts($cands[0])['manager'];
        if (!isset($best[$label]) || vg_ver_cmp($fixed, $best[$label], $mgr) > 0) { $best[$label] = $fixed; }
        foreach ($cands as $k) { $keys[$label][$k] = true; }
    }
    $byKey = [];
    foreach ($best as $label => $fixed) {
        foreach (array_keys($keys[$label] ?? []) as $k) { $byKey[$k] = $fixed; }
    }
    return ['by_label' => $best, 'by_key' => $byKey];
}

/**
 * 엣지 목록 → 그래프 구조.
 *   ['nodes' => [키 => true], 'children' => [부모키 => [자식키]], 'parents' => [자식키 => [부모키]],
 *    'roots' => [루트키], 'pom' => [pom 직접선언 키]]
 *
 *   · source='sbom' + parent 전부 NULL = 그 SBOM 의 **루트 표식행**(최상위 프로젝트 자신).
 *   · source='pom'  + parent NULL      = pom.xml 최상위 <dependencies> 직접 선언(부모가 없다).
 *   두 경우는 부모가 없다는 점은 같지만 뜻이 달라 따로 담는다 — 화면이 섞어 보이면
 *   "루트 프로젝트" 와 "루트를 모르는 직접 선언" 이 구분되지 않는다.
 */
function vg_pkgdep_build(array $edges): array
{
    $g = ['nodes' => [], 'children' => [], 'parents' => [], 'roots' => [], 'pom' => []];
    foreach ($edges as $e) {
        $child = vg_pkgdep_key((string) $e['child_manager'], (string) $e['child_name'], (string) $e['child_version']);
        $g['nodes'][$child] = true;

        $hasParent = $e['parent_manager'] !== null && $e['parent_name'] !== null && $e['parent_version'] !== null;
        if (!$hasParent) {
            if ((string) $e['source'] === 'pom') {
                $g['pom'][$child] = true;
            } else {
                $g['roots'][$child] = true;
            }
            continue;
        }
        $parent = vg_pkgdep_key((string) $e['parent_manager'], (string) $e['parent_name'], (string) $e['parent_version']);
        $g['nodes'][$parent] = true;
        $g['children'][$parent][$child] = true;
        $g['parents'][$child][$parent] = true;
    }
    // 루트 표식행이 없는 SBOM(도구가 metadata.component 를 안 넣은 경우)도 화면이 비지 않게,
    //   "부모가 하나도 없는 노드" 를 루트로 승격한다. 표식행이 있으면 이 승격은 무동작이다.
    if (!$g['roots']) {
        foreach ($g['children'] as $parent => $_) {
            if (!isset($g['parents'][$parent])) { $g['roots'][$parent] = true; }
        }
    }
    $g['roots'] = array_keys($g['roots']);
    $g['pom']   = array_keys($g['pom']);
    sort($g['roots']);
    sort($g['pom']);
    return $g;
}

/**
 * 버전 문자열의 **표기 차이만** 지운다(값 자체는 바꾸지 않는다).
 *   · rpm 의 epoch 접두(`1:3.0.7-24.el9` → `3.0.7-24.el9`) — SBOM 도구는 보통 epoch 을 안 붙인다.
 *   · 빌드 메타데이터(`1.2.3+build.5` → `1.2.3`) — 같은 산출물의 표기 흔들림.
 *   이 이상은 자르지 않는다. `3.1.4-r2` 와 `3.0.7-24.el9` 는 표기 차이가 아니라 **다른 패키지**다.
 */
function vg_pkgdep_version_norm(string $v): string
{
    $v = strtolower(trim($v));
    $v = (string) preg_replace('/^\d+:/', '', $v);
    $plus = strpos($v, '+');
    return ($plus !== false && $plus > 0) ? substr($v, 0, $plus) : $v;
}

/**
 * 이름·버전으로 노드를 찾기 위한 색인. 그래프 1개당 1회만 만든다(행마다 만들면 O(N²)).
 *   반환: ['by_name_ver' => ['이름|버전' => [키…]], 'by_name_norm' => ['이름|정규화버전' => [키…]]]
 *
 *   왜 manager 를 빼고 색인하나: tb_finding 에는 manager 컬럼이 **없다**(package_name·
 *   installed_version 뿐). 그래프 키는 manager|name|version 이라 취약점 행에서 곧장 키를
 *   조립할 수 없어, 이름+버전으로 좁힌 뒤 후보를 본다.
 */
function vg_pkgdep_index(array $g): array
{
    $idx = ['by_name_ver' => [], 'by_name_norm' => []];
    foreach (array_keys($g['nodes']) as $key) {
        $p = vg_pkgdep_parts($key);
        $idx['by_name_ver'][$p['name'] . '|' . $p['version']][] = $key;
        $idx['by_name_norm'][$p['name'] . '|' . vg_pkgdep_version_norm($p['version'])][] = $key;
    }
    return $idx;
}

/**
 * 취약점 행(패키지 이름·설치버전) → 그 패키지를 **직접 손댈 수 있는가** 판정.
 *   반환: ['verdict' => 'direct'|'transitive'|'unknown',
 *          'key' => 매칭된 그래프 노드 키(unknown 이면 ''),
 *          'parents' => 전이일 때 실제로 손댈 대상(루트 바로 아래 조상) 키 목록,
 *          'truncated' => 경로 탐색이 상한에 걸려 부모 목록이 전부가 아닐 수 있나]
 *
 *   · direct     = pom 직접선언이거나, SBOM 루트 자신 / 루트의 직속 자식
 *   · transitive = 루트에서 두 단계 이상 떨어져 있다 — 이 패키지만 갈아끼우면 부모가 깨진다
 *   · unknown    = 그래프에 없다. **이게 다수이며 정상이다**(SBOM·pom 이 없는 자산이 대부분).
 *
 *   ── 버전 표기 완화 ────────────────────────────────────────────────────────
 *   설치버전 문자열은 그래프 노드의 버전과 정확히 같지 않을 수 있다(rpm 의 EVR epoch,
 *   빌드 메타데이터). 그래서 (이름+버전) 정확 일치를 먼저 보고, 없으면
 *   vg_pkgdep_version_norm() 으로 **표기 차이만 지운** 뒤 다시 본다.
 *   **이름만으로 맞추지는 않는다.** 실측(dev): 같은 스캔에 `openssl 3.1.4-r2`(alpine)와
 *   `openssl 1:3.0.7-24.el9`(rpm)가 함께 있다 — 이름만 보면 alpine 쪽이 rpm 그래프의 부모를
 *   물려받아 **틀린 조치**가 나간다. 틀린 조치 제안은 없는 것보다 나쁘다(purl.php 와 같은 원칙).
 */
function vg_pkgdep_origin(array $g, array $idx, string $name, string $version): array
{
    $none = ['verdict' => 'unknown', 'key' => '', 'parents' => [], 'truncated' => false];
    if ($name === '') { return $none; }

    $cands = $idx['by_name_ver'][$name . '|' . $version]
        ?? ($idx['by_name_norm'][$name . '|' . vg_pkgdep_version_norm($version)] ?? []);
    if (!$cands) { return $none; }
    sort($cands);

    $parents = [];
    $truncated = false;
    foreach ($cands as $key) {
        // pom 직접선언·루트 자신은 부모를 따질 것도 없이 직접 대상이다.
        if (in_array($key, $g['pom'], true) || in_array($key, $g['roots'], true)) {
            return ['verdict' => 'direct', 'key' => $key, 'parents' => [], 'truncated' => false];
        }
        $r = vg_pkgdep_paths($g, $key);
        $truncated = $truncated || $r['truncated'];
        foreach ($r['paths'] as $path) {
            // [루트, 대상] 처럼 두 칸 이하면 루트의 직속 자식 = 직접 의존성이다.
            if (count($path) <= 2) {
                return ['verdict' => 'direct', 'key' => $key, 'parents' => [], 'truncated' => false];
            }
            $parents[$path[1]] = true;   // 루트 바로 아래 조상 = 실제로 올려야 할 대상
        }
    }
    if (!$parents) { return $none; }

    $keys = array_keys($parents);
    sort($keys);
    return ['verdict' => 'transitive', 'key' => $cands[0], 'parents' => $keys, 'truncated' => $truncated];
}

/** 취약점 행 → 판정 캐시의 키. 판정 단위는 (컨테이너, 패키지, 설치버전)이다. */
function vg_pkgdep_finding_key(int $containerId, string $name, string $version): string
{
    return $containerId . '|' . $name . '|' . $version;
}

/**
 * 심각도 순위(작을수록 위험). **정본은 VG_TONE_SEV 의 선언 순서**다 —
 *   화면 표기·SQL 의 FIELD() 정렬과 같은 순서를 쓰려고 여기서 새로 정의하지 않는다.
 *   모르는 값은 맨 뒤로 보낸다(등급이 비면 최고 심각도를 부풀리지 않는다).
 */
function vg_pkgdep_sev_rank(string $sev): int
{
    $i = array_search($sev, array_keys(VG_TONE_SEV), true);
    return $i === false ? PHP_INT_MAX : (int) $i;
}

/**
 * 손댈 대상(부모)별 묶음 — "이 하나를 올리면 N건이 함께 해결된다".
 *   반환: ['origins' => [vg_pkgdep_finding_key() => 전이면 vg_pkgdep_origin() 결과 + container_id,
 *                        아니면 null(=손댈 부모가 따로 없음)],
 *          'parents' => [['key','container_id','count','severity','sev_rank','packages'], …] 정렬됨,
 *          'finding_total' => 집계에 쓴 취약점 행 수, 'finding_truncated' => 행 상한에 걸렸나,
 *          'edge_truncated' / 'path_truncated' => 그래프·경로 상한에 걸렸나]
 *
 *   ── 왜 화면의 행이 아니라 "스캔 전체" 인가 ──────────────────────────────────
 *   지금 페이지에 뜬 행만 세면 **2페이지로 넘길 때마다 "N건 해결" 이 달라진다.**
 *   운영자는 그 숫자로 조치 순서를 정하는데, 페이지마다 답이 다른 우선순위는 우선순위가
 *   아니다. 그래서 취약점 행은 여기서 스캔 단위로 **따로 한 번** 읽는다(쿼리 1건).
 *
 *   ── 판정과 집계를 분리하는 이유 ─────────────────────────────────────────────
 *   판정(direct/transitive)은 패키지 단위라 캐시해 한 번만 하고, 건수는 **행 단위**로 센다.
 *   판정 캐시를 그대로 세면 같은 패키지의 취약점 여러 건이 1건으로 접혀 과소집계된다.
 *
 *   ── 호출 조건·비용 ─────────────────────────────────────────────────────────
 *   host.php 의 $depEdgeTotal 게이트 안에서만 부른다 — 엣지가 없는 자산에서는 이 함수 자체가
 *   호출되지 않아 쿼리가 한 건도 늘지 않는다. 안에서도 엣지가 있는 단위만 적재하며,
 *   적재는 컨테이너 단위로 1회다(행마다 적재하면 N+1). uk_pkg_dep_edge 좌측 접두가
 *   (scan_id, container_id)라 이 단위 조회만 인덱스를 탄다 — 그래서 전 호스트 통합
 *   목록(findings.php)에는 붙이지 않는다.
 *
 *   **버전은 제안하지 않는다.** 설치되지 않은 부모 버전의 하위 의존성이 무엇인지 우리는 모른다.
 *   여기서 내는 사실은 "이 부모를 올리면 N건이 함께 해결된다"까지다.
 */
function vg_pkgdep_scan_rollup(PDO $pdo, int $scanId): array
{
    $out = [
        'origins'          => [],
        'parents'          => [],
        'finding_total'    => 0,
        'finding_truncated' => false,
        'edge_truncated'   => false,
        'path_truncated'   => false,
    ];

    $groups = vg_pkgdep_containers($pdo, $scanId);
    if (!$groups) { return $out; }

    // 이 스캔의 취약점 전체(등급 무관 — 최고 심각도를 재려면 MEDIUM·LOW 도 봐야 한다).
    //   화면의 정렬·페이지네이션과 무관해야 하므로 여기서 자체 조회한다.
    $st = $pdo->prepare(
        'SELECT container_id, package_name, installed_version, severity
           FROM tb_finding WHERE scan_id = ?
          LIMIT ' . VG_PKGDEP_ROLLUP_FINDING_MAX
    );
    $st->execute([$scanId]);
    $findings = $st->fetchAll();
    $out['finding_total']     = count($findings);
    $out['finding_truncated'] = count($findings) >= VG_PKGDEP_ROLLUP_FINDING_MAX;

    // 엣지가 있는 단위의 행만 남긴다 — 나머지는 판정할 그래프 자체가 없다.
    $byCid = [];
    foreach ($findings as $f) {
        $cid = (int) ($f['container_id'] ?? 0);
        if (isset($groups[$cid])) { $byCid[$cid][] = $f; }
    }

    $agg = [];
    foreach ($byCid as $cid => $rows) {
        $load = vg_pkgdep_load($pdo, $scanId, $cid);
        if ($load['truncated']) { $out['edge_truncated'] = true; }
        $graph = vg_pkgdep_build($load['edges']);
        $index = vg_pkgdep_index($graph);

        $u = vg_pkgdep_rollup_unit($graph, $index, $cid, $rows);
        $out['origins'] += $u['origins'];
        if ($u['path_truncated']) { $out['path_truncated'] = true; }
        foreach ($u['agg'] as $ak => $a) { $agg[$ak] = $a; }   // 키에 container_id 가 들어 있어 안 겹친다
    }

    $out['parents'] = vg_pkgdep_rollup_sort($agg);
    return $out;
}

/**
 * 한 단위(컨테이너)의 그래프 + 그 단위의 취약점 행 → 판정 캐시와 부모별 집계.
 *   반환: ['origins' => [키 => 전이면 판정결과+container_id, 아니면 null],
 *          'agg' => [집계키 => ['key','container_id','count','severity','sev_rank','packages'=>set]],
 *          'path_truncated' => 경로 상한에 걸렸나]
 *   DB 를 안 보는 순수 함수다 — 그래서 서버 없이 단위테스트가 된다(tests/pkgdep_rollup_test.php).
 */
function vg_pkgdep_rollup_unit(array $g, array $idx, int $containerId, array $findings): array
{
    $origins = [];
    $agg = [];
    $pathTruncated = false;

    foreach ($findings as $f) {
        $name = (string) ($f['package_name'] ?? '');
        $ver  = (string) ($f['installed_version'] ?? '');
        $key  = vg_pkgdep_finding_key($containerId, $name, $ver);

        // 판정은 패키지 단위로 한 번만(캐시). 건수는 아래에서 **행 단위**로 센다.
        if (!array_key_exists($key, $origins)) {
            $o = vg_pkgdep_origin($g, $idx, $name, $ver);
            if ($o['truncated']) { $pathTruncated = true; }
            // 전이가 아니면 null — 손댈 부모가 따로 없다(직접 조치 가능하거나 그래프에 없다).
            $origins[$key] = $o['verdict'] === 'transitive' ? $o + ['container_id' => $containerId] : null;
        }
        $o = $origins[$key];
        if ($o === null) { continue; }

        foreach ($o['parents'] as $pkey) {
            // 같은 이름의 부모라도 단위(호스트/컨테이너)가 다르면 손댈 대상이 다르다.
            $ak = $containerId . '|' . $pkey;
            if (!isset($agg[$ak])) {
                $agg[$ak] = [
                    'key' => $pkey, 'container_id' => $containerId, 'count' => 0,
                    'severity' => '', 'sev_rank' => PHP_INT_MAX, 'packages' => [],
                ];
            }
            $agg[$ak]['count']++;
            $rank = vg_pkgdep_sev_rank((string) ($f['severity'] ?? ''));
            if ($rank < $agg[$ak]['sev_rank']) {
                $agg[$ak]['sev_rank'] = $rank;
                $agg[$ak]['severity'] = (string) ($f['severity'] ?? '');
            }
            $agg[$ak]['packages'][$name . ' ' . $ver] = true;
        }
    }
    return ['origins' => $origins, 'agg' => $agg, 'path_truncated' => $pathTruncated];
}

/**
 * 집계 결과 → 조치 순서로 정렬된 목록.
 *   **최고 심각도 → 건수** 순 = "가장 위험한 것을 가장 많이 없애는 순서".
 *   둘이 같으면 키로 고정한다 — 정렬이 흔들리면 새로고침마다 조치 순서가 바뀐다.
 */
function vg_pkgdep_rollup_sort(array $agg): array
{
    $out = [];
    foreach ($agg as $a) {
        $pkgs = array_keys($a['packages']);
        sort($pkgs);
        $a['packages'] = $pkgs;
        $out[] = $a;
    }
    usort($out, fn(array $x, array $y) =>
        [$x['sev_rank'], -$x['count'], $x['key']] <=> [$y['sev_rank'], -$y['count'], $y['key']]);
    return $out;
}

/** 그 노드의 자식 키 목록(정렬). 없으면 빈 배열. */
function vg_pkgdep_children(array $g, string $key): array
{
    $kids = array_keys($g['children'][$key] ?? []);
    sort($kids);
    return $kids;
}

/** 그 노드의 부모 키 목록(정렬). 없으면 빈 배열. */
function vg_pkgdep_parents(array $g, string $key): array
{
    $ps = array_keys($g['parents'][$key] ?? []);
    sort($ps);
    return $ps;
}

/**
 * "상위 의존성 경로" — 대상에서 부모 방향으로 거슬러 올라가 루트까지의 경로들.
 *   반환: ['paths' => [[루트키, …, 대상키], …], 'truncated' => 경로/깊이 상한에 걸렸나]
 *
 *   같은 노드를 두 번 밟지 않게 경로 단위로 방문 집합을 들고 다닌다 — 의존성 그래프는
 *   순환이 없어야 정상이지만, 도구가 잘못 뱉은 SBOM 이 순환을 만들면 여기서 무한루프가 난다.
 */
function vg_pkgdep_paths(array $g, string $target): array
{
    $paths = [];
    $truncated = false;

    $walk = function (string $node, array $trail, array $seen) use (&$walk, $g, &$paths, &$truncated) {
        if (count($paths) >= VG_PKGDEP_PATH_MAX) { $truncated = true; return; }
        $trail[] = $node;
        $seen[$node] = true;

        $parents = vg_pkgdep_parents($g, $node);
        if (!$parents || count($trail) > VG_PKGDEP_DEPTH_MAX) {
            if ($parents) { $truncated = true; }   // 깊이 상한에서 끊긴 경로
            $paths[] = array_reverse($trail);
            return;
        }
        foreach ($parents as $p) {
            if (isset($seen[$p])) { $truncated = true; continue; }   // 순환 방지
            $walk($p, $trail, $seen);
        }
    };
    $walk($target, [], []);

    return ['paths' => $paths, 'truncated' => $truncated];
}
