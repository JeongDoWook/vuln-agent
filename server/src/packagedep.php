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

// 한 화면이 메모리에 올리는 엣지 상한. 넘으면 잘린 사실을 화면에 표시한다.
const VG_PKGDEP_EDGE_MAX = 20000;
// 트리 전개 깊이 상한(루트=0). 넘는 가지는 "더 깊은 의존성 있음"으로 접어 둔다.
const VG_PKGDEP_DEPTH_MAX = 6;
// 한 화면에 그리는 노드 상한. 폭이 넓은 그래프가 한 페이지를 통째로 먹지 않게.
const VG_PKGDEP_NODE_MAX = 400;
// 역추적("무엇이 끌어왔나")에서 보여주는 경로 개수 상한.
const VG_PKGDEP_PATH_MAX = 20;

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
 * "무엇이 이 패키지를 끌어왔나" — 대상에서 부모 방향으로 거슬러 올라가 루트까지의 경로들.
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
