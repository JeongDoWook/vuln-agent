<?php
declare(strict_types=1);

/**
 * pkgdep_rollup_test.php — 손댈 대상(부모)별 묶음 집계 단위 테스트.
 *   DB 없이 도는 순수 함수(vg_pkgdep_rollup_unit / vg_pkgdep_rollup_sort)만 검증한다.
 *   여기서 지키려는 성질:
 *     · 건수는 **취약점 행 단위**로 센다(패키지 단위 판정 캐시를 그대로 세면 과소집계된다).
 *     · 직접·미상은 집계에 들어가지 않는다(손댈 부모가 따로 없다).
 *     · 부모가 둘이면 양쪽 모두에 센다("이 부모를 올리면 N건"은 부모마다 따로 참이다).
 *     · 정렬은 최고 심각도 → 건수. 같으면 키로 고정(새로고침마다 순서가 바뀌면 안 된다).
 */

require_once __DIR__ . '/../server/src/packagedep.php';

$fail = 0;
$check = static function (string $label, $got, $want) use (&$fail): void {
    if ($got !== $want) {
        fwrite(STDERR, "FAIL {$label}: got=" . var_export($got, true) . " want=" . var_export($want, true) . "\n");
        $fail++;
    }
};

$edge = static function (?string $pn, ?string $pv, string $cn, string $cv, string $src = 'sbom'): array {
    return [
        'source'         => $src,
        'parent_manager' => $pn === null ? null : 'maven',
        'parent_name'    => $pn,
        'parent_version' => $pv,
        'child_manager'  => 'maven',
        'child_name'     => $cn,
        'child_version'  => $cv,
    ];
};

/* app 1.0 (루트)
 *   ├ spring-boot-starter-web 2.6.1   ← 루트의 직속 자식 = 직접 조치 대상
 *   │   ├ log4j 2.14.1
 *   │   ├ snakeyaml 1.29
 *   │   └ commons-text 1.9
 *   └ other-lib 1.0
 *       └ commons-text 1.9            ← 부모가 둘인 경우
 */
$edges = [
    $edge(null, null, 'app', '1.0'),
    $edge('app', '1.0', 'spring-boot-starter-web', '2.6.1'),
    $edge('app', '1.0', 'other-lib', '1.0'),
    $edge('spring-boot-starter-web', '2.6.1', 'log4j', '2.14.1'),
    $edge('spring-boot-starter-web', '2.6.1', 'snakeyaml', '1.29'),
    $edge('spring-boot-starter-web', '2.6.1', 'commons-text', '1.9'),
    $edge('other-lib', '1.0', 'commons-text', '1.9'),
];
$g   = vg_pkgdep_build($edges);
$idx = vg_pkgdep_index($g);

$f = static fn(string $name, string $ver, string $sev): array =>
    ['package_name' => $name, 'installed_version' => $ver, 'severity' => $sev];

$findings = [
    $f('log4j', '2.14.1', 'CRITICAL'),          // 같은 패키지에 2건 — 2건으로 세야 한다
    $f('log4j', '2.14.1', 'HIGH'),
    $f('snakeyaml', '1.29', 'HIGH'),
    $f('commons-text', '1.9', 'MEDIUM'),        // 부모가 둘
    $f('spring-boot-starter-web', '2.6.1', 'HIGH'),  // 직접 — 집계 제외
    $f('nowhere-in-graph', '0.1', 'CRITICAL'),  // 미상 — 집계 제외
];

$u = vg_pkgdep_rollup_unit($g, $idx, 0, $findings);
$parents = vg_pkgdep_rollup_sort($u['agg']);

$check('부모 2개만 집계된다', count($parents), 2);

$spring = $parents[0];
$other  = $parents[1];

$check('최고 심각도가 앞선다', $spring['key'], 'maven|spring-boot-starter-web|2.6.1');
$check('건수는 행 단위 — log4j 2건 + snakeyaml + commons-text', $spring['count'], 4);
$check('최고 심각도', $spring['severity'], 'CRITICAL');
$check('끌어오는 취약 패키지 목록', $spring['packages'], ['commons-text 1.9', 'log4j 2.14.1', 'snakeyaml 1.29']);

$check('두 번째 부모', $other['key'], 'maven|other-lib|1.0');
$check('부모가 둘이면 양쪽에 센다', $other['count'], 1);
$check('그 부모 기준 최고 심각도', $other['severity'], 'MEDIUM');

// 판정 캐시: 직접·미상은 null 로 담겨 화면에서 "직접 조치 불가" 문구가 안 붙는다.
$check('직접은 판정 캐시에 null', $u['origins'][vg_pkgdep_finding_key(0, 'spring-boot-starter-web', '2.6.1')], null);
$check('미상은 판정 캐시에 null', $u['origins'][vg_pkgdep_finding_key(0, 'nowhere-in-graph', '0.1')], null);
$check('전이는 판정 결과가 담긴다',
    $u['origins'][vg_pkgdep_finding_key(0, 'log4j', '2.14.1')]['verdict'] ?? null, 'transitive');

// 취약점이 하나도 없으면 요약 자체가 비어야 한다(화면이 빈 카드를 그리지 않는 근거).
$empty = vg_pkgdep_rollup_unit($g, $idx, 0, []);
$check('취약점이 없으면 집계도 없다', vg_pkgdep_rollup_sort($empty['agg']), []);

// 심각도 순위 — 정본은 VG_TONE_SEV 의 선언 순서다.
$check('CRITICAL 이 HIGH 보다 앞', vg_pkgdep_sev_rank('CRITICAL') < vg_pkgdep_sev_rank('HIGH'), true);
$check('LOW 가 MEDIUM 보다 뒤', vg_pkgdep_sev_rank('LOW') > vg_pkgdep_sev_rank('MEDIUM'), true);
$check('모르는 등급은 맨 뒤', vg_pkgdep_sev_rank('') , PHP_INT_MAX);

// 심각도가 같으면 건수가 많은 쪽이 먼저다.
$tie = vg_pkgdep_rollup_sort([
    '0|maven|a|1' => ['key' => 'maven|a|1', 'container_id' => 0, 'count' => 2,
                      'severity' => 'HIGH', 'sev_rank' => vg_pkgdep_sev_rank('HIGH'), 'packages' => ['x 1' => true]],
    '0|maven|b|1' => ['key' => 'maven|b|1', 'container_id' => 0, 'count' => 9,
                      'severity' => 'HIGH', 'sev_rank' => vg_pkgdep_sev_rank('HIGH'), 'packages' => ['y 1' => true]],
]);
$check('같은 심각도면 건수 많은 쪽이 먼저', array_column($tie, 'key'), ['maven|b|1', 'maven|a|1']);

// 컨테이너가 다르면 같은 이름의 부모라도 별개 대상이다.
$c1 = vg_pkgdep_rollup_unit($g, $idx, 7, [$f('log4j', '2.14.1', 'CRITICAL')]);
$check('집계 키에 컨테이너가 들어간다', array_keys($c1['agg']), ['7|maven|spring-boot-starter-web|2.6.1']);

if ($fail > 0) { fwrite(STDERR, "{$fail} case(s) failed\n"); exit(1); }
echo "pkgdep rollup: all cases passed\n";
