<?php
declare(strict_types=1);

/**
 * deptree_edge_test.php — 의존성 트리 **연결선 모양**의 단위 테스트.
 *   DB 도 서버도 안 보는 순수 함수(vg_deptree_edge_path / vg_deptree_path_marks)만 검증한다.
 *
 *   왜 있나: 선이 뭉쳐 보인다는 지적이 두 번 반복됐다(곡선 → 직교 라우팅 → 다시 지적).
 *   두 번째 원인은 눈으로는 "그냥 좀 두껍다" 로만 보였다 — 자식마다 제 경로를 따로 그려
 *   "부모→줄기" 토막과 둥근 모서리가 겹쳐 그려진 것이었다. 사람 눈으로 못 세는 종류라
 *   **path 안에 무엇이 몇 번 그려지는가**를 기계가 센다.
 *
 *   여기서 지키려는 성질:
 *     · 자식이 하나면 세로 구간이 아예 없다(곧은 가로선 하나).
 *     · 자식이 여럿이면 세로 줄기(V)는 **딱 하나**, 모서리(Q)는 **딱 둘**이다.
 *     · 부모에서 나가는 토막(M x1,y1)도 **하나**다(자식 수만큼 겹쳐 긋지 않는다).
 *     · 자식이 둘이어도 줄기에 직선 구간이 남는다(0 이면 화살촉처럼 보인다).
 *     · 경로 강조는 **실제로 지나간 이음**만 담는다(노드 집합에서 유추하지 않는다).
 */

require_once __DIR__ . '/../server/src/deptree.php';

$fail = 0;
$check = static function (string $label, $got, $want) use (&$fail): void {
    if ($got !== $want) {
        fwrite(STDERR, "FAIL {$label}: got=" . var_export($got, true) . " want=" . var_export($want, true) . "\n");
        $fail++;
    }
};

/** 부모 x=292..348(GAP_X=56), 부모 y=$y1, 자식 y 목록 $ys 인 묶음 하나. */
$path = static function (float $y1, array $ys): string {
    return vg_deptree_edge_path(['x1' => 292.0, 'y1' => $y1, 'x2' => 348.0, 'ys' => $ys, 'depth' => 0]);
};
$count = static fn(string $d, string $c): int => substr_count($d, $c);

// ── 자식 1개 — 곧은 가로선 하나. 꺾임도 세로도 없다. ─────────────────────────
$d = $path(27.0, [27.0]);
$check('자식1 · 곧은 가로선', $d, 'M292,27H348');
$check('자식1 · 세로 없음', $count($d, 'V'), 0);
$check('자식1 · 모서리 없음', $count($d, 'Q'), 0);

// 부모와 높이가 어긋난 자식 하나(묶음의 일부만 다시 그리는 경로 강조에서 나온다) —
//   이때만 한 번 꺾는다: 모서리 2개(꺾임 하나에 호가 둘), 세로 1개.
$d = $path(46.0, [84.0]);
$check('자식1(어긋남) · 세로 하나', $count($d, 'V'), 1);
$check('자식1(어긋남) · 모서리 둘', $count($d, 'Q'), 2);
$check('자식1(어긋남) · 출발 하나', $count($d, 'M'), 1);

// ── 자식 2개 — 브래킷. 줄기는 하나, 모서리는 둘. ─────────────────────────────
$d = $path(46.0, [27.0, 65.0]);
$check('자식2 · 줄기 하나', $count($d, 'V'), 1);
$check('자식2 · 모서리 둘', $count($d, 'Q'), 2);
$check('자식2 · 출발 둘(줄기획+부모토막)', $count($d, 'M'), 2);
// 형제 간격 38 · 반지름 10 이면 줄기의 직선 구간이 18 남는다 — 0 이면 화살촉이 된다.
$check('자식2 · 줄기 직선 구간이 남는다', (bool) preg_match('/V(\d+(\.\d+)?)/', $d, $m) && (float) $m[1] === 55.0, true);

// ── 자식 3개 — 가운데 자식은 줄기에서 곧게 갈라진다(T 이음). ─────────────────
$d = $path(65.0, [27.0, 65.0, 103.0]);
$check('자식3 · 줄기 하나', $count($d, 'V'), 1);
$check('자식3 · 모서리 둘', $count($d, 'Q'), 2);
$check('자식3 · 출발 셋(줄기획+가운데팔+부모토막)', $count($d, 'M'), 3);
$check('자식3 · 부모 토막은 한 번만', substr_count($d, 'M292,65'), 1);

// ── 자식 10 / 38개 — 자식이 늘어도 줄기·모서리 수는 그대로다. ────────────────
foreach ([10, 38] as $n) {
    $ys = [];
    for ($i = 0; $i < $n; $i++) { $ys[] = 27.0 + $i * 38.0; }
    $y1 = ($ys[0] + $ys[$n - 1]) / 2;
    $d  = $path($y1, $ys);
    $check("자식{$n} · 줄기 하나", $count($d, 'V'), 1);
    $check("자식{$n} · 모서리 둘", $count($d, 'Q'), 2);
    $check("자식{$n} · 출발 = 줄기획+가운데팔+부모토막", $count($d, 'M'), 1 + ($n - 2) + 1);
    $check("자식{$n} · 부모 토막은 한 번만", substr_count($d, 'M292,' . rtrim(rtrim(number_format($y1, 1, '.', ''), '0'), '.')), 1);
}

// ── 자식 y 가 뒤죽박죽이어도 줄기는 위·아래 끝을 잇는다. ─────────────────────
$d = $path(65.0, [103.0, 27.0, 65.0]);
$check('순서 무관 · 줄기 하나', $count($d, 'V'), 1);
$check('순서 무관 · 위 끝에서 시작', str_starts_with($d, 'M348,27'), true);

// ── 부모 y 가 자식 띠 밖일 때(묶음의 일부만 강조) 줄기를 늘려 잇는다. ────────
$d = $path(84.0, [27.0, 65.0]);
$check('부모가 띠 밖 · 줄기를 늘려 잇는다', $count($d, 'V'), 2);
$check('부모가 띠 밖 · 부모 y 에서 자식 띠까지', str_contains($d, 'M320,84V65'), true);

// ── 경로 강조 표식 — 노드와 **이음**을 따로 담는다. ─────────────────────────
$marks = vg_deptree_path_marks([['r', 'a', 't'], ['r', 'b', 't']]);
$check('강조 · 노드 집합', array_keys($marks['nodes']), ['r', 'a', 't', 'b']);
$check('강조 · 이음 수', count($marks['edges']), 4);
$check('강조 · r→a 이음', isset($marks['edges']["r\na"]), true);
// a→b 는 어느 경로에도 없다 — 노드만 보고 유추하면 여기가 틀린다(다이아몬드 모양).
$check('강조 · 경로에 없는 이음은 안 담는다', isset($marks['edges']["a\nb"]), false);
$check('강조 · 경로 없음', vg_deptree_path_marks([]), ['nodes' => [], 'edges' => []]);

if ($fail > 0) {
    fwrite(STDERR, "\n{$fail}건 실패\n");
    exit(1);
}
echo "deptree_edge_test: 통과\n";
