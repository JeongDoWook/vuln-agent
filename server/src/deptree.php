<?php
declare(strict_types=1);

/**
 * deptree.php — 패키지 의존성 **가로 계층 트리**의 배치와 SVG 출력.
 *
 *   같은 그림을 두 곳이 그린다: 자산 상세의 '의존성' 탭(host/tabs/depgraph.php)과 전용
 *   화면(public/depgraph.php). 렌더를 복사하면 한쪽만 고쳐진 채로 갈라지므로 여기 한곳에 둔다.
 *   데이터(엣지 조회·그래프 조립)는 packagedep.php 소유고, 이 파일은 그것을 **좌표와 SVG 로만**
 *   옮긴다(SRP) — 그래서 여기에는 엣지 SQL 이 없다.
 *
 * ── 왜 서버가 SVG 를 직접 그리나 ─────────────────────────────────────────
 *   이 서버의 CSP 는 default-src 'self' 라 인라인 <script> 를 쓸 수 없다(charts.php 참고).
 *   좌표 계산은 PHP 가 하고 SVG 만 내보낸다 — vg_sev_donut() 과 같은 방식이다.
 *   외부 그래프 라이브러리(d3 등)는 들이지 않는다(YAGNI/KISS).
 *
 * ── 조회 범위를 넓히지 않는다 ────────────────────────────────────────────
 *   tb_package_dependency 의 uk_pkg_dep_edge 좌측 접두가 (scan_id, container_id)라 이 둘로
 *   좁혀야 인덱스를 탄다. 심각도 조회(vg_deptree_severity)도 **같은 단위**로만 묻는다.
 */

require_once __DIR__ . '/packagedep.php';   // 그래프 구조·키 형식의 정본
require_once __DIR__ . '/view.php';         // vg_h · vg_sev_tone

/* ── 가로 계층 트리의 배치 상수(SVG 논리좌표, px) ──────────────────────────
 *   화면 코드에 숫자를 박지 않고 여기 한곳에서만 정한다. 값을 바꾸면 두 화면이 함께 따라온다. */
const VG_DEPTREE_ROOTS_PER_PAGE = 10;   // 한 페이지에 그리는 루트 수(?per_page 로 바꾼다)
const VG_DEPTREE_NODE_W  = 280;         // 노드 박스 폭
const VG_DEPTREE_NODE_H  = 30;          // 노드 박스 높이
const VG_DEPTREE_GAP_X   = 56;          // 열(depth) 사이 가로 간격 = 엣지가 꺾여 지나는 폭
const VG_DEPTREE_GAP_Y   = 8;           // 형제 사이 세로 간격
const VG_DEPTREE_PAD     = 12;          // SVG 바깥 여백
const VG_DEPTREE_CHAR_W  = 6.4;         // 12px 글자 한 칸의 근사폭 — 이름 말줄임 계산용
const VG_DEPTREE_META_W  = 82;          // 노드 오른쪽 칸(버전/심각도 배지)의 폭
const VG_DEPTREE_ELBOW_R = 10;          // 엣지가 꺾이는 모서리의 반지름(직각을 둥글린다)

/* 깊이별 엣지 클래스 — 루트에서 멀어질수록 옅어져 흐름이 눈에 잡힌다(색이 아니라 농도).
 *   문자열로 조립하지 않고 리터럴 배열로 둔다: ui_lint.sh 의 "아무도 안 쓰는 CSS 클래스"
 *   검사는 리터럴 일치라, 접두사에 깊이를 붙여 만들면 정의만 있고 참조가 없어 보인다. */
const VG_DEPTREE_EDGE_CLASS = [
    'deptree__edge--d0', 'deptree__edge--d1', 'deptree__edge--d2', 'deptree__edge--d3',
];

/* 노드 **면**을 칠하는 등급 — 조치 대상(CRITICAL·HIGH·MEDIUM)만이다.
 *   LOW 와 취약점 없는 노드는 중립으로 둔다(왼쪽 악센트 바·배지로는 여전히 구분된다) —
 *   전부 칠하면 아무것도 강조되지 않는다. 심각도 도넛이 LOW 를 뺀 것과 같은 기준이다. */
const VG_DEPTREE_FILL_TONES = ['crit', 'high', 'med'];

/**
 * 이 조회 단위(스캔 × 컨테이너)의 취약점 → 그래프 노드 키별 **최고 심각도**.
 *   조회 범위를 넓히지 않는다: uq_find 좌측 접두가 (scan_id, container_id)라 엣지 조회와
 *   같은 단위로 좁혀야 인덱스를 탄다. 패키지명 전역 역추적은 인덱스가 없어 풀스캔이 된다.
 *   매칭은 vg_pkgdep_index() 의 이름+버전 색인을 그대로 쓴다 — **이름만으로는 맞추지 않는다**
 *   (같은 스캔에 alpine 의 openssl 과 rpm 의 openssl 이 함께 있으면 서로 물려받는다).
 */
function vg_deptree_severity(PDO $pdo, int $scanId, int $containerId, array $graph): array
{
    $st = $pdo->prepare(
        'SELECT package_name, installed_version, severity
           FROM tb_finding
          WHERE scan_id = ? AND container_id = ? AND is_deleted = 0
          LIMIT ' . VG_PKGDEP_ROLLUP_FINDING_MAX
    );
    $st->execute([$scanId, $containerId]);
    $rows = $st->fetchAll();
    if (!$rows) { return []; }

    $idx = vg_pkgdep_index($graph);
    $out = [];
    foreach ($rows as $r) {
        $name = (string) $r['package_name'];
        $ver  = (string) $r['installed_version'];
        $sev  = (string) $r['severity'];
        $keys = $idx['by_name_ver'][$name . '|' . $ver]
            ?? ($idx['by_name_norm'][$name . '|' . vg_pkgdep_version_norm($ver)] ?? []);
        foreach ($keys as $k) {
            if (!isset($out[$k]) || vg_pkgdep_sev_rank($sev) < vg_pkgdep_sev_rank($out[$k])) {
                $out[$k] = $sev;
            }
        }
    }
    return $out;
}

/**
 * 의존성 그래프 화면(depgraph.php)으로 가는 링크.
 *   자산 상세의 '의존성' 탭도 노드 링크는 이 화면으로 보낸다 — 탭은 호스트 단위 전체 트리만
 *   보여주고, 대상 패키지 역추적("무엇이 끌어왔나")·다른 조회 단위는 그 화면이 맡는다.
 */
function vg_deptree_url(int $hostId, int $cid, array $over = []): string
{
    $q = ['id' => $hostId, 'cid' => $cid] + $over;
    $parts = [];
    foreach ($q as $k => $v) {
        if ($v === null || $v === '') { continue; }
        $parts[] = urlencode((string) $k) . '=' . urlencode((string) $v);
    }
    return '/depgraph.php?' . implode('&', $parts);
}

/**
 * 노드의 표시 역할(루트/대상/기타). 목록 라벨과 SVG 노드가 같은 판정을 쓰게 한곳에 둔다.
 *   $ctx: ['roots' => [키 => true], 'target' => 대상 키] — 아래 렌더 함수들과 같은 배열이다.
 */
function vg_deptree_role(string $key, array $ctx): string
{
    if (isset($ctx['roots'][$key])) { return 'root'; }
    if ($key !== '' && $key === (string) ($ctx['target'] ?? '')) { return 'target'; }
    return 'other';
}

/**
 * 가로 계층 트리 배치 — 루트 하나를 좌(부모)→우(자식) 열로 눕히고 형제는 위→아래로 쌓는다.
 *   고전적인 tidy tree: **리프를 순서대로 쌓고, 부모의 y 는 자식들 y 의 중앙**에 둔다.
 *   반환: ['nodes' => [['key','x','y','hidden','kids'], …],
 *          'edges' => [['x1','y1','x2','ys'(자식 y 목록),'depth'], …]  ← **부모 하나가 한 묶음**,
 *          'w' => SVG 폭, 'h' => SVG 높이, 'drawn' => 그린 노드 수]
 *   엣지를 자식마다 흩지 않고 부모 단위로 묶는 이유는 vg_deptree_edge_path() 주석에 있다.
 *   $budget 은 화면 전체가 나눠 쓰는 남은 노드 수다(참조로 깎는다) — 루트가 수십 개인
 *   자산에서 SVG 하나가 페이지를 통째로 먹지 않게 한다. 바닥나면 그 아래는 hidden 으로만 센다.
 *   $seen 은 **경로 단위** 방문 집합이다(순환 방지) — 전역으로 두면 여러 부모가 공유하는
 *   라이브러리가 처음 만난 가지에서만 펼쳐져 다른 가지가 통째로 비어 보인다.
 */
function vg_deptree_layout(array $graph, string $root, int &$budget): array
{
    $nodes = [];
    $edges = [];
    $cursorY = VG_DEPTREE_PAD;   // 다음 리프가 놓일 위쪽 좌표
    $maxDepth = 0;

    $place = function (string $key, int $depth, array $seen) use (
        &$place, $graph, &$nodes, &$edges, &$cursorY, &$maxDepth, &$budget
    ): ?float {
        if ($budget <= 0) { return null; }
        $budget--;
        if ($depth > $maxDepth) { $maxDepth = $depth; }

        $kids = vg_pkgdep_children($graph, $key);
        $seen[$key] = true;
        $childY = [];
        $hidden = 0;
        if ($kids && $depth >= VG_PKGDEP_DEPTH_MAX) {
            $hidden = count($kids);          // 깊이 상한 — 여기서 접는다
        } else {
            foreach ($kids as $k) {
                if (isset($seen[$k])) { $hidden++; continue; }   // 순환 참조라 더 펴지 않는다
                $y = $place($k, $depth + 1, $seen);
                if ($y === null) { $hidden++; continue; }        // 노드 예산 소진
                $childY[] = $y;
            }
        }

        if ($childY) {
            $y = ($childY[0] + $childY[count($childY) - 1]) / 2;
        } else {
            $y = $cursorY + VG_DEPTREE_NODE_H / 2;
            $cursorY += VG_DEPTREE_NODE_H + VG_DEPTREE_GAP_Y;
        }
        $x = VG_DEPTREE_PAD + $depth * (VG_DEPTREE_NODE_W + VG_DEPTREE_GAP_X);
        // kids = 이 노드에서 **실제로 그려진** 자식 수(hidden 은 뺀 것) — '+N' 글자를 엣지가
        //   지나가는 자리에서 비켜 놓을지 판정하는 데 쓴다(vg_deptree_node_svg).
        $nodes[] = ['key' => $key, 'x' => $x, 'y' => $y, 'hidden' => $hidden, 'kids' => count($childY)];
        if ($childY) {
            // 한 부모의 자식 전부를 **한 묶음**으로 넘긴다(자식마다 흩지 않는다). depth 는 이
            //   엣지가 나가는 쪽 깊이다 — 옅기(농도)를 그리는 쪽이 여기서 읽는다.
            $edges[] = [
                'x1'    => $x + VG_DEPTREE_NODE_W,
                'y1'    => $y,
                'x2'    => $x + VG_DEPTREE_NODE_W + VG_DEPTREE_GAP_X,
                'ys'    => $childY,
                'depth' => $depth,
            ];
        }
        return $y;
    };
    $place($root, 0, []);

    $h = max($cursorY - VG_DEPTREE_GAP_Y + VG_DEPTREE_PAD, VG_DEPTREE_NODE_H + VG_DEPTREE_PAD * 2);
    $w = VG_DEPTREE_PAD * 2 + ($maxDepth + 1) * VG_DEPTREE_NODE_W + $maxDepth * VG_DEPTREE_GAP_X;
    return ['nodes' => $nodes, 'edges' => $edges, 'w' => (int) $w, 'h' => (int) ceil($h), 'drawn' => count($nodes)];
}

/**
 * 노드 한 칸(SVG <a> 안의 rect·text) — 왼쪽 악센트 바 + 이름(왼쪽) + 버전/심각도(오른쪽).
 *
 *   **색은 정보다.** 면(박스 배경·테두리)은 취약점 등급 전용으로 쓰고, 조치 대상
 *   (CRITICAL·HIGH·MEDIUM)만 옅게 칠한다 — LOW·무취약 노드까지 칠하면 강조가 사라진다.
 *   맞닿은 HIGH(#f0883e)·MEDIUM(#e3b341) 은 색각이상 기준 색차가 6.1 로 면만으로는 안 갈리므로
 *   같은 톤의 **테두리**(--*-bd)를 함께 준다 — 두 노드가 이웃해도 경계선이 먼저 보인다.
 *   관리자·잘린 전체 이름처럼 칸에 안 들어가는 사실은 <title>(툴팁)로 넘긴다.
 *   좌표·크기는 SVG 속성이라 CSS 가 가질 수 없다. 색은 전부 class 로만 준다(app.css 소유).
 *
 *   $ctx: ['sev' => [키 => 심각도], 'roots' => [키 => true], 'target' => 키, 'link' => callable]
 */
function vg_deptree_node_svg(array $n, array $ctx): string
{
    $p    = vg_pkgdep_parts((string) $n['key']);
    $sev  = (string) ($ctx['sev'][$n['key']] ?? '');
    $role = vg_deptree_role((string) $n['key'], $ctx);
    $tone = $sev !== '' ? vg_sev_tone($sev) : ($role === 'root' ? 'info' : 'muted');
    // 면을 칠하는 건 조치 대상 등급뿐이다(위 주석). 나머지는 지금까지처럼 중립 박스다.
    $fill = in_array($tone, VG_DEPTREE_FILL_TONES, true) ? ' tone-' . $tone : '';

    $x   = (float) $n['x'];
    $y   = round((float) $n['y'], 1);
    $top = round($y - VG_DEPTREE_NODE_H / 2, 1);

    // 오른쪽 칸: 취약점이 있으면 심각도 배지, 없으면 버전.
    $rightW = $sev !== '' ? strlen($sev) * 5.6 + 14 : VG_DEPTREE_META_W;
    $avail  = VG_DEPTREE_NODE_W - 12 - 8 - $rightW - 10;
    $name   = mb_strimwidth($p['name'], 0, max(4, (int) ($avail / VG_DEPTREE_CHAR_W)), '…');

    $href = ($ctx['link'])([
        'mgr' => $p['manager'], 'name' => $p['name'], 'ver' => $p['version'], 'tab' => 'from',
    ]);
    $svg  = '<a href="' . vg_h($href) . '" class="deptree__node">'
        . '<title>' . vg_h($p['name'] . ' ' . $p['version'] . ' · ' . $p['manager']
            . ($sev !== '' ? ' · ' . $sev : '')) . '</title>'
        . '<rect class="deptree__box' . $fill . ($role === 'target' ? ' deptree__box--on' : '') . '"'
        . ' x="' . $x . '" y="' . $top . '" width="' . VG_DEPTREE_NODE_W . '" height="' . VG_DEPTREE_NODE_H . '" rx="7"/>'
        . '<rect class="deptree__accent tone-' . $tone . '"'
        . ' x="' . ($x + 1.5) . '" y="' . ($top + 4) . '" width="3.5" height="' . (VG_DEPTREE_NODE_H - 8) . '" rx="2"/>'
        . '<text class="deptree__name" x="' . ($x + 12) . '" y="' . $y . '">' . vg_h($name) . '</text>';

    if ($sev !== '') {
        $px = round($x + VG_DEPTREE_NODE_W - 10 - $rightW, 1);
        $svg .= '<rect class="deptree__pill tone-' . $tone . '" x="' . $px . '" y="' . round($y - 8, 1) . '"'
            . ' width="' . round($rightW, 1) . '" height="16" rx="8"/>'
            . '<text class="deptree__pilltext tone-' . $tone . '" x="' . round($px + $rightW / 2, 1) . '" y="' . $y . '">'
            . vg_h($sev) . '</text>';
    } else {
        $svg .= '<text class="deptree__meta" x="' . ($x + VG_DEPTREE_NODE_W - 10) . '" y="' . $y . '">'
            . vg_h(mb_strimwidth($p['version'], 0, (int) (VG_DEPTREE_META_W / VG_DEPTREE_CHAR_W), '…')) . '</text>';
    }
    // 접힌 자식(깊이·노드 상한, 순환)이 있으면 그 수를 노드 오른쪽에 남긴다 — 조용히 자르지 않는다.
    //   그려진 자식이 함께 있으면 그 자리로 엣지의 가로 줄기가 지나가므로 한 칸 위로 비킨다
    //   (엘보 라우팅은 부모 y 에서 곧게 나간다 — 글자와 선이 정확히 같은 높이에 놓인다).
    if ($n['hidden'] > 0) {
        $moreY = ((int) ($n['kids'] ?? 0)) > 0 ? round($y - 9, 1) : $y;
        $svg .= '<text class="deptree__more" x="' . ($x + VG_DEPTREE_NODE_W + 8) . '" y="' . $moreY . '">+'
            . (int) $n['hidden'] . '</text>';
    }
    return $svg . '</a>';
}

/**
 * 한 부모에서 자식들로 가는 엣지 **한 묶음**의 SVG path — 직교(elbow) 라우팅.
 *
 *   부모 오른쪽에서 수평으로 나가 두 열 사이 **가운데 세로 줄기**에 붙고, 거기서 자식마다
 *   갈라져 다시 수평으로 자식 왼쪽에 닿는다. 꺾이는 곳은 반지름 VG_DEPTREE_ELBOW_R 로 둥글린다.
 *
 *   왜 곡선(3차 베지에)에서 바꿨나: 예전에는 자식이 몇이든 **부모 오른쪽 한 점**에서 모두
 *   출발하고 전부 수평 접선으로 떠나, 그 언저리에서 선이 뭉치고 서로 겹쳐 보였다(사용자 지적).
 *   출발점만 노드 높이 안에서 분산하는 안도 있었지만, 자식이 열 개를 넘으면 30px 안에서 다시
 *   0.7px 간격이 되어 같은 문제가 돌아온다. 직교 라우팅은 자식 수와 무관하게 **자식마다 제
 *   행(row)** 을 갖는다 — 형제 사이 간격이 곧 선 사이 간격이다.
 *
 *   겹침 판정: 형제끼리는 세로 줄기 하나를 나눠 쓰고 가로 팔은 자식 y 로 갈리므로 교차가 없다.
 *   다른 부모의 묶음과도 안 겹친다 — tidy 배치라 한 부모의 자식들은 연속된 y 띠를 차지하고
 *   부모 y 는 그 띠의 가운데다(띠끼리 서로 겹치지 않는다). 줄기·팔은 모두 열 사이 빈칸에만
 *   놓이므로 노드 박스를 관통하지도 않는다.
 *
 *   묶음을 **path 하나**로 내는 것이 핵심이다: 각 자식의 경로가 줄기 구간을 공유해 겹쳐 그려지는데,
 *   .deptree__edge--d* 의 opacity 는 **요소 단위로 합성**되므로 한 요소 안의 겹침은 진해지지 않는다.
 *   자식마다 path 를 나누면 부모 쪽 줄기만 자식 수만큼 짙어져 또 다른 얼룩이 생긴다.
 */
function vg_deptree_edge_path(array $e): string
{
    $x1 = round((float) $e['x1'], 1);
    $y1 = round((float) $e['y1'], 1);
    $x2 = round((float) $e['x2'], 1);
    $tx = round(($x1 + $x2) / 2, 1);   // 세로 줄기 = 두 열 사이의 가운데
    $d  = '';
    foreach ($e['ys'] as $cy) {
        $y2 = round((float) $cy, 1);
        $dy = $y2 - $y1;
        // 부모와 같은 높이의 자식(사슬처럼 이어지는 가지)은 꺾을 것이 없다 — 곧은 가로선.
        if (abs($dy) < 1) { $d .= 'M' . $x1 . ',' . $y1 . 'H' . $x2; continue; }
        $dir = $dy > 0 ? 1 : -1;
        // 꺾이는 폭·높이를 넘지 않게 반지름을 줄인다 — 짧은 구간에서 곡선이 튀지 않는다.
        $r = round(min((float) VG_DEPTREE_ELBOW_R, ($x2 - $x1) / 2, abs($dy) / 2), 1);
        $d .= 'M' . $x1 . ',' . $y1
            . 'H' . round($tx - $r, 1)
            . 'Q' . $tx . ',' . $y1 . ' ' . $tx . ',' . round($y1 + $dir * $r, 1)
            . 'V' . round($y2 - $dir * $r, 1)
            . 'Q' . $tx . ',' . $y2 . ' ' . round($tx + $r, 1) . ',' . $y2
            . 'H' . $x2;
    }
    return $d;
}

/**
 * 트리 한 장 — 좌표는 vg_deptree_layout() 이 계산하고 여기서는 그리기만 한다(SRP).
 *   부모→자식은 직교(elbow)로 잇는다 — 부모마다 path 하나다(vg_deptree_edge_path 주석 참고).
 *   엣지는 깊이가 깊을수록 옅다 — 어느 가지가 루트에서 바로 나온 것인지가 먼저 읽힌다.
 *   SVG 폭은 노드가 정하므로 늘이지 않는다 — 넘치면 .deptree 안에서만 가로로 스크롤한다.
 */
function vg_deptree_render(array $graph, string $root, int &$budget, array $ctx): void
{
    $l = vg_deptree_layout($graph, $root, $budget);
    $p = vg_pkgdep_parts($root);
    echo '<div class="deptree">';
    echo '<svg class="deptree__svg" width="' . $l['w'] . '" height="' . $l['h'] . '"'
        . ' viewBox="0 0 ' . $l['w'] . ' ' . $l['h'] . '" role="img"'
        . ' aria-label="' . vg_h($p['name'] . ' 의존성 트리 · 노드 ' . $l['drawn'] . '개') . '">';
    $deepest = count(VG_DEPTREE_EDGE_CLASS) - 1;
    foreach ($l['edges'] as $e) {
        echo '<path class="deptree__edge ' . VG_DEPTREE_EDGE_CLASS[min((int) $e['depth'], $deepest)]
            . '" d="' . vg_deptree_edge_path($e) . '"/>';
    }
    foreach ($l['nodes'] as $n) { echo vg_deptree_node_svg($n, $ctx); }
    echo '</svg></div>';
}
