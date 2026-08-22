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
const VG_DEPTREE_ROLE_CHAR_W = 11.0;    // 역할 표식(한글) 한 글자의 근사폭 — 라틴 문자보다 넓다

/* ── 조치방안 카드의 "경로만 뽑은" 세로 그림(작은 SVG) 배치 상수 ───────────────
 *   전체 트리(가로 계층)와는 다른 작은 그림이라 좌표계를 따로 둔다 — 다만 색·톤 어휘
 *   (tone-crit 등)는 그대로 재사용한다(app.css 의 .deptree__accent·.deptree__pill). */
const VG_DEPTREE_MINI_W       = 420;    // 그림 폭(px)
const VG_DEPTREE_MINI_ROW_H   = 30;     // 노드 한 줄 높이
const VG_DEPTREE_MINI_PAD     = 12;     // 위아래·왼쪽 여백
const VG_DEPTREE_MINI_DOT_R   = 5;      // 노드 점 반지름
const VG_DEPTREE_MINI_CHAR_W  = 6.4;    // 이름(라틴) 한 글자의 근사폭 — 위 VG_DEPTREE_CHAR_W 와 동일
const VG_DEPTREE_MINI_VER_W   = 50;     // 버전 칸 폭
const VG_DEPTREE_MINI_NOTE_W  = 140;    // 오른쪽 역할/배지 칸 폭(세로 그림이라 이름 칸을 넉넉히 준다)

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
    $rows = vg_pkgdep_unit_findings($pdo, $scanId, $containerId);
    return $rows ? vg_deptree_severity_map($rows, vg_pkgdep_index($graph)) : [];
}

/**
 * 위 함수의 순수 부분 — 취약점 행 + 이름/버전 색인 → [노드 키 => 최고 심각도].
 *   조회와 나눠 둔 이유: 한 화면이 같은 취약점 한 벌로 **색칠과 조치 묶음을 둘 다** 만들 때
 *   같은 쿼리를 두 번 치지 않게 하려는 것이다(depgraph.php). DB 를 안 보므로 단위테스트도 된다.
 */
function vg_deptree_severity_map(array $rows, array $idx): array
{
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
 * 노드의 표시 역할(루트/대상/올릴 부모/기타). 목록 라벨과 SVG 노드가 같은 판정을 쓰게 한곳에 둔다.
 *   $ctx: ['roots' => [키 => true], 'target' => 대상 키, 'fixparents' => [키 => true](선택)]
 *         — 아래 렌더 함수들과 같은 배열이다.
 *   fixparents 는 vg_pkgdep_origin() 의 parents(전이일 때 실제로 올려야 할 루트 직속 조상)다 —
 *   depgraph.php 의 조치방안 문장이 가리키는 바로 그 부모라, 트리 위에서도 같은 노드를
 *   "올릴 부모" 로 짚어야 문장과 그림이 어긋나지 않는다.
 */
function vg_deptree_role(string $key, array $ctx): string
{
    if (isset($ctx['roots'][$key])) { return 'root'; }
    if ($key !== '' && $key === (string) ($ctx['target'] ?? '')) { return 'target'; }
    if (isset($ctx['fixparents'][$key])) { return 'fixparent'; }
    return 'other';
}

/**
 * 역추적 경로 목록(vg_pkgdep_paths) → 트리에서 강조할 노드·이음 집합.
 *   반환: ['nodes' => [노드키 => true], 'edges' => ["부모키\n자식키" => true]]
 *
 *   이음을 노드 집합에서 유추하지 않는 이유: 루트→A→대상, 루트→B→대상 처럼 갈래가 둘인
 *   그래프에 A→B 엣지까지 있으면, 노드만 보고 칠할 때 **경로가 아닌 이음**이 함께 강조된다.
 *   실제로 지나간 이음만 담는다 — 이 화면은 근거 없는 선을 긋지 않는다.
 */
function vg_deptree_path_marks(array $paths): array
{
    $m = ['nodes' => [], 'edges' => []];
    foreach ($paths as $path) {
        $prev = null;
        foreach ($path as $k) {
            $m['nodes'][$k] = true;
            if ($prev !== null) { $m['edges'][$prev . "\n" . $k] = true; }
            $prev = $k;
        }
    }
    return $m;
}

/**
 * 가로 계층 트리 배치 — 루트 하나를 좌(부모)→우(자식) 열로 눕히고 형제는 위→아래로 쌓는다.
 *   고전적인 tidy tree: **리프를 순서대로 쌓고, 부모의 y 는 자식들 y 의 중앙**에 둔다.
 *   반환: ['nodes' => [['key','x','y','hidden','kids'], …],
 *          'edges' => [['x1','y1','x2','ys'(자식 y 목록),'ys_on'(그중 강조 경로),'depth'], …]
 *                    ← **부모 하나가 한 묶음**,
 *          'w' => SVG 폭, 'h' => SVG 높이, 'drawn' => 그린 노드 수]
 *   엣지를 자식마다 흩지 않고 부모 단위로 묶는 이유는 vg_deptree_edge_path() 주석에 있다.
 *   $budget 은 화면 전체가 나눠 쓰는 남은 노드 수다(참조로 깎는다) — 루트가 수십 개인
 *   자산에서 SVG 하나가 페이지를 통째로 먹지 않게 한다. 바닥나면 그 아래는 hidden 으로만 센다.
 *   $seen 은 **경로 단위** 방문 집합이다(순환 방지) — 전역으로 두면 여러 부모가 공유하는
 *   라이브러리가 처음 만난 가지에서만 펼쳐져 다른 가지가 통째로 비어 보인다.
 *   $onPath 는 강조할 이음의 집합("부모키\n자식키")이다(vg_deptree_path_marks). 비우면 강조가 없다.
 */
function vg_deptree_layout(array $graph, string $root, int &$budget, array $onPath = []): array
{
    $nodes = [];
    $edges = [];
    $cursorY = VG_DEPTREE_PAD;   // 다음 리프가 놓일 위쪽 좌표
    $maxDepth = 0;

    $place = function (string $key, int $depth, array $seen) use (
        &$place, $graph, &$nodes, &$edges, &$cursorY, &$maxDepth, &$budget, $onPath
    ): ?float {
        if ($budget <= 0) { return null; }
        $budget--;
        if ($depth > $maxDepth) { $maxDepth = $depth; }

        $kids = vg_pkgdep_children($graph, $key);
        $seen[$key] = true;
        $childY = [];
        $childOn = [];   // 그중 강조 경로 위에 있는 자식의 y 만(없으면 빈 배열)
        $hidden = 0;
        if ($kids && $depth >= VG_PKGDEP_DEPTH_MAX) {
            $hidden = count($kids);          // 깊이 상한 — 여기서 접는다
        } else {
            foreach ($kids as $k) {
                if (isset($seen[$k])) { $hidden++; continue; }   // 순환 참조라 더 펴지 않는다
                $y = $place($k, $depth + 1, $seen);
                if ($y === null) { $hidden++; continue; }        // 노드 예산 소진
                $childY[] = $y;
                if (isset($onPath[$key . "\n" . $k])) { $childOn[] = $y; }
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
                'ys_on' => $childOn,
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
 *   $ctx: ['sev' => [키 => 심각도], 'roots' => [키 => true], 'target' => 키, 'link' => callable,
 *          'path' => [키 => true](강조 경로 위의 노드), 'pathedge' => [이음 => true](비어 있지
 *          않으면 "지금 강조 중" — 경로 밖 노드를 흐리게 누르고 역할 표식을 켠다),
 *          'fixparents' => [키 => true](올려야 할 부모, 선택)]
 */
function vg_deptree_node_svg(array $n, array $ctx): string
{
    $key  = (string) $n['key'];
    $p    = vg_pkgdep_parts($key);
    $sev  = (string) ($ctx['sev'][$key] ?? '');
    $role = vg_deptree_role($key, $ctx);
    $tone = $sev !== '' ? vg_sev_tone($sev) : ($role === 'root' ? 'info' : 'muted');
    // 면을 칠하는 건 조치 대상 등급뿐이다(위 주석). 나머지는 지금까지처럼 중립 박스다.
    $fill = in_array($tone, VG_DEPTREE_FILL_TONES, true) ? ' tone-' . $tone : '';

    $x   = (float) $n['x'];
    $y   = round((float) $n['y'], 1);
    $top = round($y - VG_DEPTREE_NODE_H / 2, 1);

    // 강조가 켜져 있는지(대상 패키지가 지정돼 실제 경로가 있는지)와, 이 노드가 그 위에 있는지.
    $highlightOn = !empty($ctx['pathedge']);
    $isPathNode  = isset($ctx['path'][$key]);

    // 역할 표식(루트/올릴 부모/취약) — 강조 중인 경로 위의 세 지점에만 붙는다. 짧게 두는 이유는
    //   이름 칸을 더 뺏지 않기 위해서다 — 전체 문장은 <title> 툴팁과 조치방안 카드가 말한다.
    $roleTag = '';
    if ($highlightOn && $isPathNode) {
        if ($role === 'root') { $roleTag = '루트'; }
        elseif ($role === 'fixparent') { $roleTag = '부모'; }
        elseif ($role === 'target') { $roleTag = '취약'; }
    }
    $roleTone = $role === 'target' ? $tone : 'info';
    $roleW    = $roleTag !== '' ? mb_strlen($roleTag) * VG_DEPTREE_ROLE_CHAR_W + 12 : 0;
    $nameLead = 12 + ($roleTag !== '' ? $roleW + 6 : 0);   // 이름이 시작하는 왼쪽 여백(역할 칩 포함)

    // 오른쪽 칸: 취약점이 있으면 심각도 배지, 없으면 버전.
    $rightW = $sev !== '' ? strlen($sev) * 5.6 + 14 : VG_DEPTREE_META_W;
    $avail  = VG_DEPTREE_NODE_W - $nameLead - 8 - $rightW - 10;
    $name   = mb_strimwidth($p['name'], 0, max(4, (int) ($avail / VG_DEPTREE_CHAR_W)), '…');

    $href = ($ctx['link'])([
        'mgr' => $p['manager'], 'name' => $p['name'], 'ver' => $p['version'], 'tab' => 'from',
    ]);
    // 강조 경로(취약 하위 → 루트) 위의 노드는 테두리로 표시한다 — 지금 보는 패키지(--on)는
    //   그 위에 다시 얹혀 이긴다(app.css 의 선언 순서가 그렇게 맞춰져 있다).
    $pathBoxCls = $isPathNode && $role !== 'target' ? ' deptree__box--path' : '';
    // 강조가 켜져 있고 이 노드가 그 경로 밖이면 통째로 흐리게 누른다(면·테두리·글자 한 번에) —
    //   "어디부터 어디까지" 가 굵기·색만이 아니라 **여백**(흐린 나머지)으로도 갈리게 한다.
    $dimCls = $highlightOn && !$isPathNode ? ' deptree__node--dim' : '';
    $svg  = '<a href="' . vg_h($href) . '" class="deptree__node' . $dimCls . '">'
        . '<title>' . vg_h(($roleTag !== '' ? '[' . $roleTag . '] ' : '') . $p['name'] . ' ' . $p['version']
            . ' · ' . $p['manager'] . ($sev !== '' ? ' · ' . $sev : '')) . '</title>'
        . '<rect class="deptree__box' . $fill . $pathBoxCls . ($role === 'target' ? ' deptree__box--on' : '') . '"'
        . ' x="' . $x . '" y="' . $top . '" width="' . VG_DEPTREE_NODE_W . '" height="' . VG_DEPTREE_NODE_H . '" rx="7"/>'
        . '<rect class="deptree__accent tone-' . $tone . '"'
        . ' x="' . ($x + 1.5) . '" y="' . ($top + 4) . '" width="3.5" height="' . (VG_DEPTREE_NODE_H - 8) . '" rx="2"/>';
    if ($roleTag !== '') {
        $rx = round($x + 9, 1);
        $svg .= '<rect class="deptree__pill tone-' . $roleTone . '" x="' . $rx . '" y="' . round($y - 8, 1) . '"'
            . ' width="' . round($roleW, 1) . '" height="16" rx="8"/>'
            . '<text class="deptree__pilltext tone-' . $roleTone . '" x="' . round($rx + $roleW / 2, 1) . '" y="' . $y . '">'
            . vg_h($roleTag) . '</text>';
    }
    $svg .= '<text class="deptree__name" x="' . ($x + $nameLead) . '" y="' . $y . '">' . vg_h($name) . '</text>';

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
 *   ── 줄기는 **한 번만** 그린다 ────────────────────────────────────────────
 *   직교로 바꾼 뒤에도 부모 쪽이 뭉쳐 보인다는 지적이 남았다. 원인은 자식마다 제 경로를
 *   따로 그린 데 있었다: 자식이 셋이면 "부모→줄기" 수평 토막이 세 번, 줄기에 붙는 **둥근
 *   모서리도 자식마다** 겹쳐 그려져 그 자리에 매듭이 생겼다. 자식이 둘일 때는 더 나빴다 —
 *   반지름이 |dy|/2 로 깎여 줄기의 직선 구간이 0 이 되고, 두 호가 한 점에서 만나 브래킷이
 *   아니라 **화살촉(<)** 으로 보였다.
 *   지금은 한 묶음을 이렇게 나눈다:
 *     ① 맨 위 자식 → 줄기 → 맨 아래 자식을 **한 획**으로(모서리는 양 끝에 하나씩만),
 *     ② 가운데 자식들은 줄기에서 곧게 갈라지는 가로 팔(T 이음),
 *     ③ 부모 → 줄기 수평 토막 하나.
 *   같은 선을 두 번 긋지 않으므로 매듭이 없고, 줄기 직선 구간이 살아 브래킷 모양이 된다.
 *
 *   ── 자식이 하나면 줄기가 없다 ────────────────────────────────────────────
 *   배치상 부모 y 는 첫·끝 자식의 가운데라, 자식이 하나면 부모와 높이가 같다 — 곧은 가로선
 *   하나면 된다. 세로 토막을 남기면 사슬처럼 이어지는 가지가 계단으로 보인다.
 *   (경로 강조처럼 묶음의 **일부만** 다시 그릴 때는 높이가 어긋난 한 자식이 올 수 있다.
 *    그때만 한 번 꺾는 엘보로 잇는다.)
 *
 *   겹침 판정: 형제끼리는 세로 줄기 하나를 나눠 쓰고 가로 팔은 자식 y 로 갈리므로 교차가 없다.
 *   다른 부모의 묶음과도 안 겹친다 — tidy 배치라 한 부모의 자식들은 연속된 y 띠를 차지하고
 *   부모 y 는 그 띠의 가운데다(띠끼리 서로 겹치지 않는다). 줄기·팔은 모두 열 사이 빈칸에만
 *   놓이므로 노드 박스를 관통하지도 않는다.
 *
 *   묶음을 **path 하나**로 내는 것이 핵심이다: .deptree__edge--d* 의 opacity 는 **요소 단위로
 *   합성**되므로 한 요소 안의 겹침은 진해지지 않는다. 자식마다 path 를 나누면 부모 쪽 줄기만
 *   자식 수만큼 짙어져 또 다른 얼룩이 생긴다.
 */
function vg_deptree_edge_path(array $e): string
{
    $x1 = round((float) $e['x1'], 1);
    $y1 = round((float) $e['y1'], 1);
    $x2 = round((float) $e['x2'], 1);

    $ys = [];
    foreach ($e['ys'] as $cy) { $ys[] = round((float) $cy, 1); }
    sort($ys);                          // 배치는 위→아래 순으로 놓지만 줄기 양 끝은 여기서 확정한다
    $n = count($ys);
    if ($n === 0) { return ''; }

    $tx = round(($x1 + $x2) / 2, 1);    // 세로 줄기 = 두 열 사이의 가운데
    $r  = (float) VG_DEPTREE_ELBOW_R;

    if ($n === 1) {
        // 자식 하나 — 같은 높이면 곧은 가로선, 어긋나 있으면 줄기에서 한 번만 꺾는다.
        $y2 = $ys[0];
        if (abs($y2 - $y1) < 1) { return 'M' . $x1 . ',' . $y1 . 'H' . $x2; }
        $dir = $y2 > $y1 ? 1 : -1;
        $r = round(min($r, ($x2 - $x1) / 2, abs($y2 - $y1) / 2), 1);
        return 'M' . $x1 . ',' . $y1
            . 'H' . round($tx - $r, 1)
            . 'Q' . $tx . ',' . $y1 . ' ' . $tx . ',' . round($y1 + $dir * $r, 1)
            . 'V' . round($y2 - $dir * $r, 1)
            . 'Q' . $tx . ',' . $y2 . ' ' . round($tx + $r, 1) . ',' . $y2
            . 'H' . $x2;
    }

    $top = $ys[0];
    $bot = $ys[$n - 1];
    $r   = round(min($r, ($x2 - $x1) / 2, ($bot - $top) / 2), 1);

    // ① 맨 위 자식 → 줄기 → 맨 아래 자식: 한 획. 모서리는 이 두 곳에만 있다.
    $d = 'M' . $x2 . ',' . $top
       . 'H' . round($tx + $r, 1)
       . 'Q' . $tx . ',' . $top . ' ' . $tx . ',' . round($top + $r, 1)
       . 'V' . round($bot - $r, 1)
       . 'Q' . $tx . ',' . $bot . ' ' . round($tx + $r, 1) . ',' . $bot
       . 'H' . $x2;
    // ② 가운데 자식들 — 줄기에서 곧게 갈라진다.
    for ($i = 1; $i < $n - 1; $i++) { $d .= 'M' . $tx . ',' . $ys[$i] . 'H' . $x2; }
    // ③ 부모 → 줄기. 부모 y 는 첫·끝 자식의 가운데라 보통 줄기 위에 떨어지지만, 묶음의
    //    일부만 다시 그리는 경우(경로 강조)에는 밖일 수 있다 — 그때만 줄기를 그만큼 늘린다.
    $d .= 'M' . $x1 . ',' . $y1 . 'H' . $tx;
    if ($y1 < $top - 0.05) { $d .= 'M' . $tx . ',' . $y1 . 'V' . $top; }
    if ($y1 > $bot + 0.05) { $d .= 'M' . $tx . ',' . $y1 . 'V' . $bot; }
    return $d;
}

/**
 * 트리 한 장 — 좌표는 vg_deptree_layout() 이 계산하고 여기서는 그리기만 한다(SRP).
 *   부모→자식은 직교(elbow)로 잇는다 — 부모마다 path 하나다(vg_deptree_edge_path 주석 참고).
 *   $ctx['pathedge'] 가 있으면 그 이음만 한 겹 더 긋는다 — 취약 하위에서 루트까지의 경로 강조다.
 *   엣지는 깊이가 깊을수록 옅다 — 어느 가지가 루트에서 바로 나온 것인지가 먼저 읽힌다.
 *
 *   $ctx['pathedge'] 가 **비어 있지 않으면**("지금 강조 중인 경로가 있다") 깊이 농도 대신
 *   경로 밖 이음 전부를 한 톤(deptree__edge--dim)으로 눌러 둔다 — 깊이 0 인 가지도 강조선과
 *   굵기를 다투지 않게. 대상 패키지가 없거나(host.php 의 '의존성' 탭) 경로가 없을 때(루트가
 *   직접 선언한 패키지)는 pathedge 가 비어 있으므로 지금까지처럼 깊이 농도 그대로 그려진다 —
 *   즉 이 화면은 "강조할 것이 실제로 있을 때만" 나머지를 흐리게 만든다.
 *   SVG 폭은 노드가 정하므로 늘이지 않는다 — 넘치면 .deptree 안에서만 가로로 스크롤한다.
 */
function vg_deptree_render(array $graph, string $root, int &$budget, array $ctx): void
{
    $l = vg_deptree_layout($graph, $root, $budget, $ctx['pathedge'] ?? []);
    $p = vg_pkgdep_parts($root);
    $highlightOn = !empty($ctx['pathedge']);
    echo '<div class="deptree">';
    echo '<svg class="deptree__svg" width="' . $l['w'] . '" height="' . $l['h'] . '"'
        . ' viewBox="0 0 ' . $l['w'] . ' ' . $l['h'] . '" role="img"'
        . ' aria-label="' . vg_h($p['name'] . ' 의존성 트리 · 노드 ' . $l['drawn'] . '개') . '">';
    $deepest = count(VG_DEPTREE_EDGE_CLASS) - 1;
    foreach ($l['edges'] as $e) {
        $baseCls = $highlightOn ? 'deptree__edge--dim' : VG_DEPTREE_EDGE_CLASS[min((int) $e['depth'], $deepest)];
        echo '<path class="deptree__edge ' . $baseCls . '" d="' . vg_deptree_edge_path($e) . '"/>';
        // 강조 경로 위의 이음만 같은 자리에 한 겹 더 긋는다(색이 진한 클래스로).
        //   깊이 농도 클래스를 빼는 것이 핵심 — 붙이면 깊은 가지에서 강조가 옅어져 안 보인다.
        if (!empty($e['ys_on'])) {
            echo '<path class="deptree__edge deptree__edge--path" d="'
                . vg_deptree_edge_path(['x1' => $e['x1'], 'y1' => $e['y1'], 'x2' => $e['x2'], 'ys' => $e['ys_on']])
                . '"/>';
        }
    }
    foreach ($l['nodes'] as $n) { echo vg_deptree_node_svg($n, $ctx); }
    echo '</svg></div>';
}

/**
 * 조치방안 카드 안의 "경로만 뽑은" 작은 세로 그림 — 전체 트리(위)와는 완전히 다른 SVG다.
 *   $path: vg_pkgdep_paths() 가 주는 경로 하나 그대로([루트키, …, 대상키]) — 여기서 새로
 *   계산하지 않는다. $ctx 는 vg_deptree_render() 와 같은 모양(sev·roots·target·fixparents·link)을
 *   그대로 받아 색·역할 판정을 공유한다(DRY) — 전체 트리와 이 그림이 같은 노드를 다르게
 *   부르는 일이 없다.
 *
 *   점 하나 = 노드 하나, 세로줄 하나로 잇는다. 이미 "경로만" 걸러진 목록이라 안/밖을 가를
 *   필요가 없다 — 전부가 강조 대상이므로 흐리게 누르는 로직이 없다(vg_deptree_node_svg 와의
 *   차이). 새 사실은 만들지 않는다: 부모의 목표 버전 같은 건 이 그림에도 없다.
 */
function vg_deptree_path_svg(array $path, array $ctx): void
{
    $n = count($path);
    if ($n === 0) { return; }

    $w  = VG_DEPTREE_MINI_W;
    $h  = VG_DEPTREE_MINI_PAD * 2 + $n * VG_DEPTREE_MINI_ROW_H;
    $cx = VG_DEPTREE_MINI_PAD;
    $noteX = $w - VG_DEPTREE_MINI_PAD - VG_DEPTREE_MINI_NOTE_W;
    $verRight = $noteX - 10;
    $nameX = $cx + VG_DEPTREE_MINI_DOT_R + 10;
    $nameAvail = max(4, (int) (($verRight - VG_DEPTREE_MINI_VER_W - 8 - $nameX) / VG_DEPTREE_MINI_CHAR_W));

    echo '<svg class="deptree-mini__svg" width="' . $w . '" height="' . $h . '"'
        . ' viewBox="0 0 ' . $w . ' ' . $h . '" role="img"'
        . ' aria-label="' . vg_h('이 패키지를 끌어온 경로 · 노드 ' . $n . '개') . '">';

    if ($n > 1) {
        $cy0 = VG_DEPTREE_MINI_PAD + VG_DEPTREE_MINI_ROW_H / 2;
        $cyN = VG_DEPTREE_MINI_PAD + ($n - 1) * VG_DEPTREE_MINI_ROW_H + VG_DEPTREE_MINI_ROW_H / 2;
        echo '<line class="deptree-mini__stem" x1="' . $cx . '" y1="' . $cy0 . '" x2="' . $cx . '" y2="' . $cyN . '"/>';
    }

    foreach ($path as $i => $key) {
        $key  = (string) $key;
        $p    = vg_pkgdep_parts($key);
        $sev  = (string) ($ctx['sev'][$key] ?? '');
        $role = vg_deptree_role($key, $ctx);
        $tone = $sev !== '' ? vg_sev_tone($sev) : ($role === 'root' ? 'info' : 'muted');
        $cy   = round(VG_DEPTREE_MINI_PAD + $i * VG_DEPTREE_MINI_ROW_H + VG_DEPTREE_MINI_ROW_H / 2, 1);

        $note = '';
        if ($role === 'root') { $note = '루트'; }
        elseif ($role === 'fixparent') { $note = '← 여기를 올린다'; }

        $href = ($ctx['link'])([
            'mgr' => $p['manager'], 'name' => $p['name'], 'ver' => $p['version'], 'tab' => 'from',
        ]);
        $name = mb_strimwidth($p['name'], 0, $nameAvail, '…');

        echo '<a href="' . vg_h($href) . '" class="deptree-mini__node">'
            . '<title>' . vg_h($p['name'] . ' ' . $p['version'] . ' · ' . $p['manager']
                . ($sev !== '' ? ' · ' . $sev : '')) . '</title>'
            . '<circle class="deptree__accent deptree-mini__dot tone-' . $tone . '" cx="' . $cx . '" cy="' . $cy
                . '" r="' . VG_DEPTREE_MINI_DOT_R . '"/>'
            . '<text class="deptree-mini__name" x="' . $nameX . '" y="' . $cy . '">' . vg_h($name) . '</text>'
            . '<text class="deptree-mini__ver" x="' . $verRight . '" y="' . $cy . '">' . vg_h($p['version']) . '</text>';

        if ($sev !== '') {
            $pillW = round(strlen($sev) * 5.6 + 14, 1);
            echo '<rect class="deptree__pill tone-' . $tone . '" x="' . $noteX . '" y="' . round($cy - 8, 1) . '"'
                . ' width="' . $pillW . '" height="16" rx="8"/>'
                . '<text class="deptree__pilltext tone-' . $tone . '" x="' . round($noteX + $pillW / 2, 1) . '" y="' . $cy . '">'
                . vg_h($sev) . '</text>'
                . '<text class="deptree-mini__note" x="' . round($noteX + $pillW + 8, 1) . '" y="' . $cy . '">취약</text>';
        } elseif ($note !== '') {
            echo '<text class="deptree-mini__note" x="' . $noteX . '" y="' . $cy . '">' . vg_h($note) . '</text>';
        }
        echo '</a>';
    }
    echo '</svg>';
}
