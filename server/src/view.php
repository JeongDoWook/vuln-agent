<?php
declare(strict_types=1);

/**
 * view.php — 공통 레이아웃(헤더/네비/푸터) + 다크 테마 CSS.
 *   vg_h() 이스케이프, vg_header($title,$active) 로 시작, vg_footer() 로 끝.
 */

function vg_h(?string $s): string {
    return htmlspecialchars((string) $s, ENT_QUOTES, 'UTF-8');
}

// 심각도 색상 (findings 공용)
function vg_sev_color(string $sev): string {
    $m = ['CRITICAL' => '#da3633', 'HIGH' => '#db6d28', 'MEDIUM' => '#9e6a03', 'LOW' => '#6e7681'];
    return $m[$sev] ?? '#6e7681';
}

// 런타임 상태 라벨/색상 (EXTERNAL/LISTENING/RUNNING/LOADED/INSTALLED)
function vg_status_label(?string $s): string {
    $m = ['EXTERNAL' => '외부노출', 'LISTENING' => '로컬리스닝', 'RUNNING' => '실행중', 'LOADED' => '사용중', 'INSTALLED' => '설치만'];
    return $m[$s ?? ''] ?? (string) $s;
}
function vg_status_color(?string $s): string {
    $m = ['EXTERNAL' => '#da3633', 'LISTENING' => '#db6d28', 'RUNNING' => '#9e6a03', 'LOADED' => '#8250df', 'INSTALLED' => '#6e7681'];
    return $m[$s ?? ''] ?? '#6e7681';
}

// 긴 텍스트 말줄임 + 툴팁(title 에 원문). 안 잘리면 그냥 이스케이프만.
function vg_trunc(?string $text, int $len = 72): string {
    $text = (string) $text;
    $cut = mb_strimwidth($text, 0, $len, '…');
    if ($cut === $text) {
        return vg_h($text);
    }
    return '<span class="trunc" title="' . vg_h($text) . '">' . vg_h($cut) . '</span>';
}

// 현재 $_GET 에 $overrides 를 병합한 쿼리스트링(?a=1&b=2). 값이 null/빈문자면 해당 키 제거.
function vg_qs(array $overrides = []): string {
    $params = $_GET;
    foreach ($overrides as $k => $v) {
        if ($v === null || $v === '') {
            unset($params[$k]);
        } else {
            $params[$k] = $v;
        }
    }
    $parts = [];
    foreach ($params as $k => $v) {
        if ($v === null || $v === '' || is_array($v)) { // 배열값(?a[]=)은 무시
            continue;
        }
        $parts[] = urlencode((string) $k) . '=' . urlencode((string) $v);
    }
    return '?' . implode('&', $parts);
}

// 페이지당 표시 개수 선택지(SSOT). vg_perpage / vg_perpage_select 가 공유한다.
const VG_PERPAGE_OPTIONS = [10, 20, 40, 60, 100];
const VG_PERPAGE_DEFAULT = 10;

// 페이지당 표시 개수. ?per_page= 를 화이트리스트로 검증해 반환. 잘못된 값이면 $default.
function vg_perpage(int $default = VG_PERPAGE_DEFAULT): int {
    $v = (int) ($_GET['per_page'] ?? $default);
    return in_array($v, VG_PERPAGE_OPTIONS, true) ? $v : $default;
}

// "페이지당 N개" 셀렉트. onchange 시 현재 쿼리스트링 유지한 채 per_page 변경 + page=1 로 이동.
function vg_perpage_select(): void {
    $current = vg_perpage();
    echo '<select onchange="location.href=this.value" aria-label="페이지당 표시 개수">';
    foreach (VG_PERPAGE_OPTIONS as $n) {
        $url = vg_qs(['per_page' => $n, 'page' => 1]);
        echo '<option value="' . vg_h($url) . '"' . ($current === $n ? ' selected' : '') . '>' . $n . '개씩 보기</option>';
    }
    echo '</select>';
}

/**
 * 페이지네이션 출력. 한 페이지에 다 들어가도 "N개씩 보기" 셀렉트는 남긴다
 * (큰 값을 고른 뒤 되돌릴 UI가 사라지지 않게). 최소 선택지 이하면 아예 생략.
 */
function vg_page_nav(int $total, int $perPage, int $page): void {
    $totalPages = max(1, (int) ceil($total / $perPage));
    if ($totalPages === 1 && $total <= VG_PERPAGE_OPTIONS[0]) {
        return;
    }
    if ($page < 1) { $page = 1; }
    if ($page > $totalPages) { $page = $totalPages; }

    if ($totalPages === 1) {   // 페이지 링크는 필요없고 개수 셀렉트만
        echo '<div class="pager"><span class="muted">· 총 ' . number_format($total) . '건</span>';
        vg_perpage_select();
        echo '</div>';
        return;
    }

    // 표시할 페이지 번호: 처음, 현재 ±2, 끝
    $show = [1, $totalPages];
    for ($p = $page - 2; $p <= $page + 2; $p++) {
        if ($p >= 1 && $p <= $totalPages) { $show[] = $p; }
    }
    $show = array_values(array_unique($show));
    sort($show);

    echo '<div class="pager">';
    if ($page > 1) {
        echo '<a href="' . vg_h(vg_qs(['page' => $page - 1])) . '">‹ 이전</a>';
    } else {
        echo '<span class="muted">‹ 이전</span>';
    }
    $prev = 0;
    foreach ($show as $p) {
        if ($prev !== 0 && $p - $prev > 1) {
            echo '<span class="muted">…</span>';
        }
        if ($p === $page) {
            echo '<span class="cur">' . $p . '</span>';
        } else {
            echo '<a href="' . vg_h(vg_qs(['page' => $p])) . '">' . $p . '</a>';
        }
        $prev = $p;
    }
    if ($page < $totalPages) {
        echo '<a href="' . vg_h(vg_qs(['page' => $page + 1])) . '">다음 ›</a>';
    } else {
        echo '<span class="muted">다음 ›</span>';
    }
    echo '<span class="muted">· 총 ' . number_format($total) . '건 · ' . $page . '/' . $totalPages . '페이지</span>';
    vg_perpage_select();
    echo '</div>';
}

/**
 * 카드+테이블 렌더 (DRY — 각 페이지가 반복하던 <div class="card"><table>… 마크업 통합).
 *   $headers: [['label'=>'등급','align'=>'left'|'right'|'center','width'=>'80px','key'=>'severity'], ...]
 *     'key' 는 콜백이 없을 때 $row[key] 를 자동 이스케이프해서 출력하는 데 쓰인다(없으면 빈칸).
 *   $opts['cell']: 컬럼 인덱스(0,1,2…) 또는 header 의 'key' → function($row): string.
 *     콜백 반환값은 이미 이스케이프된 HTML 이라는 규약(콜백 안에서 vg_h 책임).
 *   $opts['empty']: 빈 목록 메시지. $opts['card']: 카드 래핑 여부(기본 true). $opts['class']: <table> 에 추가할 클래스.
 */
function vg_table(array $headers, array $rows, array $opts = []): void {
    $card  = $opts['card'] ?? true;
    $class = $opts['class'] ?? '';
    $cell  = $opts['cell'] ?? [];
    $empty = $opts['empty'] ?? '데이터가 없습니다.';

    if ($card) { echo '<div class="card">'; }

    if (!$rows) {
        echo '<div class="empty">' . vg_h($empty) . '</div>';
        if ($card) { echo '</div>'; }
        return;
    }

    echo '<table' . ($class !== '' ? ' class="' . vg_h($class) . '"' : '') . '>';
    echo '<thead><tr>';
    foreach ($headers as $h) {
        $label = is_array($h) ? (string) ($h['label'] ?? '') : (string) $h;
        $align = is_array($h) ? ($h['align'] ?? null) : null;
        $width = is_array($h) ? ($h['width'] ?? null) : null;
        $style = '';
        if ($align && $align !== 'left') { $style .= 'text-align:' . $align . ';'; }
        if ($width) { $style .= 'width:' . $width . ';'; }
        echo '<th' . ($style !== '' ? ' style="' . vg_h($style) . '"' : '') . '>' . vg_h($label) . '</th>';
    }
    echo '</tr></thead><tbody>';
    foreach ($rows as $row) {
        echo '<tr>';
        foreach (array_values($headers) as $i => $h) {
            $key   = is_array($h) ? ($h['key'] ?? null) : null;
            $align = is_array($h) ? ($h['align'] ?? null) : null;
            $cb    = $cell[$i] ?? ($key !== null ? ($cell[$key] ?? null) : null);
            if ($cb) {
                $html = $cb($row);
            } elseif ($key !== null) {
                $html = vg_h((string) ($row[$key] ?? ''));
            } else {
                $html = '';
            }
            $nowrap = is_array($h) && !empty($h['nowrap']);
            $style = ($align && $align !== 'left') ? ' style="text-align:' . vg_h($align) . ';"' : '';
            echo '<td' . ($nowrap ? ' class="nowrap"' : '') . $style . '>' . $html . '</td>';
        }
        echo '</tr>';
    }
    echo '</tbody></table>';
    if ($card) { echo '</div>'; }
}

/**
 * GET 검색/필터 툴바(class="toolbar"). 값이 있으면 제출버튼 옆에 초기화 링크 자동 표시.
 *   $fields 각 항목: ['type'=>'search'|'select'|'hidden', 'name'=>, 'value'=>, 'placeholder'=>,
 *                     'options'=>['값'=>'라벨'], 'selected'=>, 'empty_label'=>'전체']
 */
function vg_toolbar(array $fields, array $opts = []): void {
    $resetOverrides = ['page' => null];
    $hasValue = false;

    echo '<form class="toolbar" method="get">';
    foreach ($fields as $f) {
        $type = $f['type'] ?? 'search';
        $name = (string) ($f['name'] ?? '');
        $value = (string) ($f['value'] ?? '');

        if ($type === 'hidden') {
            echo '<input type="hidden" name="' . vg_h($name) . '" value="' . vg_h($value) . '">';
            continue;
        }

        if ($type === 'search') {
            $ph = (string) ($f['placeholder'] ?? '');
            echo '<input type="search" name="' . vg_h($name) . '" placeholder="' . vg_h($ph) . '" value="' . vg_h($value) . '">';
            if ($value !== '') { $hasValue = true; }
            $resetOverrides[$name] = null;
        } elseif ($type === 'select') {
            $options  = $f['options'] ?? [];
            $selected = (string) ($f['selected'] ?? '');
            $emptyLabel = (string) ($f['empty_label'] ?? '전체');
            echo '<select name="' . vg_h($name) . '">';
            echo '<option value="">' . vg_h($emptyLabel) . '</option>';
            foreach ($options as $val => $label) {
                $val = (string) $val;
                echo '<option value="' . vg_h($val) . '"' . ($selected === $val ? ' selected' : '') . '>' . vg_h((string) $label) . '</option>';
            }
            echo '</select>';
            if ($selected !== '') { $hasValue = true; }
            $resetOverrides[$name] = null;
        }
    }
    echo '<button type="submit" class="btn-sm">검색</button>';
    if ($hasValue) {
        echo '<a class="btn-sm" href="' . vg_h(vg_qs($resetOverrides)) . '">초기화</a>';
    }
    echo '</form>';
}

/**
 * 사이드바 메뉴(SSOT). 대분류(섹션 라벨) → 중분류(링크) 2단.
 *   섹션 라벨이 '' 이면 라벨 없이 링크만 렌더한다(대시보드처럼 단독 항목).
 *   각 링크의 'perm' 은 vg_can() 메뉴코드, 'key' 는 vg_header($active) 와 맞춘다.
 */
function vg_nav_sections(): array {
    return [
        '' => [
            ['perm' => 'dashboard', 'href' => '/', 'label' => '대시보드', 'key' => 'dashboard'],
        ],
        '취약점' => [
            ['perm' => 'findings',   'href' => '/findings.php',   'label' => '취약점 현황',   'key' => 'findings'],
            ['perm' => 'findings',   'href' => '/cves.php',       'label' => 'CVE 목록',      'key' => 'cves'],
            ['perm' => 'advisories', 'href' => '/advisories.php', 'label' => '국내 보안공지', 'key' => 'advisories'],
        ],
        '자산' => [
            ['perm' => 'assets', 'href' => '/assets.php', 'label' => '자산 관리', 'key' => 'assets'],
        ],
        '수집' => [
            ['perm' => 'connectors', 'href' => '/connectors.php', 'label' => '피드 커넥터', 'key' => 'connectors'],
        ],
        '시스템' => [
            ['perm' => 'users',       'href' => '/users.php',       'label' => '사용자',    'key' => 'users'],
            ['perm' => 'permissions', 'href' => '/permissions.php', 'label' => '권한 설정', 'key' => 'permissions'],
            ['perm' => 'activity',    'href' => '/activity.php',    'label' => '감사 로그', 'key' => 'activity'],
        ],
    ];
}

// 사이드바 렌더. 권한 없는 링크는 빼고, 링크가 하나도 안 남은 섹션은 라벨째 숨긴다.
function vg_nav(string $active): void {
    foreach (vg_nav_sections() as $section => $links) {
        $visible = array_filter($links, fn($l) => vg_can($l['perm']));
        if (!$visible) {
            continue;
        }
        if ($section !== '') {
            echo '<div class="grp">' . vg_h($section) . '</div>';
        }
        foreach ($visible as $l) {
            $cls = 'link' . ($active === $l['key'] ? ' active' : '');
            echo '<a class="' . $cls . '" href="' . vg_h($l['href']) . '">' . vg_h($l['label']) . '</a>';
        }
    }
}

function vg_header(string $title, string $active = ''): void {
    $user = function_exists('vg_current_user') ? vg_current_user() : null;
    ?>
<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= vg_h($title) ?> · vuln-agent</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body { font-family: system-ui,-apple-system,"Segoe UI",sans-serif; margin:0; background:#0f1115; color:#e6e6e6; display:flex; min-height:100vh; }
  a { color:#58a6ff; text-decoration:none; } a:hover { text-decoration:underline; }
  /* 좌측 사이드바: 대분류(.grp) → 중분류(a.link) 2단 */
  .side { flex:0 0 232px; width:232px; height:100vh; position:sticky; top:0; overflow-y:auto;
          display:flex; flex-direction:column; background:#171a21; border-right:1px solid #262b36; }
  .side .brand { display:block; font-weight:700; font-size:1rem; color:#e6e6e6; padding:1rem 1.15rem;
                 border-bottom:1px solid #262b36; white-space:nowrap; }
  .side a.brand:hover { text-decoration:none; opacity:.85; }
  .side .menu { flex:1; padding:.6rem .55rem 1rem; }
  .side .grp { color:#6e7681; font-size:.68rem; font-weight:700; letter-spacing:.09em; text-transform:uppercase;
               padding:.95rem .6rem .3rem; }
  .side a.link { display:block; padding:.48rem .6rem; margin-bottom:.1rem; border-radius:8px;
                 color:#adbac7; font-size:.88rem; }
  .side a.link:hover { background:#1c2029; color:#e6e6e6; text-decoration:none; }
  .side a.link.active { background:#1f6feb26; color:#fff; font-weight:600; box-shadow:inset 3px 0 0 #1f6feb; }
  .side .foot { border-top:1px solid #262b36; padding:.85rem 1.15rem; }
  .side .who { display:block; color:#8b93a1; font-size:.8rem; margin-bottom:.45rem; }
  .side .foot a { color:#adbac7; font-size:.82rem; margin-right:.7rem; }
  /* min-width:0 이 없으면 넓은 표가 사이드바를 밀어낸다(flex 자식 기본 min-width:auto) */
  .app { flex:1; min-width:0; }
  main { padding:1.8rem 1.6rem; max-width:1760px; margin:0 auto; }
  /* 좁은 화면: 사이드바를 상단 가로 메뉴로 되돌린다 */
  @media (max-width:860px) {
    body { display:block; }
    .side { position:static; width:auto; height:auto; flex:none; border-right:none; border-bottom:1px solid #262b36; }
    .side .menu { display:flex; flex-wrap:wrap; gap:.15rem; padding:.5rem .6rem; }
    .side .grp { display:none; }
    .side a.link.active { box-shadow:none; }
    main { padding:1.4rem 1rem; }
  }
  h1 { font-size:1.3rem; margin:0 0 .3rem; }
  .sub { color:#8b93a1; font-size:.85rem; margin-bottom:1.3rem; }
  .cards { display:flex; gap:.7rem; margin-bottom:1.3rem; flex-wrap:wrap; }
  .kpi { border-radius:10px; padding:.7rem 1.2rem; min-width:100px; }
  .kpi.big { background:#171a21; border:1px solid #262b36; }
  .kpi b { font-size:1.5rem; display:block; line-height:1.2; }
  .kpi span { font-size:.74rem; opacity:.85; }
  .card { background:#171a21; border:1px solid #262b36; border-radius:12px; padding:1.1rem 1.4rem; overflow-x:auto; margin-bottom:1.2rem; }
  table { width:100%; border-collapse:collapse; font-size:.93rem; }
  th,td { text-align:left; padding:.7rem .9rem; border-bottom:1px solid #262b36; vertical-align:top; }
  th { color:#8b93a1; font-weight:600; font-size:.74rem; text-transform:uppercase; letter-spacing:.04em; white-space:nowrap; }
  td.nowrap { white-space:nowrap; }
  td code { white-space:nowrap; }
  .badge, .pill { white-space:nowrap; }
  tr:last-child td { border-bottom:none; }
  .badge { display:inline-block; padding:.12rem .55rem; border-radius:999px; font-size:.72rem; font-weight:700; color:#fff; }
  .badge.outline { background:transparent; border:1px solid currentColor; color:inherit; font-weight:600; }
  .pill { display:inline-block; padding:.1rem .5rem; border-radius:999px; background:#1f6feb22; color:#58a6ff; font-size:.76rem; }
  .why { color:#adbac7; font-size:.82rem; }
  .empty { color:#8b93a1; padding:2rem 0; text-align:center; }
  .err { background:#3b1418; border:1px solid #6e2830; color:#ffb3ba; padding:.8rem 1rem; border-radius:10px; margin-bottom:1rem; }
  code { background:#262b36; padding:.1rem .4rem; border-radius:6px; font-size:.85em; }
  form.card { max-width:360px; margin:3rem auto; }
  label { display:block; font-size:.82rem; color:#adbac7; margin:.8rem 0 .3rem; }
  input[type=text],input[type=password] { width:100%; padding:.55rem .65rem; background:#0f1115; border:1px solid #30363d; border-radius:8px; color:#e6e6e6; font-size:.95rem; }
  button { margin-top:1.1rem; width:100%; padding:.6rem; background:#238636; color:#fff; border:none; border-radius:8px; font-size:.95rem; font-weight:600; cursor:pointer; }
  button:hover { background:#2ea043; }
  .btn-sm { width:auto; margin:0; padding:.35rem .8rem; font-size:.82rem; }
  .trunc { display:inline-block; max-width:min(46vw, 820px); overflow:hidden; text-overflow:ellipsis; white-space:nowrap; vertical-align:bottom; }
  tbody tr:hover { background:#1c2029; }
  .toolbar { display:flex; gap:.5rem; flex-wrap:wrap; align-items:center; margin-bottom:1rem; }
  input[type=search],select { padding:.45rem .6rem; background:#0f1115; border:1px solid #30363d; border-radius:8px; color:#e6e6e6; font-size:.85rem; }
  .pager { display:flex; gap:.3rem; justify-content:center; align-items:center; flex-wrap:wrap; margin-top:1rem; }
  .pager a,.pager span { padding:.3rem .6rem; border-radius:7px; font-size:.82rem; border:1px solid #262b36; color:#adbac7; }
  .pager a:hover { background:#1c2029; text-decoration:none; }
  .pager .cur { background:#1f6feb; color:#fff; border-color:#1f6feb; }
  .pager .muted { border:none; color:#6e7681; }
  .card strong { color:#e6e6e6; }
  .kpi.big:hover, .card:hover { border-color:#30363d; }
  a.kpi:hover { filter:brightness(1.08); }
  /* 작업(액션) 열: 버튼·링크·인풋 높이/간격 정렬 (connectors·users) */
  .actions { display:flex; flex-wrap:wrap; gap:.4rem; align-items:center; }
  .actions form { margin:0; display:inline-flex; gap:.25rem; align-items:center; }
  .btn-sm { display:inline-flex; align-items:center; justify-content:center; height:1.9rem; line-height:1; border-radius:8px; }
  .actions input[type=password], .actions select { height:1.9rem; }
</style>
</head>
<body>
<?php if ($user !== null): ?>
  <aside class="side">
    <?php if (vg_can('dashboard')): ?>
      <a class="brand" href="/" title="대시보드로 이동">🛡️ vuln-agent</a>
    <?php else: ?>
      <span class="brand">🛡️ vuln-agent</span>
    <?php endif; ?>
    <nav class="menu"><?php vg_nav($active); ?></nav>
    <div class="foot">
      <span class="who"><?= vg_h($user['username']) ?> (<?= vg_h(vg_role_label(vg_role())) ?>)</span>
      <a href="/profile.php"<?= $active==='profile' ? ' style="color:#fff;font-weight:600;"' : '' ?>>내 프로필</a>
      <a href="/logout.php">로그아웃</a>
    </div>
  </aside>
<?php endif; ?>
<div class="app">
<main>
<?php
}

function vg_footer(): void {
    ?>
</main>
</div>
</body>
</html>
<?php
}
