<?php
declare(strict_types=1);

/**
 * view.php — 공통 레이아웃(헤더/네비/푸터) + 렌더 헬퍼.
 *   vg_h() 이스케이프, vg_header($title,$active) 로 시작, vg_footer() 로 끝.
 *   스타일·스크립트는 public/assets/app.{css,js} 가 소유한다. 여기에 색상을 하드코딩하지 않는다.
 */

function vg_h(?string $s): string {
    return htmlspecialchars((string) $s, ENT_QUOTES, 'UTF-8');
}

/** 정적 파일 URL + 캐시버스팅(mtime). 파일이 없으면 경로만 돌려준다. */
function vg_asset(string $path): string {
    $file = __DIR__ . '/../public' . $path;
    $v = is_file($file) ? (string) filemtime($file) : '';
    return vg_h($path . ($v !== '' ? '?v=' . $v : ''));
}

/* --- 톤 어휘 --------------------------------------------------------------
 * 색은 CSS 의 .tone-* 이 정한다. PHP 는 "어떤 톤인가" 만 고른다.
 * 뱃지를 쓰는 모든 화면(심각도·런타임상태·피드상태·노출범위·자산상태)이 이 어휘를 공유한다. */

const VG_TONE_SEV = ['CRITICAL' => 'crit', 'HIGH' => 'high', 'MEDIUM' => 'med', 'LOW' => 'low'];

/** 임의의 라벨을 톤 뱃지로. $label 은 여기서 이스케이프한다. */
function vg_badge(string $label, string $tone = 'muted', string $title = ''): string {
    return '<span class="badge tone-' . vg_h($tone) . '"'
        . ($title !== '' ? ' title="' . vg_h($title) . '"' : '')
        . '>' . vg_h($label) . '</span>';
}

/** 심각도(CRITICAL/HIGH/MEDIUM/LOW) 뱃지. */
function vg_sev_badge(string $sev): string {
    return vg_badge($sev, vg_sev_tone($sev));
}

/** 심각도 → 톤 클래스명. KPI 카드도 같은 톤을 쓴다. */
function vg_sev_tone(string $sev): string {
    return VG_TONE_SEV[$sev] ?? 'muted';
}

/**
 * 심각도별 건수 뱃지 묶음. 0건인 등급은 생략하고, 전부 0이면 '–'.
 *   $href 를 주면 각 뱃지를 링크로 만든다(자산관리: 등급별 취약점 목록으로).
 *   대시보드 · 자산관리 · 호스트 스캔이력이 공유한다.
 */
function vg_sev_counts(array $counts, ?callable $href = null): string {
    $out = [];
    foreach (VG_TONE_SEV as $sev => $tone) {
        $n = (int) ($counts[$sev] ?? 0);
        if ($n === 0) {
            continue;
        }
        $attr = 'class="badge tone-' . $tone . '" title="' . vg_h($sev) . '"';
        $out[] = $href !== null
            ? '<a ' . $attr . ' href="' . vg_h($href($sev)) . '">' . $n . '</a>'
            : '<span ' . $attr . '>' . $n . '</span>';
    }
    return $out ? implode(' ', $out) : '<span class="why">–</span>';
}

// 런타임 상태(EXTERNAL/LISTENING/RUNNING/LOADED/INSTALLED)
function vg_status_label(?string $s): string {
    $m = ['EXTERNAL' => '외부노출', 'LISTENING' => '로컬리스닝', 'RUNNING' => '실행중', 'LOADED' => '사용중', 'INSTALLED' => '설치만'];
    return $m[$s ?? ''] ?? (string) $s;
}
function vg_status_badge(?string $s): string {
    $tone = ['EXTERNAL' => 'crit', 'LISTENING' => 'high', 'RUNNING' => 'med', 'LOADED' => 'purple', 'INSTALLED' => 'muted'];
    return vg_badge(vg_status_label($s), $tone[$s ?? ''] ?? 'muted');
}

/** 성공/오류 알림. $msg 가 null·빈문자면 아무것도 출력하지 않는다. */
function vg_alert(?string $msg, string $type = 'err'): void {
    if ($msg === null || $msg === '') {
        return;
    }
    echo '<div class="alert alert--' . ($type === 'ok' ? 'ok' : 'err') . '">' . vg_h($msg) . '</div>';
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
//   data-nav 는 app.js 가 이동 시작을 알아채 상단 진행바를 띄우는 표식이다.
function vg_perpage_select(): void {
    $current = vg_perpage();
    echo '<select data-nav onchange="location.href=this.value" aria-label="페이지당 표시 개수">';
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
 *   per_page 는 이 폼의 입력이 아니므로 hidden 으로 실어 보낸다 —
 *   안 그러면 "100개씩 보기" 상태에서 검색할 때마다 기본값으로 돌아간다.
 */
function vg_toolbar(array $fields): void {
    $resetOverrides = ['page' => null];
    $hasValue = false;

    echo '<form class="toolbar" method="get">';

    $perPage = vg_perpage();
    if ($perPage !== VG_PERPAGE_DEFAULT) {
        echo '<input type="hidden" name="per_page" value="' . $perPage . '">';
    }

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
            // data-autosubmit: 고르는 즉시 폼 제출(app.js). JS 가 없으면 검색 버튼이 그대로 동작한다.
            echo '<select name="' . vg_h($name) . '" data-autosubmit>';
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
    echo '<button type="submit" class="btn btn--sm btn--primary" data-loading="검색 중…">검색</button>';
    if ($hasValue) {
        echo '<a class="btn btn--sm btn--ghost" href="' . vg_h(vg_qs($resetOverrides)) . '">초기화</a>';
    }
    echo '</form>';
}

/**
 * 사이드바 메뉴(라벨 SSOT). 대분류(섹션 라벨) → 중분류(링크) 2단.
 *   섹션 라벨이 '' 이면 라벨 없이 링크만 렌더한다(대시보드처럼 단독 항목).
 *   각 링크의 'perm' 은 vg_can() 메뉴코드, 'key' 는 vg_header($active) 와 맞춘다.
 *   'perm' 은 vg_menus() 의 코드와 반드시 일치해야 한다 — 어긋나면 사이드바에 보이는데
 *   눌러보면 403 나는 링크가 생긴다. 단, findings 처럼 코드 하나가 링크 둘을 열 수 있다.
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
<link rel="stylesheet" href="<?= vg_asset('/assets/app.css') ?>">
<script src="<?= vg_asset('/assets/app.js') ?>" defer></script>
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
      <a href="/profile.php"<?= $active === 'profile' ? ' class="active"' : '' ?>>내 프로필</a>
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
