<?php
declare(strict_types=1);

/**
 * nav.php — 사이드바·브레드크럼·활동로그 라벨의 SSOT.
 *   메뉴 구조(vg_nav_sections)를 사이드바 렌더(vg_nav)와 브레드크럼(vg_breadcrumb)이
 *   함께 참조한다 — 메뉴를 바꾸면 두 화면이 자동으로 같이 바뀐다.
 *   vg_can()/vg_role() 은 인증·권한 부트스트랩(auth.php)이 이미 로드된 상태를 전제한다.
 */

require_once __DIR__ . '/../format.php';

/**
 * 활동 로그 activity_type → 한글 라벨(SSOT). activity.php(전체 로그) 와 user.php(사용자별
 * 최근 로그) 가 같은 매핑을 쓴다 — 실제 존재하는 값만(vg_log_activity 호출부 기준),
 * 코드에 없으면 원본 그대로 fallback 하니 새 값이 추가돼도 화면이 깨지진 않는다.
 */
function vg_activity_type_labels(): array {
    return [
        'login'                => '로그인',
        'password_change'      => '비밀번호 변경',
        'agent_token_issue'    => '에이전트 토큰 발급',
        'agent_token_revoke'   => '에이전트 토큰 폐기',
        'agent_token_delete'   => '에이전트 토큰 삭제',
        'token_issue'          => 'API 토큰 발급',
        'token_revoke'         => 'API 토큰 폐기',
        'host_delete'          => '호스트 삭제',
        'connector_save'       => '커넥터 저장',
        'connector_toggle'     => '커넥터 사용여부 전환',
        'connector_delete'     => '커넥터 삭제',
        'ingest'               => '수집 반영',
        'ingest_spoof_blocked' => '수집 위조 차단',
        'ingest_shared_token'  => '공유 토큰 수집',
        'permission_update'    => '권한 변경',
        'user_add'             => '사용자 추가',
        'user_role'            => '사용자 권한 변경',
        'user_pw_reset'        => '사용자 비밀번호 재설정',
        'user_delete'          => '사용자 삭제',
        'feed_run'             => '피드 실행',
    ];
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
            ['perm' => 'findings',   'href' => '/changes.php',    'label' => '변화 추적',     'key' => 'changes'],
            ['perm' => 'findings',   'href' => '/cves.php',       'label' => 'CVE 목록',      'key' => 'cves'],
            ['perm' => 'findings',   'href' => '/packages.php',   'label' => '영향 패키지',   'key' => 'packages'],
            ['perm' => 'findings',   'href' => '/vendor.php',     'label' => '벤더 판정',     'key' => 'vendor'],
            ['perm' => 'findings',   'href' => '/compliance_rules.php', 'label' => '보안설정 룰셋', 'key' => 'compliance'],
            ['perm' => 'advisories', 'href' => '/advisories.php', 'label' => '국내 보안공지', 'key' => 'advisories'],
        ],
        '자산' => [
            ['perm' => 'assets', 'href' => '/assets.php', 'label' => '자산 관리', 'key' => 'assets'],
        ],
        '수집' => [
            ['perm' => 'connectors', 'href' => '/connectors.php', 'label' => '피드 커넥터', 'key' => 'connectors'],
        ],
        '시스템' => [
            ['perm' => 'users',       'href' => '/users.php',        'label' => '사용자',      'key' => 'users'],
            ['perm' => 'permissions', 'href' => '/permissions.php',  'label' => '권한 설정',   'key' => 'permissions'],
            ['perm' => 'agenttokens', 'href' => '/agent-tokens.php', 'label' => '에이전트 토큰', 'key' => 'agenttokens'],
            ['perm' => 'apitokens',   'href' => '/api-tokens.php',   'label' => 'API 토큰',    'key' => 'apitokens'],
            ['perm' => 'activity',    'href' => '/activity.php',     'label' => '감사 로그',   'key' => 'activity'],
            ['perm' => 'stats',       'href' => '/stats.php',        'label' => '사용 통계',   'key' => 'stats'],
        ],
    ];
}

/**
 * 사이드바 메뉴 아이콘 — 단색 라인 SVG. stroke=currentColor 라 링크 색을 그대로
 * 상속한다(테마·활성 상태에 자동으로 따라간다). key 는 vg_nav_sections() 의 것과 맞춘다.
 * 이미 이스케이프가 필요 없는 정적 마크업이라 그대로 돌려준다.
 */
function vg_nav_icon(string $key): string {
    static $paths = [
        'dashboard'   => '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/>',
        'findings'    => '<path d="m10.29 3.86-8.4 14.55A2 2 0 0 0 3.62 21h16.76a2 2 0 0 0 1.73-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
        'changes'     => '<polyline points="22 7 13.5 15.5 8.5 10.5 2 17"/><polyline points="16 7 22 7 22 13"/>',
        'cves'        => '<line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/>',
        'packages'    => '<path d="M21 8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22" x2="12" y2="12"/>',
        // 벤더 판정 — 검인(도장) 모양: 벤더가 "고쳤다/안 고쳤다" 를 확인해 준 것이라는 뜻.
        'vendor'      => '<circle cx="12" cy="9" r="6"/><polyline points="9.3 9 11.2 10.9 14.9 7.2"/><path d="M8.5 14.4 7.4 21l4.6-2.3 4.6 2.3-1.1-6.6"/>',
        // 보안설정 룰셋 — 체크리스트 모양: 기준(CIS/NIST/STIG)에 맞나 항목별로 확인한다는 뜻.
        'compliance'  => '<path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>',
        'advisories'  => '<path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10.3 21a1.94 1.94 0 0 0 3.4 0"/>',
        'assets'      => '<rect x="2" y="3" width="20" height="8" rx="2"/><rect x="2" y="13" width="20" height="8" rx="2"/><line x1="6" y1="7" x2="6.01" y2="7"/><line x1="6" y1="17" x2="6.01" y2="17"/>',
        'connectors'  => '<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>',
        'users'       => '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>',
        'permissions' => '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
        'agenttokens' => '<path d="M2 9a3 3 0 0 1 0 6v2a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-2a3 3 0 0 1 0-6V7a2 2 0 0 0-2-2H4a2 2 0 0 0-2 2z"/><line x1="13" y1="5" x2="13" y2="19"/>',
        'apitokens'   => '<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>',
        'activity'    => '<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>',
        // 사용 통계 — 막대그래프(추이) 느낌의 라인 아이콘, 다른 아이콘과 같은 톤.
        'stats'       => '<line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/>',
    ];
    $p = $paths[$key] ?? '<circle cx="12" cy="12" r="9"/>';
    return '<svg class="ico" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor"'
        . ' stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' . $p . '</svg>';
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
            echo '<a class="' . $cls . '" href="' . vg_h($l['href']) . '">'
                . vg_nav_icon($l['key']) . '<span>' . vg_h($l['label']) . '</span></a>';
        }
    }
}

/**
 * 상단바 브레드크럼 — "지금 어디" 를 사이드바 밖에서 한 줄로. 홈 › 섹션 › 현재.
 *   active 키로 vg_nav_sections() 에서 소속 섹션·라벨을 찾는다. 네비에 없는 상세
 *   페이지(cve·advisory·host 등)는 섹션을 못 찾으니 제목($title)을 잎으로 쓴다.
 */
function vg_breadcrumb(string $active, string $title): void {
    $section = null;
    $label = null;
    foreach (vg_nav_sections() as $sec => $links) {
        foreach ($links as $l) {
            if ($l['key'] === $active) { $section = $sec; $label = $l['label']; break 2; }
        }
    }
    $leaf = $label ?? $title;
    echo '<nav class="crumbs" aria-label="위치">';
    echo '<a href="/">홈</a>';
    if ($section !== null && $section !== '') {
        echo '<span class="sep">›</span><span>' . vg_h($section) . '</span>';
    }
    echo '<span class="sep">›</span><span class="cur">' . vg_h($leaf) . '</span>';
    echo '</nav>';
}
