<?php
declare(strict_types=1);

/**
 * nav.php — 사이드바·브레드크럼·활동로그 라벨의 SSOT.
 *   메뉴 구조(vg_nav_sections)를 사이드바 렌더(vg_nav)와 브레드크럼(vg_breadcrumb)이
 *   함께 참조한다 — 메뉴를 바꾸면 두 화면이 자동으로 같이 바뀐다.
 *   vg_can()/vg_role() 은 인증·권한 부트스트랩(auth.php)이 이미 로드된 상태를 전제한다.
 */

require_once __DIR__ . '/../format.php';
require_once __DIR__ . '/components.php';   // vg_subtabs() — vg_findings_subtabs() 가 쓴다.

/**
 * 활동 로그 activity_type → 한글 라벨(SSOT). activity.php(전체 로그) 와 user.php(사용자별
 * 최근 로그) 가 같은 매핑을 쓴다 — 실제 존재하는 값만(vg_log_activity 호출부 기준),
 * 코드에 없으면 원본 그대로 fallback 하니 새 값이 추가돼도 화면이 깨지진 않는다.
 */
function vg_activity_type_labels(): array {
    return [
        'login'                => '로그인',
        'login_fail'           => '로그인 실패',
        'account_lock'         => '계정 잠금',
        'account_unlock'       => '계정 잠금 해제',
        'password_change'      => '비밀번호 변경',
        'agent_token_issue'    => '에이전트 토큰 발급',
        'agent_token_revoke'   => '에이전트 토큰 폐기',
        'agent_token_delete'   => '에이전트 토큰 삭제',
        'token_issue'          => 'API 토큰 발급',
        'token_revoke'         => 'API 토큰 폐기',
        'host_delete'          => '호스트 삭제',
        'host_set_grade'       => '자산 등급 확정',
        'host_grade_review_save' => '자산 등급 검토 저장',
        'host_grade_review_clear'=> '자산 등급 검토 삭제',
        'connector_save'       => '커넥터 저장',
        'connector_toggle'     => '커넥터 사용여부 전환',
        'connector_delete'     => '커넥터 삭제',
        'ingest'               => '수집 반영',
        'ingest_spoof_blocked' => '수집 위조 차단',
        'permission_update'    => '권한 변경',
        'setting_update'       => '운영 설정 변경',
        'user_add'             => '사용자 추가',
        'user_role'            => '사용자 권한 변경',
        'user_pw_reset'        => '사용자 비밀번호 재설정',
        'user_delete'          => '사용자 삭제',
        'feed_run'             => '피드 실행',
        'export_data'          => '데이터 내보내기',
        'export_sbom'          => 'SBOM 내보내기',
        'view_host'            => '호스트 상세 조회',
        'view_host_accounts'   => '호스트 계정 목록 조회',
        'view_depgraph'        => '패키지 의존성 그래프 조회',
        'view_cve'             => '취약점 상세 조회',
        'view_advisory'        => '보안공지 상세 조회',
        'view_compliance_rule' => '보안설정 룰 상세 조회',
        'view_compliance'      => '컴플라이언스 매핑 조회',
        'view_nofix_packages'  => '제거·대체 검토 권고 조회',
        'view_changes'         => '변화 추적 조회',
        'view_asset_packages'  => '전체 설치 패키지 조회',
        'view_control_mapping' => '통제 기준 매핑 조회',
        'view_control'         => '통제 상세 조회',
        // 기능은 제거됐지만 과거 감사로그 표시용으로 남김.
        'host_perimeter_update'=> '경계 방화벽 설정 변경',
        'page_view'            => '페이지 열람',
        'activity_review_save' => '접속기록 점검 기록',
        // 기능은 제거됐지만 과거 감사로그 표시용으로 남김(매핑을 지우면 원시 코드가 그대로 노출된다).
        'saved_view_save'      => '저장된 보기 저장',
    ];
}

/**
 * 수행업무(action) 코드 → 한글 라벨. 접속기록 5요소의 "수행업무" 자리 표시·필터가 함께 쓴다.
 *   코드 어휘의 SSOT 는 audit.php 의 VG_ACTIVITY_ACTIONS 이고, 여기는 그 표시 라벨만 갖는다.
 */
function vg_activity_action_labels(): array {
    return [
        'READ'    => '조회',
        'CREATE'  => '생성',
        'UPDATE'  => '수정',
        'DELETE'  => '삭제',
        'EXPORT'  => '내보내기',
        'LOGIN'   => '로그인',
        'EXECUTE' => '실행',
        'OTHER'   => '기타',
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
        '바로가기' => [
            // 전체 설치 패키지는 자산 목록의 서브탭으로만 들어온다 — 사이드바엔 대표 링크
            // 하나만 두되, 그 탭에 있어도 같은 항목을 활성화해 현재 위치를 잃지 않게 한다.
            ['perm' => 'assets',     'href' => '/assets.php',     'label' => '자산',        'key' => 'assets',
             'active_keys' => ['assets', 'asset_packages']],
            ['perm' => 'connectors', 'href' => '/connectors.php', 'label' => '데이터 수집', 'key' => 'connectors'],
        ],
        '취약점' => [
            // 변화 추적·제거 권고는 vg_findings_subtabs() 의 서브탭으로만 들어온다 —
            // 어느 탭에 있어도 이 항목이 활성이어야 현재 위치를 잃지 않는다.
            ['perm' => 'findings',   'href' => '/findings.php',   'label' => '탐지 결과', 'key' => 'findings',
             'active_keys' => ['findings', 'changes', 'nofix_packages']],
            ['perm' => 'findings',   'href' => '/cves.php',       'label' => 'CVE',       'key' => 'cves'],
            ['perm' => 'findings',   'href' => '/packages.php',   'label' => '패키지',    'key' => 'packages'],
            ['perm' => 'findings',   'href' => '/vendor.php',     'label' => '판정 근거', 'key' => 'vendor'],
            ['perm' => 'advisories', 'href' => '/advisories.php', 'label' => '보안 공지', 'key' => 'advisories'],
        ],
        '보안 기준' => [
            ['perm' => 'findings', 'href' => '/compliance_rules.php', 'label' => '보안 설정', 'key' => 'compliance'],
            // 통제 기준 매핑(control_mapping)은 서브탭에서 내려 본문 링크로만 들어간다 —
            // 탭이 없어졌으니 그 키로 이 항목이 활성화될 일도 없다(화면 자체는 살아 있다).
            ['perm' => 'findings', 'href' => '/compliance.php', 'label' => '컴플라이언스·통제',
             'key' => 'compliance_mapping'],
        ],
        '관리' => [
            ['perm' => 'users',       'href' => '/users.php',        'label' => '사용자',    'key' => 'users'],
            ['perm' => 'permissions', 'href' => '/permissions.php',  'label' => '권한',      'key' => 'permissions'],
            ['perm' => 'agenttokens', 'href' => '/agent-tokens.php', 'label' => '에이전트 키', 'key' => 'agenttokens'],
            ['perm' => 'apitokens',   'href' => '/api-tokens.php',   'label' => 'API 키',    'key' => 'apitokens'],
            ['perm' => 'activity',    'href' => '/activity.php',     'label' => '감사 로그', 'key' => 'activity'],
            ['perm' => 'settings',    'href' => '/settings.php',     'label' => '설정',      'key' => 'settings'],
        ],
    ];
}

/**
 * 탐지 결과 계열 서브탭의 SSOT — 라벨·순서·목적지가 여기 한 곳에만 있다.
 *   같은 줄을 findings.php(조립) · changes.php(하드코딩) · nofix-packages.php(하드코딩) 세 곳이
 *   각자 그리다가 개수(3개 vs 5개)와 라벨('현황' vs '취약점(CVE)')이 어긋났다. 사이드바엔
 *   '탐지 결과' 하나만 있고 변화·제거 권고는 이 줄로만 들어오므로, 세 화면이 글자 그대로
 *   같은 줄을 그려야 사용자가 위치를 잃지 않는다. 내비게이션 정의가 사는 nav.php 에 둔다.
 */
function vg_findings_subtab_labels(): array {
    return [
        'cve'      => '취약점(CVE)',
        'cce'      => '보안설정(CCE)',
        'exposure' => '노출',
        'changes'  => '변화',
        'nofix'    => '제거 권고',
    ];
}

/**
 * 위 정의를 vg_subtabs() 로 그린다. $active 는 현재 화면의 탭 키.
 *   $overrides 는 findings.php 전용 보강분이다 — 탭 키별로 ['href'=>…, 'n'=>…] 을 준다.
 *   그 화면에서만 뱃지 숫자를 붙이고 vg_qs() 로 필터를 이어받기 때문이며, 안 주면 필터
 *   컨텍스트가 없는 changes.php·nofix-packages.php 처럼 단순 href 로 떨어진다.
 */
function vg_findings_subtabs(string $active, array $overrides = []): void {
    $hrefs = [
        'cve'      => '/findings.php',
        'cce'      => '/findings.php?type=cce',
        'exposure' => '/findings.php?type=exposure',
        'changes'  => '/changes.php',
        'nofix'    => '/nofix-packages.php',
    ];
    $tabs = [];
    foreach (vg_findings_subtab_labels() as $key => $label) {
        $tabs[$key] = [
            'label' => $label,
            'href'  => $overrides[$key]['href'] ?? $hrefs[$key],
            'n'     => $overrides[$key]['n'] ?? null,
        ];
    }
    vg_subtabs($tabs, $active);
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
        // 컴플라이언스 매핑 — 방패 모양: 외부 기준(ISMS-P/ISO 27001)에 대한 준수 여부를 나타낸다.
        'compliance_mapping' => '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/>',
        // 통제 기준 매핑 — 나침반 모양: 같은 점검 결과를 어느 기준(ISMS-P/U-코드/N2SF)으로 볼지 고른다는 뜻.
        'control_mapping' => '<circle cx="12" cy="12" r="9"/><polygon points="15.5 8.5 10 10 8.5 15.5 14 14 15.5 8.5"/>',
        'advisories'  => '<path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10.3 21a1.94 1.94 0 0 0 3.4 0"/>',
        'assets'      => '<rect x="2" y="3" width="20" height="8" rx="2"/><rect x="2" y="13" width="20" height="8" rx="2"/><line x1="6" y1="7" x2="6.01" y2="7"/><line x1="6" y1="17" x2="6.01" y2="17"/>',
        'connectors'  => '<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>',
        'users'       => '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>',
        'permissions' => '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
        'agenttokens' => '<path d="M2 9a3 3 0 0 1 0 6v2a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-2a3 3 0 0 1 0-6V7a2 2 0 0 0-2-2H4a2 2 0 0 0-2 2z"/><line x1="13" y1="5" x2="13" y2="19"/>',
        'apitokens'   => '<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>',
        'activity'    => '<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>',
        // 설정 — 슬라이더 모양: 판정 기준값을 조직에 맞춰 조정한다는 뜻.
        'settings'    => '<line x1="4" y1="8" x2="20" y2="8"/><line x1="4" y1="16" x2="20" y2="16"/><circle cx="9" cy="8" r="2.2"/><circle cx="15" cy="16" r="2.2"/>',
    ];
    $p = $paths[$key] ?? '<circle cx="12" cy="12" r="9"/>';
    return '<svg class="ico" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor"'
        . ' stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' . $p . '</svg>';
}

// 사이드바 링크 하나를 렌더한다(단독 링크·그룹 내부 링크가 함께 쓴다 — DRY).
function vg_nav_link(array $l, string $active, bool $root = false): string {
    $activeKeys = $l['active_keys'] ?? [$l['key']];
    $cls = 'link' . ($root ? ' link--root' : '') . (in_array($active, $activeKeys, true) ? ' active' : '');
    return '<a class="' . $cls . '" href="' . vg_h($l['href']) . '">'
        . vg_nav_icon($l['key']) . '<span>' . vg_h($l['label']) . '</span></a>';
}

// 사이드바 렌더. 권한 없는 링크는 빼고, 링크가 하나도 안 남은 섹션은 라벨째 숨긴다.
//   라벨 있는 그룹은 <details>(접이식) 로 감싼다 — 헤더(<summary>) 클릭으로 펼침/접힘,
//   키보드·aria-expanded 는 네이티브가 준다. 서버는 모든 그룹을 open 으로 렌더한다:
//   JS 가 없거나 죽어도 링크가 다 보여 접근 가능하다(progressive enhancement 폴백).
//   접힘 상태 기억·활성 그룹 우선 펼침은 app.js 가 얹는다.
function vg_nav(string $active): void {
    foreach (vg_nav_sections() as $section => $links) {
        $visible = array_filter($links, fn($l) => vg_can($l['perm']));
        if (!$visible) {
            continue;
        }
        // 대시보드와 자주 쓰는 바로가기는 아코디언 밖에 항상 노출한다.
        if ($section === '' || $section === '바로가기') {
            foreach ($visible as $l) {
                echo vg_nav_link($l, $active, true);
            }
            continue;
        }
        echo '<details class="nav-grp" data-grp="' . vg_h($section) . '" open>';
        echo '<summary class="grp">' . vg_h($section) . '</summary>';
        foreach ($visible as $l) {
            echo vg_nav_link($l, $active);
        }
        echo '</details>';
    }
}

/**
 * 사이드바 아코디언 안티-FOUC 부트스트랩. 사이드바 마크업 '직후' 동기 실행돼(테마 초기화와
 * 같은 방식) 저장된 접힘 상태를 첫 페인트 전에 반영한다 — defer 되는 app.js 로는 늦어
 * 저장해 둔 접힘 그룹이 매 로드마다 '펼쳐졌다 접히는' 깜빡임(FOUC)이 보이기 때문.
 * 여기서는 '접기'만 한다(서버가 전부 open 이므로). 토글·저장·반응형은 app.js 가 얹는다.
 * 활성 그룹(현재 페이지)과 모바일(<=860px)은 항상 펼침이라 건드리지 않는다.
 * 정적 마크업이라(사용자 입력 없음) 그대로 출력한다.
 */
function vg_nav_boot(): void {
    echo '<script>(function(){try{'
        . 'if(window.matchMedia&&window.matchMedia("(max-width: 860px)").matches)return;'
        . 'var s=JSON.parse(localStorage.getItem("vg-nav")||"{}");'
        . 'var g=document.querySelectorAll(".side details.nav-grp");'
        . 'for(var i=0;i<g.length;i++){var d=g[i];'
        . 'if(d.querySelector("a.link.active"))continue;'
        . 'if(s[d.getAttribute("data-grp")]===false)d.removeAttribute("open");}'
        . '}catch(e){}})();</script>';
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
            $activeKeys = $l['active_keys'] ?? [$l['key']];
            if (in_array($active, $activeKeys, true)) {
                $section = $sec;
                // 대표 링크의 보조 탭은 실제 페이지 제목을 잎으로 써 의미를 보존한다.
                $label = $l['key'] === $active ? $l['label'] : $title;
                break 2;
            }
        }
    }
    $leaf = $label ?? $title;
    echo '<nav class="crumbs" aria-label="위치">';
    echo '<a href="/">홈</a>';
    if ($section !== null && $section !== '' && $section !== '바로가기') {
        echo '<span class="sep">›</span><span>' . vg_h($section) . '</span>';
    }
    echo '<span class="sep">›</span><span class="cur">' . vg_h($leaf) . '</span>';
    echo '</nav>';
}
