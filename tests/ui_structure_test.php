<?php
declare(strict_types=1);

/** UI 공통 구조 회귀 테스트 — 서버나 DB 없이 소스 구조만 검사한다. */
$root = dirname(__DIR__);
$public = $root . '/server/public';
require_once $root . '/server/src/view/components.php';
$fail = 0;
$check = static function (bool $ok, string $label) use (&$fail): void {
    if (!$ok) { printf("  ✗ %s\n", $label); $fail++; }
};

$phpFiles = glob($public . '/*.php') ?: [];
foreach ($phpFiles as $file) {
    $source = (string) file_get_contents($file);
    $name = basename($file);
    $check(!preg_match('/<(?:table|dialog)\b/i', $source), "$name 직접 table/dialog 금지");
    $check(!preg_match('/\s(?:onclick|onsubmit)\s*=/i', $source), "$name 인라인 이벤트 금지");
    // 브라우저 confirm() 금지(확인은 app.js 의 data-confirm 모달이 한다). 문자열 포함으로만 보면
    //   이름이 'confirm' 으로 끝나는 서버측 함수 호출(vg_asset_grade_confirm(...))까지 걸린다 —
    //   앞 글자가 식별자 문자면 그 함수의 일부이므로 제외한다. window.confirm( 은 '.' 이 앞이라 그대로 걸린다.
    $check(!preg_match('/(?<![\w$])confirm\s*\(/', $source), "$name 브라우저 confirm 금지");
    $check(!preg_match('/\sstyle="/i', $source), "$name 인라인 style 금지");
}

$titlePages = [
    'activity.php', 'advisories.php', 'agent-tokens.php', 'assets.php',
    'cce-rules.php', 'changes.php', 'compliance_rules.php', 'connectors.php', 'cves.php', 'index.php',
    'packages.php', 'permissions.php', 'profile.php', 'users.php', 'vendor.php',
];
foreach ($titlePages as $name) {
    $source = (string) file_get_contents($public . '/' . $name);
    $check(str_contains($source, 'vg_page_title('), "$name 공통 페이지 제목 사용");
}

foreach (['agent-tokens.php', 'users.php'] as $name) {
    $source = (string) file_get_contents($public . '/' . $name);
    $check(str_contains($source, 'vg_toolbar('), "$name 검색 툴바 제공");
    $check(str_contains($source, 'prepare('), "$name 검색 SQL 바인딩");
}

$permissionsPhp = (string) file_get_contents($public . '/permissions.php');
$appCss = (string) file_get_contents($public . '/assets/app.css');
$appJs = (string) file_get_contents($public . '/assets/app.js');
$loginPhp = (string) file_get_contents($public . '/login.php');
$loginJs = (string) file_get_contents($public . '/assets/js/login.js');
$hostJs = (string) file_get_contents($public . '/assets/js/host.js');
/* 공용 컴포넌트도 파일 하나가 아니다 — 진입점(components.php)은 require 목록만 남고 구현은
 *   server/src/view/components/** 에 있다. 진입점만 읽으면 코드가 옮겨졌을 뿐인데 아래 계약
 *   검사가 통째로 통과해 버린다(host: #621 · findings: #624 의 $splitSources 와 같은 처리). */
$componentsPhp = implode("\n", array_map(
    static fn(string $f): string => (string) file_get_contents($f),
    array_merge(
        [$root . '/server/src/view/components.php'],
        glob($root . '/server/src/view/components/*.php') ?: []
    )
));
$chartsPhp = (string) file_get_contents($root . '/server/src/view/charts.php');
/* 자기 속을 server/src/<화면>/ 로 나눠 둔 페이지는 파일 하나가 아니다 — 조회층·탭 렌더가
 *   거기 있다. "그 화면의 소스" 는 페이지 + 그 디렉터리 전체이고, 페이지 파일만 읽으면 코드가
 *   옮겨졌을 뿐인데 계약이 깨진다(host: #621 · findings: 이번 분리).
 *   탭이 아니라 섹션으로 나뉜 화면도 있다(cve: 한 화면에 섹션이 여럿) — sections/ 도 함께 읽는다. */
$splitSources = static function (string $public, string $root, string $page, string $dir): string {
    $files = array_merge(
        [$public . '/' . $page],
        glob($root . '/server/src/' . $dir . '/*.php') ?: [],
        glob($root . '/server/src/' . $dir . '/tabs/*.php') ?: [],
        glob($root . '/server/src/' . $dir . '/sections/*.php') ?: [],
        // 조회층도 탭마다 파일 하나로 갈렸다(findings/queries/) — 탭별 SQL 이 여기 있다.
        glob($root . '/server/src/' . $dir . '/queries/*.php') ?: []
    );
    return implode("\n", array_map(static fn(string $f): string => (string) file_get_contents($f), $files));
};
$hostPhp = $splitSources($public, $root, 'host.php', 'host');
$check(str_contains($loginPhp, 'id="loginForm"')
    && str_contains($loginPhp, 'target="_self"')
    && str_contains($loginPhp, 'formtarget="_self"'),
    'login form and submitter stay in the current browsing context');
$check(str_contains($loginJs, 'HTMLFormElement.prototype.submit.call(form)')
    && str_contains($loginJs, "form.setAttribute('target', '_self')"),
    'login submit neutralizes modifier or injected popup targets');
$check(str_contains($appJs, "window.addEventListener('pageshow', function ()")
    && !str_contains($appJs, "if (!e.persisted) { return; }"),
    'pageshow always clears stale submitting state');
$check(str_contains($permissionsPhp, 'class="permission-form"'), '권한 매트릭스 전용 레이아웃');
$check(str_contains($permissionsPhp, "'class' => 'permission-role'"), '권한 역할 열 클래스');
$check(str_contains($appCss, '.page--permissions .check-cell'), '권한 체크박스 중앙 정렬');
$check(str_contains($appCss, '.sr-only'), '보조기술 전용 텍스트 숨김');
$check(str_contains($appJs, "querySelectorAll('[title]')") && str_contains($appJs, "querySelectorAll('svg title')"),
    'HTML·SVG 네이티브 title을 즉시 공통 툴팁으로 변환');
$check(str_contains($appJs, "closest('[data-tip]')") && str_contains($appCss, '.info-tooltip'),
    '전역 툴팁 이벤트 위임과 body 레이어 스타일');
$check(str_contains($appJs, "addEventListener('mouseover'") && str_contains($appJs, "addEventListener('focusin'")
    && !str_contains($appJs, 'setTimeout(showInfoTip'),
    '툴팁을 지연 없이 hover·키보드 focus 모두에 표시');
$check(str_contains($hostPhp, '$runtimeTotal = $exposureCount + $processCount;')
    // 탭 줄 정의는 server/src/host/tabs.php 로 옮겼다(숫자는 페이지가 센 값을 그대로 받는다).
    // 공백·키 순서·icon/group 값은 이 불변식과 무관하므로, "runtime 탭의 n 이 $n['runtimeTotal']
    // 을 쓴다"만 정규식으로 확인한다(리터럴 문자열 통째 비교는 아이콘만 추가해도 깨진다).
    && preg_match("/'runtime'\s*=>\s*\[[^\]]*'n'\s*=>\s*\\\$n\['runtimeTotal'\]/", $hostPhp) === 1,
    '런타임 탭 건수에 노출 소켓과 실행 프로세스 모두 포함');
$check(str_contains($componentsPhp, "!empty(\$h['class'])"), '공통 테이블 열 클래스 지원');
$check(str_contains($componentsPhp, 'function vg_kpi_strip('), '공통 KPI 스트립 렌더러 제공');
$check(str_contains($componentsPhp, "'exposure' =>") && str_contains($componentsPhp, "'exploit'  =>")
    && str_contains($componentsPhp, "'severity' =>") && str_contains($componentsPhp, "'action'   =>"),
    '판단 신호 4축 고정 순서');

$render = static function (callable $fn): string {
    ob_start();
    $fn();
    return (string) ob_get_clean();
};
$kpiHtml = $render(static fn() => vg_kpi_strip([
    ['label' => '<전체>', 'value' => 0, 'tone' => 'crit', 'href' => '/assets.php?q=<x>'],
    ['label' => '위험', 'value' => 2, 'tone' => 'evil', 'href' => 'javascript:alert(1)'],
    ['label' => '우회', 'value' => 3, 'href' => '/\\evil.example'],
]));
$check(str_contains($kpiHtml, 'kpi--zero') && str_contains($kpiHtml, 'tone-muted'), 'KPI 0값과 tone 화이트리스트');
$check(str_contains($kpiHtml, 'href="/assets.php?q=&lt;x&gt;"') && !str_contains($kpiHtml, 'javascript:')
    && !str_contains($kpiHtml, 'evil.example'), 'KPI 내부 링크 이스케이프·위험 링크 거부');
$check(str_contains($kpiHtml, '&lt;전체&gt;') && !str_contains($kpiHtml, '<전체>'), 'KPI 출력 이스케이프');

$signalHtml = $render(static fn() => vg_signal_slots([
    'exposure' => ['value' => '<외부>', 'tone' => 'evil'],
    'exploit' => ['state' => 'na'],
    'severity' => ['value' => 'HIGH', 'tone' => 'high'],
    'action' => ['state' => 'unknown'],
    'other' => ['value' => '출력 금지'],
]));
$positions = array_map(static fn(string $axis): int|false => strpos($signalHtml, 'data-axis="' . $axis . '"'),
    ['exposure', 'exploit', 'severity', 'action']);
$check(!in_array(false, $positions, true) && $positions === array_values($positions)
    && $positions[0] < $positions[1] && $positions[1] < $positions[2] && $positions[2] < $positions[3],
    '판단 신호 노출→악용→등급→조치 순서');
$check(str_contains($signalHtml, '해당 없음') && str_contains($signalHtml, '미제공')
    && !str_contains($signalHtml, '출력 금지'), '판단 신호 비해당·미제공·axis 화이트리스트');
$check(str_contains($signalHtml, '&lt;외부&gt;') && !str_contains($signalHtml, 'tone-evil'), '판단 신호 이스케이프·tone 화이트리스트');
$check(str_contains($chartsPhp, '$min = 0.0;') && str_contains($chartsPhp, '$max = 100.0;'),
    '에이전트 리소스 사용률 차트 0~100% 절대 축');
// connectors.php 는 자기 속을 server/src/connectors/** 로 나눠 뒀다 — 화면의 계약은 그 묶음 전체다.
$connectorPhp = $splitSources($public, $root, 'connectors.php', 'connectors');
$connectorJs = (string) file_get_contents($public . '/assets/js/connectors.js');
$navPhp = (string) file_get_contents($root . '/server/src/view/nav.php');
$check(str_contains($connectorPhp, 'data-feed-preview'), '커넥터 미리보기 data 속성');
$check(str_contains($connectorJs, "closest('[data-feed-preview]')"), '커넥터 미리보기 이벤트 위임');
$check(str_contains($navPhp, "'데이터' =>"), '참조 카탈로그는 데이터 그룹으로 분리');
$check(str_contains($navPhp, "'관리' =>"), '관리 메뉴 통합');
$check(!str_contains($navPhp, "'취약점' =>") && !str_contains($navPhp, "'보안 기준' =>")
    && !str_contains($navPhp, "'바로가기' =>"),
    '업무 화면은 라벨 없는 최상위 묶음으로 통합');
$check(!str_contains($navPhp, "'계정' =>") && !str_contains($navPhp, "'연동' =>"), '잘게 나뉜 관리 그룹 제거');
$check(str_contains($navPhp, 'function vg_compliance_subtabs('), '컴플라이언스 서브탭 정의는 nav.php 한 곳');
/* 메뉴코드 정본(vg_menus) ↔ 사이드바 'perm' ↔ 화면 가드(vg_require_menu[_any]) 대조.
   셋이 어긋나면 "사이드바에 보이는데 눌러보면 403" 링크가 생긴다. auth.php 는 include 만 해도
   세션을 열고 DB 를 잡으므로 실행하지 않고 소스만 읽는다(이 테스트는 서버 없이 돈다). */
$authPhp = (string) file_get_contents($root . '/server/src/auth.php');
preg_match('/function vg_menus\(\): array \{.*?\n\}/s', $authPhp, $menuBody);
preg_match_all("/'([a-z]+)'\s*=>/", $menuBody[0] ?? '', $menuMatch);
$menuCodes = $menuMatch[1];
$check($menuCodes !== [], 'vg_menus() 메뉴코드 목록 파싱');
preg_match_all("/'perm'\s*=>\s*'([a-z]+)'/", $navPhp, $permMatch);
$unknownPerm = array_values(array_diff(array_unique($permMatch[1]), $menuCodes));
$check($unknownPerm === [], '사이드바 perm 코드가 전부 vg_menus() 에 있음(' . implode(',', $unknownPerm) . ')');
$guardCodes = [];
foreach ($phpFiles as $file) {
    preg_match_all("/vg_require_menu(?:_any)?\(([^)]*)\)/", (string) file_get_contents($file), $guardMatch);
    foreach ($guardMatch[1] as $args) {
        preg_match_all("/'([a-z]+)'/", $args, $one);
        foreach ($one[1] as $code) { $guardCodes[$code] = basename($file); }
    }
}
$unknownGuard = array_diff_key($guardCodes, array_flip($menuCodes));
$check($unknownGuard === [], '화면 가드 메뉴코드가 전부 vg_menus() 에 있음(' . implode(',', array_keys($unknownGuard)) . ')');
// 사이드바에 뜨는 화면은 그 링크의 perm 으로 열려야 한다(카탈로그 4종은 catalog 하나를 공유).
//   compliance_rules.php(SSG 룰셋)는 사이드바에서 내렸지만 URL 은 살아 있다 — CCE 상세가
//   참조 근거로 링크하므로 같은 가드를 계속 지켜야 한다.
foreach (['findings.php' => 'findings', 'assets.php' => 'assets', 'compliance.php' => 'compliance',
          'cves.php' => 'catalog', 'packages.php' => 'catalog', 'vendor.php' => 'catalog',
          'cce-rules.php' => 'catalog', 'compliance_rules.php' => 'catalog'] as $page => $code) {
    $check(str_contains((string) file_get_contents($public . '/' . $page), "vg_require_menu('$code')"),
        "$page 가드는 $code");
}
// API 토큰 인증은 폐지됐다 — 화면·헬퍼·문서 어디에도 남기지 않는다(과거 감사로그 라벨은 예외).
$check(!file_exists($public . '/api-tokens.php') && !file_exists($root . '/server/src/apitoken.php'),
    'API 키 화면·헬퍼 제거');
$check(!str_contains($navPhp, '/api-tokens.php') && !str_contains($authPhp, "'apitokens'"),
    '사이드바·메뉴코드에 API 키 없음');
$check(str_contains($navPhp, "'token_issue'"), '과거 API 토큰 감사로그 라벨 보존');

$check(str_contains($connectorPhp, "['label' => '실행 시각'"), '커넥터 실행 시각 열 통합');
$check(!str_contains($connectorPhp, "['label' => '마지막 실행'"), '커넥터 중복 시각 열 제거');

// CVE 상세도 조회층·섹션 렌더가 server/src/cve/** 로 나뉘어 있다(위 $splitSources 주석).
$cvePhp = $splitSources($public, $root, 'cve.php', 'cve');
$vendorPhp = (string) file_get_contents($public . '/vendor.php');
$check(str_contains($cvePhp, 'LEFT JOIN tb_finding_evidence fe'), 'CVE 위치별 수정 버전 근거 결합');
$check(str_contains($cvePhp, "['label' => '현재 → 권장 조치'"), 'CVE 위치별 권장 조치 열 제공');
$check(str_contains($cvePhp, "vg_is_kernel_code_pkg"), 'CVE 조치에서 프로세스 재시작과 커널 재부팅 구분');
$check(str_contains($cvePhp, '완화·격리·제거 검토'), '수정본 미공개 CVE의 대체 안내');
$check(str_contains($vendorPhp, "preg_match('/^TEMP-/i") && str_contains($vendorPhp, '>CVE 미배정</span>'),
    'Debian TEMP 식별자를 CVE 미배정으로 표시');
$check(str_contains($vendorPhp, "' · 원본 ' . \$cveId"), 'Debian TEMP 원본 식별자를 툴팁에 보존');

// assets.php 도 마찬가지로 server/src/assets/** 와 한 묶음이다(표·모달이 거기 있다).
$assetsPhp = $splitSources($public, $root, 'assets.php', 'assets');
$assetPackagesPhp = (string) file_get_contents($public . '/asset-packages.php');
// 탭 줄의 정의는 nav.php 의 vg_asset_subtab_labels() 하나뿐이다 — 세 화면은 부르기만 한다.
//   예전엔 화면마다 배열 리터럴을 갖고 있어 라벨·개수가 어긋날 수 있었다(#556).
$navPhp = (string) file_get_contents($root . '/server/src/view/nav.php');
$discoveryPhp = (string) file_get_contents($public . '/discovery.php');
$check(str_contains($navPhp, "'packages'  => '전체 설치 패키지'")
    && str_contains($navPhp, "'discovery' => '자산 탐색'")
    && str_contains($assetsPhp, "vg_asset_subtabs('assets')")
    && str_contains($assetPackagesPhp, "vg_asset_subtabs('packages')")
    && str_contains($discoveryPhp, "vg_asset_subtabs('discovery')"),
    '자산 목록·전체 설치 패키지·자산 탐색을 상호 이동 탭으로 제공');
$check(!str_contains($assetsPhp, 'echo \'<a class="btn btn--sm btn--ghost" href="/asset-packages.php"'),
    '자산 제목의 중복 설치 패키지 버튼 제거');
$ingestPhp = (string) file_get_contents($public . '/ingest.php');
$caddyfile = (string) file_get_contents($root . '/deploy/caddy/Caddyfile');
$agentSh = (string) file_get_contents($root . '/agent/vuln-inventory-agent.sh');
/* 목록은 "이 행을 열어볼지 말지" 를 정하는 열만 둔다(docs/dev/ui-design-system.md).
 *   OS·에이전트 버전·패키지 수·담당 부서는 **지운 게 아니라 호스트 상세로 옮겼다** —
 *   목록에서 빠진 것과 상세에 있는 것을 한 쌍으로 확인한다(한쪽만 보면 값이 사라져도 통과한다).
 *   IP 는 그 뒤 목록으로 **되돌아왔다**: 검색창이 'IP 검색' 이라 적고 실제로 IP 로 걸리는데
 *   표에 IP 가 없어 왜 걸렸는지 안 보였다(사용자 지시). 값의 출처도 바뀌었다 —
 *   호스트가 신고한 전 인터페이스(tb_host_address) 중 대표 하나이지, 상세가 쓰는
 *   last_seen_ip(서버가 수집 요청을 받은 주소) 한 개가 아니다. */
$hostPhpSrc = $splitSources($public, $root, 'host.php', 'host');   // host.php + server/src/host/**(위 주석 참고)
$check(!str_contains($assetsPhp, "['label' => '스캔'")
    && !str_contains($assetsPhp, "['label' => 'OS'") && !str_contains($assetsPhp, "['label' => '에이전트'")
    && !str_contains($assetsPhp, "['label' => '담당 부서'"),
    '자산 목록에서 상세로 옮긴 열 제거(OS·에이전트·담당 부서)');
/* IP 열은 조회 한 번으로 묶은 값을 쓴다(N+1 금지) — 행마다 조회하면 페이지당 25번이 된다. */
$check(str_contains($assetsPhp, "['label' => 'IP'")
    && str_contains($assetsPhp, 'vg_assets_load_addresses($pdo, array_column($rows,')
    && str_contains($assetsPhp, '$ipsByHost[(int) $r[\'host_id\']]'),
    '자산 목록 IP 열은 조회 한 번으로 묶은 대표 IP 를 쓴다');
$check(str_contains($hostPhpSrc, "'IP ' . vg_h(\$host['last_seen_ip'])")
    && str_contains($hostPhpSrc, "\$meta[] = '에이전트 <code>'")
    && str_contains($hostPhpSrc, "vg_badge('구버전', 'med'")
    // 소유 부서는 '자산 설정' 탭의 등급 검토 폼이 갖는다. 읽기 전용 정의목록(<dt>소유 부서</dt>)은
    //   같은 값을 바로 아래 입력칸이 이미 보여주고 있어 걷었다 — 값을 들고 있는 입력을 확인한다.
    && str_contains($hostPhpSrc, 'name="owning_department"'),
    '옮긴 값이 호스트 상세에 남아 있음(IP·OS·에이전트 구버전 신호·소유 부서)');
$check(str_contains($ingestPhp, "vg_request_header('X-Real-IP')") && str_contains($caddyfile, 'header_up X-Real-IP {remote_host}'),
    'Caddy 원본 IP 전달과 ingest 저장 연계');
$check(str_contains($agentSh, 'CPU_QUOTA="${CPU_QUOTA:-10%}"') && str_contains($agentSh, 'DO_LIMIT="${AGENT_LIMIT:-1}"'),
    '에이전트 CPU 10% cgroup 제한 기본 적용');
$processHtml = (string) file_get_contents($public . '/process.html');
$check(!str_contains($processHtml, '시간마다 자동 수집') && !str_contains($processHtml, 'tb_kernel_cves'),
    '공개 프로세스 설명에 폐기된 고정 주기·구 테이블명 없음');
$check(str_contains($processHtml, 'tb_scan_run') && str_contains($processHtml, 'tb_agent_command')
    && str_contains($processHtml, '즉시·예약·중단 명령은 지원하지 않는다'),
    '공개 프로세스 설명에 실행 이력·명령 큐·cron 제약 명시');
$check(str_contains($assetsPhp, 'POSIX <code>awk</code>') && str_contains($assetsPhp, '<code>curl</code> 또는 <code>wget</code>')
    && str_contains($assetsPhp, '<code>jq</code>는 선택 사항'),
    '에이전트 설치 모달의 실제 선행 조건 안내');

// #599 W3 — 기존 route/query 키를 유지한 행동 흐름·접근성 회귀.
// 대시보드도 조회층·섹션 렌더가 server/src/dashboard/** 로 나뉘어 있다(위 $splitSources 주석).
$indexPhp = $splitSources($public, $root, 'index.php', 'dashboard');
// 탐지 결과도 조회층·탭 렌더가 server/src/findings/** 로 나뉘어 있다(위 $splitSources 주석).
$findingsPhp = $splitSources($public, $root, 'findings.php', 'findings');
$cceRulePhp = (string) file_get_contents($public . '/cce-rule.php');
$compliancePhp = (string) file_get_contents($public . '/compliance.php');
$findingStatusPhp = (string) file_get_contents($root . '/server/src/finding_status.php');
$layoutPhp = (string) file_get_contents($root . '/server/src/view/layout.php');

$check(str_contains($indexPhp, "'/findings.php?sev=HIGH%2B'")
    && str_contains($findingsPhp, "'HIGH+'")
    && str_contains($findingsPhp, "f.severity IN ('CRITICAL','HIGH')"),
    'High 이상 KPI가 CRITICAL+HIGH 모집단을 여는 canonical sev 값 사용');
$check(str_contains($findingsPhp, 'data-action-queue')
    && str_contains($findingsPhp, "'kev' => 'KEV 등재'")
    && str_contains($findingsPhp, "'overdue' => '기한 초과'"),
    '탐지 결과 첫 화면 행동 큐와 기존 fx 키 기반 우선순위 필터');
$check(str_contains($findingsPhp, '/cce-rule.php?code=')
    && str_contains($findingsPhp, '/compliance_rule.php?rule='),
    'CCE FAIL 행의 직접 CCE 상세 링크와 SSG 보조 링크 보존');
$check(substr_count($assetsPhp, 'data-install-step-panel=') === 4
    && str_contains($assetsPhp, '완료 조건') && str_contains($assetsPhp, '다시 시도')
    && str_contains($assetsPhp, '/agent-tokens.php') && str_contains($assetsPhp, '/agent-dl.php?f='),
    '에이전트 설치 4단계·완료 조건·복사/재시도·기존 route 제공');
$check(str_contains($findingStatusPhp, "\$status === 'EXCEPTED' && \$note === ''"),
    'EXCEPTED 상태는 기존 note 필드에 사유가 있어야 저장');
$check(str_contains($hostPhp, "\$code === 'EXCEPTED' ? ' (메모 필수)'")
    && str_contains($hostPhp, '메모 (예외 선택 시 필수)'),
    'EXCEPTED 선택지와 메모 입력에 필수 사유 계약 표시');
$check(str_contains($hostJs, "fixNote.required = fixStatus.value === 'EXCEPTED'")
    && str_contains($hostJs, "addEventListener('change', syncFindingNoteRequired)"),
    'EXCEPTED 선택에 따라 메모 required 속성 동기화');
$check(str_contains($componentsPhp, '<nav class="pager" aria-label="페이지 탐색">')
    && str_contains($componentsPhp, 'aria-current="page"'),
    '페이지네이션 nav·현재 페이지 접근성');
$check(str_contains($appJs, "setAttribute('aria-pressed'")
    && str_contains($appJs, 'modalOpeners') && str_contains($appJs, "addEventListener('close'"),
    '테마 aria-pressed 동기화와 dialog 닫힘 후 포커스 복귀');
$check(str_contains($layoutPhp, 'aria-controls="primaryNavigation"')
    && str_contains($layoutPhp, 'id="primaryNavigation"'),
    '모바일 내비게이션 제어 대상 연결');
$check(substr_count($processHtml, 'class="operator-step"') === 4
    && str_contains($processHtml, '설치') && str_contains($processHtml, '피드 동기화')
    && str_contains($processHtml, '자산 스캔') && str_contains($processHtml, '우선순위 확인')
    && str_contains($processHtml, '조치') && str_contains($processHtml, 'https://github.com/JeongDoWook/vuln-agent/'),
    'process.html 운영자 4단계·용어 구분·외부 개발자 문서 링크');
// 수동(문서 심사) 구역은 화면에서 내렸다 — 자동판정 근거가 제품 안에 없는 항목이라
//   화면은 자동판정과 그 추이만 갖는다. 상수·조항 매핑은 policy.php 에 그대로 있다.
$check(str_contains($cvePhp, 'vg_decision_flow(') && str_contains($cceRulePhp, 'vg_decision_flow(')
    && str_contains($compliancePhp, 'data-compliance-zone="automatic"')
    && !str_contains($compliancePhp, 'data-compliance-zone="manual"')
    && str_contains($compliancePhp, 'data-compliance-zone="trend"'),
    'CVE/CCE 판단 흐름과 컴플라이언스 자동·추이 구역(수동 구역 없음)');

if ($fail > 0) { printf("ui_structure_test: %d건 실패\n", $fail); exit(1); }
printf("ui_structure_test: 전부 통과\n");
