<?php
declare(strict_types=1);

/** UI 공통 구조 회귀 테스트 — 서버나 DB 없이 소스 구조만 검사한다. */
$root = dirname(__DIR__);
$public = $root . '/server/public';
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
    $check(!str_contains($source, 'confirm('), "$name 브라우저 confirm 금지");
    $check(!preg_match('/\sstyle="/i', $source), "$name 인라인 style 금지");
}

$titlePages = [
    'activity.php', 'advisories.php', 'agent-tokens.php', 'api-tokens.php', 'assets.php',
    'changes.php', 'compliance_rules.php', 'connectors.php', 'cves.php', 'index.php',
    'packages.php', 'permissions.php', 'profile.php', 'users.php', 'vendor.php',
];
foreach ($titlePages as $name) {
    $source = (string) file_get_contents($public . '/' . $name);
    $check(str_contains($source, 'vg_page_title('), "$name 공통 페이지 제목 사용");
}

foreach (['agent-tokens.php', 'api-tokens.php', 'users.php'] as $name) {
    $source = (string) file_get_contents($public . '/' . $name);
    $check(str_contains($source, 'vg_toolbar('), "$name 검색 툴바 제공");
    $check(str_contains($source, 'prepare('), "$name 검색 SQL 바인딩");
}

$permissionsPhp = (string) file_get_contents($public . '/permissions.php');
$appCss = (string) file_get_contents($public . '/assets/app.css');
$appJs = (string) file_get_contents($public . '/assets/app.js');
$componentsPhp = (string) file_get_contents($root . '/server/src/view/components.php');
$chartsPhp = (string) file_get_contents($root . '/server/src/view/charts.php');
$hostPhp = (string) file_get_contents($public . '/host.php');
$check(str_contains($permissionsPhp, 'class="permission-form"'), '권한 매트릭스 전용 레이아웃');
$check(str_contains($permissionsPhp, "'class' => 'permission-role'"), '권한 역할 열 클래스');
$check(str_contains($appCss, '.page--permissions .check-cell'), '권한 체크박스 중앙 정렬');
$check(str_contains($appCss, '.sr-only'), '보조기술 전용 텍스트 숨김');
$check(str_contains($appJs, "querySelectorAll('[title]')") && str_contains($appJs, "querySelectorAll('svg title')"),
    'HTML·SVG 네이티브 title을 즉시 공통 툴팁으로 변환');
$check(str_contains($appJs, "closest('[data-tip]')") && str_contains($appCss, '.info-tooltip'),
    '전역 툴팁 이벤트 위임과 body 레이어 스타일');
$check(str_contains($hostPhp, '$runtimeTotal = $exposureCount + $processCount;')
    && str_contains($hostPhp, "'runtime' => ['label' => '런타임',    'n' => \$runtimeTotal]"),
    '런타임 탭 건수에 노출 소켓과 실행 프로세스 모두 포함');
$check(str_contains($componentsPhp, "!empty(\$h['class'])"), '공통 테이블 열 클래스 지원');
$check(str_contains($chartsPhp, '$min = 0.0;') && str_contains($chartsPhp, '$max = 100.0;'),
    '에이전트 리소스 사용률 차트 0~100% 절대 축');
$connectorPhp = (string) file_get_contents($public . '/connectors.php');
$connectorJs = (string) file_get_contents($public . '/assets/js/connectors.js');
$navPhp = (string) file_get_contents($root . '/server/src/view/nav.php');
$check(str_contains($connectorPhp, 'data-feed-preview'), '커넥터 미리보기 data 속성');
$check(str_contains($connectorJs, "closest('[data-feed-preview]')"), '커넥터 미리보기 이벤트 위임');
$check(str_contains($navPhp, "'바로가기' =>"), '자산·데이터 수집 최상위 바로가기');
$check(str_contains($navPhp, "'관리' =>"), '관리 메뉴 통합');
$check(!str_contains($navPhp, "'계정' =>") && !str_contains($navPhp, "'연동' =>"), '잘게 나뉜 관리 그룹 제거');
$check(str_contains($connectorPhp, "['label' => '실행 시각'"), '커넥터 실행 시각 열 통합');
$check(!str_contains($connectorPhp, "['label' => '마지막 실행'"), '커넥터 중복 시각 열 제거');

$cvePhp = (string) file_get_contents($public . '/cve.php');
$vendorPhp = (string) file_get_contents($public . '/vendor.php');
$check(str_contains($cvePhp, 'LEFT JOIN tb_finding_evidence fe'), 'CVE 위치별 수정 버전 근거 결합');
$check(str_contains($cvePhp, "['label' => '현재 → 권장 조치'"), 'CVE 위치별 권장 조치 열 제공');
$check(str_contains($cvePhp, "vg_is_kernel_code_pkg"), 'CVE 조치에서 프로세스 재시작과 커널 재부팅 구분');
$check(str_contains($cvePhp, '완화·격리·제거 검토'), '수정본 미공개 CVE의 대체 안내');
$check(str_contains($vendorPhp, "preg_match('/^TEMP-/i") && str_contains($vendorPhp, '>CVE 미배정</span>'),
    'Debian TEMP 식별자를 CVE 미배정으로 표시');
$check(str_contains($vendorPhp, "' · 원본 ' . \$cveId"), 'Debian TEMP 원본 식별자를 툴팁에 보존');

$assetsPhp = (string) file_get_contents($public . '/assets.php');
$assetPackagesPhp = (string) file_get_contents($public . '/asset-packages.php');
$check(str_contains($assetsPhp, "'packages' => ['label' => '전체 설치 패키지', 'href' => '/asset-packages.php']")
    && str_contains($assetPackagesPhp, "'assets' => ['label' => '자산 목록', 'href' => '/assets.php']"),
    '자산 목록과 전체 설치 패키지를 상호 이동 탭으로 제공');
$check(!str_contains($assetsPhp, 'echo \'<a class="btn btn--sm btn--ghost" href="/asset-packages.php"'),
    '자산 제목의 중복 설치 패키지 버튼 제거');
$ingestPhp = (string) file_get_contents($public . '/ingest.php');
$caddyfile = (string) file_get_contents($root . '/deploy/caddy/Caddyfile');
$agentSh = (string) file_get_contents($root . '/agent/vuln-inventory-agent.sh');
$check(str_contains($assetsPhp, "['label' => 'IP'") && !str_contains($assetsPhp, "['label' => '스캔'"),
    '자산 목록 IP 표시 및 스캔 열 제거');
$check(str_contains($ingestPhp, "vg_request_header('X-Real-IP')") && str_contains($caddyfile, 'header_up X-Real-IP {remote_host}'),
    'Caddy 원본 IP 전달과 ingest 저장 연계');
$check(str_contains($agentSh, 'CPU_QUOTA="${CPU_QUOTA:-10%}"') && str_contains($agentSh, 'DO_LIMIT="${AGENT_LIMIT:-1}"'),
    '에이전트 CPU 10% cgroup 제한 기본 적용');

if ($fail > 0) { printf("ui_structure_test: %d건 실패\n", $fail); exit(1); }
printf("ui_structure_test: 전부 통과\n");
