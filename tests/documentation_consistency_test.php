<?php
declare(strict_types=1);

/** 저장소 문서가 현재 DB/화면 계약에서 조용히 뒤처지는 것을 막는 정적 회귀 테스트. */
$root = dirname(__DIR__);
$dbDoc = file_get_contents($root . '/docs/dev/데이터베이스.md');
$erd = file_get_contents($root . '/docs/specs/diagrams/erd.puml');
$site = file_get_contents($root . '/docs/specs/diagrams/사이트맵.puml');
$deploy = file_get_contents($root . '/docs/specs/diagrams/배포구성.puml');
$process = file_get_contents($root . '/server/public/process.html');
$readme = file_get_contents($root . '/README.md');
$context = file_get_contents($root . '/CONTEXT.md');
$agentGuide = file_get_contents($root . '/agent/README.md');
$secretGuide = file_get_contents($root . '/secrets/README.md');
$screenGuide = file_get_contents($root . '/docs/dev/화면-안내.md');
$uiConfig = file_get_contents($root . '/docs/ui-configuration.md');
$routes = json_decode(file_get_contents($root . '/tests/fixtures/route-query-contract.json'), true);
if (!is_array($routes)) {
    fwrite(STDERR, "documentation consistency: route registry JSON을 읽을 수 없습니다\n");
    exit(1);
}

$fail = static function (string $message): never {
    fwrite(STDERR, "documentation consistency: {$message}\n");
    exit(1);
};
$contains = static function (string $haystack, string $needle): bool {
    return strpos($haystack, $needle) !== false;
};

preg_match_all('/^\| \[(tb_[a-z_]+)\]/m', $dbDoc, $docMatches);
$documented = array_values(array_unique($docMatches[1]));
preg_match_all('/^\s*entity (tb_[a-z_]+)/m', $erd, $erdMatches);
$entities = array_values(array_unique($erdMatches[1]));
$expectedEntities = array_values(array_diff($documented, ['tb_schema_migrations']));
sort($entities);
sort($expectedEntities);
if ($entities !== $expectedEntities) {
    $fail('ERD 엔티티 집합은 DB 문서에서 마이그레이션 이력만 뺀 집합이어야 합니다');
}

foreach (['tb_scan_run', 'tb_agent_command', 'tb_asset_grade_review',
          'tb_asset_grade_suggestion_history', 'tb_package_integrity', 'tb_finding_status'] as $table) {
    if (!in_array($table, $documented, true) || !in_array($table, $entities, true)) {
        $fail("최근 실행 제어 테이블 {$table}이 DB 문서 또는 ERD에서 빠졌습니다");
    }
}
foreach (['tb_api_token', 'tb_api_tokens', 'tb_activity_review'] as $retiredTable) {
    if (in_array($retiredTable, $documented, true) || in_array($retiredTable, $entities, true)) {
        $fail("폐기된 테이블 {$retiredTable}이 현재 스키마 산출물에 남았습니다");
    }
}
if (!preg_match('/entity tb_asset_grade_review[\s\S]+article9_reference\s*:\s*string/', $erd)) {
    $fail('ERD의 자산 등급 검토 엔티티에 조문·판단 참조 컬럼이 없습니다');
}

foreach (['/assets.php', '/asset-packages.php', '/agent-poll.php', '/agent-progress.php'] as $route) {
    if (!$contains($site, $route)) {
        $fail("사이트맵에 현재 경로 {$route}가 없습니다");
    }
}
foreach (['/export.php', '/sbom.php'] as $route) {
    if (($routes['routes'][$route]['auth'] ?? null) !== 'menu:assets') {
        $fail("route registry의 {$route} 인증이 현재 세션 assets 권한과 다릅니다");
    }
}

if (preg_match('/\bS3\s*-->/', $deploy)) {
    $fail('배포 구성에 정의되지 않은 S3 secret 연결이 남았습니다');
}
if ($contains($process, 'systemd-timer(우선)/cron') || $contains($process, '자동 등록 → 매시간')) {
    $fail('프로세스 문서에 폐기된 timer 기반 에이전트 설명이 남았습니다');
}

foreach (['무엇이 다른가', '동작 방식', '빠르게 실행해 보기', '문서'] as $heading) {
    if (!$contains($readme, "## {$heading}")) {
        $fail("루트 README의 첫 방문자 안내 섹션이 빠졌습니다: {$heading}");
    }
}
if (substr_count($readme, "\n") > 180) {
    $fail('루트 README에 운영 세부사항이 다시 누적됐습니다. 전문 문서로 분리하세요');
}
foreach (['agent/README.md', 'deploy/README.md', 'docs/dev/architecture.md', 'docs/dev/데이터베이스.md'] as $guide) {
    if (!$contains($readme, $guide)) {
        $fail("루트 README에서 상세 가이드 링크가 빠졌습니다: {$guide}");
    }
}

$retiredGuidance = [
    'README.md' => [$readme, ['월 1회 점검 결과', 'API 키·에이전트 키']],
    'CONTEXT.md' => [$context, ['읽기 전용 토큰은 DB', '같은 읽기 토큰', '접속기록 5요소 + 월 1회 점검']],
    'agent/README.md' => [$agentGuide, ['주기 변경은 재설치']],
    'secrets/README.md' => [$secretGuide, ['웹(`/api-tokens.php`)에서 발급']],
    'docs/dev/화면-안내.md' => [$screenGuide, ['월 1회 접속기록 점검 카드']],
    'docs/ui-configuration.md' => [$uiConfig, ['API 키·에이전트 키 공통', 'api_token_expired']],
];
foreach ($retiredGuidance as $path => [$text, $phrases]) {
    foreach ($phrases as $phrase) {
        if ($contains($text, $phrase)) {
            $fail("{$path}에 폐기된 현재형 안내가 남았습니다: {$phrase}");
        }
    }
}
foreach (['에이전트 키', 'caddy-root.crt', 'sudo bash install-agent.sh', '첫 스캔'] as $step) {
    if (!$contains($agentGuide, $step)) {
        $fail("에이전트 설치 4단계 안내가 빠졌습니다: {$step}");
    }
}

$readmeFlows = [
    'docs/readme-flow.svg' => 'viewBox="0 0 1400 900"',
    'docs/readme-flow-mobile.svg' => 'viewBox="0 0 720 1580"',
];
foreach ($readmeFlows as $relativePath => $expectedViewBox) {
    $flowPath = $root . '/' . $relativePath;
    if (!$contains($readme, $relativePath) || !is_file($flowPath)) {
        $fail("루트 README의 화면별 핵심 흐름 SVG가 빠졌습니다: {$relativePath}");
    }
    $flow = file_get_contents($flowPath);
    foreach (['<title', '<desc', $expectedViewBox] as $requiredSvgMarkup) {
        if (!$contains($flow, $requiredSvgMarkup)) {
            $fail("README 핵심 흐름 SVG의 접근성 또는 화면 크기 정보가 빠졌습니다: {$relativePath} {$requiredSvgMarkup}");
        }
    }
}

echo "documentation consistency: ok\n";
