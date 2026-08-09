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

$fail = static function (string $message): never {
    fwrite(STDERR, "documentation consistency: {$message}\n");
    exit(1);
};

preg_match_all('/^\| \[(tb_[a-z_]+)\]/m', $dbDoc, $docMatches);
$documented = array_values(array_unique($docMatches[1]));
if (count($documented) !== 49) {
    $fail('데이터베이스 요약은 운영 테이블 49개를 각각 한 번씩 열거해야 합니다: ' . count($documented));
}

preg_match_all('/^\s*entity (tb_[a-z_]+)/m', $erd, $erdMatches);
$entities = array_values(array_unique($erdMatches[1]));
if (count($entities) !== 48 || in_array('tb_schema_migrations', $entities, true)) {
    $fail('ERD는 마이그레이션 이력 테이블을 뺀 도메인 엔티티 48개여야 합니다');
}

foreach (['tb_scan_run', 'tb_agent_command'] as $table) {
    if (!in_array($table, $documented, true) || !in_array($table, $entities, true)) {
        $fail("최근 실행 제어 테이블 {$table}이 DB 문서 또는 ERD에서 빠졌습니다");
    }
}

foreach (['/assets.php', '/asset-packages.php', '/agent-poll.php', '/agent-progress.php'] as $route) {
    if (!str_contains($site, $route)) {
        $fail("사이트맵에 현재 경로 {$route}가 없습니다");
    }
}

if (preg_match('/\bS3\s*-->/', $deploy)) {
    $fail('배포 구성에 정의되지 않은 S3 secret 연결이 남았습니다');
}
if (str_contains($process, 'systemd-timer(우선)/cron') || str_contains($process, '자동 등록 → 매시간')) {
    $fail('프로세스 문서에 폐기된 timer 기반 에이전트 설명이 남았습니다');
}

foreach (['무엇이 다른가', '동작 방식', '빠르게 실행해 보기', '문서'] as $heading) {
    if (!str_contains($readme, "## {$heading}")) {
        $fail("루트 README의 첫 방문자 안내 섹션이 빠졌습니다: {$heading}");
    }
}
if (substr_count($readme, "\n") > 180) {
    $fail('루트 README에 운영 세부사항이 다시 누적됐습니다. 전문 문서로 분리하세요');
}
foreach (['agent/README.md', 'deploy/README.md', 'docs/dev/architecture.md', 'docs/dev/데이터베이스.md'] as $guide) {
    if (!str_contains($readme, $guide)) {
        $fail("루트 README에서 상세 가이드 링크가 빠졌습니다: {$guide}");
    }
}

$readmeFlows = [
    'docs/readme-flow.svg' => 'viewBox="0 0 1400 720"',
    'docs/readme-flow-mobile.svg' => 'viewBox="0 0 720 1180"',
];
foreach ($readmeFlows as $relativePath => $expectedViewBox) {
    $flowPath = $root . '/' . $relativePath;
    if (!str_contains($readme, $relativePath) || !is_file($flowPath)) {
        $fail("루트 README의 화면별 핵심 흐름 SVG가 빠졌습니다: {$relativePath}");
    }
    $flow = file_get_contents($flowPath);
    foreach (['<title', '<desc', $expectedViewBox] as $requiredSvgMarkup) {
        if (!str_contains($flow, $requiredSvgMarkup)) {
            $fail("README 핵심 흐름 SVG의 접근성 또는 화면 크기 정보가 빠졌습니다: {$relativePath} {$requiredSvgMarkup}");
        }
    }
}

echo "documentation consistency: ok\n";
