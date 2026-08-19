<?php
declare(strict_types=1);
// =============================================================================
// agent-dl.php — 에이전트 설치 파일 배포
// =============================================================================
// 대상 서버에 레포 체크아웃 없이 설치 파일을 받게 한다. 자산 화면 '에이전트 설치 안내'
// 모달의 다운로드 링크가 여기를 가리킨다.
//
// 파일 출처는 둘로 나뉜다:
//   - 스크립트 2개 + 서명 공개키: /var/www/agent-src (compose 가 ../agent 를 ro 로 마운트, git 추적).
//     공개키(vuln-inventory-agent.pub)는 install-agent.sh 가 최초 설치 시 여기서 받아 고정(pin)한다
//     (server/src/agentupdate.php 의 "커밋 시점 서명" 참고).
//   - 루트 CA:      /var/www/agent-ca  (compose 가 ../agent-ca 를 ro 로 마운트, gitignore).
//     CA 는 배포마다 다른 값이라 레포에 넣지 않는다 — 각 배포 관리자가 자기 Caddy 루트를
//     추출해 agent-ca/caddy-root.crt 에 둔다(deploy/README.md 의 "에이전트 CA 준비").
//
// 무인증인 이유: 스크립트·공개키엔 비밀이 없고(토큰은 설치 시 사람이 대화형으로 넣는다, 서명
//   개인키는 이 서버에 절대 오지 않는다), CA 는 공개 인증서(개인키 아님)다. 화이트리스트를
//   고정하므로 경로 traversal 은 불가능하다.

$base = dirname(__DIR__, 2);   // /var/www
$files = [
    'install-agent.sh'         => [$base . '/agent-src/install-agent.sh',         'text/x-shellscript'],
    'vuln-inventory-agent.sh'  => [$base . '/agent-src/vuln-inventory-agent.sh',  'text/x-shellscript'],
    'vuln-inventory-agent.pub' => [$base . '/agent-src/vuln-inventory-agent.pub', 'application/x-pem-file'],
    'caddy-root.crt'           => [$base . '/agent-ca/caddy-root.crt',            'application/x-x509-ca-cert'],
];

$f = (string) ($_GET['f'] ?? '');
if (!isset($files[$f])) {
    http_response_code(404);
    header('Content-Type: text/plain; charset=utf-8');
    echo '받을 수 있는 파일: ' . implode(', ', array_keys($files)) . "\n";
    exit;
}

[$path, $ctype] = $files[$f];
if (!is_file($path) || !is_readable($path)) {
    http_response_code(503);
    header('Content-Type: text/plain; charset=utf-8');
    if ($f === 'caddy-root.crt') {
        echo "루트 CA 가 아직 준비되지 않았습니다 — 중앙 서버 관리자가 최초 1회 추출해야 합니다:\n";
        echo "  docker exec vulnagent-caddy cat /data/caddy/pki/authorities/local/root.crt > agent-ca/caddy-root.crt\n";
    } else {
        echo "파일을 찾지 못했습니다(agent 마운트 누락?): {$f}\n";
    }
    exit;
}

header('Content-Type: ' . $ctype . '; charset=utf-8');
header('Content-Disposition: attachment; filename="' . $f . '"');
header('Content-Length: ' . (string) filesize($path));
header('X-Content-Type-Options: nosniff');
readfile($path);
