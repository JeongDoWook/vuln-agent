<?php
declare(strict_types=1);

/**
 * agentupdate.php — "지금 배포된 에이전트 스크립트가 최신 버전인가"를 파일에서 직접 읽는다.
 *   DB 에 최신 버전을 따로 저장하지 않는다 — agent-dl.php 가 서빙하는 파일(agent-src/
 *   vuln-inventory-agent.sh, compose 가 ../agent 를 ro 로 마운트)이 곧 정본이라, agent_push.sh
 *   로 배포한 순간 이 값도 같이 바뀐다(두 곳을 맞출 필요가 없다).
 */

/**
 * 배포된 에이전트 스크립트의 버전·sha256 을 읽는다. 파일이 없거나 버전 문자열을 못 찾으면 null
 * (미설정 환경에서도 agent-poll.php 가 죽지 않고 "업데이트 없음"으로 넘어가게 하기 위해서다).
 */
function vg_agent_release_info(): ?array {
    static $cache = false; // false=미계산, null=조회 실패, array=결과
    if ($cache !== false) {
        return $cache;
    }
    // server/src 기준 두 단계 위 = /var/www (agent-dl.php 의 $base 계산과 동일 깊이).
    $path = dirname(__DIR__, 2) . '/agent-src/vuln-inventory-agent.sh';
    if (!is_file($path) || !is_readable($path)) {
        $cache = null;
        return null;
    }
    $content = file_get_contents($path);
    if ($content === false || !preg_match('/^SCRIPT_VERSION="([^"]+)"/m', $content, $m)) {
        $cache = null;
        return null;
    }
    $cache = [
        'version' => $m[1],
        'sha256'  => hash('sha256', $content),
    ];
    return $cache;
}
