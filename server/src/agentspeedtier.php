<?php
declare(strict_types=1);

/**
 * agentspeedtier.php — 호스트별 에이전트 속도 티어(4단계: very_fast/fast/normal/slow) 매핑의
 *   유일한 정의처. agent-poll.php(에이전트에 CPU%·타임아웃 전달), agentcommand.php(입력 검증),
 *   host.php(화면 라벨) 가 모두 이 파일 하나만 본다 — 값이 바뀌면 셋이 같이 바뀐다.
 *   server/public/ 은 HTTP 엔드포인트 전용이라 다른 엔드포인트가 재사용할 수 없다 —
 *   그래서 여러 엔드포인트가 공유하는 이 정의는 server/src/ 로 뺀다.
 */

const VG_AGENT_SPEED_TIERS = ['very_fast', 'fast', 'normal', 'slow'];

const VG_AGENT_SPEED_TIER_MAP = [
    'very_fast' => ['cpu_quota_percent' => 80, 'packaging_timeout_seconds' => 300, 'mem_max_mb' => 1024],
    'fast'      => ['cpu_quota_percent' => 40, 'packaging_timeout_seconds' => 200, 'mem_max_mb' => 512],
    'normal'    => ['cpu_quota_percent' => 10, 'packaging_timeout_seconds' => 120, 'mem_max_mb' => 300],
    'slow'      => ['cpu_quota_percent' => 5,  'packaging_timeout_seconds' => 90,  'mem_max_mb' => 200],
];

const VG_AGENT_SPEED_TIER_NAME_KO = [
    'very_fast' => '매우 빠름',
    'fast'      => '빠름',
    'normal'    => '보통',
    'slow'      => '느림',
];

/** 화면(host.php)의 <select> 옵션 라벨. 이름만 내보낸다 — 예전엔 괄호로 CPU%·MEM 까지
 *  붙여 `매우 빠름 (CPU 80%·MEM 1024MB)` 처럼 셀렉트 한 칸이 통째로 높았는데,
 *  고르는 사람이 보는 건 빠르냐 느리냐라 숫자는 읽힐 자리가 아니었다.
 *  자원 배분의 정본은 그대로 VG_AGENT_SPEED_TIER_MAP 이다(정책은 안 바뀐다). */
function vg_agent_speed_tier_label(string $tier): string {
    return VG_AGENT_SPEED_TIER_NAME_KO[$tier] ?? $tier;
}
