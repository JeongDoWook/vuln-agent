<?php
declare(strict_types=1);

/**
 * agentspeedtier.php — 호스트별 에이전트 속도 티어(4단계: very_fast/fast/normal/slow) 매핑의
 *   유일한 정의처. agent-poll.php(에이전트에 CPU%·타임아웃 전달), agentcommand.php(입력 검증),
 *   host.php(화면 라벨) 가 모두 이 파일 하나만 본다 — 값이 바뀌면 셋이 같이 바뀐다.
 *   server/public/ 은 HTTP 엔드포인트 전용이라 다른 엔드포인트가 재사용할 수 없다(CLAUDE.md
 *   파일 배치 규칙) — 그래서 server/src/ 로 뺀다.
 */

const VG_AGENT_SPEED_TIERS = ['very_fast', 'fast', 'normal', 'slow'];

const VG_AGENT_SPEED_TIER_MAP = [
    'very_fast' => ['cpu_quota_percent' => 80, 'packaging_timeout_seconds' => 300],
    'fast'      => ['cpu_quota_percent' => 40, 'packaging_timeout_seconds' => 200],
    'normal'    => ['cpu_quota_percent' => 10, 'packaging_timeout_seconds' => 120],
    'slow'      => ['cpu_quota_percent' => 5,  'packaging_timeout_seconds' => 90],
];

const VG_AGENT_SPEED_TIER_NAME_KO = [
    'very_fast' => '매우 빠름',
    'fast'      => '빠름',
    'normal'    => '보통',
    'slow'      => '느림',
];

/** 화면(host.php)의 <select> 옵션 라벨. CPU% 는 VG_AGENT_SPEED_TIER_MAP 에서 가져오므로
 *  매핑 값을 바꿔도 라벨이 손으로 복제한 숫자와 어긋나지 않는다. */
function vg_agent_speed_tier_label(string $tier): string {
    $name = VG_AGENT_SPEED_TIER_NAME_KO[$tier] ?? $tier;
    $cpu = VG_AGENT_SPEED_TIER_MAP[$tier]['cpu_quota_percent'] ?? null;
    $suffix = $tier === 'normal' ? ', 기본값' : '';
    return $cpu !== null ? "{$name} (CPU {$cpu}%{$suffix})" : $name;
}
