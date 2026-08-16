<?php
declare(strict_types=1);

/**
 * format/asset_state.php — 자산 연결 상태(정상/지연/오프라인/수집없음) 판정.
 *   PHP 판정(vg_asset_state_key)과 SQL 판정(vg_asset_state_sql_expr)이 **같은 임계값**을 써야
 *   화면마다 자산 대수가 어긋나지 않는다 — 그래서 상수와 두 판정식을 한 파일에 묶어 둔다.
 */

/* 연결 상태 판정 기준(분). 데몬은 10초마다 poll 하므로 수집 주기와 무관하다.
 * 일시적인 네트워크 흔들림은 허용하되 1분을 넘기면 지연, 5분을 넘기면 오프라인이다. */
const VG_POLL_STALE_MIN   = 1;
const VG_POLL_OFFLINE_MIN = 5;

/** 자산 연결 상태 키. poll 관측 전 구버전 자산만 수집 주기를 고려한 호환 판정을 쓴다. */
function vg_asset_state_key(bool $hasScan, $pollAgeMin, $scanAgeMin, int $scheduleSeconds = 3600): string {
    if (!$hasScan) { return 'none'; }
    if ($pollAgeMin !== null) {
        $m = (int) $pollAgeMin;
        if ($m > VG_POLL_OFFLINE_MIN) { return 'offline'; }
        if ($m > VG_POLL_STALE_MIN)   { return 'stale'; }
        return 'ok';
    }

    // 개별 토큰/poll 기능이 없던 구버전은 최신 수집만 관측할 수 있다. 12시간 주기를
    // 3시간 고정 임계값으로 오판하지 않도록 설정 주기의 1.5배까지 정상으로 본다.
    $scheduleMin = max(1, (int) ceil($scheduleSeconds / 60));
    $staleAfter = max(180, (int) ceil($scheduleMin * 1.5));
    $offlineAfter = max(10080, $scheduleMin * 3);
    $m = (int) $scanAgeMin;
    if ($m > $offlineAfter) { return 'offline'; }
    if ($m > $staleAfter)   { return 'stale'; }
    return 'ok';
}

/**
 * 호스트 연결 상태 판정 CASE 식(SQL). assets.php·compliance.php 가 공유(SSOT) — 다른 식을 쓰면
 *   두 화면의 자산 대수가 어긋난다. 별칭 h(tb_host)·s(tb_scan, LEFT JOIN)·agent_seen(host_fqdn,
 *   last_seen_at) 를 호출부 쿼리가 그대로 갖추고 있어야 한다.
 */
function vg_asset_state_sql_expr(): string {
    $legacyStaleMin = 'GREATEST(180, CEIL(h.poll_schedule_seconds / 60 * 1.5))';
    $legacyOfflineMin = 'GREATEST(10080, CEIL(h.poll_schedule_seconds / 60 * 3))';
    return "CASE WHEN s.scan_id IS NULL THEN 'none'
          WHEN agent_seen.last_seen_at IS NOT NULL
            AND TIMESTAMPDIFF(MINUTE, agent_seen.last_seen_at, NOW()) > " . VG_POLL_OFFLINE_MIN . " THEN 'offline'
          WHEN agent_seen.last_seen_at IS NOT NULL
            AND TIMESTAMPDIFF(MINUTE, agent_seen.last_seen_at, NOW()) > " . VG_POLL_STALE_MIN . " THEN 'stale'
          WHEN agent_seen.last_seen_at IS NOT NULL THEN 'ok'
          WHEN TIMESTAMPDIFF(MINUTE, s.collected_at, NOW()) > $legacyOfflineMin THEN 'offline'
          WHEN TIMESTAMPDIFF(MINUTE, s.collected_at, NOW()) > $legacyStaleMin THEN 'stale'
          ELSE 'ok' END";
}

/** 연결 상태 뱃지. 최신 수집 시각은 상태와 분리해 목록·상세에 따로 표시한다. */
function vg_asset_state(bool $hasScan, $pollAgeMin, $scanAgeMin, int $scheduleSeconds = 3600): string {
    $state = vg_asset_state_key($hasScan, $pollAgeMin, $scanAgeMin, $scheduleSeconds);
    return match ($state) {
        'none'    => vg_badge('수집없음', 'muted'),
        'offline' => vg_badge('오프라인', 'crit'),
        'stale'   => vg_badge('지연', 'high'),
        default   => vg_badge('정상', 'ok'),
    };
}
