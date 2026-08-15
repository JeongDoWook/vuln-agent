<?php
declare(strict_types=1);

/**
 * schedule.php — 커넥터 스케줄(cron/interval/daily) 계산 순수 함수.
 *   feeds.php 에서 분리했다: 이 4개 함수는 DB·전역상태에 의존하지 않고 time()/입력값만
 *   본다(SRP — 피드 실행과 무관한 시간 계산 책임). vg_feed_due/vg_feed_run 처럼 DB 를
 *   쓰는 스케줄 "적용"은 feeds.php 에 남아 여기 함수를 호출만 한다.
 *   단위테스트: tests/schedule_test.php.
 */

// cron 필드 한 개 매칭 (*, 숫자, a-b 범위, */n 스텝, 콤마 목록 지원)
function vg_cron_field_match(string $field, int $val, int $min, int $max): bool {
    foreach (explode(',', $field) as $part) {
        $step = 1;
        if (strpos($part, '/') !== false) {
            [$part, $s] = explode('/', $part, 2);
            $step = max(1, (int) $s);
        }
        if ($part === '*' || $part === '') { $lo = $min; $hi = $max; }
        elseif (strpos($part, '-') !== false) { [$a, $b] = explode('-', $part, 2); $lo = (int) $a; $hi = (int) $b; }
        else { $lo = $hi = (int) $part; }
        for ($i = $lo; $i <= $hi; $i += $step) {
            if ($i === $val) { return true; }
        }
    }
    return false;
}

// 표준 5필드 cron(분 시 일 월 요일)이 주어진 시각과 일치하는가. 요일 0=일요일(7도 일요일).
function vg_cron_match(string $expr, int $ts): bool {
    $f = preg_split('/\s+/', trim($expr));
    if (count($f) !== 5) { return false; }
    $dow = (int) date('w', $ts);
    return vg_cron_field_match($f[0], (int) date('i', $ts), 0, 59)
        && vg_cron_field_match($f[1], (int) date('G', $ts), 0, 23)
        && vg_cron_field_match($f[2], (int) date('j', $ts), 1, 31)
        && vg_cron_field_match($f[3], (int) date('n', $ts), 1, 12)
        && (vg_cron_field_match($f[4], $dow, 0, 6) || ($dow === 0 && vg_cron_field_match($f[4], 7, 0, 7)));
}

// 지금 실행 대상인가 (스케줄러가 매 tick 마다 판정). last_run 기준 중복 방지.
function vg_schedule_due(array $schedule, ?string $lastRun, ?int $now = null): bool {
    $now = $now ?? time();
    $lastTs = $lastRun ? strtotime($lastRun) : null;
    switch ($schedule['mode'] ?? 'manual') {
        case 'interval':
            $min = max(1, (int) ($schedule['interval_minutes'] ?? 1440));
            return $lastTs === null || ($now - $lastTs) >= $min * 60;
        case 'daily':
            [$h, $m] = array_map('intval', array_pad(explode(':', (string) ($schedule['time'] ?? '03:00')), 2, 0));
            $sched = strtotime(date('Y-m-d', $now) . sprintf(' %02d:%02d:00', $h, $m));
            return $now >= $sched && ($lastTs === null || $lastTs < $sched);
        case 'cron':
            $expr = (string) ($schedule['expr'] ?? '');
            if ($expr === '' || !vg_cron_match($expr, $now)) { return false; }
            return $lastTs === null || $lastTs < $now - ($now % 60); // 같은 분 중복 방지
        default: // manual
            return false;
    }
}

// 다음 실행 예정 시각(표시용).
function vg_schedule_next(array $schedule, ?int $fromTs = null): ?string {
    $fromTs = $fromTs ?? time();
    switch ($schedule['mode'] ?? 'manual') {
        case 'interval':
            $min = max(1, (int) ($schedule['interval_minutes'] ?? 1440));
            return date('Y-m-d H:i:s', $fromTs + $min * 60);
        case 'daily':
            [$h, $m] = array_map('intval', array_pad(explode(':', (string) ($schedule['time'] ?? '03:00')), 2, 0));
            $next = strtotime(date('Y-m-d', $fromTs) . sprintf(' %02d:%02d:00', $h, $m));
            if ($next <= $fromTs) { $next += 86400; }
            return date('Y-m-d H:i:s', $next);
        case 'cron':
            $expr = (string) ($schedule['expr'] ?? '');
            if ($expr === '') { return null; }
            $t = $fromTs - ($fromTs % 60) + 60;
            for ($i = 0; $i < 527040; $i++) { // 최대 366일 앞으로 스캔
                if (vg_cron_match($expr, $t)) { return date('Y-m-d H:i:s', $t); }
                $t += 60;
            }
            return null;
        default: // manual
            return null;
    }
}

/**
 * scheduler sidecar tick state -> health 판정.
 *
 * 컨테이너의 running 상태와 실제 tick 성공은 다르다. 마지막 시작이 오래됐거나 최신 종료가
 * 실패면 unhealthy 로 판정한다. 파일 I/O는 scheduler.php가 맡고 이 함수는 단위 테스트 가능한
 * 순수 판정만 담당한다.
 *
 * @return array{status:string,healthy:bool,running:bool,stale:bool,message:string}
 */
function vg_scheduler_health_status(array $state, ?int $now = null, int $staleAfterSeconds = 600): array {
    $now = $now ?? time();
    $staleAfterSeconds = max(1, $staleAfterSeconds);
    $started = !empty($state['last_started_at']) ? strtotime((string) $state['last_started_at']) : false;
    $success = !empty($state['last_success_at']) ? strtotime((string) $state['last_success_at']) : false;
    $failure = !empty($state['last_failure_at']) ? strtotime((string) $state['last_failure_at']) : false;
    $running = !empty($state['running']);
    $stale = $started === false || ($now - $started) > $staleAfterSeconds;
    $message = (string) ($state['last_message'] ?? '');

    if ($started === false) {
        $status = 'unavailable';
        $message = $message !== '' ? $message : 'scheduler tick evidence is unavailable';
    } elseif ($stale) {
        $status = 'stale';
        $message = 'last scheduler tick is stale';
    } elseif ($failure !== false && ($success === false || $failure > $success)) {
        $status = 'failed';
        $message = (string) ($state['last_failure_message'] ?? $message ?: 'last scheduler tick failed');
    } elseif ($running) {
        $status = 'running';
        $message = $message !== '' ? $message : 'scheduler tick is running';
    } elseif ($success !== false) {
        $status = 'healthy';
        $message = $message !== '' ? $message : 'last scheduler tick succeeded';
    } else {
        $status = 'unavailable';
        $message = $message !== '' ? $message : 'scheduler has not completed a tick';
    }

    return [
        'status' => $status,
        'healthy' => $status === 'healthy' || $status === 'running',
        'running' => $running,
        'stale' => $stale,
        'message' => $message,
    ];
}
