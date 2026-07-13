<?php
declare(strict_types=1);

/**
 * schedule 단위 테스트 — feeds.php 에서 뽑아낸 스케줄 순수 함수(server/src/schedule.php).
 * DB·커넥터 실행은 건드리지 않는다(그건 feeds.php 에 남아 tests/smoke.sh 의 e2e 로 검증됨).
 *
 * 실행:
 *   docker run --rm -v "$PWD:/w" -w /w php:8.3-cli php tests/schedule_test.php
 */

require_once __DIR__ . '/../server/src/schedule.php';

date_default_timezone_set('UTC');   // strtotime/date 가 TZ 에 의존하므로 환경과 무관하게 고정

$fail = 0;
$eq = static function (string $label, $got, $want) use (&$fail): void {
    if ($got !== $want) {
        printf("  ✗ [%s] 기대 %s, 실제 %s\n", $label, var_export($want, true), var_export($got, true));
        $fail++;
    }
};

// 시각 고정: 2026-07-13(월) 10:15:00 UTC
$now = strtotime('2026-07-13 10:15:00');

// ── vg_cron_field_match ────────────────────────────────────────────────────
$eq('필드 * 는 전부 매치', vg_cron_field_match('*', 30, 0, 59), true);
$eq('필드 숫자 매치', vg_cron_field_match('15', 15, 0, 59), true);
$eq('필드 숫자 불일치', vg_cron_field_match('15', 16, 0, 59), false);
$eq('필드 범위 a-b 안', vg_cron_field_match('10-20', 15, 0, 59), true);
$eq('필드 범위 a-b 밖', vg_cron_field_match('10-20', 21, 0, 59), false);
$eq('필드 스텝 */n 매치', vg_cron_field_match('*/15', 30, 0, 59), true);
$eq('필드 스텝 */n 불일치', vg_cron_field_match('*/15', 31, 0, 59), false);
$eq('필드 콤마 목록 매치', vg_cron_field_match('5,15,25', 15, 0, 59), true);
$eq('필드 콤마 목록 불일치', vg_cron_field_match('5,15,25', 16, 0, 59), false);

// ── vg_cron_match (5필드: 분 시 일 월 요일) ─────────────────────────────────
$eq('매 분(전부 *)', vg_cron_match('* * * * *', $now), true);
$eq('정확한 분/시 매치', vg_cron_match('15 10 * * *', $now), true);
$eq('분 불일치', vg_cron_match('16 10 * * *', $now), false);
$eq('시 불일치', vg_cron_match('15 11 * * *', $now), false);
$eq('일/월 매치', vg_cron_match('15 10 13 7 *', $now), true);
// 2026-07-13 은 월요일 → date('w')=1
$eq('요일 매치(월=1)', vg_cron_match('15 10 * * 1', $now), true);
$eq('요일 불일치', vg_cron_match('15 10 * * 2', $now), false);
$eq('필드 개수 다르면 false', vg_cron_match('* * * *', $now), false);

// 일요일 0/7 동치 확인: 2026-07-12(일) 10:15:00
$sun = strtotime('2026-07-12 10:15:00');
$eq('요일 0=일요일', vg_cron_match('15 10 * * 0', $sun), true);
$eq('요일 7도 일요일', vg_cron_match('15 10 * * 7', $sun), true);
$eq('요일 6(토)엔 불일치', vg_cron_match('15 10 * * 6', $sun), false);

// ── vg_schedule_due ─────────────────────────────────────────────────────────
// interval: lastRun 없으면 항상 due, 있으면 간격 경과 여부로 판정.
$eq('interval lastRun 없음 → due', vg_schedule_due(['mode' => 'interval', 'interval_minutes' => 60], null, $now), true);
$lastRun30 = date('Y-m-d H:i:s', $now - 30 * 60);
$eq('interval 30분 전, 60분 간격 → 미도래', vg_schedule_due(['mode' => 'interval', 'interval_minutes' => 60], $lastRun30, $now), false);
$lastRun90 = date('Y-m-d H:i:s', $now - 90 * 60);
$eq('interval 90분 전, 60분 간격 → due', vg_schedule_due(['mode' => 'interval', 'interval_minutes' => 60], $lastRun90, $now), true);

// daily: 지정 시각 이후이고 아직 그 시각 이후로 안 돌았으면 due.
$eq('daily 지정시각 이후·미실행 → due', vg_schedule_due(['mode' => 'daily', 'time' => '09:00'], null, $now), true);
$eq('daily 지정시각 이전 → 미도래', vg_schedule_due(['mode' => 'daily', 'time' => '11:00'], null, $now), false);
$ranAt0930 = date('Y-m-d H:i:s', strtotime('2026-07-13 09:30:00'));
$eq('daily 이미 지정시각 이후 실행됨 → 중복방지', vg_schedule_due(['mode' => 'daily', 'time' => '09:00'], $ranAt0930, $now), false);

// cron: 표현식이 현재 분과 일치해야 하고, 같은 분 중복 실행은 방지.
$eq('cron 현재 분과 일치·미실행 → due', vg_schedule_due(['mode' => 'cron', 'expr' => '15 10 * * *'], null, $now), true);
$eq('cron 현재 분과 불일치 → 미도래', vg_schedule_due(['mode' => 'cron', 'expr' => '16 10 * * *'], null, $now), false);
$ranSameMinute = date('Y-m-d H:i:s', $now); // 같은 분(정확히 이번 분 시작 시각)에 이미 실행
$eq('cron 같은 분 중복 실행 방지', vg_schedule_due(['mode' => 'cron', 'expr' => '15 10 * * *'], $ranSameMinute, $now), false);

// manual: 항상 미도래.
$eq('manual 항상 미도래', vg_schedule_due(['mode' => 'manual'], null, $now), false);
$eq('mode 없으면 manual 취급', vg_schedule_due([], null, $now), false);

// ── vg_schedule_next ─────────────────────────────────────────────────────────
$eq('interval 다음실행 = now+간격', vg_schedule_next(['mode' => 'interval', 'interval_minutes' => 60], $now), date('Y-m-d H:i:s', $now + 3600));
$eq('daily 다음실행(오늘 지정시각 미도래)', vg_schedule_next(['mode' => 'daily', 'time' => '11:00'], $now), '2026-07-13 11:00:00');
$eq('daily 다음실행(오늘 지정시각 이미 지남 → 내일)', vg_schedule_next(['mode' => 'daily', 'time' => '09:00'], $now), '2026-07-14 09:00:00');
$eq('cron 다음실행(당일 나중 시각)', vg_schedule_next(['mode' => 'cron', 'expr' => '0 11 * * *'], $now), '2026-07-13 11:00:00');
$eq('cron 빈 expr → null', vg_schedule_next(['mode' => 'cron', 'expr' => ''], $now), null);
$eq('manual → null', vg_schedule_next(['mode' => 'manual'], $now), null);

// ── 결과 ──────────────────────────────────────────────────────────────────
if ($fail > 0) {
    printf("schedule_test: %d건 실패\n", $fail);
    exit(1);
}
printf("schedule_test: 전부 통과\n");
