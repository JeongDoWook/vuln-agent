<?php
declare(strict_types=1);

/**
 * 계정 인벤토리 단위 테스트 — server/src/account_inventory.php 의 순수 함수(파싱·파생 판정).
 *   DB 는 건드리지 않는다(저장은 tests/smoke.sh 의 e2e 가 본다).
 *
 * 이 테스트가 지키는 계약은 하나다: **판정 불가(NA)를 정상(PASS)으로 위장하지 않는다.**
 *   비-root 로 돌면 /etc/shadow·sudoers 를 못 읽는다 → 그 판정은 NA 여야 하고, 절대 PASS 가
 *   되면 안 된다. PASS 로 새면 감사에서 "점검했고 문제없음"으로 읽히는데 실제로는 안 봤다.
 *
 * 실행:
 *   docker run --rm -v "$PWD:/w" -w /w php:8.3-cli php tests/account_inventory_test.php
 */

require_once __DIR__ . '/../server/src/account_inventory.php';

date_default_timezone_set('UTC');

$fail = 0;
$eq = static function (string $label, $got, $want) use (&$fail): void {
    if ($got !== $want) {
        printf("  ✗ [%s] 기대 %s, 실제 %s\n", $label, var_export($want, true), var_export($got, true));
        $fail++;
    }
};
/** 판정 목록에서 코드로 하나 꺼낸다. */
$judge = static function (array $judgments, string $code): array {
    foreach ($judgments as $j) { if ($j['code'] === $code) { return $j; } }
    return ['code' => $code, 'result' => '<없음>', 'names' => []];
};

$today   = time();
$oldDays = (int) floor(($today - 200 * 86400) / 86400);   // shadow 의 epoch 일수
$recent  = date('D M j H:i:s O Y', $today - 3 * 86400);   // lastlog 형식(LC_ALL=C)
$stale   = date('D M j H:i:s O Y', $today - 200 * 86400);

// ── 1) root 로 전부 수집된 정상 페이로드 ────────────────────────────────────
$full = ['users' => [
    'account_passwd' =>
        "root\t0\t0\t/bin/bash\t/root\n"
      . "daemon\t1\t1\t/usr/sbin/nologin\t/usr/sbin\n"
      . "alice\t1000\t1000\t/bin/bash\t/home/alice\n"
      . "bob\t1001\t1001\t/bin/bash\t/home/bob\n"
      . "admin\t1002\t1002\t/bin/bash\t/home/admin\n"
      . "clone\t1000\t1000\t/bin/bash\t/home/clone",
    'account_shadow' =>
        "root\t{$oldDays}\t0\t99999\t7\t\t\t0\n"
      . "daemon\t{$oldDays}\t0\t99999\t7\t\t\t1\n"
      . "alice\t{$oldDays}\t0\t90\t7\t\t\t0\n"
      . "bob\t{$oldDays}\t0\t99999\t7\t\t\t0\n"
      . "admin\t{$oldDays}\t0\t99999\t7\t\t\t0\n"
      . "clone\t{$oldDays}\t0\t99999\t7\t\t\t1",
    'account_lastlog' =>
        "root\t{$recent}\ndaemon\tNEVER\nalice\t{$recent}\nbob\t{$stale}\nadmin\tNEVER\nclone\tNEVER",
    'account_sudoers' => "root ALL=(ALL:ALL) ALL\n%sudo ALL=(ALL:ALL) ALL\nDefaults env_reset\nalice ALL=(ALL) NOPASSWD: ALL",
    'sudo_group'      => "sudo:x:27:bob",
]];

$p = vg_account_parse($full);
$rows = $p['rows'];
$eq('계정 6건 파싱', count($rows), 6);
$eq('root uid', $rows['root']['uid'], 0);
$eq('root 는 시스템 계정', $rows['root']['is_system'], 1);
$eq('alice 는 사용자 계정', $rows['alice']['is_system'], 0);
$eq('alice 셸', $rows['alice']['shell'], '/bin/bash');
$eq('alice 홈', $rows['alice']['home'], '/home/alice');
$eq('daemon 잠김', $rows['daemon']['is_locked'], 1);
$eq('alice 미잠김', $rows['alice']['is_locked'], 0);
$eq('alice pw_max_days', $rows['alice']['pw_max_days'], 90);
$eq('alice 만료일 없음', $rows['alice']['expire_date'], null);
$eq('sudoers 규칙의 alice', $rows['alice']['is_sudoer'], 1);
$eq('sudo 그룹의 bob', $rows['bob']['is_sudoer'], 1);
$eq('sudo 없는 admin', $rows['admin']['is_sudoer'], 0);
$eq('daemon 로그인 이력 없음', $rows['daemon']['never_logged_in'], 1);
$eq('bob 로그인 이력 있음', $rows['bob']['never_logged_in'], 0);
$eq('bob 마지막 로그인 파싱', substr((string) $rows['bob']['last_login_at'], 0, 4), date('Y', $today - 200 * 86400));

// 해시는 어떤 형태로도 남지 않는다.
$eq('행에 해시 필드 없음', array_key_exists('password', $rows['alice']) || array_key_exists('hash', $rows['alice']), false);

// ── 판정 ─────────────────────────────────────────────────────────────────
// DB 는 정수/문자열로 돌려주므로 그 모양으로 판정을 검증한다(화면이 실제로 받는 값).
$asDb = static function (array $rows): array {
    $out = [];
    foreach ($rows as $r) {
        foreach (['is_locked', 'is_sudoer', 'is_system', 'never_logged_in'] as $k) {
            $r[$k] = $r[$k] === null ? null : (string) $r[$k];
        }
        $r['uid'] = $r['uid'] === null ? null : (string) $r['uid'];
        $out[] = $r;
    }
    return $out;
};
$j = vg_account_judgments($asDb($rows));

$stale90 = $judge($j, 'ACC-STALE-LOGIN');
$eq('미로그인 판정 = FAIL', $stale90['result'], 'FAIL');
$eq('bob 이 미로그인 대상', (bool) preg_grep('/^bob\(/', $stale90['names']), true);
$eq('admin(이력 없음)도 대상', in_array('admin(로그인 이력 없음)', $stale90['names'], true), true);
$eq('잠긴 clone 은 제외', (bool) preg_grep('/^clone/', $stale90['names']), false);
$eq('nologin daemon 은 제외', (bool) preg_grep('/^daemon/', $stale90['names']), false);

$sudo = $judge($j, 'ACC-SUDOERS');
$eq('sudo 판정 = REVIEW(단정 아님)', $sudo['result'], 'REVIEW');
$eq('sudo 보유자 3명(root·alice·bob)', count($sudo['names']), 3);

$shared = $judge($j, 'ACC-SHARED');
$eq('공유계정 추정 = REVIEW', $shared['result'], 'REVIEW');
$eq('UID 중복을 근거로 잡음', (bool) preg_grep('/UID 1000 공유/', $shared['names']), true);
$eq('공용 이름 admin 을 잡음', (bool) preg_grep('/^admin\(/', $shared['names']), true);

$dormant = $judge($j, 'ACC-DORMANT');
$eq('퇴직자 잔존 추정 = REVIEW', $dormant['result'], 'REVIEW');
$eq('잠긴 clone 은 제외', in_array('clone', $dormant['names'], true), false);

// ── 2) 비-root 실행 — shadow·sudoers 미수집. NA 여야 하고 PASS 면 안 된다 ──
$nonRoot = ['users' => [
    'account_passwd'  => $full['users']['account_passwd'],
    'account_lastlog' => $full['users']['account_lastlog'],
]];
$pn = vg_account_parse($nonRoot);
$eq('비-root: shadow 미수집', $pn['has_shadow'], false);
$eq('비-root: sudo 미수집', $pn['has_sudo'], false);
$eq('비-root: 잠금 여부 NULL', $pn['rows']['alice']['is_locked'], null);
$eq('비-root: sudo 여부 NULL', $pn['rows']['alice']['is_sudoer'], null);

$jn = vg_account_judgments($asDb($pn['rows']));
$eq('비-root: sudo 판정 NA', $judge($jn, 'ACC-SUDOERS')['result'], 'NA');
$eq('비-root: 퇴직자 판정 NA', $judge($jn, 'ACC-DORMANT')['result'], 'NA');
// lastlog 는 비-root 로도 읽히므로 미로그인 판정은 살아 있어야 한다(불필요한 NA 도 결함이다).
$eq('비-root: 미로그인 판정은 유효', $judge($jn, 'ACC-STALE-LOGIN')['result'], 'FAIL');

// ── 2-b) 비-root 인데 getent 로 sudo 그룹만 읽힌 경우 ──────────────────────
//   /etc/sudoers 는 0440 이라 못 읽는다 → "그룹에 없다 = sudo 없다" 라고 단정하면
//   sudoers 파일로 직접 부여된 관리자(alice)를 "권한 없음"으로 잘못 보고한다.
$groupOnly = ['users' => [
    'account_passwd'  => $full['users']['account_passwd'],
    'account_lastlog' => $full['users']['account_lastlog'],
    'sudo_group'      => "sudo:x:27:bob",
]];
$pg = vg_account_parse($groupOnly);
$eq('그룹만: 멤버 bob 은 확정 1', $pg['rows']['bob']['is_sudoer'], 1);
$eq('그룹만: 나머지는 0 이 아니라 NULL', $pg['rows']['alice']['is_sudoer'], null);
$jg = vg_account_judgments($asDb($pg['rows']));
$eq('그룹만: 목록은 나오되 불완전 표기', $judge($jg, 'ACC-SUDOERS')['result'], 'REVIEW');
$eq('그룹만: 불완전 문구 포함', strpos($judge($jg, 'ACC-SUDOERS')['detail'], '불완전') !== false, true);

// 그룹 멤버가 아무도 없고 sudoers 도 못 읽으면 "권한자 없음"이라고 말할 수 없다 → NA.
$emptyGroup = ['users' => [
    'account_passwd'  => $full['users']['account_passwd'],
    'account_lastlog' => $full['users']['account_lastlog'],
    'sudo_group'      => "sudo:x:27:",
]];
$je = vg_account_judgments($asDb(vg_account_parse($emptyGroup)['rows']));
$eq('빈 sudo 그룹 + sudoers 미수집 = NA', $judge($je, 'ACC-SUDOERS')['result'], 'NA');

// ── 3) lastlog 미수집 — 미로그인·퇴직자 판정이 NA ──────────────────────────
$noLastlog = ['users' => [
    'account_passwd' => $full['users']['account_passwd'],
    'account_shadow' => $full['users']['account_shadow'],
    'sudo_group'     => $full['users']['sudo_group'],
]];
$jl = vg_account_judgments($asDb(vg_account_parse($noLastlog)['rows']));
$eq('lastlog 없음: 미로그인 NA', $judge($jl, 'ACC-STALE-LOGIN')['result'], 'NA');
$eq('lastlog 없음: 퇴직자 NA', $judge($jl, 'ACC-DORMANT')['result'], 'NA');

// ── 4) 계정 목록 자체가 없음 — 전부 NA(빈 화면을 "계정 없음"으로 읽으면 안 된다) ──
$jEmpty = vg_account_judgments([]);
$eq('계정 미수집: 판정 1건', count($jEmpty), 1);
$eq('계정 미수집: NA', $jEmpty[0]['result'], 'NA');

// ── 5) 오염 입력 — 신뢰하지 않는다 ────────────────────────────────────────
$dirty = ['users' => [
    'account_passwd' =>
        "ok\t1000\t1000\t/bin/bash\t/home/ok\n"
      . "bad;rm -rf /\t1001\t1001\t/bin/sh\t/home/x\n"      // 문자셋 위반 → 버림
      . "\t1002\t1002\t/bin/sh\t/home/y\n"                    // 이름 없음 → 버림
      . "toolong" . str_repeat('x', 100) . "\t1003\t1003\t/bin/sh\t/home/z",   // 64자 초과 → 버림
    'account_shadow'  => "NONE",
    'account_lastlog' => "ghost\t{$recent}\nok\tnot-a-date",   // 없는 계정 · 파싱 불가 날짜
]];
$pd = vg_account_parse($dirty);
$eq('오염: 유효 계정만 1건', count($pd['rows']), 1);
$eq('오염: 버린 줄 수', $pd['skipped'], 5);
$eq('오염: 날짜 파싱 실패는 NA 로', $pd['rows']['ok']['last_login_at'], null);
$eq('오염: shadow NONE 은 정상 수집으로 인정', $pd['has_shadow'], true);

// ── 6) shadow 날짜 환산 ───────────────────────────────────────────────────
$eq('epoch 일수 → 날짜', vg_account_days_to_date('20000'), '2024-10-04');
$eq('0 은 날짜가 아니다', vg_account_days_to_date('0'), null);
$eq('빈값', vg_account_days_to_date(''), null);
$eq('숫자 아님', vg_account_days_to_date('abc'), null);

// ── 7) 셸 판정 ────────────────────────────────────────────────────────────
$eq('nologin 은 비대화형', vg_account_is_noninteractive_shell('/usr/sbin/nologin'), true);
$eq('false 는 비대화형', vg_account_is_noninteractive_shell('/bin/false'), true);
$eq('빈 셸은 비대화형', vg_account_is_noninteractive_shell(''), true);
$eq('bash 는 대화형', vg_account_is_noninteractive_shell('/bin/bash'), false);

if ($fail === 0) {
    echo "계정 인벤토리 단위 테스트 통과\n";
    exit(0);
}
printf("실패 %d건\n", $fail);
exit(1);
