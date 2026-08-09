<?php
declare(strict_types=1);

/**
 * account_inventory.php — 계정 인벤토리. 에이전트가 보낸 users 섹션(account_passwd·
 *   account_shadow·account_lastlog·account_sudoers·sudo_group)을 계정 1행으로 조립해
 *   tb_host_account 에 저장하고, 컴플라이언스 파생 판정을 계산한다.
 *
 *   왜 필요한가: 지금까지 이 제품은 계정 "설정 정책"(login.defs·PAM·sshd)만 봤고 "실제 계정
 *   목록"은 안 봤다 → ISMS-P 2.5.1·2.5.2·2.5.5·2.5.6 과 N2SF AC 계정관리가 통째로 공백이었다.
 *
 *   설계 원칙(CCE 와 동일):
 *     · **판정 불가(NA)를 정상(PASS)으로 위장하지 않는다.** /etc/shadow 를 못 읽었거나 lastlog 가
 *       없으면 그 판정은 NA 다. 이 제품의 핵심 설계 철학이다(cce.php 참고).
 *     · 추정은 추정이라고 말한다 — 공유계정·퇴직자 계정은 REVIEW(사람이 확인)지 FAIL 이 아니다.
 *     · **패스워드 해시는 받지도, 저장하지도, 표시하지도 않는다.**
 *
 *   입력은 에이전트 자기신고값이라 신뢰하지 않는다 — 길이 제한·타입 캐스팅을 여기서 건다.
 */

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/setting.php';   // vg_setting_int (미사용 판정일은 조직 규정이라 설정)

// ── 임계값 ────────────────────────────────────────────────────────────────
//   임계값을 화면·판정 로직에 흩뿌리지 않으려고 여기 한 곳에만 둔다.
//   미사용 판정일만 설정(tb_setting)으로 뺀다 — 조직 규정마다 30/60/90일로 갈린다.
//   UID 경계 둘은 리눅스 관례(login.defs SYS_UID_MAX·nobody)라 조직이 바꿀 값이 아니다(YAGNI).
const VG_ACCOUNT_STALE_LOGIN_DAYS = 90;   // 이 일수 이상 미로그인 = 미사용 계정(설정 없을 때의 폴백)
const VG_ACCOUNT_SYSTEM_UID_MAX   = 999;  // 이 값 이하 UID = 시스템 계정(데몬용)
const VG_ACCOUNT_NOBODY_UID_MIN   = 65534; // nobody/nogroup 대역도 시스템 계정으로 본다

/** 미사용 계정 판정 기준일. 설정이 없으면 VG_ACCOUNT_STALE_LOGIN_DAYS. */
function vg_account_stale_login_days(): int {
    return vg_setting_int('account.stale_login_days', VG_ACCOUNT_STALE_LOGIN_DAYS);
}

// 공유·그룹 계정으로 **추정**되는 이름들. 단정 금지 — 근거는 "이름이 개인을 특정하지 않는다"뿐이다.
const VG_ACCOUNT_SHARED_NAMES = [
    'admin', 'administrator', 'manager', 'sysadmin', 'operator', 'oper',
    'test', 'tests', 'testuser', 'guest', 'temp', 'tmp', 'demo',
    'user', 'users', 'share', 'shared', 'common', 'public',
    'dev', 'develop', 'staff', 'team', 'svc', 'service', 'deploy', 'ftpuser',
];

/** 로그인 불가 셸인가(nologin·false·sync 등) — 대화형 계정 판정용. */
function vg_account_is_noninteractive_shell(?string $shell): bool
{
    $s = strtolower(trim((string) $shell));
    if ($s === '') { return true; }
    return (bool) preg_match('#(nologin|/false|/sync|/shutdown|/halt)$#', $s);
}

/** epoch 일수(shadow 3·8번 필드) → 'Y-m-d'. 비었거나 0 이하면 null. */
function vg_account_days_to_date($days): ?string
{
    if ($days === null || $days === '' || !ctype_digit((string) $days)) { return null; }
    $d = (int) $days;
    // 0 은 "다음 로그인 시 반드시 변경"(shadow 관례)이라 날짜가 아니다 → 값 없음으로 둔다.
    if ($d <= 0) { return null; }
    return gmdate('Y-m-d', $d * 86400);
}

/** shadow 의 정수 정책 필드. 비었으면 null(미설정). */
function vg_account_int_or_null($v): ?int
{
    $v = trim((string) $v);
    if ($v === '' || !preg_match('/^-?\d+$/', $v)) { return null; }
    return (int) $v;
}

/**
 * sudo 권한 보유자 집합을 만든다.
 *   반환: ['set' => [사용자명 => true], 'complete' => bool]
 *         set 이 null 이면 sudoers·sudo 그룹을 둘 다 못 읽음 = 판정 불가.
 *   근거는 둘이다 — (1) sudo/wheel/admin 그룹 멤버, (2) /etc/sudoers 의 사용자 규칙.
 *
 *   complete=false 는 **그룹만 봤다**는 뜻이다(비-root 실행: getent 는 되지만 /etc/sudoers 는
 *   0440 이라 못 읽는다). 이때 "그룹에 없다 = sudo 없다" 라고 단정하면 sudoers 파일로 직접
 *   부여된 관리자를 "권한 없음"으로 잘못 보고한다 → 그 계정들은 0 이 아니라 NULL(판정 불가)로 둔다.
 */
function vg_account_sudoers(array $usr): array
{
    $groupText   = (string) ($usr['sudo_group'] ?? '');
    $sudoersText = (string) ($usr['account_sudoers'] ?? '');
    if ($groupText === '' && $sudoersText === '') { return ['set' => null, 'complete' => false]; }

    $set = [];
    // getent group 출력: "sudo:x:27:alice,bob"
    foreach (preg_split('/\r?\n/', $groupText) as $line) {
        $f = explode(':', trim($line));
        if (count($f) < 4) { continue; }
        foreach (explode(',', $f[3]) as $member) {
            $member = trim($member);
            if ($member !== '') { $set[$member] = true; }
        }
    }
    // sudoers 유효 라인(주석은 에이전트가 이미 제거). 사용자 규칙만 본다.
    //   %group 규칙은 여기서 풀지 않는다 — 그룹→멤버 해석은 위 getent 가 담당한다.
    foreach (preg_split('/\r?\n/', $sudoersText) as $line) {
        $line = trim($line);
        if ($line === '' || strtoupper($line) === 'NONE') { continue; }
        if ($line[0] === '%' || $line[0] === '#' || $line[0] === '@') { continue; }
        $first = preg_split('/\s+/', $line, 2)[0] ?? '';
        // Defaults·*_Alias 는 권한 부여 규칙이 아니다.
        if ($first === '' || $first === 'Defaults' || substr($first, 0, 9) === 'Defaults@'
            || preg_match('/_Alias$/', $first)) { continue; }
        foreach (explode(',', $first) as $u) {
            $u = trim($u);
            if ($u !== '' && preg_match('/^[A-Za-z0-9._-]+$/', $u)) { $set[$u] = true; }
        }
    }
    return ['set' => $set, 'complete' => $sudoersText !== ''];
}

/**
 * 에이전트 페이로드 → 계정 행 목록.
 *   반환: ['rows' => [username => 행배열], 'skipped' => 형식 오류로 버린 줄 수,
 *          'has_shadow' => bool, 'has_lastlog' => bool, 'has_sudo' => bool]
 *   passwd 를 못 받았으면 rows 가 빈 배열이다(= 계정 인벤토리 자체가 NA).
 */
function vg_account_parse(array $data): array
{
    $usr = $data['users'] ?? [];
    $skipped = 0;

    // ── /etc/passwd : username \t uid \t gid \t shell \t home ──
    $rows = [];
    foreach (preg_split('/\r?\n/', (string) ($usr['account_passwd'] ?? '')) as $line) {
        if (trim($line) === '') { continue; }
        $f = explode("\t", $line);
        $name = trim($f[0] ?? '');
        // 사용자명 문자셋을 여기서 고정한다 — 저장·표시 전 단계에서 거른다.
        if ($name === '' || !preg_match('/^[A-Za-z0-9._$-]{1,64}$/', $name)) { $skipped++; continue; }
        $uid = vg_account_int_or_null($f[1] ?? '');
        $rows[$name] = [
            'username'  => $name,
            'uid'       => $uid,
            'gid'       => vg_account_int_or_null($f[2] ?? ''),
            'shell'     => mb_strimwidth(trim($f[3] ?? ''), 0, 128, ''),
            'home'      => mb_strimwidth(trim($f[4] ?? ''), 0, 255, ''),
            'is_locked' => null,
            'is_sudoer' => null,
            'is_system' => $uid !== null
                && ($uid <= VG_ACCOUNT_SYSTEM_UID_MAX || $uid >= VG_ACCOUNT_NOBODY_UID_MIN) ? 1 : 0,
            'pw_last_change'   => null,
            'pw_min_days'      => null,
            'pw_max_days'      => null,
            'pw_warn_days'     => null,
            'pw_inactive_days' => null,
            'expire_date'      => null,
            'last_login_at'    => null,
            'never_logged_in'  => null,
        ];
    }

    // ── /etc/shadow 정책 필드 : name \t lastchg \t min \t max \t warn \t inactive \t expire \t lock ──
    //   키가 아예 없으면 못 읽은 것(비-root) → 전 계정 NA 로 남긴다.
    $shadowText = (string) ($usr['account_shadow'] ?? '');
    $hasShadow  = $shadowText !== '';
    if ($hasShadow) {
        foreach (preg_split('/\r?\n/', $shadowText) as $line) {
            $line = trim($line);
            if ($line === '' || strtoupper($line) === 'NONE') { continue; }
            $f = explode("\t", $line);
            $name = trim($f[0] ?? '');
            if ($name === '' || !isset($rows[$name])) { $skipped++; continue; }
            $rows[$name]['pw_last_change']   = vg_account_days_to_date($f[1] ?? '');
            $rows[$name]['pw_min_days']      = vg_account_int_or_null($f[2] ?? '');
            $rows[$name]['pw_max_days']      = vg_account_int_or_null($f[3] ?? '');
            $rows[$name]['pw_warn_days']     = vg_account_int_or_null($f[4] ?? '');
            $rows[$name]['pw_inactive_days'] = vg_account_int_or_null($f[5] ?? '');
            $rows[$name]['expire_date']      = vg_account_days_to_date($f[6] ?? '');
            $rows[$name]['is_locked']        = trim($f[7] ?? '') === '1' ? 1 : 0;
        }
    }

    // ── lastlog : name \t (NEVER | 'Sat Aug  8 02:01:34 +0000 2026') ──
    $lastlogText = (string) ($usr['account_lastlog'] ?? '');
    $hasLastlog  = $lastlogText !== '';
    if ($hasLastlog) {
        foreach (preg_split('/\r?\n/', $lastlogText) as $line) {
            $f = explode("\t", trim($line));
            $name = trim($f[0] ?? '');
            if ($name === '' || !isset($rows[$name])) { $skipped++; continue; }
            $when = trim($f[1] ?? '');
            if ($when === '' || strtoupper($when) === 'NEVER') {
                $rows[$name]['never_logged_in'] = 1;
                continue;
            }
            $ts = strtotime($when);
            if ($ts === false) { $skipped++; continue; }   // 파싱 실패는 NA 로 남긴다(정상으로 위장 금지)
            $rows[$name]['never_logged_in'] = 0;
            $rows[$name]['last_login_at']   = date('Y-m-d H:i:s', $ts);
        }
    }

    // ── sudo 권한 ──
    $sudo = vg_account_sudoers($usr);
    if ($sudo['set'] !== null) {
        foreach ($rows as $name => $_) {
            $rows[$name]['is_sudoer'] = isset($sudo['set'][$name]) ? 1 : ($sudo['complete'] ? 0 : null);
        }
    }

    return [
        'rows'        => $rows,
        'skipped'     => $skipped,
        'has_shadow'  => $hasShadow,
        'has_lastlog' => $hasLastlog,
        'has_sudo'    => $sudo['set'] !== null,
    ];
}

/**
 * 한 스캔의 계정 인벤토리를 재작성한다(스캔별 DELETE 후 INSERT — matcher·cce 와 같은 방식).
 *   같은 스캔을 다시 수신해도(내용 미변경 재전송) 최신 계정 상태로 갱신된다.
 *   반환: 저장한 계정 수.
 */
function vg_account_store(PDO $pdo, int $hostId, int $scanId, array $rows, ?string $collectedAt): int
{
    return vg_with_tx($pdo, function () use ($pdo, $hostId, $scanId, $rows, $collectedAt) {
        $pdo->prepare('DELETE FROM tb_host_account WHERE scan_id = ?')->execute([$scanId]);
        if (!$rows) { return 0; }
        $ins = $pdo->prepare(
            'INSERT INTO tb_host_account
                (host_id, scan_id, username, uid, gid, shell, home,
                 is_locked, is_sudoer, is_system,
                 pw_last_change, pw_min_days, pw_max_days, pw_warn_days, pw_inactive_days,
                 expire_date, last_login_at, never_logged_in, collected_at)
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'
        );
        $n = 0;
        foreach ($rows as $r) {
            $ins->execute([
                $hostId, $scanId, $r['username'],
                $r['uid'], $r['gid'],
                $r['shell'] !== '' ? $r['shell'] : null,
                $r['home']  !== '' ? $r['home']  : null,
                $r['is_locked'], $r['is_sudoer'], $r['is_system'],
                $r['pw_last_change'], $r['pw_min_days'], $r['pw_max_days'],
                $r['pw_warn_days'], $r['pw_inactive_days'],
                $r['expire_date'], $r['last_login_at'], $r['never_logged_in'],
                $collectedAt,
            ]);
            $n++;
        }
        return $n;
    });
}

/** ingest 진입점 — 파싱 → 저장. 파싱 실패는 조용히 삼키지 않고 서버 로그에 남긴다. */
function vg_ingest_accounts(PDO $pdo, int $hostId, int $scanId, array $data, ?string $collectedAt): array
{
    $parsed = vg_account_parse($data);
    if ($parsed['skipped'] > 0) {
        error_log(sprintf('[ingest] 계정 인벤토리 파싱: 형식 오류 %d줄 버림 (scan_id=%d)', $parsed['skipped'], $scanId));
    }
    $stored = vg_account_store($pdo, $hostId, $scanId, $parsed['rows'], $collectedAt);
    return [
        'accounts'    => $stored,
        'skipped'     => $parsed['skipped'],
        'has_shadow'  => $parsed['has_shadow'],
        'has_lastlog' => $parsed['has_lastlog'],
        'has_sudo'    => $parsed['has_sudo'],
    ];
}

/**
 * 저장된 계정 행(tb_host_account SELECT 결과)으로 컴플라이언스 파생 판정을 만든다.
 *   각 원소: [code, title, result(PASS|FAIL|REVIEW|NA), detail, isms, n2sf, names[]]
 *     FAIL   = 데이터가 그렇다고 말하는 위반
 *     REVIEW = **추정**. 사람이 확인해야 한다(공유계정·권한 검토 대상은 단정할 수 없다)
 *     NA     = 판정 불가(원자료 미수집) — 정상(PASS)과 절대 섞지 않는다
 */
function vg_account_judgments(array $rows): array
{
    $out = [];
    if (!$rows) {
        return [[
            'code' => 'ACC-INVENTORY', 'title' => '계정 인벤토리 수집', 'result' => 'NA',
            'detail' => '계정 목록(/etc/passwd)을 수집하지 못했습니다. 에이전트 버전·실행 권한을 확인하세요.',
            'isms' => '2.5.1', 'n2sf' => 'AC-1', 'names' => [],
        ]];
    }

    $hasShadow  = false;   // 한 계정이라도 잠금 여부를 알면 shadow 를 읽은 것이다
    $hasLastlog = false;
    $hasSudo    = false;
    foreach ($rows as $r) {
        if ($r['is_locked'] !== null)       { $hasShadow = true; }
        if ($r['never_logged_in'] !== null) { $hasLastlog = true; }
        if ($r['is_sudoer'] !== null)       { $hasSudo = true; }
    }

    $now  = time();
    $days = vg_account_stale_login_days();

    // ── 1) 90일 이상 미로그인 계정 (ISMS-P 2.5.1·2.5.6 / N2SF AC-1(2)·AC-1(3)) ──
    if (!$hasLastlog) {
        $out[] = ['code' => 'ACC-STALE-LOGIN', 'title' => $days . '일 이상 미로그인 계정', 'result' => 'NA',
            'detail' => 'lastlog 를 수집하지 못해 마지막 로그인 시각을 알 수 없습니다.',
            'isms' => '2.5.1 · 2.5.6', 'n2sf' => 'AC-1(2) · AC-1(3)', 'names' => []];
    } else {
        $stale = [];
        foreach ($rows as $r) {
            if ((int) $r['is_system'] === 1) { continue; }          // 데몬 계정은 로그인하지 않는다
            if ((int) ($r['is_locked'] ?? 0) === 1) { continue; }   // 이미 잠긴 계정은 조치 완료로 본다
            if (vg_account_is_noninteractive_shell($r['shell'])) { continue; }
            if ((int) ($r['never_logged_in'] ?? 0) === 1) {
                $stale[] = $r['username'] . '(로그인 이력 없음)';
                continue;
            }
            if (!empty($r['last_login_at'])) {
                $age = (int) floor(($now - strtotime((string) $r['last_login_at'])) / 86400);
                if ($age >= $days) { $stale[] = $r['username'] . '(' . $age . '일)'; }
            }
        }
        $out[] = ['code' => 'ACC-STALE-LOGIN', 'title' => $days . '일 이상 미로그인 계정',
            'result' => $stale ? 'FAIL' : 'PASS',
            'detail' => $stale
                ? count($stale) . '개 계정이 ' . $days . '일 이상 사용되지 않았습니다 — 비활성화 또는 삭제를 검토하세요.'
                : '대화형 계정 모두 최근 ' . $days . '일 안에 로그인 이력이 있습니다.',
            'isms' => '2.5.1 · 2.5.6', 'n2sf' => 'AC-1(2) · AC-1(3)', 'names' => $stale];
    }

    // ── 2) sudo 권한 보유자 (ISMS-P 2.5.5 / N2SF LP-4 · AC-1(5)) ──
    if (!$hasSudo) {
        $out[] = ['code' => 'ACC-SUDOERS', 'title' => 'sudo 권한 보유자', 'result' => 'NA',
            'detail' => '/etc/sudoers 와 sudo 그룹을 수집하지 못했습니다(root 실행 필요).',
            'isms' => '2.5.5', 'n2sf' => 'LP-4 · AC-1(5)', 'names' => []];
    } else {
        // is_sudoer 가 NULL 인 계정 = /etc/sudoers 를 못 읽어 그룹 멤버십만 본 계정.
        //   그 상태에서 "sudo 없음"이라고 말하면 sudoers 파일로 직접 부여된 관리자를 놓친다.
        $sudoers = []; $unknown = 0;
        foreach ($rows as $r) {
            if ($r['is_sudoer'] === null) { $unknown++; }
            elseif ((int) $r['is_sudoer'] === 1) { $sudoers[] = $r['username']; }
        }
        $partial = $unknown > 0 ? ' /etc/sudoers 를 읽지 못해 sudo 그룹 멤버십만 반영된 불완전한 목록입니다.' : '';
        if (!$sudoers && $unknown > 0) {
            $out[] = ['code' => 'ACC-SUDOERS', 'title' => 'sudo 권한 보유자', 'result' => 'NA',
                'detail' => 'sudo 그룹에 멤버가 없고 /etc/sudoers 는 읽지 못했습니다 — "권한자 없음"이라고 말할 수 없습니다.',
                'isms' => '2.5.5', 'n2sf' => 'LP-4 · AC-1(5)', 'names' => []];
        } else {
            $out[] = ['code' => 'ACC-SUDOERS', 'title' => 'sudo 권한 보유자',
                'result' => $sudoers ? 'REVIEW' : 'PASS',
                'detail' => ($sudoers
                    ? count($sudoers) . '명이 관리자 권한을 가집니다 — 업무상 필요한 인원인지 주기적으로 검토하세요.'
                    : 'sudo 권한을 가진 계정이 없습니다.') . $partial,
                'isms' => '2.5.5', 'n2sf' => 'LP-4 · AC-1(5)', 'names' => $sudoers];
        }
    }

    // ── 3) 공유·그룹 계정 **추정** (ISMS-P 2.5.2 / N2SF AC-2) ──
    //   단정하지 않는다. 근거는 둘뿐이다 — 같은 UID 를 여러 계정이 쓰거나, 이름이 개인을 특정하지 않는다.
    $byUid = [];
    foreach ($rows as $r) {
        if ($r['uid'] !== null) { $byUid[(int) $r['uid']][] = $r['username']; }
    }
    $shared = [];
    foreach ($byUid as $uid => $names) {
        if (count($names) > 1) { $shared[] = 'UID ' . $uid . ' 공유: ' . implode(', ', $names); }
    }
    foreach ($rows as $r) {
        if ((int) $r['is_system'] === 1) { continue; }
        if (vg_account_is_noninteractive_shell($r['shell'])) { continue; }
        if (in_array(strtolower((string) $r['username']), VG_ACCOUNT_SHARED_NAMES, true)) {
            $shared[] = $r['username'] . '(공용으로 흔히 쓰이는 이름)';
        }
    }
    $out[] = ['code' => 'ACC-SHARED', 'title' => '공유·그룹 계정 추정',
        'result' => $shared ? 'REVIEW' : 'PASS',
        'detail' => $shared
            ? '아래 계정은 공용일 **가능성**이 있습니다(추정). 담당자가 실제 사용 형태를 확인해야 합니다.'
            : '같은 UID 를 공유하거나 공용 이름을 쓰는 대화형 계정이 없습니다.',
        'isms' => '2.5.2', 'n2sf' => 'AC-2', 'names' => $shared];

    // ── 4) 퇴직자 계정 잔존 추정 (ISMS-P 2.2.5 / N2SF AC-3(1)) ──
    //   "미사용 + 잠기지 않음 + 만료일 없음" 인 대화형 계정. 재직 여부는 이 제품이 알 수 없다 → 추정.
    if (!$hasLastlog || !$hasShadow) {
        $out[] = ['code' => 'ACC-DORMANT', 'title' => '퇴직자 계정 잔존 추정', 'result' => 'NA',
            'detail' => !$hasShadow
                ? '/etc/shadow 를 못 읽어 잠금·만료 상태를 알 수 없습니다(root 실행 필요).'
                : 'lastlog 를 수집하지 못해 미사용 여부를 알 수 없습니다.',
            'isms' => '2.2.5', 'n2sf' => 'AC-3(1)', 'names' => []];
    } else {
        $dormant = [];
        foreach ($rows as $r) {
            if ((int) $r['is_system'] === 1) { continue; }
            if ((int) ($r['is_locked'] ?? 0) === 1) { continue; }
            if (!empty($r['expire_date'])) { continue; }
            if (vg_account_is_noninteractive_shell($r['shell'])) { continue; }
            $unused = (int) ($r['never_logged_in'] ?? 0) === 1;
            if (!$unused && !empty($r['last_login_at'])) {
                $unused = ($now - strtotime((string) $r['last_login_at'])) >= $days * 86400;
            }
            if ($unused) { $dormant[] = $r['username']; }
        }
        $out[] = ['code' => 'ACC-DORMANT', 'title' => '퇴직자 계정 잔존 추정',
            'result' => $dormant ? 'REVIEW' : 'PASS',
            'detail' => $dormant
                ? '미사용인데 잠금·만료가 걸려 있지 않은 계정입니다(추정). 인사 정보와 대조해 정리하세요.'
                : '미사용 상태로 방치된 대화형 계정이 없습니다.',
            'isms' => '2.2.5', 'n2sf' => 'AC-3(1)', 'names' => $dormant];
    }

    return $out;
}
