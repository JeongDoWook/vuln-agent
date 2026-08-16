<?php
declare(strict_types=1);

/**
 * compliance/account.php — 통제 4: 계정 관리(ISMS-P 2.5.1 / ISO 27001 A.9.2).
 *   판정은 account_inventory.php 의 vg_account_judgments() 가 한다(host.php 계정 탭과 같은 함수).
 *   여기서는 최신 스캔의 계정 행을 한 번에 읽어 그 함수에 넘기고 **집계만** 한다 —
 *   판정을 여기 복사하면 화면과 증적이 갈라진다(DRY).
 *
 *   ※ compliance.php 가 로드한다. 세션·인가·출력은 여기 두지 않는다(CLI 에서도 로드된다).
 */

require_once __DIR__ . '/../db.php';                  // vg_latest_scan_subq
require_once __DIR__ . '/../account_inventory.php';   // vg_account_judgments — 계정 판정(재사용)

// 계정 통제가 한 번에 읽어 판정할 계정 행의 상한. host.php 의 VG_HOST_ACCOUNT_JUDGE_MAX(호스트
//   1대 5000행)와 같은 취지지만 이쪽은 전 호스트를 한 쿼리로 읽으므로 전체 상한이다.
//   상한에 닿으면 판정이 불완전하다는 사실을 서버 로그에 남긴다(조용히 자르지 않는다).
const VG_COMPLIANCE_ACCOUNT_ROW_MAX = 50000;

/**
 * 통제 4: 계정 관리(ISMS-P 2.5.1 / ISO 27001 A.9.2).
 *   판정 로직을 새로 만들지 않는다 — account_inventory.php 의 vg_account_judgments() 가
 *   이미 계정 파생판정(미로그인·sudo·공유계정·휴면)을 갖고 있고 host.php 계정 탭이 그걸 쓴다.
 *   여기서는 호스트별 최신 스캔의 계정 행을 **한 번에** 읽어 그 함수에 넘기고 집계만 한다(DRY).
 *
 *   판정 매핑: FAIL = 위반 / REVIEW·NA = 판정 불가 / PASS = 준수.
 *   REVIEW 를 준수로 흡수하지 않는 이유는 그 함수 주석 그대로다 — 공유계정·휴면계정은
 *   **추정**이라 사람이 확인해야 하고, NA 는 원자료를 못 걷은 것이라 준수의 근거가 없다.
 *
 *   **계정 행이 0인 호스트는 "수집 대기"로 판정 불가**다. 0행을 준수로 세면, 에이전트가 아직
 *   계정 섹션을 안 보내는 동안 전 호스트가 "계정 관리 준수"로 보인다(허위 안심).
 * @return array{violations: array<int, array<string, mixed>>, total: int, totalHosts: int,
 *               unjudged: int, unjudged_rows: array<int, array<string, mixed>>, pending_hosts: int}
 */
function vg_compliance_load_account(PDO $pdo, int $limit): array {
    $hosts = $pdo->query(
        'SELECT h.host_id, h.fqdn, t.mid AS scan_id
           FROM tb_host h
           JOIN ' . vg_latest_scan_subq() . ' t ON t.host_id = h.host_id
          WHERE h.is_deleted = 0
          ORDER BY h.fqdn'
    )->fetchAll();
    $totalHosts = count($hosts);
    if (!$hosts) {
        return ['violations' => [], 'total' => 0, 'totalHosts' => 0, 'unjudged' => 0,
                'unjudged_rows' => [], 'pending_hosts' => 0];
    }

    // 호스트별로 쿼리를 돌리면 N+1 이다 — 최신 스캔 전체를 한 번에 읽어 PHP 에서 가른다.
    //   상한을 두는 이유는 host.php 의 VG_HOST_ACCOUNT_JUDGE_MAX 와 같다(비정상 데이터가
    //   화면을 죽이지 못하게). 상한에 닿으면 조용히 자르지 않고 로그를 남긴다.
    $scanIds = array_map(static fn($h) => (int) $h['scan_id'], $hosts);
    $in = implode(',', array_fill(0, count($scanIds), '?'));
    $cap = VG_COMPLIANCE_ACCOUNT_ROW_MAX;
    $st = $pdo->prepare(
        "SELECT scan_id, username, uid, gid, shell, home, is_locked, is_sudoer, is_system,
                pw_last_change, pw_max_days, expire_date, last_login_at, never_logged_in
           FROM tb_host_account
          WHERE scan_id IN ($in) AND is_deleted = 0
          ORDER BY scan_id, username
          LIMIT $cap"
    );
    $st->execute($scanIds);
    $rows = $st->fetchAll();
    if (count($rows) >= $cap) {
        error_log('[compliance] 계정 인벤토리 ' . $cap . '행 상한에 닿아 잘렸습니다 — 판정이 불완전합니다.');
    }
    $byScan = [];
    foreach ($rows as $r) { $byScan[(int) $r['scan_id']][] = $r; }

    $violations = [];
    $unjudgedRows = [];
    $unjudged = 0;
    $pending = 0;
    foreach ($hosts as $h) {
        $hostId = (int) $h['host_id'];
        $fqdn   = (string) $h['fqdn'];
        $accounts = $byScan[(int) $h['scan_id']] ?? [];
        if (!$accounts) {
            // 계정 목록 자체가 없다 = 아직 못 걷었다. 준수도 위반도 아니다.
            $pending++;
            $unjudged++;
            $unjudgedRows[] = ['host_id' => $hostId, 'fqdn' => $fqdn, 'code' => 'ACC-INVENTORY',
                'title' => '계정 인벤토리 수집', 'result' => 'NA',
                'reason' => '수집 대기 — 계정 목록을 아직 받지 못했습니다(에이전트 버전·실행 권한 확인).'];
            continue;
        }
        foreach (vg_account_judgments($accounts) as $j) {
            if ($j['result'] === 'FAIL') {
                $violations[] = [
                    'host_id' => $hostId, 'fqdn' => $fqdn,
                    'code'    => (string) $j['code'], 'title' => (string) $j['title'],
                    'result'  => 'FAIL',
                    // names 는 계정명·"UID 1000 공유: a, b" 같은 근거 문자열이다.
                    //   패스워드 해시는 애초에 수집·저장하지 않는다(account_inventory.php).
                    'names'   => array_values((array) ($j['names'] ?? [])),
                    'detail'  => (string) ($j['detail'] ?? ''),
                ];
                continue;
            }
            if ($j['result'] === 'PASS') { continue; }
            $unjudged++;
            $unjudgedRows[] = [
                'host_id' => $hostId, 'fqdn' => $fqdn,
                'code'    => (string) $j['code'], 'title' => (string) $j['title'],
                'result'  => (string) $j['result'],
                'reason'  => (string) ($j['detail'] ?? ''),
            ];
        }
    }

    return [
        'violations'    => $violations,
        'total'         => count($violations),
        'totalHosts'    => $totalHosts,
        'unjudged'      => $unjudged,
        'unjudged_rows' => array_slice($unjudgedRows, 0, $limit),
        'pending_hosts' => $pending,
    ];
}
