<?php
declare(strict_types=1);

/**
 * compliance/snapshot.php — "지금" 판정을 하루 1건씩 남긴다.
 *   심사 증적의 본질은 시점이 아니라 시계열이다("작년 심사 시점엔 어땠나"에 답하려면
 *   그때의 판정이 저장돼 있어야 한다). 판정은 통제별 파일(patch/asset/secconfig/account)이
 *   하고, 여기서는 그 결과를 저장·조회만 한다(SRP) — 여기에 판정을 한 줄이라도 두면
 *   화면과 증적의 답이 갈라진다.
 *
 *   ※ compliance.php 가 로드한다. 세션·인가·출력은 여기 두지 않는다(CLI 에서도 로드된다).
 */

require_once __DIR__ . '/../db.php';        // vg_with_tx
require_once __DIR__ . '/policy.php';       // vg_compliance_policy · vg_compliance_status · VG_COMPLIANCE_CONTROLS
require_once __DIR__ . '/patch.php';
require_once __DIR__ . '/asset.php';
require_once __DIR__ . '/secconfig.php';
require_once __DIR__ . '/account.php';

// 스냅샷 1건이 담는 근거(evidence) 최대 개수. 무제한 JSON 은 행을 비대하게 만든다 —
//   위반이 수천 건인 환경에서 매일 전량을 박으면 스냅샷 테이블이 본 데이터보다 커진다.
//   상한을 넘으면 truncated=true 로 남겨 "잘렸다" 는 사실 자체를 증적에 기록한다.
const VG_COMPLIANCE_EVIDENCE_MAX = 500;

/**
 * 근거 목록을 상한(VG_COMPLIANCE_EVIDENCE_MAX)으로 잘라 evidence JSON 구조로 만든다.
 *   잘렸다는 사실 자체가 증적이므로 truncated 플래그와 전체 건수를 함께 남긴다.
 * @param array<int, mixed> $items 근거 항목(이미 잘려 들어올 수 있다)
 */
function vg_compliance_evidence(array $items, int $total): array {
    $cap = VG_COMPLIANCE_EVIDENCE_MAX;
    return [
        'total'     => $total,
        'truncated' => $total > min(count($items), $cap),
        'items'     => array_slice(array_values($items), 0, $cap),
    ];
}

/**
 * 오늘(또는 지정일) 스냅샷이 이미 있는지. 스케줄러가 1분마다 도는데 매번 무거운 집계를
 *   다시 돌릴 이유가 없다 — 하루 1회만 실제로 판정하게 하는 게이트.
 */
function vg_compliance_snapshot_exists(PDO $pdo, ?string $date = null): bool {
    $st = $pdo->prepare('SELECT 1 FROM tb_compliance_snapshot WHERE snapshot_date = ? AND is_deleted = 0');
    $st->execute([$date ?? date('Y-m-d')]);
    return (bool) $st->fetchColumn();
}

/**
 * 자동판정 통제(VG_COMPLIANCE_CONTROLS)를 판정해 그날짜 스냅샷으로 적재한다(UPSERT — 같은 날 두 번 돌아도 행이 안 늘어난다).
 *   무거운 집계이므로 웹 요청이 아니라 스케줄러/CLI 에서만 부른다.
 *
 *   판정 기준은 **화면과 같은 vg_compliance_policy()** 를 쓴다. 스케줄러가 상수를 따로 쓰면
 *   설정을 바꾼 조직에서 화면과 증적의 판정 기준이 갈라진다 — 그 자체가 증적 오염이다.
 *   판정 불가 건수도 함께 저장한다. 위반 건수만 남기면 "판정 불가였다"는 사실이 증적에서
 *   사라져, 나중에 그 스냅샷을 "위반 0건 = 준수"로 되읽게 된다(허위 안심의 재발).
 * @param array|null $policy 판정 기준(생략 시 vg_compliance_policy())
 * @return array<string,array{total:int,unjudged:int}> control_key => 위반·판정 불가 건수
 */
function vg_compliance_take_snapshot(PDO $pdo, ?string $date = null, ?array $policy = null): array {
    $date   = $date ?? date('Y-m-d');
    $cap    = VG_COMPLIANCE_EVIDENCE_MAX;
    $policy = $policy ?? vg_compliance_policy();

    $patch = vg_compliance_load_patch($pdo, $policy);
    $asset = vg_compliance_load_asset($pdo, $cap);
    $sec   = vg_compliance_load_secconfig($pdo, $cap);
    $acct  = vg_compliance_load_account($pdo, $cap);

    // 근거는 "무엇이 위반이었나"를 나중에 되짚을 최소 식별자만 남긴다(원문 전체를 복사하지 않는다).
    //   판정 불가 사유도 같은 evidence JSON 안에 둔다 — 건수만 있고 사유가 없으면 나중에
    //   "왜 판정을 못 했나"를 다시 조사해야 한다.
    $controls = [
        'patch' => [
            'total'    => $patch['total'],
            'unjudged' => (int) $patch['unjudged'],
            'evidence' => vg_compliance_evidence(array_map(static fn($v) => [
                'host_id' => $v['host_id'], 'fqdn' => $v['fqdn'], 'cve_id' => $v['cve_id'],
                'package' => $v['package'], 'severity' => $v['severity'], 'days' => $v['days'],
            ], array_slice($patch['violations'], 0, $cap)), $patch['total'])
                + ['unjudged' => ['total' => (int) $patch['unjudged'], 'na' => $patch['na'],
                                  'unknown' => (int) $patch['na_unknown']]],
        ],
        'asset' => [
            'total'    => $asset['total'],
            'unjudged' => (int) $asset['unjudged'],
            'evidence' => vg_compliance_evidence(array_map(static fn($v) => [
                'host_id' => $v['host_id'], 'fqdn' => $v['fqdn'], 'reasons' => $v['reasons'],
            ], $asset['violations']), $asset['total'])
                + ['unjudged' => ['total' => (int) $asset['unjudged'], 'items' => $asset['unjudged_rows']]],
        ],
        'secops' => [
            'total'    => $sec['total'],
            'unjudged' => 0,   // 이 통제는 판정 불가 개념이 없다(FAIL 집계만)
            'evidence' => vg_compliance_evidence(array_map(static fn($v) => [
                'host_id' => $v['host_id'], 'fqdn' => $v['fqdn'],
                'code' => $v['code'], 'severity' => $v['severity'],
            ], $sec['violations']), $sec['total']),
        ],
        // 계정 근거에는 계정명이 들어간다. 패스워드 해시·비밀값은 애초에 수집·저장하지 않으므로
        //   증적에 실릴 수 없다(account_inventory.php 설계 원칙).
        'account' => [
            'total'    => $acct['total'],
            'unjudged' => (int) $acct['unjudged'],
            'evidence' => vg_compliance_evidence(array_map(static fn($v) => [
                'host_id' => $v['host_id'], 'fqdn' => $v['fqdn'],
                'code' => $v['code'], 'names' => $v['names'],
            ], array_slice($acct['violations'], 0, $cap)), $acct['total'])
                + ['unjudged' => ['total' => (int) $acct['unjudged'], 'items' => $acct['unjudged_rows'],
                                  'pending_hosts' => (int) $acct['pending_hosts']]],
        ],
    ];

    vg_with_tx($pdo, static function () use ($pdo, $date, $controls, $policy) {
        // 헤더 UPSERT. 소프트삭제됐던 날짜를 다시 찍으면 되살린다(같은 날짜는 항상 1건).
        $pdo->prepare(
            'INSERT INTO tb_compliance_snapshot (snapshot_date, taken_at)
                  VALUES (?, NOW())
             ON DUPLICATE KEY UPDATE taken_at = NOW(), is_deleted = 0, deleted_at = NULL'
        )->execute([$date]);

        // lastInsertId 는 UPDATE 경로에서 신뢰할 수 없다 — 날짜로 다시 읽는다.
        $st = $pdo->prepare('SELECT compliance_snapshot_id FROM tb_compliance_snapshot WHERE snapshot_date = ?');
        $st->execute([$date]);
        $snapId = (int) $st->fetchColumn();

        $ins = $pdo->prepare(
            'INSERT INTO tb_compliance_snapshot_control
                    (compliance_snapshot_id, control_key, framework_ids, status_label,
                     violation_count, unjudged_count, evidence)
             VALUES (?,?,?,?,?,?,?)
             ON DUPLICATE KEY UPDATE framework_ids = VALUES(framework_ids), status_label = VALUES(status_label),
                                     violation_count = VALUES(violation_count),
                                     unjudged_count = VALUES(unjudged_count), evidence = VALUES(evidence),
                                     is_deleted = 0, deleted_at = NULL'
        );
        foreach ($controls as $key => $c) {
            $ins->execute([
                $snapId,
                $key,
                VG_COMPLIANCE_CONTROLS[$key]['framework'],
                vg_compliance_status($c['total'], $c['unjudged'] > 0, $policy['partial_max'])['label'],
                $c['total'],
                $c['unjudged'],
                json_encode($c['evidence'], JSON_UNESCAPED_UNICODE),
            ]);
        }
    });

    return array_map(static fn($c) => ['total' => (int) $c['total'], 'unjudged' => (int) $c['unjudged']], $controls);
}

/**
 * 최근 스냅샷 추이. 날짜 내림차순으로 최대 $limit 일치.
 *   반환: [ ['date'=>'2026-08-08', 'taken_at'=>..., 'controls'=>['patch'=>['count'=>3,'unjudged'=>0,'label'=>'부분준수'], …]], … ]
 *   판정 불가 건수까지 돌려준다 — 화면이 "위반 0건"과 "판정 불가"를 색과 문구로 구분해야 한다.
 */
function vg_compliance_trend(PDO $pdo, int $limit): array {
    $st = $pdo->prepare(
        'SELECT s.snapshot_date, s.taken_at, c.control_key, c.violation_count, c.unjudged_count, c.status_label
           FROM (SELECT compliance_snapshot_id, snapshot_date, taken_at
                   FROM tb_compliance_snapshot
                  WHERE is_deleted = 0
                  ORDER BY snapshot_date DESC
                  LIMIT ?) s
           JOIN tb_compliance_snapshot_control c
             ON c.compliance_snapshot_id = s.compliance_snapshot_id AND c.is_deleted = 0
          ORDER BY s.snapshot_date DESC'
    );
    $st->bindValue(1, $limit, PDO::PARAM_INT);
    $st->execute();

    $rows = [];
    foreach ($st->fetchAll() as $r) {
        $d = (string) $r['snapshot_date'];
        if (!isset($rows[$d])) {
            $rows[$d] = ['date' => $d, 'taken_at' => (string) $r['taken_at'], 'controls' => []];
        }
        $rows[$d]['controls'][(string) $r['control_key']] = [
            'count'    => (int) $r['violation_count'],
            'unjudged' => (int) $r['unjudged_count'],
            'label'    => (string) $r['status_label'],
        ];
    }
    return array_values($rows);
}
