<?php
declare(strict_types=1);

/**
 * compliance/asset.php — 통제 2: 정보자산 식별(ISMS-P 1.2.1 / ISO 27001 A.5.9).
 *   연결상태 분류식은 format.php 의 vg_asset_state_sql_expr() 하나만 쓴다(assets.php 와 같은 식).
 *
 *   ※ compliance.php 가 로드한다. 세션·인가·출력은 여기 두지 않는다(CLI 에서도 로드된다).
 */

require_once __DIR__ . '/../db.php';        // vg_latest_scan_subq
require_once __DIR__ . '/../format.php';    // vg_asset_state_sql_expr

/**
 * 통제 2: 정보자산 식별(ISMS-P 1.2.1 / ISO 27001 A.5.9).
 *   판정: 연결상태(assets.php 의 정상/지연/오프라인/수집없음 분류 재사용) 기준 오프라인·수집없음
 *   자산 + 필수 자산정보(OS·IP) 누락 자산. 같은 호스트가 두 사유에 다 걸려도 위반 1건으로 센다
 *   (사유별로 중복 집계하면 "위반 건수"가 자산 대수보다 부풀어 부분준수/미준수 컷라인의 의미가 흐려진다).
 *
 *   **판정 불가(부분 수집)**: 에이전트가 root 가 아닌 계정으로 돌면 외부노출(소켓→프로세스)·
 *   라이브러리 로드 같은 자산 식별 근거를 아예 못 걷는다(agent 스크립트가 그때 경고한다).
 *   그런데 이 통제는 os_id/os_version/last_seen_ip 필드가 채워졌는지만 봐서, 근거가 빠진
 *   호스트도 "준수"로 집계됐다. meta.running_as 로 이미 아는 사실이므로 준수에서 빼고
 *   판정 불가로 분류한다 — 위반(=문제가 확인됨)과도 구분해야 하므로 별도 집계다.
 * @return array{violations: array<int, array<string, mixed>>, total: int, totalHosts: int,
 *               unjudged: int, unjudged_rows: array<int, array<string, mixed>>}
 */
function vg_compliance_load_asset(PDO $pdo, int $limit): array {
    $latestSubq = vg_latest_scan_subq();
    $fromSql = 'FROM tb_host h
                LEFT JOIN ' . $latestSubq . ' t ON t.host_id = h.host_id
                LEFT JOIN tb_scan s ON s.scan_id = t.mid
                LEFT JOIN (
                    SELECT host_fqdn, MAX(last_seen_at) AS last_seen_at
                      FROM tb_agent_token
                     WHERE is_revoked = 0 AND is_deleted = 0
                     GROUP BY host_fqdn
                ) agent_seen ON agent_seen.host_fqdn = h.fqdn';
    // assets.php 와 같은 식(format.php 의 SSOT) — 다른 식을 쓰면 자산 화면과 다른 대수가 나온다.
    $stateExpr = vg_asset_state_sql_expr();

    // totalHosts 는 상태 판정과 무관한 단순 등록 대수 — 상태 조인 없이 센다.
    $totalHosts = (int) $pdo->query('SELECT COUNT(*) FROM tb_host WHERE is_deleted = 0')->fetchColumn();

    $violCond = "($stateExpr IN ('offline','none')
                 OR h.os_id IS NULL OR h.os_id = ''
                 OR h.os_version IS NULL OR h.os_version = ''
                 OR h.last_seen_ip IS NULL OR h.last_seen_ip = '')";
    $whereViol = "h.is_deleted = 0 AND $violCond";
    $total = (int) $pdo->query("SELECT COUNT(*) $fromSql WHERE $whereViol")->fetchColumn();

    $st = $pdo->prepare(
        "SELECT h.host_id, h.fqdn, h.os_id, h.os_version, h.last_seen_ip, $stateExpr AS state
           $fromSql
          WHERE $whereViol
          ORDER BY h.fqdn
          LIMIT ?"
    );
    $st->bindValue(1, $limit, PDO::PARAM_INT);
    $st->execute();
    $rows = $st->fetchAll();

    $violations = [];
    foreach ($rows as $r) {
        $reasons = [];
        if ($r['state'] === 'offline') { $reasons[] = '오프라인'; }
        if ($r['state'] === 'none') { $reasons[] = '수집없음'; }
        if (empty($r['os_id']) || empty($r['os_version'])) { $reasons[] = 'OS 정보 누락'; }
        if (empty($r['last_seen_ip'])) { $reasons[] = 'IP 정보 누락'; }
        $violations[] = [
            'host_id' => (int) $r['host_id'],
            'fqdn'    => (string) $r['fqdn'],
            'reasons' => $reasons,
        ];
    }

    // ── 부분 수집(비-root) 호스트 = 판정 불가 ──
    //   이미 위반으로 잡힌 호스트는 뺀다(NOT (위반조건)) — 확인된 문제가 판정 불가로 희석되면
    //   위반 건수가 줄어 컷라인 판정이 느슨해진다. 위반 쪽이 더 강한 진술이므로 그쪽이 이긴다.
    //   running_as 는 스캔 원본(meta)에만 있어 raw_json 에서 그 한 값만 뽑는다.
    $runAsExpr = "LOWER(TRIM(COALESCE(JSON_UNQUOTE(JSON_EXTRACT(s.raw_json, '\$.meta.running_as')), '')))";
    $whereUnjudged = "h.is_deleted = 0 AND NOT $violCond AND $runAsExpr <> 'root'";
    $unjudged = (int) $pdo->query("SELECT COUNT(*) $fromSql WHERE $whereUnjudged")->fetchColumn();

    $unjudgedRows = [];
    if ($unjudged > 0) {
        $st = $pdo->prepare(
            "SELECT h.host_id, h.fqdn, $runAsExpr AS running_as
               $fromSql
              WHERE $whereUnjudged
              ORDER BY h.fqdn
              LIMIT ?"
        );
        $st->bindValue(1, $limit, PDO::PARAM_INT);
        $st->execute();
        foreach ($st->fetchAll() as $r) {
            $runAs = (string) ($r['running_as'] ?? '');
            $unjudgedRows[] = [
                'host_id' => (int) $r['host_id'],
                'fqdn'    => (string) $r['fqdn'],
                'reason'  => $runAs === ''
                    ? '수집 계정 미상 — 외부노출·라이브러리 로드 근거 누락'
                    : '비-root 수집(' . $runAs . ') — 외부노출·라이브러리 로드 근거 누락',
            ];
        }
    }

    return [
        'violations'    => $violations,
        'total'         => $total,
        'totalHosts'    => $totalHosts,
        'unjudged'      => $unjudged,
        'unjudged_rows' => $unjudgedRows,
    ];
}
