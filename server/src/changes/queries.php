<?php
declare(strict_types=1);

/**
 * changes/queries.php — 변화 추적 화면의 조회층.
 *
 *   ⚠ 이 파일의 대조 방식은 **일부러** 이렇게 돼 있다. 스캔별 findings 를 통째로 읽어 PHP 에서
 *   맞대보는 벌크 로드를, "패키지 변경 탭처럼" SQL LIMIT/OFFSET + 자기조인으로 바꾸려는 시도가
 *   한 번 있었고 되돌려졌다(PR #292): dev DB(findings 51만행·비교대상 호스트 56개)에서 인덱스
 *   힌트를 줘도 **30초+** 였다(지금 방식은 1.2초). 구조가 어색해 보여도 이게 빠른 쪽이다.
 *
 *   같은 이유로 추이(vg_trend_load)는 **호스트를 골랐을 때만** 호출된다(PR #472) — 전체 호스트
 *   합산은 자기조인급 비용이 난다. 호출부의 그 분기를 "일관성 있게" 없애지 마라.
 */

const VG_SEV_RANK = ['LOW' => 1, 'MEDIUM' => 2, 'HIGH' => 3, 'CRITICAL' => 4];

/** 변화 1건을 표 행으로. */
function vg_change_row(string $type, int $hid, string $fqdn, string $when, array $f, ?string $from = null, int $curScanId = 0): array {
    return [
        'type'             => $type,
        'host_id'          => $hid,
        'fqdn'             => $fqdn,
        'when'             => $when,
        'cve_id'           => (string) $f['cve_id'],
        'package_name'     => (string) $f['package_name'],
        'severity'         => (string) $f['severity'],
        'from_sev'         => $from,
        'in_kev'           => (int) ($f['in_kev'] ?? 0),
        'exposed'          => (int) ($f['exposed'] ?? 0),
        'container_id'     => (int) ($f['container_id'] ?? 0),
        'installed_version'=> (string) ($f['installed_version'] ?? ''),
        'package_os_id'     => $f['package_os_id'] ?? null,
        'package_os_version'=> $f['package_os_version'] ?? null,
        'cur_scan_id'      => $curScanId,
        'reason'           => '',
    ];
}

/**
 * 패키지 변경 목록의 FROM+WHERE. COUNT 와 SELECT 가 **같은 절**을 쓰게 한 곳에서 만든다.
 *   $params 는 참조로 채운다 — WHERE 에 붙는 순서(host → q)가 곧 바인딩 순서다.
 */
function vg_change_pkg_from(int $hostId, string $q, array &$params): string {
    $from = 'FROM tb_pkg_change c
                JOIN tb_host h ON h.host_id = c.host_id AND h.is_deleted = 0
                JOIN tb_scan s ON s.scan_id = c.scan_id
               WHERE c.is_deleted = 0'
          . ($hostId ? ' AND c.host_id = ?' : '')
          . ($q !== '' ? ' AND c.package_name LIKE ?' : '');
    $params = [];
    if ($hostId)  { $params[] = $hostId; }
    if ($q !== '') { $params[] = '%' . $q . '%'; }
    return $from;
}

/** 패키지 변경 총 건수(탭 뱃지 + 페이저). */
function vg_change_pkg_count(PDO $pdo, int $hostId, string $q): int {
    $params = [];
    $from = vg_change_pkg_from($hostId, $q, $params);
    $st = $pdo->prepare("SELECT COUNT(*) $from");
    $st->execute($params);
    return (int) $st->fetchColumn();
}

/**
 * 패키지 변경 한 페이지.
 *   예전엔 LIMIT 200 으로 잘라놓고 "더 있다" 는 표시가 없어서 201번째부터의 변경은 화면에서
 *   볼 방법이 아예 없었다 — 그래서 제대로 페이지네이션한다(호스트 필터는 취약점 변화와 공유).
 */
function vg_change_pkg_load(PDO $pdo, int $hostId, string $q, int $perPage, int $offset): array {
    $params = [];
    $from = vg_change_pkg_from($hostId, $q, $params);
    $st = $pdo->prepare(
        "SELECT c.host_id, h.fqdn, c.manager, c.package_name, c.change_type,
                c.old_version, c.new_version, s.collected_at AS `when`,
                s.os_id AS package_os_id, s.os_version AS package_os_version
         $from
         ORDER BY c.pkg_change_id DESC
         LIMIT $perPage OFFSET $offset"
    );
    $st->execute($params);
    return $st->fetchAll(PDO::FETCH_ASSOC);
}

/**
 * 호스트별 스캔을 최신순으로 읽어 앞의 2개(최신·직전)만 남긴다.
 *   반환: ['perHost' => host_id => [{scan_id, fqdn, collected_at}, …], 'hostOptions' => host_id => fqdn]
 */
function vg_change_host_scans(PDO $pdo): array {
    $rows = $pdo->query(
        "SELECT s.host_id, h.fqdn, s.scan_id, s.collected_at
           FROM tb_scan s
           JOIN tb_host h ON h.host_id = s.host_id AND h.is_deleted = 0
          WHERE s.is_deleted = 0
          ORDER BY s.host_id, s.scan_id DESC"
    )->fetchAll(PDO::FETCH_ASSOC);

    $perHost = [];   // host_id => [{scan_id, fqdn, collected_at}, ...] 최신순
    $hostOptions = [];
    foreach ($rows as $r) {
        $hid = (int) $r['host_id'];
        $hostOptions[$hid] = (string) $r['fqdn'];
        if (count($perHost[$hid] ?? []) < 2) { $perHost[$hid][] = $r; }
    }
    return ['perHost' => $perHost, 'hostOptions' => $hostOptions];
}

/**
 * 최신·직전 스캔을 맞대 변화 목록을 만든다(정렬까지).
 *   반환: ['changes' => vg_change_row() 배열, 'summary' => 유형별 합계,
 *          'baselineHosts' => 스캔이 1개뿐이라 비교 불가한 호스트]
 */
function vg_change_diff(PDO $pdo, array $perHost, int $hostId): array {
    $changes = [];
    $summary = ['new' => 0, 'up' => 0, 'down' => 0, 'resolved' => 0];
    $baselineHosts = [];   // 스캔이 1개뿐이라 비교 불가(첫 수집)

    // 비교에 필요한 모든 스캔 id 수집(최신 + 직전)
    $scanIds = [];
    foreach ($perHost as $hid => $scans) {
        if ($hostId && $hid !== $hostId) { continue; }
        if (count($scans) < 2) { $baselineHosts[$hid] = $scans[0]['fqdn'] ?? (string) $hid; continue; }
        $scanIds[] = (int) $scans[0]['scan_id'];
        $scanIds[] = (int) $scans[1]['scan_id'];
    }

    // findings 를 한 번에 로드 → scan_id => key(cve|pkg) => row
    //   SQL LIMIT/OFFSET 페이지네이션(패키지 변경 탭과 동일한 방식)은 실측으로 기각됐다 —
    //   호스트쌍마다 tb_finding 을 자기조인(신규/해결 판정용 LEFT JOIN anti-join)하는 SQL 로
    //   diff 를 내리면, 이 dev DB(findings 51만행·비교대상 호스트 56개) 기준 인덱스 힌트를
    //   줘도 30초+ 걸렸다(현재 이 방식의 벌크 로드는 1.2초). 자기조인이 호스트당 반복되며
    //   인덱스 탐색 비용이 누적되는 게 원인 — 개선하려면 전용 커버링 인덱스나
    //   tb_pkg_change 처럼 변경 이력을 미리 적재해두는 테이블이 필요해, 이번 "경미한
    //   정리" 범위를 넘는다. 대신 실제 쓰지 않는 컬럼(cvss, exposure_scope)만 걷어낸다
    //   (vg_change_row() 는 cve_id/package_name/severity/in_kev/exposed/container_id/
    //    installed_version 만 쓴다).
    $bySc = [];
    if ($scanIds) {
        $in = implode(',', array_map('intval', $scanIds));
        $fst = $pdo->query(
            // rationale(판정 근거 문장)은 더 이상 목록이 쓰지 않는다 — 접이식으로 행마다 달고
            //   있던 것을 상세(finding_history.php)로 보냈다. 대신 그리로 갈 링크를 만들 수
            //   있게 container_id 를 싣는다(int 하나 ↔ 문장 하나의 교환이다).
            "SELECT f.scan_id, f.cve_id, f.package_name, f.severity, f.in_kev, f.exposed,
                    f.container_id, f.installed_version,
                    CASE WHEN f.container_id = 0 THEN s.os_id ELSE ctr.os_id END AS package_os_id,
                    CASE WHEN f.container_id = 0 THEN s.os_version ELSE ctr.os_version END AS package_os_version
               FROM tb_finding f
               JOIN tb_scan s ON s.scan_id = f.scan_id
               LEFT JOIN tb_container ctr ON ctr.container_id = f.container_id
              WHERE f.scan_id IN ($in) AND f.is_deleted = 0"
        );
        foreach ($fst->fetchAll(PDO::FETCH_ASSOC) as $f) {
            $bySc[(int) $f['scan_id']][$f['cve_id'] . '|' . $f['package_name']] = $f;
        }
    }

    // 호스트별 diff
    foreach ($perHost as $hid => $scans) {
        if ($hostId && $hid !== $hostId) { continue; }
        if (count($scans) < 2) { continue; }
        $fqdn = (string) $scans[0]['fqdn'];
        $when = (string) $scans[0]['collected_at'];
        $curScanId = (int) $scans[0]['scan_id'];
        $cur  = $bySc[$curScanId] ?? [];
        $prev = $bySc[(int) $scans[1]['scan_id']] ?? [];

        foreach ($cur as $k => $f) {
            if (!isset($prev[$k])) {
                $changes[] = vg_change_row('new', $hid, $fqdn, $when, $f, null, $curScanId);
                $summary['new']++;
            } else {
                $a = VG_SEV_RANK[$prev[$k]['severity']] ?? 0;
                $b = VG_SEV_RANK[$f['severity']] ?? 0;
                if ($b > $a) { $changes[] = vg_change_row('up', $hid, $fqdn, $when, $f, $prev[$k]['severity'], $curScanId); $summary['up']++; }
                elseif ($b < $a) { $changes[] = vg_change_row('down', $hid, $fqdn, $when, $f, $prev[$k]['severity'], $curScanId); $summary['down']++; }
            }
        }
        foreach ($prev as $k => $f) {
            if (!isset($cur[$k])) {
                $changes[] = vg_change_row('resolved', $hid, $fqdn, $when, $f, null, $curScanId);
                $summary['resolved']++;
            }
        }
    }

    // 정렬: 신규 > 등급상승 > 등급하락 > 해결, 그 안에서 심각도 높은 순
    $order = ['new' => 0, 'up' => 1, 'down' => 2, 'resolved' => 3];
    usort($changes, function ($x, $y) use ($order) {
        return [$order[$x['type']], -(VG_SEV_RANK[$x['severity']] ?? 0)]
           <=> [$order[$y['type']], -(VG_SEV_RANK[$y['severity']] ?? 0)];
    });

    return ['changes' => $changes, 'summary' => $summary, 'baselineHosts' => $baselineHosts];
}

/**
 * 회차별 추이 데이터: 회차(tb_scan_run)마다 미해결 건수 + 직전 회차 대비 신규/등급상승/
 * 등급하락/해결. 같은 scan_id 가 연속 회차에 반복될 수 있다(내용 무변경 시 스냅샷 재사용) —
 * 그 구간은 미해결 건수가 그대로 유지되는 게 맞는 동작이라 손대지 않는다.
 *   첫 회차는 비교 대상이 없어 new/up/down/resolved 가 전부 null(표·차트에서 기준선으로 제외).
 *   반환: rounds(오래된→최신), resolved(해당 구간 전체 해결 항목 — vg_change_row() 형식 + 'round'),
 *         summary(구간 합계).
 */
function vg_trend_load(PDO $pdo, int $hostId, string $fqdn, int $limit): array {
    $empty = ['rounds' => [], 'resolved' => [], 'summary' => ['new' => 0, 'up' => 0, 'down' => 0, 'resolved' => 0]];

    // tb_scan_run 은 is_deleted 컬럼이 없다 — 삭제된 호스트·스캔의 실행 이력이 그대로 남아 있으므로
    // 반드시 tb_host/tb_scan 과 조인해 살아있는지 확인해야 한다(그렇지 않으면 접근통제 우회).
    $st = $pdo->prepare(
        'SELECT r.scan_run_id, r.scan_id, r.collected_at
           FROM tb_scan_run r
           JOIN tb_host h ON h.host_id = r.host_id AND h.is_deleted = 0
           JOIN tb_scan s ON s.scan_id = r.scan_id AND s.is_deleted = 0
          WHERE r.host_id = :hid
          ORDER BY r.scan_run_id DESC LIMIT :lim'
    );
    $st->bindValue(':hid', $hostId, PDO::PARAM_INT);
    $st->bindValue(':lim', $limit, PDO::PARAM_INT);
    $st->execute();
    $rounds = array_reverse($st->fetchAll(PDO::FETCH_ASSOC));   // 오래된 → 최신(차트는 좌→우)
    if (!$rounds) { return $empty; }

    $scanIds = array_values(array_unique(array_map(fn($r) => (int) $r['scan_id'], $rounds)));
    $in = implode(',', array_map('intval', $scanIds));
    $bySc = [];
    $fst = $pdo->query(
        "SELECT scan_id, cve_id, package_name, severity, in_kev, exposed, container_id, installed_version
           FROM tb_finding WHERE scan_id IN ($in) AND is_deleted = 0"
    );
    foreach ($fst->fetchAll(PDO::FETCH_ASSOC) as $f) {
        $bySc[(int) $f['scan_id']][$f['cve_id'] . '|' . $f['package_name']] = $f;
    }

    $out = [];
    $resolvedRows = [];
    $summary = ['new' => 0, 'up' => 0, 'down' => 0, 'resolved' => 0];
    $prev = null;
    $cumNew = 0; $cumResolved = 0;

    foreach ($rounds as $i => $r) {
        $scanId = (int) $r['scan_id'];
        $when = (string) $r['collected_at'];
        $cur = $bySc[$scanId] ?? [];
        $new = null; $up = null; $down = null; $resolved = null;

        if ($prev !== null) {
            $new = 0; $up = 0; $down = 0; $resolved = 0;
            foreach ($cur as $k => $f) {
                if (!isset($prev[$k])) { $new++; $summary['new']++; continue; }
                $a = VG_SEV_RANK[$prev[$k]['severity']] ?? 0;
                $b = VG_SEV_RANK[$f['severity']] ?? 0;
                if ($b > $a) { $up++; $summary['up']++; }
                elseif ($b < $a) { $down++; $summary['down']++; }
            }
            foreach ($prev as $k => $f) {
                if (!isset($cur[$k])) {
                    $resolved++;
                    $summary['resolved']++;
                    $resolvedRows[] = vg_change_row('resolved', $hostId, $fqdn, $when, $f, null, $scanId) + ['round' => $i + 1];
                }
            }
            $cumNew += $new;
            $cumResolved += $resolved;
        }

        $out[] = [
            'round'        => $i + 1,
            'scan_run_id'  => (int) $r['scan_run_id'],
            'scan_id'      => $scanId,
            'collected_at' => $when,
            'unresolved'   => count($cur),
            'new'          => $new,
            'up'           => $up,
            'down'         => $down,
            'resolved'     => $resolved,
            'cum_rate'     => ($cumNew + $cumResolved) > 0 ? round($cumResolved / ($cumNew + $cumResolved) * 100, 1) : null,
        ];
        $prev = $cur;
    }

    return ['rounds' => $out, 'resolved' => $resolvedRows, 'summary' => $summary];
}

/**
 * 페이지에 보이는 변화 행들만 tb_pkg_change 를 배치 조회해 사유(reason)를 채운다(N+1 금지).
 *   취약점 변화 탭·추이 탭의 "해결된 항목" 목록이 같은 로직을 공유한다.
 */
function vg_attach_change_reason(PDO $pdo, array &$rows): void {
    if (!$rows) { return; }
    $curScanIds = array_values(array_unique(array_map(fn($r) => $r['cur_scan_id'], $rows)));
    $curScanIds = array_filter($curScanIds, fn($v) => $v > 0);
    if (!$curScanIds) { return; }
    $in = implode(',', array_map('intval', $curScanIds));
    $pst = $pdo->query(
        "SELECT host_id, package_name, scan_id, change_type, old_version, new_version
           FROM tb_pkg_change WHERE is_deleted = 0 AND scan_id IN ($in)"
    );
    $pkgByKey = [];
    foreach ($pst->fetchAll(PDO::FETCH_ASSOC) as $pc) {
        $pkgByKey[$pc['host_id'] . '|' . $pc['package_name'] . '|' . $pc['scan_id']] = $pc;
    }
    foreach ($rows as &$r) {
        $key = $r['host_id'] . '|' . $r['package_name'] . '|' . $r['cur_scan_id'];
        $pc = $pkgByKey[$key] ?? null;
        $r['reason'] = vg_change_reason($r['type'], $pc);
        $r['reason_short'] = vg_change_reason_short($r['type'], $pc);
    }
    unset($r);
}
