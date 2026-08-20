<?php
declare(strict_types=1);

/**
 * dashboard/queries.php — 대시보드(index.php)의 조회층. 섹션 하나가 함수 하나를 부른다.
 *
 *   ⚠ **이 파일의 SQL 은 성능 회귀가 난 자리다. 옮길 때도 한 글자도 바꾸지 않는다.**
 *   - "대응 우선순위" 쿼리를 파생테이블로 리라이트했다가 235ms → 42초가 된 운영 실측이 있다.
 *   - KEV 건수 쿼리의 GROUP BY 파생테이블을 지웠다가 33초로 회귀했다(#354) — MySQL 8 은
 *     GROUP BY 있는 파생테이블을 머지하지 않고 materialize 한다.
 *   - 추세의 scan_id 목록은 PHP 가 **값으로 펼쳐** 넘긴다. IN (서브쿼리)로 두면 옵티마이저가
 *     tb_finding 을 먼저 훑어 같은 결과에 2.06초가 걸렸다(실측).
 *   전제(옵티마이저가 올바른 인덱스를 고름)는 tb_finding STATS_SAMPLE_PAGES=200(#617)이 받친다.
 */

/**
 * 추세 창(窓) — 30일. "지난달보다 나아졌나" 에 답하는 최소 구간이다.
 *   14일이었던 적이 있는데(#221 에서 제거) 그때는 등급별 누적 막대라 창이 넓어질수록
 *   막대가 뭉갰다. 지금은 선 하나(High 이상)라 30일이 오히려 읽힌다.
 */
const VG_TREND_DAYS = 30;

/**
 * 전 호스트의 "최신 스캔" 집합 — 퍼널·주요 신호·호스트 목록이 모두 이 기준을 쓴다.
 *   tb_finding 을 조인하는 쿼리들은 WHERE scan_id IN(이 서브쿼리) 대신 JOIN 으로
 *   표현한다(cve.php·compliance_rule.php 와 동일 패턴). IN(서브쿼리) 로 두면 옵티마이저가
 *   호스트당 "최신 스캔 하나"가 아니라 tb_scan 전체(변경시에만 저장되지만 이력이 계속
 *   쌓인다 — 실측 호스트당 평균 6.5개)를 먼저 tb_finding 과 조인한 뒤에야 필터링해,
 *   스캔 이력이 쌓일수록 대시보드가 선형으로 느려진다(실측: "대응 우선순위" 카드 하나가
 *   7.2초 — EXPLAIN ANALYZE 로 확인. JOIN 전환 후 0.2초).
 *   tb_scan 자체(작은 표)에는 이 문제가 없어 IN(서브쿼리)를 그대로 둔다.
 */
function vg_dash_latest_join(): string {
    return "JOIN " . vg_latest_scan_subq() . " latest ON latest.host_id = s.host_id AND latest.mid = s.scan_id";
}

function vg_dash_host_count(PDO $pdo): int {
    return (int) $pdo->query('SELECT COUNT(*) FROM tb_host WHERE is_deleted = 0')->fetchColumn();
}

/**
 * KPI·퍼널 은 페이지 무관 — 전 호스트 최신 스캔의 심각도 총합.
 *
 * 퍼널의 네 칸(전체 → High 이상 → KEV → KEV 중 기한 초과)은 **같은 모집단을 좁혀 가는**
 * 수여야 의미가 있다. 그래서 KEV·외부노출도 별도 쿼리로 따로 세지 않고 이 한 번의
 * 스캔에서 함께 뽑는다 — 기준(tb_finding 행)이 하나로 고정되고, 예전에 KEV 만 자산·CVE·
 * 패키지로 묶어 세던 별도 쿼리(#354 에서 파생테이블로 최적화했던 것)도 사라진다.
 * 이 값들은 findings.php 의 등급 카드와 같은 기준이라 링크를 눌렀을 때 숫자가 이어진다.
 *
 * KEV 를 **High 이상 안에서만** 세는 건 퍼널이 진짜로 포함관계여야 하기 때문이다.
 * KEV 는 등급과 독립이라 MEDIUM 에도 붙는다(실측 dev 344건) — 전 등급으로 세면 3번째 칸이
 * 2번째 칸의 부분집합이 아니게 되고, 좁혀지는 그림 자체가 거짓말이 된다. 등급이 낮은 KEV 는
 * [주요 취약점 신호] 카드가 KEV 우선 정렬로 계속 보여준다(가려지지 않는다).
 *
 * 실행 상태(runtime_status) 구성도 **같은 쿼리에서** 함께 뽑는다. SUM(...) 표현식을 몇 개
 * 더 얹는 것은 이미 훑고 있는 행을 세는 것뿐이라 접근 경로(EXPLAIN)가 바뀌지 않는다 —
 * 별도 GROUP BY 쿼리를 하나 더 만드는 것과는 비용이 다르다(이 파일 머리주석의 회귀 이력).
 * runtime_status 는 VARCHAR NULL 이라 네 어휘 밖·NULL 이 남을 수 있어 '미상' 으로 받는다.
 *
 * 반환: ['totals' => [등급 => n], 'kev' => n, 'runtime' => [상태 => n]]
 */
function vg_dash_severity_totals(PDO $pdo): array {
    $latestJoin = vg_dash_latest_join();
    $totals = ['CRITICAL' => 0, 'HIGH' => 0, 'MEDIUM' => 0, 'LOW' => 0];
    $runtime = ['EXTERNAL' => 0, 'LISTENING' => 0, 'RUNNING' => 0, 'INSTALLED' => 0];
    $kevCount = 0;
    $allCount = 0;
    $totalsRows = $pdo->query(
        "SELECT f.severity, COUNT(*) c,
                SUM(f.in_kev = 1 AND f.severity IN ('CRITICAL','HIGH')) kev,
                SUM(f.runtime_status = 'EXTERNAL')  rt_external,
                SUM(f.runtime_status = 'LISTENING') rt_listening,
                SUM(f.runtime_status = 'RUNNING')   rt_running,
                SUM(f.runtime_status = 'INSTALLED') rt_installed
           FROM tb_finding f
           JOIN tb_scan s ON s.scan_id = f.scan_id
           JOIN tb_host h ON h.host_id = s.host_id AND h.is_deleted = 0
           $latestJoin
          GROUP BY f.severity"
    )->fetchAll();
    foreach ($totalsRows as $f) {
        if (isset($totals[$f['severity']])) { $totals[$f['severity']] = (int) $f['c']; }
        $kevCount += (int) $f['kev'];
        $allCount += (int) $f['c'];
        $runtime['EXTERNAL']  += (int) $f['rt_external'];
        $runtime['LISTENING'] += (int) $f['rt_listening'];
        $runtime['RUNNING']   += (int) $f['rt_running'];
        $runtime['INSTALLED'] += (int) $f['rt_installed'];
    }
    // 남은 것은 상태를 모르는 건이다 — 0 으로 감추면 도넛의 합이 전체와 안 맞는다.
    $runtime['미상'] = max(0, $allCount - array_sum($runtime));
    return ['totals' => $totals, 'kev' => $kevCount, 'runtime' => $runtime];
}

/**
 * 퍼널 4번 칸 — **KEV 중 조치 기한 초과**.
 *
 * 모집단은 3번 칸(High 이상 중 KEV)과 정확히 같다. 그 안에서 기한을 넘긴 것만 센다 —
 * 퍼널이 포함관계를 그리는 그림이라, 4번 칸이 3번 칸의 부분집합이 아니게 되면 형태가
 * 거짓말이 된다. 그래서 "전체 기한 초과" 가 아니라 KEV 안에서만 센다(라벨도 그렇게 적는다).
 *
 * 기한 계산은 finding_sla.php 것을 그대로 쓴다 — 대시보드가 따로 세면 목록의 남은 일수
 * 뱃지와 숫자가 어긋난다(DRY). 완료·예외 처리된 건은 세지 않는 것도 목록과 같은 규칙
 * (vg_finding_due_cell 이 그 둘을 '—' 로 둔다).
 *
 * 성능: 되짚을 대상은 최신 스캔의 KEV(High 이상)뿐이다 — 3번 칸의 값이 곧 그 상한이라
 * 전체 탐지 건수(수십만)를 훑지 않는다. 최초 발견 시각은 목록 화면과 같은 배치 조회
 * 한 번으로 받는다(N+1 없음).
 *
 * 반환: ['overdue' => n, 'slaDays' => KEV 조치 기한(일)] — 기한 일수는 퍼널 라벨이 그대로 말한다.
 */
function vg_dash_kev_overdue(PDO $pdo): array {
    $latestJoin = vg_dash_latest_join();
    $policy     = vg_compliance_policy();
    $kevSlaDays = (int) vg_finding_sla_days(true, 'CRITICAL', $policy);   // KEV 기한이 등급보다 우선한다
    $kevOverdue = 0;
    $kevRows = $pdo->query(
        "SELECT s.host_id, COALESCE(ctr.cid, '') AS cid, f.cve_id, f.package_name,
                fst.status AS fix_status
           FROM tb_finding f
           JOIN tb_scan s ON s.scan_id = f.scan_id
           JOIN tb_host h ON h.host_id = s.host_id AND h.is_deleted = 0
           $latestJoin
           LEFT JOIN tb_container ctr ON ctr.container_id = f.container_id
           LEFT JOIN tb_finding_status fst ON fst.host_id = s.host_id
                 AND fst.container_ref = COALESCE(ctr.cid, '')
                 AND fst.cve_id = f.cve_id AND fst.package_name = f.package_name
          WHERE f.in_kev = 1 AND f.severity IN ('CRITICAL','HIGH') AND f.is_deleted = 0"
    )->fetchAll();
    $kevKeys = [];
    foreach ($kevRows as $r) {
        $fixStatus = (string) ($r['fix_status'] ?? '');
        if ($fixStatus === 'DONE' || $fixStatus === 'EXCEPTED') { continue; }
        $kevKeys[] = [(int) $r['host_id'], (string) $r['cid'],
                      (string) $r['cve_id'], (string) $r['package_name']];
    }
    if ($kevKeys) {
        $kevFirstSeen = vg_finding_first_seen_map($pdo, $kevKeys, vg_finding_sla_lookback_days($policy));
        foreach ($kevKeys as $k) {
            $seen = $kevFirstSeen[vg_finding_status_key($k[0], $k[1], $k[2], $k[3])] ?? null;
            // 최초 발견 시각을 못 찾은 건은 세지 않는다 — 모르는 것을 초과로 단정하지 않는다
            //   (목록의 남은 일수 칸이 '–' 로 두는 것과 같은 판단).
            if ($seen !== null && (int) $seen['days'] > $kevSlaDays) { $kevOverdue++; }
        }
    }
    return ['overdue' => $kevOverdue, 'slaDays' => $kevSlaDays];
}

/**
 * 최근 $days 일 추세 — **자산별** 날짜별 "High 이상" 건수.
 *
 * 이월(carry-forward): 스캔은 바뀔 때만 저장되므로 그날 스캔이 없는 호스트는
 * **직전 스캔 값을 이어 쓴다**(0 으로 떨구면 "취약점이 사라졌다"는 거짓말).
 *
 * 자산별로 나눠 담는 것 말고는 예전(전체 합산 한 줄)과 **쿼리가 같다** — 읽는 스캔도,
 * 세는 기준도, 이월 규칙도 그대로다. 달라진 것은 이미 호스트별로 갖고 있던 중간 결과를
 * 합치지 않고 그대로 돌려준다는 것뿐이라, 새 쿼리도 새 인덱스도 필요 없다.
 * (호스트 이름은 이미 조인돼 있는 tb_host 에서 한 칸 더 읽는다 — 접근 경로가 안 바뀐다.)
 *
 * 읽는 스캔은 두 묶음뿐이다 — 창 안의 스캔 + 각 호스트가 창 시작 전에 가진 마지막 스캔
 * (이월의 출발점). 전체 스캔을 다 읽으면 이력이 쌓일수록 대시보드가 선형으로 느려진다.
 *
 * 사전집계 테이블을 새로 만들지 않았다: 기존 집계 자산(tb_package_summary·tb_scan_run)
 * 어디에도 스캔별 심각도 건수가 없고, 실측(dev: 호스트 208 · 스캔 951 · finding 42만)에서
 * 이 두 쿼리 합이 45ms 라 사전집계의 갱신 비용·정합성 부담을 살 이유가 없다(YAGNI).
 * 단, scan_id 목록은 **PHP 가 값으로 펼쳐** 넘긴다 — IN (서브쿼리) 로 두면 옵티마이저가
 * tb_finding 을 먼저 훑어 같은 결과에 2.06초가 걸렸다(실측).
 *
 * 반환: [['name' => 자산 이름, 'points' => [['d' => 'Y-m-d', 'v' => High 이상 건수], …]], …]
 *   — vg_multi_trend() 의 계열 계약 그대로다. 상위 N + 기타로 접는 것은 그 함수가 한다
 *     (여기서 미리 접으면 화면마다 다른 기준으로 접힌다).
 */
function vg_dash_trend(PDO $pdo, int $days): array {
    $since = date('Y-m-d', strtotime('-' . ($days - 1) . ' days'));
    $trendScans = $pdo->query(
        "SELECT s.scan_id AS id, s.host_id, h.fqdn, DATE(s.collected_at) AS d
           FROM tb_scan s
           JOIN tb_host h ON h.host_id = s.host_id AND h.is_deleted = 0
          WHERE s.is_deleted = 0 AND DATE(s.collected_at) >= '$since'
          UNION
         SELECT s.scan_id, s.host_id, h.fqdn, DATE(s.collected_at)
           FROM tb_scan s
           JOIN tb_host h ON h.host_id = s.host_id AND h.is_deleted = 0
           JOIN (SELECT host_id, MAX(scan_id) AS mid FROM tb_scan
                  WHERE is_deleted = 0 AND DATE(collected_at) < '$since'
                  GROUP BY host_id) b ON b.mid = s.scan_id"
    )->fetchAll();

    // 호스트별 (날짜, 스캔id) 를 id 순으로 — 이월은 "그날 이하의 마지막 스캔" 고르기다.
    $trendByHost = []; $hostName = [];
    foreach ($trendScans as $s) {
        if ($s['d'] === null) { continue; }   // collected_at 이 비어 있으면 어느 날짜에도 못 건다
        $hid = (int) $s['host_id'];
        $trendByHost[$hid][] = ['d' => (string) $s['d'], 'id' => (int) $s['id']];
        $hostName[$hid] = (string) ($s['fqdn'] ?? ('자산 #' . $hid));
    }
    foreach ($trendByHost as &$list) { usort($list, fn($a, $b) => $a['id'] <=> $b['id']); }
    unset($list);

    // 스캔별 High 이상 건수 — 퍼널 2번째 칸과 같은 기준(CRITICAL + HIGH).
    $highByScan = [];
    $trendIds = array_values(array_unique(array_map(fn($s) => (int) $s['id'], $trendScans)));
    if ($trendIds) {
        $in = implode(',', array_fill(0, count($trendIds), '?'));
        $st = $pdo->prepare(
            "SELECT scan_id, COUNT(*) c FROM tb_finding
              WHERE scan_id IN ($in) AND severity IN ('CRITICAL','HIGH')
              GROUP BY scan_id"
        );
        $st->execute($trendIds);
        foreach ($st->fetchAll() as $r) { $highByScan[(int) $r['scan_id']] = (int) $r['c']; }
    }

    $points = [];   // hostId => [['d'=>…, 'v'=>…], …]
    for ($i = $days - 1; $i >= 0; $i--) {
        $day = date('Y-m-d', strtotime("-$i days"));
        foreach ($trendByHost as $hid => $list) {
            $pick = null;
            foreach ($list as $s) { if ($s['d'] <= $day) { $pick = $s['id']; } }   // 그날까지의 최신
            // 첫 수집 이전의 날은 "0건" 이 아니라 "아직 자료가 없음" 이다 — 그 자산의
            //   선을 아직 시작하지 않는다(0 으로 채우면 없던 개선처럼 보인다).
            if ($pick === null) { continue; }
            $points[$hid][] = ['d' => $day, 'v' => (int) ($highByScan[$pick] ?? 0)];
        }
    }

    $series = [];
    foreach ($points as $hid => $pts) {
        $series[] = ['name' => $hostName[$hid] ?? ('자산 #' . $hid), 'points' => $pts];
    }
    return $series;
}

/** 목록 대상 = 최신 스캔이 있는 비삭제 호스트 수(페이지네이션 총건). */
function vg_dash_host_total(PDO $pdo): int {
    return (int) $pdo->query(
        'SELECT COUNT(*) FROM tb_host h WHERE h.is_deleted = 0
          AND EXISTS (SELECT 1 FROM tb_scan s WHERE s.host_id = h.host_id)'
    )->fetchColumn();
}

/**
 * 호스트별 최신 스캔(한 페이지) — **위험도 높은 순**.
 *
 * 정렬은 반드시 SQL 에서 한다. 페이지네이션이 걸려 있어 PHP 로 현재 페이지만 정렬하면
 * 1페이지에 못 들어온 위험 호스트가 영영 안 보인다(지금은 11대라 한 페이지지만 자산이 늘면 깨진다).
 *
 * tb_finding 은 위 주석과 같은 이유로 IN(서브쿼리)가 아니라 JOIN 으로 붙인다.
 * LEFT JOIN 이어야 findings 0건인 호스트가 목록에서 사라지지 않는다.
 * COALESCE 가 필요한 이유: 매칭 행이 없으면 SUM(...) 이 NULL 이라 정렬·렌더가 흔들린다.
 * (scan_id, severity) 인덱스 idx_find_scan_sev 가 이 집계를 받쳐준다.
 *
 * 반환: ['rows' => 한 페이지, 'sevByScan' => 스캔별 심각도 분포(정렬용 집계를 그대로 쓴다)]
 */
function vg_dash_host_rows(PDO $pdo, int $perPage, int $offset): array {
    $rows = $pdo->query(
        "SELECT s.scan_id, s.collected_at, s.package_count, s.exposure_count, s.agent_version,
                h.host_id, h.fqdn, h.os_id, h.os_version,
                COALESCE(SUM(f.severity = 'CRITICAL'), 0) sev_critical,
                COALESCE(SUM(f.severity = 'HIGH'), 0)     sev_high,
                COALESCE(SUM(f.severity = 'MEDIUM'), 0)   sev_medium,
                COALESCE(SUM(f.severity = 'LOW'), 0)      sev_low
         FROM tb_scan s
         JOIN " . vg_latest_scan_subq() . " t ON t.mid = s.scan_id
         JOIN tb_host h ON h.host_id = s.host_id
         LEFT JOIN tb_finding f ON f.scan_id = s.scan_id
         WHERE h.is_deleted = 0
         GROUP BY s.scan_id, s.collected_at, s.package_count, s.exposure_count, s.agent_version,
                  h.host_id, h.fqdn, h.os_id, h.os_version
         ORDER BY sev_critical DESC, sev_high DESC, sev_medium DESC, sev_low DESC,
                  s.collected_at DESC, s.scan_id DESC
         LIMIT $perPage OFFSET $offset"
    )->fetchAll();

    // 심각도 카운트는 위 정렬용 집계를 그대로 쓴다 — vg_sev_by_scan_ids() 로 한 번 더 세지 않는다(DRY).
    $sevByScan = [];
    foreach ($rows as $r) {
        $sevByScan[(int) $r['scan_id']] = [
            'CRITICAL' => (int) $r['sev_critical'], 'HIGH' => (int) $r['sev_high'],
            'MEDIUM'   => (int) $r['sev_medium'],   'LOW'  => (int) $r['sev_low'],
        ];
    }
    return ['rows' => $rows, 'sevByScan' => $sevByScan];
}
