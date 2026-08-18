<?php
declare(strict_types=1);

/**
 * assets/queries.php — 자산 목록(assets.php)의 **조회층**. SQL 은 전부 여기 있고, 화면은 없다.
 *
 *   왜 결과를 반환값이 아니라 `&$out` 으로 돌려주나: 원래 이 코드는 assets.php 의 try 블록
 *   안에서 한 줄씩 변수에 쌓였고, **중간에 예외가 나면 그때까지 쌓인 값이 그대로 화면에**
 *   쓰였다(부서 옵션까지 읽고 목록 쿼리에서 실패하면 부서 필터는 떠 있었다). 반환값으로
 *   바꾸면 그 부분 상태가 사라져 오류 화면의 생김새가 달라진다 — finally 로 지금까지의 값을
 *   그대로 내보내 옛 동작을 보존한다.
 */

/**
 * 목록 화면이 쓰는 값을 모두 읽는다. 예외는 삼키지 않고 호출부(assets.php)로 올린다 —
 *   사용자에게 보일 문구와 error_log 태그는 화면이 정한다.
 *
 * @param string $dept 목록에 없는 값이면 '' 로 되돌린다(조작된 쿼리스트링) — 그래서 참조다.
 * @param array  $out  {deptOptions, stateCounts, rows, total, sevByScan, ipsByHost, systemGrade, unconfirmed}
 */
function vg_assets_load(
    PDO $pdo,
    string $q,
    string $state,
    string $grade,
    string &$dept,
    int $page,
    int $perPage,
    array &$out
): void {
    $deptOptions = [];
    $stateCounts = ['ok' => 0, 'stale' => 0, 'offline' => 0, 'none' => 0];
    $rows = []; $total = 0; $sevByScan = [];
    $ipsByHost = [];       // host_id => [[iface, ip], ...] (대표 IP 가 맨 앞)
    $systemGrade = null;   // 함대 전체를 하나의 정보시스템으로 볼 때의 승계 등급
    $unconfirmed = 0;      // 아직 사람이 등급을 확정하지 않은 자산 수

    /* 호스트 한 대의 연결 상태를 SQL 안에서 판정하는 식(format.php 의 vg_asset_state_sql_expr() —
     * compliance.php 와 공유하는 SSOT). 목록 필터·KPI 집계가 같은 식을 써야 "지연 3대" 를 눌렀을 때
     * 3대가 나온다. */
    $stateExpr = vg_asset_state_sql_expr();

    // 호스트 + 최신 스캔. LEFT JOIN 이라 등록만 되고 아직 수집이 없는 호스트도 남는다.
    $fromSql = 'FROM tb_host h
                LEFT JOIN ' . vg_latest_scan_subq() . ' t ON t.host_id = h.host_id
                LEFT JOIN tb_scan s ON s.scan_id = t.mid
                LEFT JOIN (
                    SELECT host_fqdn, MAX(last_seen_at) AS last_seen_at
                      FROM tb_agent_token
                     WHERE is_revoked = 0 AND is_deleted = 0
                     GROUP BY host_fqdn
                ) agent_seen ON agent_seen.host_fqdn = h.fqdn
                LEFT JOIN tb_asset_grade_review gr ON gr.host_id = h.host_id';

    try {
        /* 부서 드롭다운 옵션 — 살아 있는 자산에 실제로 붙어 있는 값만. 검토 정보는 호스트당 1행이라
         *   행 수가 자산 수를 넘지 않는다(별도 집계 테이블이 필요한 규모가 아니다). */
        $deptOptions = $pdo->query(
            'SELECT DISTINCT gr.owning_department
               FROM tb_asset_grade_review gr
               JOIN tb_host h ON h.host_id = gr.host_id AND h.is_deleted = 0
              WHERE gr.owning_department IS NOT NULL AND gr.owning_department <> \'\'
              ORDER BY gr.owning_department'
        )->fetchAll(PDO::FETCH_COLUMN);
        $deptOptions = array_combine($deptOptions, $deptOptions) ?: [];
        // 목록에 없는 값이 오면 필터를 건 것으로 치지 않는다(조작된 쿼리스트링).
        if ($dept !== '' && !isset($deptOptions[$dept])) { $dept = ''; }

        // KPI — 검색어·상태 필터와 무관하게 전체 기준(필터를 걸어도 전체 그림은 유지된다).
        $kpi = $pdo->query("SELECT $stateExpr AS st, COUNT(*) c $fromSql WHERE h.is_deleted = 0 GROUP BY st")->fetchAll();
        foreach ($kpi as $k) {
            if (isset($stateCounts[$k['st']])) { $stateCounts[$k['st']] = (int) $k['c']; }
        }

        $where  = 'h.is_deleted = 0';
        $params = [];
        if ($q !== '') {
            /* IP 검색은 두 곳을 본다. h.last_seen_ip 는 **서버가 수집 요청을 받은 주소** 하나뿐이라
             *   NAT·게이트웨이 뒤에서는 호스트가 실제로 가진 주소와 다르고, 화면의 IP 열은
             *   tb_host_address(호스트가 신고한 전 인터페이스)에서 그린다 — 여기를 안 보면
             *   **표에 보이는 IP 로 검색했는데 0건**이 된다(검색창은 이미 'IP 검색' 이라 적고 있다).
             *   tb_host_address 는 호스트당 몇 행짜리 작은 표라 EXISTS 한 번이 붙는 비용뿐이다. */
            $where .= " AND (h.fqdn LIKE ? OR h.last_seen_ip LIKE ? OR EXISTS (
                SELECT 1 FROM tb_host_address search_addr
                 WHERE search_addr.host_id=h.host_id AND search_addr.is_deleted=0
                   AND search_addr.ip LIKE ?
            ) OR EXISTS (
                SELECT 1 FROM tb_package search_pkg
                 WHERE search_pkg.scan_id=s.scan_id AND search_pkg.is_deleted=0
                   AND search_pkg.container_id=0 AND search_pkg.manager IN ('dpkg','rpm','apk')
                   AND (search_pkg.name LIKE ? OR search_pkg.source_pkg LIKE ?)
            ))";
            $like = '%' . $q . '%';
            array_push($params, $like, $like, $like, $like, $like);
        }
        if ($state !== '') {
            // KPI 와 같은 식을 쓴다 — 다른 식을 쓰면 "지연 3대" 를 눌렀는데 2대가 나오는 일이 생긴다.
            $where .= " AND $stateExpr = ?";
            $params[] = $state;
        }
        if ($grade === 'none') {
            $where .= ' AND h.grade IS NULL';
        } elseif ($grade !== '') {
            $where .= ' AND h.grade = ?';
            $params[] = $grade;
        }
        if ($dept !== '') {
            $where .= ' AND gr.owning_department = ?';
            $params[] = $dept;
        }

        // COUNT 도 목록과 같은 FROM 을 써야 한다. 상태 필터가 최신 스캔(s)을 참조하기 때문이다.
        $st = $pdo->prepare("SELECT COUNT(*) $fromSql WHERE $where");
        $st->execute($params);
        $total = (int) $st->fetchColumn();

        $offset = ($page - 1) * $perPage;

        $st = $pdo->prepare(
            /* 목록에서 뺀 값(OS·패키지 수·에이전트 버전·담당 부서)은 SELECT 에서도 뺀다 —
             *   화면이 안 쓰는 값을 페이지마다 실어 오지 않는다. 검색·필터가 쓰는 컬럼
             *   (h.last_seen_ip · gr.owning_department)은 WHERE 절에 그대로 남아 있어 영향이 없다.
             *   IP 열은 여기서 안 읽는다 — 호스트당 여러 행이라 조인하면 목록이 뻥튀기된다.
             *   별도 조회 한 번(vg_assets_load_addresses)으로 읽어 메모리에서 묶는다. */
            "SELECT h.host_id, h.fqdn,
                    s.scan_id, s.collected_at,
                    h.poll_schedule_seconds,
                    h.criticality, h.grade, h.grade_reason,
                    h.grade_suggested, h.grade_suggested_reason,
                    TIMESTAMPDIFF(MINUTE, s.collected_at, NOW()) AS age_min,
                    TIMESTAMPDIFF(MINUTE, agent_seen.last_seen_at, NOW()) AS poll_age_min
               $fromSql
              WHERE $where
              ORDER BY h.fqdn
              LIMIT $perPage OFFSET $offset"
        );
        $st->execute($params);
        $rows = $st->fetchAll();

        // 이 페이지에 보이는 최신 스캔들의 심각도 카운트
        $ids = [];
        foreach ($rows as $r) { if ($r['scan_id'] !== null) { $ids[] = (int) $r['scan_id']; } }
        $sevByScan = vg_sev_by_scan_ids($pdo, $ids);

        /* 이 페이지에 보이는 호스트들의 IP — **조회 한 번**으로 전부 읽고 메모리에서 묶는다.
         *   행마다 부르면 페이지당 25번(N+1)이 된다. */
        $ipsByHost = vg_assets_load_addresses($pdo, array_column($rows, 'host_id'));

        /* 함대 최신 에이전트 버전 조회는 여기서 걷어냈다 — 에이전트 버전 열이 호스트 상세로
         *   옮겨 갔고(vg_host_load_latest_agent_version() 을 그쪽에서 부른다), 목록이 안 쓰는 값을 위해
         *   전 스캔의 DISTINCT 를 매 요청 돌릴 이유가 없다. '구버전' 신호 자체는 그대로 살아 있다. */
        /* 정보시스템 등급 — 여러 업무정보 등급이 한 시스템에 있으면 **최고등급을 승계**한다.
         *   여기서 "정보시스템"은 이 함대(자산 전체)다. 확정된 등급만 센다 — 제안값을 섞으면
         *   "시스템이 등급을 정했다"가 되어 사람 확정과의 경계가 무너진다.
         *   필터와 무관하게 전체 기준(KPI 와 같은 성격). */
        $confirmed = $pdo->query(
            'SELECT grade FROM tb_host WHERE is_deleted = 0 AND grade IS NOT NULL'
        )->fetchAll(PDO::FETCH_COLUMN);
        $systemGrade = vg_asset_grade_max($confirmed);

        /* 미확정 자산 수 — 심사 관점에선 "정보시스템 등급이 무엇인가" 보다 **아직 아무도 판정하지 않은
         *   자산이 몇 대인가** 가 먼저 나오는 질문이다. 승계 등급만 보이면 미확정이 몇 대든 숫자 하나가
         *   떠 있어 다 정해진 것처럼 읽힌다. 제안값이 붙어 있어도 확정은 아니므로 여기 포함된다. */
        $unconfirmed = (int) $pdo->query(
            'SELECT COUNT(*) FROM tb_host WHERE is_deleted = 0 AND grade IS NULL'
        )->fetchColumn();
    } finally {
        // 예외가 나도 **그때까지 읽은 값**을 그대로 내보낸다(위 머리주석의 이유).
        $out = compact(
            'deptOptions', 'stateCounts', 'rows', 'total', 'sevByScan', 'ipsByHost',
            'systemGrade', 'unconfirmed'
        );
    }
}

/* 대표 IP 를 고를 때 뒤로 미는 인터페이스 접두사. 컨테이너·가상 브리지·오버레이가 만든
 *   주소는 **어느 호스트에나 비슷하게 있고 밖에서 그 주소로 그 자산에 닿지도 않는다** —
 *   실측(deskmini-x300)에서 IP 6개 중 5개가 이 부류였다(docker0·브리지 3개·calico).
 *   목록에 하나만 세울 자리라 물리 NIC(enp1s0 등)를 앞에 둔다.
 *   이름으로 거른다(대역이 아니라): 172.17/16 은 도커 기본값이지만 사내에서 실제로 쓰는
 *   기관도 있어 대역으로 자르면 진짜 주소를 숨기게 된다. */
const VG_ASSET_VIRTUAL_IFACES = ['docker', 'br-', 'virbr', 'veth', 'cali', 'cni', 'flannel',
                                 'vxlan', 'kube', 'tun', 'tap', 'lo'];

/**
 * 이 페이지 호스트들의 IP 를 한 번에 읽어 host_id 로 묶는다. 각 호스트의 목록은 **대표 IP 가
 *   맨 앞**이 되도록 정렬해 둔다(vg_assets_sort_addresses 의 기준). 화면은 [0] 만 세우고
 *   나머지는 '+N' 으로 접는다.
 *
 * @param  array $hostIds 이 페이지 행들의 host_id
 * @return array host_id(int) => [['iface' => ?string, 'ip' => string], ...]
 */
function vg_assets_load_addresses(PDO $pdo, array $hostIds): array
{
    if ($hostIds === []) { return []; }
    $ids = array_map('intval', $hostIds);
    $in = implode(',', array_fill(0, count($ids), '?'));
    $st = $pdo->prepare(
        "SELECT host_id, ip, iface FROM tb_host_address
          WHERE is_deleted = 0 AND host_id IN ($in)"
    );
    $st->execute($ids);

    $by = [];
    foreach ($st->fetchAll() as $r) {
        $by[(int) $r['host_id']][] = ['iface' => $r['iface'], 'ip' => (string) $r['ip']];
    }
    foreach ($by as $hostId => $addrs) { $by[$hostId] = vg_assets_sort_addresses($addrs); }
    return $by;
}

/**
 * 대표 IP 가 맨 앞에 오도록 정렬한다. 기준은 두 단계뿐이다(단순하게 — 여기서 대역 정책을
 *   만들지 않는다):
 *     1) 물리 인터페이스(VG_ASSET_VIRTUAL_IFACES 로 시작하지 않는 것)가 앞.
 *     2) 같은 등급이면 IP 문자열 오름차순 — **정렬이 결정적이어야** 새로고침마다 대표가
 *        바뀌지 않는다(MySQL 은 ORDER BY 없이 순서를 보장하지 않는다).
 *   iface 가 NULL 인 옛 백필 행은 물리로 본다 — 가상이라는 근거가 없는데 뒤로 미는 것은
 *   추측이고, 백필된 행이야말로 그 호스트의 유일한 주소인 경우가 많다.
 */
function vg_assets_sort_addresses(array $addrs): array
{
    usort($addrs, static function (array $a, array $b): int {
        $rank = static function (array $x): int {
            $iface = strtolower((string) ($x['iface'] ?? ''));
            if ($iface === '') { return 0; }
            foreach (VG_ASSET_VIRTUAL_IFACES as $prefix) {
                if (strncmp($iface, $prefix, strlen($prefix)) === 0) { return 1; }
            }
            return 0;
        };
        return [$rank($a), $a['ip']] <=> [$rank($b), $b['ip']];
    });
    return $addrs;
}
