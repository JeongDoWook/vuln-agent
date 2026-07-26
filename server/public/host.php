<?php
declare(strict_types=1);

/**
 * host.php — 호스트 상세(자산 상세). 로그인 필요.
 *   ?id=<host_id> 의 최신 스캔을 하나의 자산 화면으로 보여준다.
 *   상단: 자산 식별 + 최고 위험도 히어로 + KPI.
 *   그 아래 섹션 탭(취약점 / 런타임 / 보안설정 / 억제 / 스캔이력) — 각 탭이 자기 데이터를
 *   서버 페이지네이션한다. ?tab= 이 활성 탭, ?page= 는 그 활성 탭에만 적용된다.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require __DIR__ . '/../src/distro.php';   // vg_distro_unsupported — 피드 미지원 배포판 경고
require_once __DIR__ . '/../src/audit.php';   // vg_log_activity
require_once __DIR__ . '/../src/matcher.php';
vg_require_menu('findings');

$err = null; $msg = null; $host = null; $scan = null; $scanAge = null;
$unsupContainers = [];   // 피드 미지원 배포판 컨테이너

// 재시작·재부팅 표에 보여줄 최대 건수. 나머지는 취약점 현황(fx=restart)으로 넘긴다.


// 리소스 추이 차트에 그릴 최대 스캔 건수(최근 것부터).


// --- 탭별 데이터 조회 (?tab= 에 따라 갈리는 SQL). 각자 {total, rows, ...} 형태의 배열을 반환한다. ---

function vg_host_load_vuln_tab(PDO $pdo, int $sid, int $critHighTotal, int $perPage, int $offset, ?string $q = null): array {
    /* 성격이 다른 두 부류를 한 목록에 섞고 페이지를 나누면, 어느 한쪽은 반드시 뒤로 밀린다.
     *   - 등급순으로 정렬했더니: 커널 재부팅 건(등급이 낮다)이 2페이지로 밀려 사라졌다.
     *   - 그래서 needs_restart 를 맨 위로 올렸더니: 이번엔 **CRITICAL 이 안 보였다**
     *     (실측: web01 은 재시작 필요 건이 앞을 다 채워 CRITICAL 2건이 44페이지 뒤로 갔다).
     * 정렬로는 못 푼다 — 표를 둘로 나눈다. 각자 자기 기준으로 정렬하고, 둘 다 첫 화면에 있다.
     *   표1(주 목록·페이지네이션): CRITICAL·HIGH — 등급 → EPSS 순
     *   표2(상위 N건 + 전체보기):  재시작·재부팅 필요 — 등급이 낮아도 놓치면 안 되는 부류
     *                              (이미 패치됐는데 옛 코드가 상주해 "패치됨"으로 사라진다)
     * 검색(q)은 표1(주 목록)에만 적용한다 — 표2는 "상위 N건은 놓치지 않는다"가 목적이라
     *   필터링하면 그 의도와 충돌한다.
     */
    $sel = "SELECT f.severity, f.runtime_status, f.cve_id, f.package_name, f.installed_version, f.rationale,
                   f.needs_restart, c.epss, c.epss_percentile, c.ref_urls_json,
               " . VG_FIXED_VERSION_SUBQ . "
              FROM tb_finding f LEFT JOIN tb_cve c ON c.cve_id = f.cve_id";

    $where = "f.scan_id = ? AND f.severity IN ('CRITICAL','HIGH')";
    $params = [$sid];
    if ($q !== null && $q !== '') {
        $where .= ' AND (f.cve_id LIKE ? OR f.package_name LIKE ?)';
        $params[] = '%' . $q . '%';
        $params[] = '%' . $q . '%';
    }

    if ($q !== null && $q !== '') {
        $cnt = $pdo->prepare("SELECT COUNT(*) FROM tb_finding f WHERE $where");
        $cnt->execute($params);
        $total = (int) $cnt->fetchColumn();
    } else {
        $total = $critHighTotal;
    }

    $st = $pdo->prepare(
        "$sel WHERE $where
         ORDER BY FIELD(f.severity,'CRITICAL','HIGH'), c.epss DESC, f.cve_id
         LIMIT $perPage OFFSET $offset"
    );
    $st->execute($params);
    $rows = $st->fetchAll();

    $st = $pdo->prepare(
        "$sel WHERE f.scan_id = ? AND f.needs_restart = 1
         ORDER BY FIELD(f.severity,'CRITICAL','HIGH','MEDIUM','LOW'), c.epss DESC, f.cve_id
         LIMIT " . vg_ui_detail_preview_limit()
    );
    $st->execute([$sid]);
    $restartRows = $st->fetchAll();

    return ['total' => $total, 'rows' => $rows, 'restartRows' => $restartRows];
}

function vg_host_load_runtime_tab(PDO $pdo, int $sid, int $perPage, int $offset, int $ePage, ?string $q = null): array {
    // 노출·프로세스 모두 건수가 늘 수 있어 각자 페이지네이션한다(노출은 ?epage=, 프로세스는 ?page=).
    // 컨테이너 안의 프로세스·포트도 여기 함께 있다(container_id > 0).
    //   출처를 표시하지 않으면 컨테이너의 nginx 가 호스트의 nginx 처럼 보인다 → "위치" 열.
    $q = ($q !== null && $q !== '') ? $q : null;

    $eWhere = 'e.scan_id = ?';
    $eParams = [$sid];
    if ($q !== null) {
        $eWhere .= ' AND (e.proc LIKE ? OR e.exe_pkg LIKE ?)';
        $eParams[] = '%' . $q . '%';
        $eParams[] = '%' . $q . '%';
    }
    $cnt = $pdo->prepare("SELECT COUNT(*) FROM tb_exposure e WHERE $eWhere");
    $cnt->execute($eParams);
    $exposureTotal = (int) $cnt->fetchColumn();

    // vg_toolbar() 의 기본 "초기화" 링크는 page 만 지우고 epage 는 모른다(공용 컴포넌트, 이번
    //   범위에서 손 안 댐) — 검색 초기화 후에도 epage 가 URL 에 남을 수 있다. 그 값을 신뢰해
    //   그대로 OFFSET 에 쓰면 총건수를 넘겨 빈 표가 뜬다. 여기서 유효 범위로 접어 방어한다.
    $eMaxPage = max(1, (int) ceil($exposureTotal / $perPage));
    if ($ePage > $eMaxPage) { $ePage = $eMaxPage; }
    $eOffset = ($ePage - 1) * $perPage;

    $st = $pdo->prepare("SELECT e.proc, e.proto, e.bind_addr, e.port, e.scope, e.exe_pkg, e.loaded_pkgs,
                                IFNULL(c.cid, '') AS ctr
                           FROM tb_exposure e LEFT JOIN tb_container c ON c.container_id = e.container_id
                          WHERE $eWhere
                          ORDER BY FIELD(e.scope,'EXTERNAL','LAN','BOUND','FILTERED','LOCAL','-'), e.port
                          LIMIT $perPage OFFSET $eOffset");
    $st->execute($eParams);
    $exposures = $st->fetchAll();

    $pWhere = 'p.scan_id = ?';
    $pParams = [$sid];
    if ($q !== null) {
        $pWhere .= ' AND (p.comm LIKE ? OR p.username LIKE ? OR p.exe_pkg LIKE ?)';
        $pParams[] = '%' . $q . '%';
        $pParams[] = '%' . $q . '%';
        $pParams[] = '%' . $q . '%';
    }
    $cnt = $pdo->prepare("SELECT COUNT(*) FROM tb_process p WHERE $pWhere");
    $cnt->execute($pParams);
    $total = (int) $cnt->fetchColumn();

    $st = $pdo->prepare("SELECT p.pid, p.comm, p.username, p.exe_pkg, p.loaded_pkgs,
                                IFNULL(c.cid, '') AS ctr
                           FROM tb_process p LEFT JOIN tb_container c ON c.container_id = p.container_id
                          WHERE $pWhere ORDER BY p.comm LIMIT $perPage OFFSET $offset");
    $st->execute($pParams);
    $rows = $st->fetchAll();

    return ['total' => $total, 'exposures' => $exposures, 'exposureTotal' => $exposureTotal, 'rows' => $rows, 'ePage' => $ePage];
}

function vg_host_load_cce_tab(PDO $pdo, int $sid, int $perPage, int $offset, ?string $q = null): array {
    $where = 'f.scan_id = ?';
    $params = [$sid];
    if ($q !== null && $q !== '') {
        $where .= ' AND (f.code LIKE ? OR f.title LIKE ? OR f.ssg_rule_id LIKE ?)';
        $params[] = '%' . $q . '%';
        $params[] = '%' . $q . '%';
        $params[] = '%' . $q . '%';
    }
    $st = $pdo->prepare("SELECT COUNT(*) FROM tb_cce_finding f WHERE $where");
    $st->execute($params); $total = (int) $st->fetchColumn();
    // 점검 항목을 **검증된 룰셋(SSG)** 에 묶어 두었으므로, 그 룰의 기준 참조(CIS/NIST/STIG)를
    //   함께 읽어 화면이 근거를 인용할 수 있게 한다. 묶이지 않은 항목은 refs 가 비어 있다.
    $st = $pdo->prepare(
        "SELECT f.code, f.ssg_rule_id, f.title, f.result, f.severity, f.evidence, f.rationale,
                r.refs_json, r.title AS ssg_title
           FROM tb_cce_finding f
           LEFT JOIN tb_compliance_rule r ON r.rule_id = f.ssg_rule_id AND r.is_deleted = 0
          WHERE $where
          ORDER BY FIELD(f.result,'FAIL','NA','PASS'), FIELD(f.severity,'HIGH','MEDIUM','LOW'), f.code
          LIMIT $perPage OFFSET $offset"
    );
    $st->execute($params);
    $rows = $st->fetchAll();

    return ['total' => $total, 'rows' => $rows];
}

function vg_host_load_suppressed_tab(PDO $pdo, int $sid, int $suppressedCount, int $perPage, int $offset, ?string $q = null): array {
    $where = 'sf.scan_id = ?';
    $params = [$sid];
    if ($q !== null && $q !== '') {
        $where .= ' AND (sf.cve_id LIKE ? OR sf.package_name LIKE ?)';
        $params[] = '%' . $q . '%';
        $params[] = '%' . $q . '%';
    }

    if ($q !== null && $q !== '') {
        $cnt = $pdo->prepare("SELECT COUNT(*) FROM tb_suppressed_finding sf WHERE $where");
        $cnt->execute($params);
        $total = (int) $cnt->fetchColumn();
    } else {
        $total = $suppressedCount;
    }

    $st = $pdo->prepare(
        "SELECT cve_id, package_name, installed_version, base_severity, in_kev, suppress_reason,
                CASE WHEN sf.container_id = 0 THEN 'HOST'
                     ELSE COALESCE((SELECT c.name FROM tb_container c WHERE c.container_id = sf.container_id), CONCAT('container #', sf.container_id)) END AS target
           FROM tb_suppressed_finding sf WHERE $where
          ORDER BY FIELD(base_severity,'CRITICAL','HIGH','MEDIUM','LOW'), cve_id
          LIMIT $perPage OFFSET $offset"
    );
    $st->execute($params);
    $rows = $st->fetchAll();

    return ['total' => $total, 'rows' => $rows];
}

function vg_host_load_resources_tab(PDO $pdo, int $hostId): array {
    // 새 수집·새 컬럼 없이 스캔 이력 탭과 같은 데이터를 시간순으로만 가져온다.
    //   최신 N건을 DESC 로 뽑은 뒤 뒤집는다 — 표는 최신이 위, 차트는 최신이 오른쪽이라 방향이 반대다.
    $st = $pdo->prepare(
        'SELECT collected_at, peak_rss_mb, cpu_seconds, mem_total_mb, cpu_cores, elapsed_seconds
           FROM tb_scan WHERE host_id = ? ORDER BY scan_id DESC LIMIT ' . vg_ui_trend_limit()
    );
    $st->execute([$hostId]);
    $resourceScans = array_reverse($st->fetchAll());

    // 스캔(행) 단위로 먼저 %를 계산한다 — 절대치를 먼저 모아 나중에 나누면 스캔마다
    //   다른 스펙(mem_total_mb/cpu_cores)이 섞여 값이 왜곡된다. 필요값이 하나라도 없거나
    //   분모가 0이면 그 스캔은 이 지표에서 제외(NULL) — 0/100 대체 금지.
    foreach ($resourceScans as &$s) {
        $s['mem_pct'] = null;
        if ($s['peak_rss_mb'] !== null && $s['peak_rss_mb'] !== ''
            && $s['mem_total_mb'] !== null && $s['mem_total_mb'] !== '' && (float) $s['mem_total_mb'] > 0) {
            $s['mem_pct'] = (float) $s['peak_rss_mb'] / (float) $s['mem_total_mb'] * 100;
        }
        $s['cpu_pct'] = null;
        if ($s['cpu_seconds'] !== null && $s['cpu_seconds'] !== ''
            && $s['cpu_cores'] !== null && $s['cpu_cores'] !== '' && (float) $s['cpu_cores'] > 0
            && $s['elapsed_seconds'] !== null && $s['elapsed_seconds'] !== '' && (float) $s['elapsed_seconds'] > 0) {
            $s['cpu_pct'] = (float) $s['cpu_seconds'] / ((float) $s['elapsed_seconds'] * (float) $s['cpu_cores']) * 100;
        }
    }
    unset($s);

    return ['resourceScans' => $resourceScans];
}

function vg_host_load_scans_tab(PDO $pdo, int $hostId, int $scanTotal, int $perPage, int $offset): array {
    $total = $scanTotal;
    $st = $pdo->prepare(
        "SELECT scan_id, collected_at, received_at, package_count, exposure_count, agent_version,
                elapsed_seconds, peak_rss_mb, cpu_seconds
           FROM tb_scan WHERE host_id = ? ORDER BY scan_id DESC LIMIT $perPage OFFSET $offset"
    );
    $st->execute([$hostId]);
    $rows = $st->fetchAll();

    $ids = [];
    foreach ($rows as $s) { $ids[] = (int) $s['scan_id']; }
    $sevByScan = vg_sev_by_scan_ids($pdo, $ids);

    return ['total' => $total, 'rows' => $rows, 'sevByScan' => $sevByScan];
}

$counts =['CRITICAL'=>0,'HIGH'=>0,'MEDIUM'=>0,'LOW'=>0];
$exposureCount = 0; $cceFail = 0; $suppressedCount = 0; $vulnTotal = 0; $scanTotal = 0;
$critHighTotal = 0; $restartTotal = 0; $restartRows = [];
$tab = 'vuln'; $page = 1; $ePage = 1; $perPage = vg_perpage(); $total = 0; $exposureTotal = 0;
$rows = []; $exposures = []; $sevByScan = []; $resourceScans = [];
$q = trim((string) ($_GET['q'] ?? ''));
$hasFilter = $q !== '';

try {
    $pdo = vg_pdo();
    $hostId = (int) ($_POST['id'] ?? $_GET['id'] ?? 0);

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (!vg_csrf_check($_POST['csrf'] ?? null)) {
            throw new RuntimeException('잘못된 요청입니다. 페이지를 새로고침한 뒤 다시 시도하세요.');
        }
        $perimeter = isset($_POST['perimeter_firewalled']) ? 1 : 0;
        $portsText = trim((string) ($_POST['external_ports'] ?? ''));
        $ports = [];
        if ($portsText !== '') {
            foreach (preg_split('/[\s,]+/', $portsText) ?: [] as $token) {
                if (!preg_match('/^([1-9][0-9]{0,4})\/(tcp|udp)$/i', $token, $m) || (int) $m[1] > 65535) {
                    throw new InvalidArgumentException('노출 포트는 22/tcp, 53/udp 형식으로 입력하세요.');
                }
                $ports[strtolower($m[2]) . '/' . (int) $m[1]] = [(int) $m[1], strtolower($m[2])];
            }
        }
        $pdo->beginTransaction();
        $exists = $pdo->prepare('SELECT fqdn FROM tb_host WHERE host_id = ? AND is_deleted = 0 FOR UPDATE');
        $exists->execute([$hostId]);
        $fqdn = $exists->fetchColumn();
        if ($fqdn === false) { throw new RuntimeException('호스트를 찾을 수 없습니다.'); }
        $pdo->prepare('UPDATE tb_host SET perimeter_firewalled = ? WHERE host_id = ?')->execute([$perimeter, $hostId]);
        $pdo->prepare('DELETE FROM tb_host_ext_port WHERE host_id = ?')->execute([$hostId]);
        $insPort = $pdo->prepare('INSERT INTO tb_host_ext_port (host_id, port, proto) VALUES (?, ?, ?)');
        foreach ($ports as [$port, $proto]) { $insPort->execute([$hostId, $port, $proto]); }
        $pdo->commit();
        vg_log_activity($pdo, 'HOST', $hostId, 'host_perimeter_update', '경계 방화벽 설정 변경: ' . (string) $fqdn,
            ['perimeter_firewalled' => $perimeter, 'external_ports' => array_keys($ports)]);
        $latest = $pdo->prepare('SELECT scan_id FROM tb_scan WHERE host_id = ? ORDER BY scan_id DESC LIMIT 1');
        $latest->execute([$hostId]);
        $latestScanId = (int) ($latest->fetchColumn() ?: 0);
        if ($latestScanId > 0) { vg_match_scan($pdo, $latestScanId); }
        $msg = '경계 방화벽 설정을 저장하고 최신 스캔을 다시 매칭했습니다.';
    }
    $st = $pdo->prepare('SELECT * FROM tb_host WHERE host_id = ? AND is_deleted = 0');
    $st->execute([$hostId]);
    $host = $st->fetch() ?: null;

    if ($host) {
        // 호스트 상세(설치 패키지·노출 포트·실행 프로세스 등 인프라 민감정보) 열람 감사로그.
        vg_log_activity($pdo, 'HOST', $hostId, 'view_host', (string) ($host['fqdn'] ?? null));

        // 컬럼을 못 박는 이유: tb_scan.raw_json 은 호스트당 MB 단위(실측 3.14MB)라
        // SELECT * 로 끌면 ORDER BY 의 정렬 버퍼(운영 sort_buffer_size=2M)를 한 행만으로도 넘겨 1038 이 난다.
        $st = $pdo->prepare('SELECT scan_id, collected_at, package_count,
                                    TIMESTAMPDIFF(MINUTE, collected_at, NOW()) AS age_min
                               FROM tb_scan WHERE host_id = ? ORDER BY scan_id DESC LIMIT 1');
        $st->execute([$hostId]);
        $scan = $st->fetch() ?: null;
    }

    if ($scan) {
        $sid = (int) $scan['scan_id'];
        $scanAge = $scan['age_min'];

        // 취약점 0건이 "판정 불가"인 컨테이너 — 피드 미지원 배포판 + **패키지 DB 없는 이미지**.
        //   후자는 rhel 처럼 피드가 지원하는 배포판이라 미지원 경고에 안 걸린다 → 따로 잡아야 한다.
        $st = $pdo->prepare('SELECT cid, os_id, os_version, manager, pkg_count FROM tb_container WHERE scan_id = ?');
        $st->execute([$sid]);
        foreach ($st->fetchAll() as $c) {
            $reason = vg_container_unjudgeable(
                $c['os_id'] ?? null, $c['os_version'] ?? null,
                $c['manager'] ?? null, (int) ($c['pkg_count'] ?? 0)
            );
            if ($reason !== null) {
                $unsupContainers[] = ['cid' => (string) $c['cid'], 'reason' => $reason];
            }
        }

        // --- 히어로/KPI 집계 (탭과 무관한 값싼 COUNT) ---
        $st = $pdo->prepare('SELECT severity, COUNT(*) c FROM tb_finding WHERE scan_id = ? GROUP BY severity');
        $st->execute([$sid]);
        foreach ($st->fetchAll() as $r) { if (isset($counts[$r['severity']])) { $counts[$r['severity']] = (int) $r['c']; } }

        $st = $pdo->prepare('SELECT COUNT(*) FROM tb_exposure WHERE scan_id = ?');
        $st->execute([$sid]); $exposureCount = (int) $st->fetchColumn();

        $st = $pdo->prepare("SELECT COUNT(*) FROM tb_cce_finding WHERE scan_id = ? AND result = 'FAIL'");
        $st->execute([$sid]); $cceFail = (int) $st->fetchColumn();

        $st = $pdo->prepare('SELECT COUNT(*) FROM tb_suppressed_finding WHERE scan_id = ?');
        $st->execute([$sid]); $suppressedCount = (int) $st->fetchColumn();

        // 우선순위 취약점 = CRITICAL·HIGH + 재시작 필요(등급이 낮아도 숨기지 않는다).
        //   탭 배지는 둘의 합, 화면은 두 표로 나눠 보여준다(아래 vuln 탭 주석 참고).
        $st = $pdo->prepare("SELECT COUNT(*) FROM tb_finding
                              WHERE scan_id = ? AND (severity IN ('CRITICAL','HIGH') OR needs_restart = 1)");
        $st->execute([$sid]); $vulnTotal = (int) $st->fetchColumn();

        $st = $pdo->prepare("SELECT COUNT(*) FROM tb_finding
                              WHERE scan_id = ? AND severity IN ('CRITICAL','HIGH')");
        $st->execute([$sid]); $critHighTotal = (int) $st->fetchColumn();

        $st = $pdo->prepare('SELECT COUNT(*) FROM tb_finding WHERE scan_id = ? AND needs_restart = 1');
        $st->execute([$sid]); $restartTotal = (int) $st->fetchColumn();

        $st = $pdo->prepare('SELECT COUNT(*) FROM tb_scan WHERE host_id = ?');
        $st->execute([$hostId]); $scanTotal = (int) $st->fetchColumn();

        $st = $pdo->prepare('SELECT COUNT(*) FROM tb_process WHERE scan_id = ?');
        $st->execute([$sid]); $processCount = (int) $st->fetchColumn();

        // --- 활성 탭 결정 (억제 탭은 건이 있을 때만 존재) ---
        $validTabs = ['vuln', 'runtime', 'cce'];
        if ($suppressedCount > 0) { $validTabs[] = 'suppressed'; }
        $validTabs[] = 'resources';
        $validTabs[] = 'scans';
        $tab = (string) ($_GET['tab'] ?? 'vuln');
        if (!in_array($tab, $validTabs, true)) { $tab = 'vuln'; }

        $page   = vg_page();
        $offset = ($page - 1) * $perPage;
        $ePage  = vg_page('epage');

        // --- 활성 탭 데이터만 조회(+페이지네이션+검색) ---
        if ($tab === 'vuln') {
            ['total' => $total, 'rows' => $rows, 'restartRows' => $restartRows]
                = vg_host_load_vuln_tab($pdo, $sid, $critHighTotal, $perPage, $offset, $q);
        } elseif ($tab === 'runtime') {
            ['total' => $total, 'exposures' => $exposures, 'exposureTotal' => $exposureTotal, 'rows' => $rows, 'ePage' => $ePage]
                = vg_host_load_runtime_tab($pdo, $sid, $perPage, $offset, $ePage, $q);
        } elseif ($tab === 'cce') {
            ['total' => $total, 'rows' => $rows]
                = vg_host_load_cce_tab($pdo, $sid, $perPage, $offset, $q);
        } elseif ($tab === 'suppressed') {
            ['total' => $total, 'rows' => $rows]
                = vg_host_load_suppressed_tab($pdo, $sid, $suppressedCount, $perPage, $offset, $q);
        } elseif ($tab === 'resources') {
            ['resourceScans' => $resourceScans] = vg_host_load_resources_tab($pdo, $hostId);
        } else { // scans
            ['total' => $total, 'rows' => $rows, 'sevByScan' => $sevByScan]
                = vg_host_load_scans_tab($pdo, $hostId, $scanTotal, $perPage, $offset);
        }
    }
} catch (Throwable $e) {
    if (isset($pdo) && $pdo instanceof PDO && $pdo->inTransaction()) { $pdo->rollBack(); }
    error_log('[host] ' . $e->getMessage());
    $err = $e instanceof InvalidArgumentException || $e instanceof RuntimeException ? $e->getMessage() : '처리 중 오류가 발생했습니다.';
}

// 노출 범위 → 뱃지 톤(색은 CSS 가 결정).
//   FILTERED = 전체 인터페이스에 떠 있지만 방화벽이 막아 외부에서 못 닿는 포트.
// LAN = 링크로컬 멀티캐스트(mDNS 등) — 인터넷엔 안 닿고 같은 세그먼트만(외부노출보다 아래).
$scopeTone = ['EXTERNAL' => 'crit', 'LAN' => 'med', 'BOUND' => 'med', 'FILTERED' => 'muted', 'LOCAL' => 'muted'];

vg_header($host['fqdn'] ?? '호스트', 'assets');
?>
<?php if ($err !== null): ?>
  <?php vg_page_title('호스트 상세', 'ASSET DETAIL', '호스트 정보를 불러오지 못했습니다.'); ?>
  <?php vg_alert('오류 · ' . $err); ?>
<?php elseif (!$host): ?>
  <?php vg_page_title('호스트를 찾을 수 없습니다', 'ASSET DETAIL', '삭제되었거나 존재하지 않는 자산입니다.'); ?>
  <div class="card"><?php vg_empty(['icon' => '🖥️', 'title' => '요청한 호스트 정보가 없습니다.', 'cta' => ['href' => '/', 'label' => '← 대시보드']]); ?></div>
<?php elseif (!$scan): ?>
  <?php vg_hero(vg_h($host['fqdn']), [vg_h(trim($host['os_id'] . ' ' . $host['os_version'])), '<a href="/">대시보드</a>'], null, 'ok', '수집 상태', 'ASSET DETAIL'); ?>
  <div class="card"><?php vg_empty(['icon' => '📭', 'title' => '아직 수집된 스캔이 없습니다.', 'hint' => '에이전트를 --send 로 실행하면 여기에 나타납니다.']); ?></div>
<?php else:
    // 최고 위험도 → 히어로 톤. 하나도 없으면 '양호'(ok).
    $worst = null;
    foreach (['CRITICAL','HIGH','MEDIUM','LOW'] as $s) { if ($counts[$s] > 0) { $worst = $s; break; } }
    $heroTone = $worst ? vg_sev_tone($worst) : 'ok';

    // 탭 정의(배열 순서 = 표시 순서). n 은 라벨 옆 숫자(null 이면 숨김).
    $tabDefs = [
        'vuln'    => ['label' => '취약점',    'n' => $vulnTotal],
        'runtime' => ['label' => '런타임',    'n' => $processCount],
        'cce'     => ['label' => '보안 설정', 'n' => $cceFail],
    ];
    if ($suppressedCount > 0) { $tabDefs['suppressed'] = ['label' => '억제', 'n' => $suppressedCount]; }
    $tabDefs['resources'] = ['label' => '리소스', 'n' => null];
    $tabDefs['scans'] = ['label' => '스캔 이력', 'n' => $scanTotal];
?>
  <?php
  $meta = [
      vg_h(trim($host['os_id'] . ' ' . $host['os_version'])) ?: 'OS 미상',
      vg_asset_state($scanAge),
      '최신 수집 ' . vg_h($scan['collected_at']),
      '패키지 ' . number_format((int) $scan['package_count']) . '개',
      '<a href="/">대시보드</a>',
  ];
  if (vg_can('assets')) { $meta[] = '<a href="/assets.php">자산관리</a>'; }
  vg_hero(vg_h($host['fqdn']), $meta, $worst ?? '양호', $heroTone, '최고 위험도', 'ASSET DETAIL');

  $portStmt = $pdo->prepare('SELECT port, proto FROM tb_host_ext_port WHERE host_id = ? AND is_deleted = 0 ORDER BY port, proto');
  $portStmt->execute([$hostId]);
  $portValues = [];
  foreach ($portStmt->fetchAll() as $portRow) {
      $portValues[] = (int) $portRow['port'] . '/' . strtolower((string) $portRow['proto']);
  }
  if ($msg !== null) { vg_alert(['type' => 'ok', 'title' => $msg]); }
  vg_section_title('경계 방화벽 설정', '에이전트가 볼 수 없는 라우터·경계 방화벽 뒤의 호스트만 설정하세요.');
  echo '<div class="card setting-card"><div class="card__body"><form method="post" class="setting-form">';
  echo '<input type="hidden" name="csrf" value="' . vg_h(vg_csrf_token()) . '">';
  echo '<input type="hidden" name="id" value="' . (int) $hostId . '">';
  echo '<label class="check-row"><input type="checkbox" name="perimeter_firewalled" value="1" '
      . (!empty($host['perimeter_firewalled']) ? 'checked' : '')
      . '><span><strong>경계 방화벽 뒤에 있음</strong><small>이 호스트에 실제 외부 공개 포트 기준을 적용합니다.</small></span></label>';
  echo '<label class="field"><span>실제 인터넷 공개 포트</span><input type="text" name="external_ports" value="'
      . vg_h(implode(', ', $portValues)) . '" placeholder="22/tcp, 443/tcp, 8080/tcp"></label>';
  echo '<p class="hint">쉼표 또는 공백으로 구분합니다. 목록에 없는 호스트 EXTERNAL 포트만 FILTERED로 강등되며 컨테이너에는 적용되지 않습니다.</p>';
  echo '<div class="actions"><button type="submit" class="btn btn--primary" data-loading="저장 및 재매칭 중…">저장 및 최신 스캔 재매칭</button></div>';
  echo '</form></div></div>';

  // CVE 피드가 지원하지 않는 배포판이면 매칭 후보가 아예 없어 **취약점이 0건으로 뜬다.**
  //   운영자는 "안전하다"고 읽는다 — 침묵하는 미탐이라 반드시 화면에 알린다.
  $unsup = [];
  $u = vg_distro_unsupported($host['os_id'] ?? null, $host['os_version'] ?? null);
  if ($u !== null) { $unsup[] = '이 호스트 — ' . $u; }
  foreach ($unsupContainers as $c) {
      $unsup[] = '컨테이너 ' . $c['cid'] . ' — ' . $c['reason'];
  }
  if ($unsup) {
      vg_alert([
          'type'  => 'warn',
          'title' => '취약점 매칭이 수행되지 않습니다',
          'hints' => array_merge(
              [
                  '아래 대상은 피드가 모르는 배포판이거나, 패키지 DB 가 없어 무엇이 깔렸는지 알 수 없습니다.',
                  '취약점 0건은 "안전함"이 아니라 "판정 불가"입니다.',
              ],
              $unsup
          ),
      ]);
  }
  ?>

  <div class="cards">
    <?php foreach (['CRITICAL','HIGH','MEDIUM','LOW'] as $s): ?>
      <div class="kpi tone-<?= vg_sev_tone($s) ?>"><b><?= (int) $counts[$s] ?></b><span><?= $s ?></span></div>
    <?php endforeach; ?>
    <div class="kpi"><b><?= number_format($exposureCount) ?></b><span>노출 소켓</span></div>
    <a class="kpi tone-<?= $cceFail > 0 ? 'high' : 'ok' ?>" href="<?= vg_h(vg_qs(['tab' => 'cce', 'page' => null])) ?>">
      <b><?= (int) $cceFail ?></b><span>설정 취약</span>
    </a>
  </div>

  <?php vg_subtabs($tabDefs, $tab); ?>

  <?php if ($tab === 'vuln'):
    // 두 표(CRITICAL·HIGH / 재시작·재부팅)는 열 구성이 같다 — 스펙을 한 번만 만들어 나눠 쓴다.
    $vulnHeaders = [
        ['label' => '등급', 'key' => 'severity'],
        ['label' => '상태', 'key' => 'runtime_status'],
        ['label' => 'CVE'],
        ['label' => 'EPSS'],
        ['label' => '패키지'],
        ['label' => '근거'],
        ['label' => '조치'],
    ];
    $vulnCells = [
        'severity'       => fn($f) => vg_sev_badge((string) $f['severity']),
        'runtime_status' => fn($f) => vg_status_badge($f['runtime_status']),
        2 => fn($f) => '<strong><a href="/cve.php?cve=' . urlencode($f['cve_id']) . '">' . vg_h($f['cve_id']) . '</a></strong>',
        3 => fn($f) => vg_epss_cell($f['epss'], $f['epss_percentile']),
        // 커널은 재부팅해야 새 코드가 올라온다 — 프로세스 재시작으로는 안 고쳐진다.
        4 => fn($f) => vg_h($f['package_name']) . ' <span class="why">' . vg_h($f['installed_version']) . '</span>'
                       . (!empty($f['needs_restart'])
                          ? ' ' . vg_badge(vg_is_kernel_code_pkg((string) ($f['package_name'] ?? '')) ? '재부팅 필요' : '재시작 필요', 'high')
                          : ''),
        5 => fn($f) => '<span class="why">' . vg_trunc($f['rationale']) . '</span>',
        // 재시작/재부팅이 필요하면 조치는 "업그레이드"가 아니다(이미 패치돼 있다).
        6 => fn($f) => !empty($f['needs_restart'])
                       ? '<span class="pill">' . (vg_is_kernel_code_pkg((string) ($f['package_name'] ?? '')) ? '재부팅' : '프로세스 재시작') . '</span>'
                       : vg_fix_cell($f['fixed_version'] ?? null, $f['ref_urls_json'] ?? null, $f['installed_version'] ?? null),
    ];
    $vulnOpts = [
        'card'      => false,
        'row_class' => fn($f) => vg_sev_row((string) $f['severity']),
        'cell'      => $vulnCells,
    ];
  ?>
    <?php vg_toolbar([
        ['type' => 'search', 'name' => 'q', 'placeholder' => 'CVE 또는 패키지명 검색', 'value' => $q],
        ['type' => 'hidden', 'name' => 'tab', 'value' => $tab],
        ['type' => 'hidden', 'name' => 'id', 'value' => (string) $hostId],
    ]); ?>
    <div class="card">
      <strong>우선순위 취약점 (CRITICAL·HIGH)</strong>
      <span class="why">— <a href="/findings.php?scan_id=<?= (int) $scan['scan_id'] ?>">전체 취약점 보기 →</a></span>
      <div class="card__body">
      <?php
      vg_table($vulnHeaders, $rows, $vulnOpts + [
          'empty' => $hasFilter
              ? [
                  'icon'  => '🔍',
                  'title' => '검색 결과가 없습니다.',
                  'hint'  => '검색어를 확인하거나 초기화해 보세요.',
                  'cta'   => ['href' => vg_qs(['q' => null, 'page' => null]), 'label' => '검색 초기화'],
              ]
              : [
                  'icon'  => '✅',
                  'title' => 'CRITICAL·HIGH 가 없습니다.',
                  'hint'  => '아래의 재시작·재부팅 필요 항목은 등급이 낮아도 확인하세요.',
              ],
      ]);
      ?>
      </div>
    </div>
    <?php vg_page_nav($total, $perPage, $page); ?>

    <div class="card mt-lg">
      <strong>재시작·재부팅 필요 <span class="hint">(<?= number_format($restartTotal) ?>건)</span></strong>
      <span class="why">— 패치 완료, 재시작 전까지 옛 코드 실행 중
        <?php if ($restartTotal > count($restartRows)): ?>
          · 상위 <?= count($restartRows) ?>건 ·
          <a href="/findings.php?scan_id=<?= (int) $scan['scan_id'] ?>&amp;fx=restart">전체 보기 →</a>
        <?php endif; ?>
      </span>
      <div class="card__body">
      <?php
      vg_table($vulnHeaders, $restartRows, $vulnOpts + [
          'empty' => [
              'icon'  => '✅',
              'title' => '재시작·재부팅이 필요한 항목이 없습니다.',
              'hint'  => '패치된 라이브러리를 옛 프로세스가 물고 있는 경우가 없습니다.',
          ],
      ]);
      ?>
      </div>
    </div>

  <?php elseif ($tab === 'runtime'): ?>
    <?php vg_toolbar([
        ['type' => 'search', 'name' => 'q', 'placeholder' => '프로세스명·사용자·실행패키지 검색', 'value' => $q],
        ['type' => 'hidden', 'name' => 'tab', 'value' => $tab],
        ['type' => 'hidden', 'name' => 'id', 'value' => (string) $hostId],
    ]); ?>
    <div class="card">
      <strong>런타임 노출</strong> <span class="why">— 어떤 프로세스가 무슨 포트를 열고 어떤 라이브러리를 로드했나</span>
      <div class="card__body">
      <?php
      vg_table(
          [
              ['label' => '범위'],
              ['label' => '위치'],
              ['label' => '프로세스', 'key' => 'proc'],
              ['label' => '포트'],
              ['label' => '실행패키지', 'key' => 'exe_pkg'],
              ['label' => '로드한 패키지'],
          ],
          $exposures,
          [
              'card' => false,
              'empty' => $hasFilter
                  ? [
                      'icon'  => '🔍',
                      'title' => '검색 결과가 없습니다.',
                      'hint'  => '검색어를 확인하거나 초기화해 보세요.',
                      'cta'   => ['href' => vg_qs(['q' => null, 'page' => null, 'epage' => null]), 'label' => '검색 초기화'],
                  ]
                  : [
                      'icon'  => '✅',
                      'title' => '리스닝 소켓이 없습니다.',
                      'hint'  => '외부·내부 포함 열린 포트가 없습니다.',
                  ],
              'cell' => [
                  0 => fn($e) => vg_badge(vg_scope_label((string) $e['scope']), $scopeTone[$e['scope']] ?? 'muted'),
                  1 => fn($e) => $e['ctr'] !== ''
                        ? '<span class="why">컨테이너 ' . vg_h($e['ctr']) . '</span>'
                        : '<span class="why">호스트</span>',
                  3 => fn($e) => vg_h($e['proto']) . '/' . (int) $e['port'],
                  5 => fn($e) => '<span class="why">' . vg_trunc($e['loaded_pkgs'], 60) . '</span>',
              ],
          ]
      );
      ?>
      </div>
    </div>
    <?php vg_page_nav($exposureTotal, $perPage, $ePage, 'epage'); ?>

    <div class="card mt-lg">
      <strong>실행 프로세스</strong> <span class="why">— 실행 중인 프로그램과 소속 패키지(=실행중), 로드한 라이브러리(=사용중)</span>
      <div class="card__body">
      <?php
      vg_table(
          [
              ['label' => 'PID'],
              ['label' => '위치'],
              ['label' => '프로세스', 'key' => 'comm'],
              ['label' => '사용자'],
              ['label' => '실행 패키지', 'key' => 'exe_pkg'],
              ['label' => '로드한 패키지'],
          ],
          $rows,
          [
              'card' => false,
              'empty' => $hasFilter
                  ? [
                      'icon'  => '🔍',
                      'title' => '검색 결과가 없습니다.',
                      'hint'  => '검색어를 확인하거나 초기화해 보세요.',
                      'cta'   => ['href' => vg_qs(['q' => null, 'page' => null, 'epage' => null]), 'label' => '검색 초기화'],
                  ]
                  : [
                      'icon'  => '🗂️',
                      'title' => '실행 프로세스 데이터가 없습니다.',
                      'hint'  => '구버전 에이전트로 수집된 스캔입니다.',
                  ],
              'cell' => [
                  0 => fn($pr) => '<span class="why">' . (int) $pr['pid'] . '</span>',
                  1 => fn($pr) => $pr['ctr'] !== ''
                        ? '<span class="why">컨테이너 ' . vg_h($pr['ctr']) . '</span>'
                        : '<span class="why">호스트</span>',
                  3 => fn($pr) => '<span class="why">' . vg_h($pr['username']) . '</span>',
                  5 => fn($pr) => '<span class="why">' . vg_trunc($pr['loaded_pkgs'], 60) . '</span>',
              ],
          ]
      );
      ?>
      </div>
    </div>
    <?php vg_page_nav($total, $perPage, $page); ?>

  <?php elseif ($tab === 'cce'): ?>
    <?php vg_toolbar([
        ['type' => 'search', 'name' => 'q', 'placeholder' => '코드·점검항목·SSG 룰 검색', 'value' => $q],
        ['type' => 'hidden', 'name' => 'tab', 'value' => $tab],
        ['type' => 'hidden', 'name' => 'id', 'value' => (string) $hostId],
    ]); ?>
    <div class="card">
      <strong>보안 설정 점검 (CCE)</strong>
      <span class="why">— 버전이 아닌 설정 점검 · NA=미수집</span>
      <div class="card__body">
      <?php
      // 결과 → 톤: FAIL 은 위험도색, PASS 는 low(초록), NA 는 muted.
      $cceBadge = function (array $r): string {
          $tone = $r['result'] === 'FAIL' ? vg_sev_tone($r['severity'])
                : ($r['result'] === 'PASS' ? 'low' : 'muted');
          return vg_badge($r['result'], $tone);
      };
      // 기준 배지 — 이 점검이 **어느 룰셋의 어느 항목**에 근거하는지 보여준다.
      //   예전엔 우리가 정한 코드(CCE-SSH-ROOT)만 있어서 "왜 이게 기준인가" 를 답할 수 없었다.
      //   이제 SSG 룰에 묶여 있고, 그 룰이 CIS·NIST·STIG 참조를 들고 있다.
      $refBadges = static function (array $r): string {
          if (empty($r['ssg_rule_id'])) {
              return '<span class="why">자체 기준(대응 SSG 룰 없음)</span>';
          }
          $refs = vg_json_col($r['refs_json'] ?? '');
          $html = '';
          foreach ($refs as $k => $v) {
              // 기관 기준만 보여준다 — cis-csc 같은 상위 카테고리는 항목 번호가 아니라 생략.
              if (strncmp((string) $k, 'cis@', 4) === 0) {
                  $html .= ' ' . vg_badge('CIS ' . $v, 'info', 'CIS 벤치마크 ' . $k . ' 항목 ' . $v);
              } elseif ($k === 'nist') {
                  $html .= ' ' . vg_badge('NIST ' . vg_trunc((string) $v, 14), 'muted', 'NIST 800-53: ' . $v);
              } elseif ($k === 'stigid') {
                  $html .= ' ' . vg_badge('STIG', 'muted', 'DISA STIG: ' . $v);
              }
          }
          $ruleId = (string) $r['ssg_rule_id'];
          $rule = '<a href="/compliance_rule.php?rule=' . urlencode($ruleId) . '">'
              . '<code class="why">' . vg_h($ruleId) . '</code></a>';
          return $rule . ($html !== '' ? '<br>' . $html : '');
      };

      vg_table(
          [
              ['label' => '결과', 'key' => 'result'],
              ['label' => '점검 항목', 'key' => 'title'],
              ['label' => '코드', 'key' => 'code'],
              ['label' => '기준(SSG 룰 · CIS/NIST)'],
              ['label' => '근거'],
              ['label' => '사유'],
          ],
          $rows,
          [
              'card' => false,
              'empty' => $hasFilter
                  ? [
                      'icon'  => '🔍',
                      'title' => '검색 결과가 없습니다.',
                      'hint'  => '검색어를 확인하거나 초기화해 보세요.',
                      'cta'   => ['href' => vg_qs(['q' => null, 'page' => null]), 'label' => '검색 초기화'],
                  ]
                  : [
                      'icon'  => '🗂️',
                      'title' => 'CCE 점검 데이터가 없습니다.',
                      'hint'  => '구버전 에이전트 또는 security/users 미수집입니다.',
                  ],
              'cell' => [
                  'result' => $cceBadge,
                  'code'   => fn($r) => '<code>' . vg_h($r['code']) . '</code>',
                  3 => $refBadges,
                  4 => fn($r) => '<span class="why">' . vg_trunc($r['evidence'], 40) . '</span>',
                  5 => fn($r) => '<span class="why">' . vg_trunc($r['rationale']) . '</span>',
              ],
          ]
      );
      ?>
      </div>
    </div>
    <?php vg_page_nav($total, $perPage, $page); ?>

  <?php elseif ($tab === 'suppressed'): ?>
    <?php vg_toolbar([
        ['type' => 'search', 'name' => 'q', 'placeholder' => 'CVE 또는 패키지명 검색', 'value' => $q],
        ['type' => 'hidden', 'name' => 'tab', 'value' => $tab],
        ['type' => 'hidden', 'name' => 'id', 'value' => (string) $hostId],
    ]); ?>
    <div class="card">
      <strong>백포트로 억제된 취약점</strong>
      <span class="why">— 백포트로 이미 수정됨 · 오탐 제외 근거</span>
      <div class="card__body">
      <?php
      vg_table(
          [
              ['label' => '원래등급', 'key' => 'base_severity'],
              ['label' => 'CVE'],
              ['label' => '대상', 'key' => 'target'],
              ['label' => '패키지'],
              ['label' => '억제 근거'],
          ],
          $rows,
          [
              'card' => false,
              'empty' => $hasFilter
                  ? [
                      'icon'  => '🔍',
                      'title' => '검색 결과가 없습니다.',
                      'hint'  => '검색어를 확인하거나 초기화해 보세요.',
                      'cta'   => ['href' => vg_qs(['q' => null, 'page' => null]), 'label' => '검색 초기화'],
                  ]
                  : [
                      'icon'  => '✅',
                      'title' => '억제된 취약점이 없습니다.',
                      'hint'  => '백포트로 억제 처리된 항목이 없습니다.',
                  ],
              'row_class' => fn($r) => vg_sev_row((string) $r['base_severity']),
              'cell' => [
                  'base_severity' => fn($r) => vg_sev_badge((string) $r['base_severity'])
                      . ((int) $r['in_kev'] === 1 ? ' ' . vg_badge('KEV', 'crit') : ''),
                  1 => fn($r) => '<strong><a href="/cve.php?cve=' . urlencode($r['cve_id']) . '">' . vg_h($r['cve_id']) . '</a></strong>',
                  3 => fn($r) => vg_h($r['package_name']) . ' <span class="why">' . vg_h($r['installed_version']) . '</span>',
                  4 => fn($r) => '<span class="why">' . vg_trunc($r['suppress_reason'], 90) . '</span>',
              ],
          ]
      );
      ?>
      </div>
    </div>
    <?php vg_page_nav($total, $perPage, $page); ?>

  <?php elseif ($tab === 'resources'):
    $latestResourceScan = $resourceScans ? end($resourceScans) : null;
  ?>
    <div class="card">
      <strong>메모리 사용률 추이</strong>
      <span class="why">— 호스트 총 메모리(mem_total_mb) 대비 %. 스펙 미수집 스캔은 이 지표에서 제외됩니다.</span>
      <div class="card__body">
      <?php vg_resource_trend($resourceScans, 'mem_pct', '%', 1, 'mem'); ?>
      </div>
    </div>

    <div class="card mt-lg">
      <strong>메모리 사용량 추이</strong>
      <span class="why">— 스캔당 피크 RSS(최근 <?= count($resourceScans) ?>건)
        <?php if ($latestResourceScan && $latestResourceScan['mem_pct'] !== null): ?>
          · 현재 <?= vg_resource_pct($latestResourceScan['mem_pct']) ?>(호스트 총 메모리 대비)
        <?php endif; ?>
      </span>
      <div class="card__body">
      <?php vg_resource_trend($resourceScans, 'peak_rss_mb', 'MB', 0, 'mem'); ?>
      </div>
    </div>

    <div class="card mt-lg">
      <strong>CPU 사용률 추이</strong>
      <span class="why">— 코어수(cpu_cores) 대비 %. 스펙 미수집 스캔은 이 지표에서 제외됩니다.</span>
      <div class="card__body">
      <?php vg_resource_trend($resourceScans, 'cpu_pct', '%', 1, 'cpu'); ?>
      </div>
    </div>

    <div class="card mt-lg">
      <strong>CPU 사용량 추이</strong>
      <span class="why">— 스캔당 CPU 점유 시간(초, 자식 프로세스 포함)
        <?php if ($latestResourceScan && $latestResourceScan['cpu_pct'] !== null): ?>
          · 현재 <?= vg_resource_pct($latestResourceScan['cpu_pct']) ?>(코어수 대비)
        <?php endif; ?>
      </span>
      <div class="card__body">
      <?php vg_resource_trend($resourceScans, 'cpu_seconds', 's', 1, 'cpu'); ?>
      </div>
    </div>

  <?php else: /* scans */ ?>
    <div class="card">
      <strong>스캔 이력</strong> <span class="why">— 회차를 눌러 그 시점의 취약점을 본다</span>
      <div class="card__body">
      <?php
      vg_table(
          [
              ['label' => '스캔', 'key' => 'scan_id'],
              ['label' => '수집시각', 'key' => 'collected_at'],
              ['label' => '수신시각', 'key' => 'received_at'],
              ['label' => '패키지', 'key' => 'package_count', 'align' => 'right'],
              ['label' => '노출', 'key' => 'exposure_count', 'align' => 'right'],
              ['label' => '메모리', 'key' => 'peak_rss_mb', 'align' => 'right'],
              ['label' => 'CPU', 'key' => 'cpu_seconds', 'align' => 'right'],
              ['label' => '에이전트', 'key' => 'agent_version'],
              ['label' => '심각도', 'key' => 'sev'],
          ],
          $rows,
          [
              'card' => false,
              'empty' => [
                  'icon'  => '🕘',
                  'title' => '스캔 이력이 없습니다.',
              ],
              'cell' => [
                  'scan_id'        => fn($s) => '<a href="/findings.php?scan_id=' . (int) $s['scan_id'] . '">#' . (int) $s['scan_id'] . '</a>',
                  'collected_at'   => fn($s) => vg_h($s['collected_at']),
                  'received_at'    => fn($s) => '<span class="why">' . vg_h($s['received_at']) . '</span>',
                  'package_count'  => fn($s) => number_format((int) $s['package_count']),
                  'exposure_count' => fn($s) => number_format((int) $s['exposure_count']),
                  'peak_rss_mb'    => fn($s) => vg_resource_mem($s['peak_rss_mb']),
                  'cpu_seconds'    => fn($s) => vg_resource_cpu($s['cpu_seconds']),
                  'agent_version'  => fn($s) => $s['agent_version'] ? '<code>' . vg_h($s['agent_version']) . '</code>' : '<span class="why">–</span>',
                  'sev' => fn($s) => vg_sev_counts($sevByScan[(int) $s['scan_id']] ?? []),
              ],
          ]
      );
      ?>
      </div>
    </div>
    <?php vg_page_nav($total, $perPage, $page); ?>
  <?php endif; ?>
<?php endif; ?>
<?php vg_footer();
