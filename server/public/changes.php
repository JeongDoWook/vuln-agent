<?php
declare(strict_types=1);

/**
 * changes.php — 변화 추적(시계열). 로그인 필요(취약점 메뉴 권한 재사용).
 *   각 호스트의 "최근 2개 스캔"을 비교해 무엇이 달라졌는지 보여준다.
 *     - 신규   : 지난 스캔엔 없다가 이번에 생긴 취약점
 *     - 해결   : 지난 스캔엔 있었는데 이번에 사라진 것
 *     - 등급↑/↓: 양쪽에 있으나 심각도가 바뀐 것
 *   취약점 식별자는 (cve_id, package_name). 새 테이블 없이 tb_finding 만 대조한다.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require_once __DIR__ . '/../src/audit.php';   // vg_log_activity — auth.php 가 이미 로드했을 수 있다
require_once __DIR__ . '/../src/distro.php'; // vg_osv_ecosystem — 패키지 상세 링크(아래 vg_package_detail_link)
vg_require_menu('findings');

const VG_SEV_RANK = ['LOW' => 1, 'MEDIUM' => 2, 'HIGH' => 3, 'CRITICAL' => 4];
// 변화유형: 정렬·필터·배지에 공유
const VG_CHANGE_TYPES = ['new' => '신규', 'up' => '등급 상승', 'down' => '등급 하락', 'resolved' => '해결'];
// 패키지 변경유형(tb_pkg_change.change_type)
const VG_PKG_CHANGE_TYPES = [
    'installed'   => '설치',
    'removed'     => '제거',
    'upgraded'    => '업그레이드',
    'downgraded'  => '다운그레이드',
];
// 다운그레이드는 되돌아간 것이라 눈에 띄어야 한다(취약 버전으로 회귀했을 수 있다).
function vg_pkgchg_tone(string $t): string {
    return ['upgraded' => 'ok', 'installed' => 'med', 'removed' => 'muted', 'downgraded' => 'high'][$t] ?? 'muted';
}

$err = null;
$changes = [];
$summary = ['new' => 0, 'up' => 0, 'down' => 0, 'resolved' => 0];
$hostOptions = [];
$baselineHosts = [];   // 스캔이 1개뿐이라 비교 불가(첫 수집)

$hostId = (int) ($_GET['host'] ?? 0);
$type   = (string) ($_GET['type'] ?? '');
$q      = trim((string) ($_GET['q'] ?? ''));   // CVE·패키지명 부분일치 검색
$page   = vg_page();
$perPage = vg_perpage();
if (!isset(VG_CHANGE_TYPES[$type])) { $type = ''; }

// 회차별 추이 탭의 구간 선택. 'all' 은 무한정 불러오지 않도록 vg_ui_trend_limit() 로 상한을 건다.
$windowOptions = ['5' => '최근 5회차', '10' => '최근 10회차', 'all' => '전체 기간'];
$window = (string) ($_GET['window'] ?? '10');
if (!isset($windowOptions[$window])) { $window = '10'; }
$windowLimit = $window === 'all' ? vg_ui_trend_limit() : (int) $window;

// 취약점 변화 / 패키지 변경 / 추이 — 세 목록을 세로로 쌓지 않고 탭으로 가른다.
//   ?page= 는 활성 탭에만 적용된다(페이저가 하나만 살아 있게).
$tab = (string) ($_GET['tab'] ?? 'vuln');
if (!in_array($tab, ['vuln', 'pkg', 'trend'], true)) { $tab = 'vuln'; }

$pkgChanges = []; $pkgTotal = 0;
$trendRounds = []; $trendResolvedAll = [];
$trendSummary = ['new' => 0, 'up' => 0, 'down' => 0, 'resolved' => 0];
$trendNeedsHost = false;

try {
    $pdo = vg_pdo();

    /* 패키지 변경 이력. 예전엔 LIMIT 200 으로 잘라놓고 "더 있다" 는 표시가 없어서
     * 201번째부터의 변경은 화면에서 볼 방법이 아예 없었다 — 제대로 페이지네이션한다.
     * 호스트 필터는 취약점 변화 목록과 공유한다. */
    $pkgFrom = 'FROM tb_pkg_change c
                JOIN tb_host h ON h.host_id = c.host_id AND h.is_deleted = 0
                JOIN tb_scan s ON s.scan_id = c.scan_id
               WHERE c.is_deleted = 0'
             . ($hostId ? ' AND c.host_id = ?' : '')
             . ($q !== '' ? ' AND c.package_name LIKE ?' : '');
    // COUNT·SELECT 가 같은 WHERE 를 쓰므로 파라미터 순서를 그대로 맞춘다(host → q).
    $pkgParams = [];
    if ($hostId)  { $pkgParams[] = $hostId; }
    if ($q !== '') { $pkgParams[] = '%' . $q . '%'; }

    $st = $pdo->prepare("SELECT COUNT(*) $pkgFrom");
    $st->execute($pkgParams);
    $pkgTotal = (int) $st->fetchColumn();

    if ($tab === 'pkg') {
        $pkgOffset = ($page - 1) * $perPage;
        $st = $pdo->prepare(
            "SELECT c.host_id, h.fqdn, c.manager, c.package_name, c.change_type,
                    c.old_version, c.new_version, s.collected_at AS `when`,
                    s.os_id AS package_os_id, s.os_version AS package_os_version
             $pkgFrom
             ORDER BY c.pkg_change_id DESC
             LIMIT $perPage OFFSET $pkgOffset"
        );
        $st->execute($pkgParams);
        $pkgChanges = $st->fetchAll(PDO::FETCH_ASSOC);
    }

    // 호스트별 스캔을 최신순으로. PHP 에서 앞의 2개(최신·직전)만 취한다.
    $rows = $pdo->query(
        "SELECT s.host_id, h.fqdn, s.scan_id, s.collected_at
           FROM tb_scan s
           JOIN tb_host h ON h.host_id = s.host_id AND h.is_deleted = 0
          WHERE s.is_deleted = 0
          ORDER BY s.host_id, s.scan_id DESC"
    )->fetchAll(PDO::FETCH_ASSOC);

    $perHost = [];   // host_id => [{scan_id, fqdn, collected_at}, ...] 최신순
    foreach ($rows as $r) {
        $hid = (int) $r['host_id'];
        $hostOptions[$hid] = (string) $r['fqdn'];
        if (count($perHost[$hid] ?? []) < 2) { $perHost[$hid][] = $r; }
    }

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
    //   (vg_change_row() 는 cve_id/package_name/severity/in_kev/exposed/rationale 만 쓴다).
    $bySc = [];
    if ($scanIds) {
        $in = implode(',', array_map('intval', $scanIds));
        $fst = $pdo->query(
            "SELECT f.scan_id, f.cve_id, f.package_name, f.severity, f.in_kev, f.exposed,
                    f.rationale, f.installed_version,
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

    if ($type !== '') {
        $changes = array_values(array_filter($changes, fn($c) => $c['type'] === $type));
    }
    if ($q !== '') {
        // CVE·패키지명 대소문자 무시 부분일치(둘 다 ASCII라 stripos 로 충분).
        $changes = array_values(array_filter(
            $changes,
            fn($c) => stripos($c['cve_id'], $q) !== false || stripos($c['package_name'], $q) !== false
        ));
    }

    // 추이 탭 — 호스트 전체 합산은 findings 자기조인급 비용이 나므로(위 주석과 같은 이유)
    // 호스트를 선택했을 때만 계산한다. 전체는 안내 문구로 유도.
    if ($tab === 'trend') {
        if ($hostId <= 0 || !isset($hostOptions[$hostId])) {
            // 존재하지 않거나 삭제된 호스트 id 는 존재하는 것처럼 라벨을 만들지 않는다 — 그냥 미선택으로 취급.
            $trendNeedsHost = true;
        } else {
            $trendFqdn = $hostOptions[$hostId];
            $trendData = vg_trend_load($pdo, $hostId, $trendFqdn, $windowLimit);
            $trendRounds = $trendData['rounds'];
            $trendResolvedAll = $trendData['resolved'];
            $trendSummary = $trendData['summary'];
        }
    }

    /* 열람 감사 — 이 화면은 자산별 CVE·패키지 변경 이력을 보여준다. 같은 성격의
     *   nofix-packages.php 는 남기는데 여기만 빠져 있어서, "누가 어느 자산의 변화를 봤나"가
     *   기록되지 않았다. scope_id 는 비운다(scope 가 'PAGE' 인데 host_id 를 넣으면 페이지 id 로 읽힌다). */
    vg_log_activity($pdo, 'PAGE', null, 'view_changes', '변화 추적 조회',
        ['tab' => $tab, 'host_id' => $hostId, 'type' => $type, 'q' => $q]);
} catch (Throwable $e) {
    error_log('[changes] ' . $e->getMessage());
    $err = '처리 중 오류가 발생했습니다.';
}

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
        'rationale'        => (string) ($f['rationale'] ?? ''),
        'installed_version'=> (string) ($f['installed_version'] ?? ''),
        'package_os_id'     => $f['package_os_id'] ?? null,
        'package_os_version'=> $f['package_os_version'] ?? null,
        'cur_scan_id'      => $curScanId,
        'reason'           => '',
    ];
}

function vg_change_tone(string $type): string {
    return ['new' => 'crit', 'up' => 'high', 'down' => 'muted', 'resolved' => 'ok'][$type] ?? 'muted';
}

/**
 * 이 화면 안의 갈래(취약점 변화 · 패키지 변경 · 추이).
 *   위의 '탐지 결과' 줄(vg_findings_subtabs → .subtabs, 밑줄형)은 **화면을 바꾸는** 내비이고,
 *   이 줄은 **같은 화면 안에서 무엇을 볼지** 고르는 것이다. 둘 다 vg_subtabs() 로 그리던 동안엔
 *   탭 줄이 두 개 똑같이 생겨 어느 쪽이 상위인지 화면에서 안 읽혔다 — 그래서 이 줄만
 *   알약형(.tabs/.pill, cves.php·vendor.php 의 화면 내 선택과 같은 컴포넌트)으로 내려 그린다.
 *   ?tab= 키 이름은 그대로 둔다(다른 화면에서 들어오는 링크가 깨지지 않게).
 */
function vg_change_tabs(array $tabs, string $active): void {
    echo '<div class="tabs">';
    foreach ($tabs as $key => $def) {
        $on = $active === (string) $key;
        echo '<a class="pill' . ($on ? ' pill--on' : '') . '"'
            . ' href="' . vg_h(vg_qs(['tab' => $key, 'page' => null])) . '">'
            . vg_h((string) $def['label'])
            . (isset($def['n']) ? ' ' . number_format((int) $def['n']) : '')
            . '</a>';
    }
    echo '</div>';
}

/** 실제 스캔 대상의 OS 생태계가 식별되는 패키지만 상세 링크로 만든다. */
function vg_package_detail_link(array $row): string {
    $name = (string) $row['package_name'];
    $ecosystem = vg_osv_ecosystem($row['package_os_id'] ?? null, $row['package_os_version'] ?? null);
    if ($ecosystem === null) { return vg_h($name); }
    return '<a href="/package.php?name=' . urlencode($name) . '&amp;eco=' . urlencode($ecosystem) . '">'
         . vg_h($name) . '</a>';
}

/** 취약점 변화·추이의 패키지 셀. 두 목록이 같은 판정 근거를 빠뜨리지 않게 한곳에서 렌더한다. */
function vg_change_package_cell(array $row): string {
    $out = vg_package_detail_link($row);
    if (($row['installed_version'] ?? '') !== '') {
        $out .= ' <span class="why">' . vg_h((string) $row['installed_version']) . '</span>';
    }

    $rationale = trim((string) ($row['rationale'] ?? ''));
    if ($rationale !== '') {
        $label = ($row['type'] ?? '') === 'resolved' ? '직전 판정 근거' : '판정 근거';
        $out .= '<details><summary>' . $label . '</summary><div class="why">'
              . nl2br(vg_h($rationale)) . '</div></details>';
    }
    return $out;
}

/**
 * 취약점 변화·추이의 등급 셀 — 등급(+이전 등급)과 외부노출까지. **가로로** 눕힌다.
 *   예전엔 여기에 변화 사유까지 얹혀 6.5rem 칸 안에서 세 값이 세로로 쌓였고(한 행이 3줄),
 *   사유는 그 좁은 칸에서 잘려 문장이 끊겼다. 사유는 '변화' 칸으로 옮겼다(변화와 그 이유는
 *   같이 읽는 값이다). 이 칸의 폭(10rem)은 'MEDIUM → [HIGH] [외부노출]' 이 한 줄에 들어가는 값.
 */
function vg_change_severity_cell(array $row): string {
    $severity = vg_sev_badge((string) $row['severity']);
    if (!empty($row['from_sev'])) {
        $severity = '<span class="why">' . vg_h((string) $row['from_sev']) . ' →</span> ' . $severity;
    }
    if (!empty($row['exposed'])) { $severity .= ' ' . vg_badge('외부노출', 'high'); }
    return $severity;
}

/** 수집 시각 셀 — 분까지만 보이고 전체 값은 title 로 남긴다(좁은 칸에서 잘리지 않게). */
function vg_change_when_cell(array $row): string {
    $when = (string) ($row['when'] ?? '');
    if ($when === '') { return '<span class="why">–</span>'; }
    return '<span class="why" title="' . vg_h($when) . '">' . vg_h(substr($when, 0, 16)) . '</span>';
}

/** 변화 유형 + 그렇게 된 이유. 사유는 문장이라 이 칸에서 접히게 둔다(잘리지 않는다). */
function vg_change_type_cell(array $row): string {
    $out = vg_badge(VG_CHANGE_TYPES[$row['type']], vg_change_tone((string) $row['type']));
    // 사유는 문장이라 셀에 그대로 깔면 행 높이가 제각각이 된다(실측: '업그레이드로 신규 노출
    //   (1.2.3 → 1.2.4)' 는 이 칸에서 세 줄로 접혔다). **짧은 라벨 뱃지로 접고 원문은 툴팁으로**
    //   넘긴다 — title 은 app.js 가 CSS 툴팁(.info-tooltip)으로 승격하므로 브라우저 기본
    //   툴팁의 1초 지연·OS 기본 모양을 타지 않는다(PR#225 와 같은 경로).
    if (($row['reason'] ?? '') !== '') {
        $short = (string) ($row['reason_short'] ?? '');
        $out .= ' ' . vg_badge($short !== '' ? $short : '사유', 'muted', (string) $row['reason']);
    }
    return $out;
}

/**
 * 사유의 **짧은 라벨**(표 셀의 뱃지용). 원문은 vg_change_reason() 이 그대로 만들고 툴팁으로 붙는다.
 *   두 함수는 같은 판정(type + tb_pkg_change 대조)을 보므로 분기를 나란히 둔다 — 한쪽만 고치면
 *   뱃지와 툴팁이 서로 다른 말을 하게 된다.
 */
function vg_change_reason_short(string $type, ?array $pc): string {
    if ($type === 'new') {
        if ($pc && $pc['change_type'] === 'installed') { return '새 설치'; }
        if ($pc && $pc['change_type'] === 'upgraded')  { return '버전 변경'; }
        return '신규 공표';
    }
    if ($type === 'resolved') {
        if ($pc && $pc['change_type'] === 'removed')  { return '제거됨'; }
        if ($pc && $pc['change_type'] === 'upgraded') { return '패치 적용'; }
        return '재판정';
    }
    return $pc && in_array($pc['change_type'], ['upgraded', 'downgraded'], true) ? '버전 변경' : '';
}

/** tb_pkg_change 대조 결과(없으면 null)로 변화 사유 문구를 만든다. 추측성 사유는 만들지 않는다. */
function vg_change_reason(string $type, ?array $pc): string {
    if ($type === 'new') {
        if ($pc && in_array($pc['change_type'], ['installed', 'upgraded'], true)) {
            return $pc['change_type'] === 'installed'
                ? '새 설치 (' . $pc['new_version'] . ')'
                : '업그레이드로 신규 노출 (' . $pc['old_version'] . ' → ' . $pc['new_version'] . ')';
        }
        return '기존 패키지·신규 CVE 공표';
    }
    if ($type === 'resolved') {
        if ($pc && in_array($pc['change_type'], ['removed', 'upgraded'], true)) {
            return $pc['change_type'] === 'removed'
                ? '패키지 제거됨'
                : '패치 적용 (' . $pc['new_version'] . ')';
        }
        return '재판정으로 해결';
    }
    // up | down: 등급 변화는 이미 배지로 보이므로, 버전도 같이 바뀐 경우에만 부가 정보를 붙인다.
    if ($pc && in_array($pc['change_type'], ['upgraded', 'downgraded'], true)) {
        return '패키지 버전도 ' . $pc['old_version'] . ' → ' . $pc['new_version'] . ' 변경됨';
    }
    return '';
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
        "SELECT scan_id, cve_id, package_name, severity, in_kev, exposed, rationale, installed_version
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

vg_header('변화 추적', 'changes');
?>
  <?php vg_page_title('변화 추적', 'CHANGES', '직전 수집과 비교해 신규·해결·등급 변화를 보여줍니다.'); ?>

  <?php /* 탐지 결과 계열의 갈래 — 정의는 nav.php 의 vg_findings_subtabs() 한 곳에만 있다.
           사이드바엔 '탐지 결과' 하나만 있고 이 화면은 이 줄로만 들어온다. */ ?>
  <?php vg_findings_subtabs('changes'); ?>

  <?php
  // 화면 오리엔테이션 도식 — 이 화면의 모든 수는 **두 수집 사이의 차이**다. 무엇과 무엇을
  //   비교했는지가 안 보이면 "신규 12" 가 전체 12건인지 늘어난 12건인지 읽히지 않는다.
  //   값은 '취약점 변화' 탭의 합계($summary)와 같은 것이다(탭을 옮겨도 비교 축은 그대로다).
  vg_explain_flow([
      ['icon' => 'clock', 'label' => '직전 수집', 'state' => 'done'],
      ['icon' => 'clock', 'label' => '이번 수집', 'state' => 'active'],
      ['icon' => 'warn',  'label' => '신규',      'value' => number_format((int) $summary['new'])],
      ['icon' => 'check', 'label' => '해결',      'value' => number_format((int) $summary['resolved'])],
  ], ['label' => '변화 비교 흐름']);
  ?>

<?php if ($err !== null): ?>
  <?php vg_alert('오류 · ' . $err); ?>
<?php else: ?>

  <?php
  /* 두 단의 탭을 시각적으로 가른다 — 위 줄(.subtabs)은 화면 전환, 이 줄(.tabs/.pill)은
   * 이 화면 안의 갈래. 그리고 요약 KPI 는 두 탭 줄 **사이**에 두지 않는다(예전엔 거기 끼어
   * 있어서 "지금 어디에 있는지" 를 잃었다). KPI 는 '취약점 변화' 탭의 내용이라 그 탭 안으로
   * 내렸다 — 실제로 그 4개는 취약점 변화 목록의 type 필터이기도 하다. */
  $total = count($changes);
  vg_change_tabs([
      'vuln'  => ['label' => '취약점 변화', 'n' => $total],
      'pkg'   => ['label' => '패키지 변경', 'n' => $pkgTotal],
      'trend' => ['label' => '추이'],
  ], $tab);
  ?>

  <?php if ($tab === 'vuln'): ?>
    <?php
    /* 요약 KPI — '취약점 변화' 탭의 내용이다(다른 탭에선 뜻이 없다). 눌러서 그 변화유형만
     *   거른다(다시 누르면 풀린다). 0건이면 톤을 뺀다 — "신규 0건" 은 좋은 소식인데 붉은
     *   테두리가 붙으면 경고로 읽힌다. */
    $changeTone = ['new' => 'crit', 'up' => 'high', 'down' => 'low', 'resolved' => 'ok'];
    ?>
    <div class="cards">
      <?php foreach (VG_CHANGE_TYPES as $k => $lbl): ?>
        <a class="kpi kpi--sm<?= $summary[$k] > 0 ? ' tone-' . vg_h($changeTone[$k]) : '' ?><?= $type === $k ? ' is-selected' : '' ?>"
           href="<?= vg_h(vg_qs(['type' => $type === $k ? '' : $k, 'tab' => 'vuln', 'page' => 1])) ?>">
          <b><?= (int) $summary[$k] ?></b><span><?= vg_h($lbl) ?></span>
        </a>
      <?php endforeach; ?>
    </div>
  <?php endif; ?>

  <?php
  // 변화유형 필터는 취약점 변화 탭에만, 구간 필터는 추이 탭에만 뜻이 있다.
  //   추이 탭엔 검색어(q)도 뜻이 없다 — 회차 전체를 보는 화면이라.
  $filters = [];
  $filters[] = ['type' => 'select', 'name' => 'host', 'selected' => (string) ($hostId ?: ''),
                'empty_label' => '전체 호스트', 'options' => $hostOptions];
  if ($tab === 'vuln') {
      $filters[] = ['type' => 'select', 'name' => 'type', 'selected' => $type,
                    'empty_label' => '전체 변화', 'options' => VG_CHANGE_TYPES];
  }
  if ($tab === 'trend') {
      $filters[] = ['type' => 'select', 'name' => 'window', 'selected' => $window,
                    'empty_label' => '최근 10회차(기본)', 'options' => $windowOptions];
  }
  if ($tab !== 'trend') {
      $filters[] = ['type' => 'search', 'name' => 'q', 'placeholder' => 'CVE·패키지명 검색', 'value' => $q];
  }
  $filters[] = ['type' => 'hidden', 'name' => 'tab', 'value' => $tab];
  vg_toolbar($filters);

  if ($baselineHosts) {
      // 호스트 수가 많으면(운영에서 실측 50+대) 한 줄 텍스트로는 화면을 다 차지한다 —
      // findings.php 의 "판정 불가" 목록과 같은 컴포넌트(.hint-list, 스크롤 캡)를 재사용한다.
      echo '<div class="sub">기준선(첫 수집이라 비교 대상 없음)</div>';
      echo '<ul class="hint-list">';
      foreach ($baselineHosts as $bh) { echo '<li>' . vg_h($bh) . '</li>'; }
      echo '</ul>';
  }
  ?>

  <?php if ($tab === 'vuln'): ?>
    <?php
    $paged = array_slice($changes, ($page - 1) * $perPage, $perPage);

    // 사유 판별: 현재 페이지 행만 대상으로 tb_pkg_change 를 한 번에 대조(N+1 금지).
    if ($err === null && $paged) {
        try {
            vg_attach_change_reason($pdo, $paged);
        } catch (Throwable $e) {
            error_log('[changes] detail lookup: ' . $e->getMessage());
        }
    }

    vg_table(
        [
            // 폭은 머리글 글자까지 담아야 한다 — th 는 nowrap 이라 좁으면 옆 열을 덮고,
            //   맨 끝 열('수집 시각')이 넘치면 표가 카드 밖으로 밀린다(861px 에서 1px 넘쳤다).
            //   남는 폭은 자유폭인 '호스트'·'패키지' 가 나눠 갖는다 — 열을 새로 늘리지 않은 이유가
            //   이것이다: 열이 하나 늘면 그 폭은 결국 식별자(호스트·패키지)에서 빠져 나온다.
            // 변화 뱃지 + 그 이유(문장)를 한 칸에 담는다. 사유는 nowrap 을 주지 않아 접힌다.
            ['label' => '변화 · 사유', 'width' => '16%',
             'title' => '무엇이 달라졌는지와, 왜 그렇게 됐는지(패키지 변경 이력 대조 결과)'],
            ['label' => '호스트'],
            // 'CVE-2023-44487' + KEV 뱃지 + 칸 여백이 들어가야 한다 — 16%(1030px 표에서 165px)는
            //   nowrap·말줄임이라 KEV 뱃지가 잘려 나갔다. 1440px 에서 이 칸의 실측 필요폭은
            //   180px(값 + 뱃지 + 칸 여백 35) → 11.5rem.
            ['label' => 'CVE', 'width' => '11.5rem', 'nowrap' => true],
            ['label' => '패키지'],
            // 등급 뱃지도 고정 크기다 — 12% 는 870px 에서 66px 라 CRITICAL 뱃지가 18.3px 넘쳤다.
            //   여기엔 이전 등급·외부노출까지 가로로 눕혀 담는다:
            //   'MEDIUM →' + 뱃지 + '외부노출' 셋이 동시에 오는 건 등급 변화 행뿐이다. 흔한 조합
            //   (등급 뱃지 + 외부노출)이 한 줄에 들어가는 값으로 잡는다 — 10rem(160px)에선 실측
            //   4px 이 모자라 두 줄로 접혔다 → 11rem.
            ['label' => '등급 · 노출', 'width' => '11rem'],
            // 'YYYY-MM-DD HH:MM:SS'(19자)는 이 폭에 안 들어가 말줄임으로 잘렸다 —
            //   열을 넓히는 대신 분까지만 보이고(초는 이 목록의 판단에 안 쓴다) 전체는 title 로.
            //   그렇게 줄인 값의 실측 필요폭이 143px 이다 → 9rem.
            ['label' => '수집 시각', 'width' => '9rem', 'nowrap' => true],
        ],
        $paged,
        [
            'empty' => ($type !== '' || $hostId || $q !== '')
                ? [
                    'icon'  => '🔍',
                    'title' => '조건에 맞는 변화가 없습니다.',
                    'hint'  => '검색어나 호스트·변화유형 필터를 바꿔 보세요.',
                    'cta'   => ['href' => '/changes.php', 'label' => '필터 초기화'],
                ]
                : [
                    'icon'  => '📉',
                    'title' => '아직 비교할 변화가 없습니다.',
                    'hint'  => '호스트마다 스캔이 2회 이상 쌓여야 직전과 비교할 수 있습니다.',
                ],
            'row_class' => fn($r) => vg_sev_row((string) $r['severity']),
            'cell' => [
                0 => fn($r) => vg_change_type_cell($r),
                1 => fn($r) => '<a href="/host.php?id=' . (int) $r['host_id'] . '">' . vg_h($r['fqdn']) . '</a>',
                2 => fn($r) => '<a href="/cve.php?cve=' . urlencode($r['cve_id']) . '">' . vg_h($r['cve_id']) . '</a>'
                              . ($r['in_kev'] ? ' ' . vg_badge('KEV', 'crit') : ''),
                3 => fn($r) => vg_change_package_cell($r),
                4 => fn($r) => vg_change_severity_cell($r),
                5 => fn($r) => vg_change_when_cell($r),
            ],
        ]
    );
    // 변화 종류의 색은 KPI 카드·행 뱃지·행 배경이 함께 쓴다 — 그 색이 무슨 뜻인지 한 줄로
    //   못박는다(위 $changeTone 과 같은 어휘다. 여기서 색을 새로 만들지 않는다).
    vg_legend([
        ['label' => '신규',      'tone' => 'crit'],
        ['label' => '등급 상승', 'tone' => 'high'],
        ['label' => '등급 하락', 'tone' => 'low'],
        ['label' => '해결',      'tone' => 'ok'],
    ], ['inline' => true, 'caption' => '변화 종류']);
    if ($paged) { vg_page_nav($total, $perPage, $page); }
    ?>

  <?php elseif ($tab === 'pkg'): ?>
    <div class="sub">직전 수집 이후 실제로 달라진 패키지만 표시합니다.</div>
    <?php
    vg_table(
        [
            // 변화유형 뱃지는 고정 크기다 — 9%(1110px 표에서 100px)는 '다운그레이드' 뱃지(실측
            //   136px)를 못 담아 말줄임으로 잘렸다("다운그레이…"). 값 136 + 여백 → 8.5rem.
            ['label' => '변화', 'width' => '8.5rem', 'nowrap' => true],
            ['label' => '호스트'],
            ['label' => '패키지'],
            ['label' => '버전'],
            // 취약점 변화 표와 같은 기준 — 분까지만 보이고(vg_change_when_cell) 폭은 그 값에 맞춘다.
            ['label' => '시각', 'width' => '9rem', 'nowrap' => true],
        ],
        $pkgChanges,
        [
            'empty' => [
                'icon'  => '📦',
                'title' => '아직 패키지 변경이 없습니다.',
                'hint'  => '첫 수집 이후 실제로 달라진 것이 생기면 여기에 남습니다.',
            ],
            'cell' => [
                0 => fn($r) => vg_badge(VG_PKG_CHANGE_TYPES[$r['change_type']] ?? $r['change_type'],
                                        vg_pkgchg_tone((string) $r['change_type'])),
                1 => fn($r) => '<a href="/host.php?id=' . (int) $r['host_id'] . '">' . vg_h($r['fqdn']) . '</a>',
                2 => fn($r) => vg_package_detail_link($r)
                              . ' <span class="why">' . vg_h((string) $r['manager']) . '</span>',
                3 => fn($r) => $r['old_version'] !== null && $r['new_version'] !== null
                              ? '<span class="why">' . vg_h($r['old_version']) . ' →</span> ' . vg_h($r['new_version'])
                              : vg_h((string) ($r['new_version'] ?? $r['old_version'])),
                4 => fn($r) => vg_change_when_cell($r),
            ],
        ]
    );
    if ($pkgChanges) { vg_page_nav($pkgTotal, $perPage, $page); }
    ?>

  <?php else: /* trend */ ?>
    <?php if ($trendNeedsHost): ?>
      <?php vg_empty([
          'icon'  => '📌',
          'title' => '호스트를 선택하면 추이를 볼 수 있습니다.',
          'hint'  => '전체 자산 합산은 데이터가 많으면 무거워질 수 있어, 위 필터에서 호스트를 먼저 고르세요.',
      ]); ?>
    <?php elseif (!$trendRounds): ?>
      <?php vg_empty([
          'icon'  => '📉',
          'title' => '아직 비교할 수집 이력이 없습니다.',
          'hint'  => '이 호스트의 스캔 이력이 쌓이면 회차별 추이가 표시됩니다.',
      ]); ?>
    <?php else: ?>
      <?php $trendLatest = $trendRounds[count($trendRounds) - 1]; ?>
      <?php /* 0건이면 톤을 뺀다(위 취약점 변화 KPI 와 같은 판단 — 0 은 경고가 아니다). */
      $trendKpi = [
          ['new', '신규', 'crit'], ['up', '등급 상승', 'high'], ['down', '등급 하락', 'low'],
          ['resolved', '해결', 'ok'],
      ]; ?>
      <div class="cards">
        <?php foreach ($trendKpi as [$key, $label, $tone]): ?>
          <div class="kpi kpi--sm<?= $trendSummary[$key] > 0 ? ' tone-' . vg_h($tone) : '' ?>">
            <b><?= number_format($trendSummary[$key]) ?></b><span><?= vg_h($label) ?></span>
          </div>
        <?php endforeach; ?>
        <div class="kpi kpi--sm tone-muted"><b><?= number_format($trendLatest['unresolved']) ?></b><span>현재 잔존</span></div>
      </div>

      <div class="sub">① 미해결 취약점 수 추이</div>
      <div class="card"><?php vg_count_trend($trendRounds); ?></div>

      <div class="sub">② 회차별 신규·해결</div>
      <div class="card"><?php vg_change_bars($trendRounds); ?></div>

      <div class="sub">③ 회차별 요약</div>
      <?php
      vg_table(
          [
              ['label' => '회차', 'width' => '8%', 'align' => 'center'],
              ['label' => '수집일시'],
              ['label' => '신규', 'width' => '10%', 'align' => 'right'],
              ['label' => '해결', 'width' => '10%', 'align' => 'right'],
              ['label' => '잔존', 'width' => '10%', 'align' => 'right'],
              ['label' => '누적 조치율', 'width' => '12%', 'align' => 'right'],
          ],
          array_reverse($trendRounds),   // 최신 회차가 맨 위
          [
              'cell' => [
                  0 => fn($r) => (string) $r['round'],
                  1 => fn($r) => '<span class="why">' . vg_h($r['collected_at'] ?: '–') . '</span>',
                  2 => fn($r) => $r['new'] === null ? '<span class="why">–</span>' : number_format($r['new']),
                  3 => fn($r) => $r['resolved'] === null ? '<span class="why">–</span>' : number_format($r['resolved']),
                  4 => fn($r) => number_format($r['unresolved']),
                  5 => fn($r) => $r['cum_rate'] === null ? '<span class="why">–</span>' : number_format($r['cum_rate'], 1) . '%',
              ],
          ]
      );
      ?>

      <div class="sub">④ 이번 구간 해결된 항목</div>
      <?php
      $trendResolvedTotal = count($trendResolvedAll);
      $trendResolvedPaged = array_slice($trendResolvedAll, ($page - 1) * $perPage, $perPage);
      if ($trendResolvedPaged) {
          try {
              vg_attach_change_reason($pdo, $trendResolvedPaged);
          } catch (Throwable $e) {
              error_log('[changes] trend detail lookup: ' . $e->getMessage());
          }
      }
      vg_table(
          [
              // 위 '취약점 변화' 표와 같은 셀 함수를 쓰므로 열 구성·폭 기준도 그대로 맞춘다.
              ['label' => '회차', 'width' => '4rem', 'align' => 'center'],
              ['label' => '변화 · 사유', 'width' => '15%',
               'title' => '무엇이 달라졌는지와, 왜 그렇게 됐는지(패키지 변경 이력 대조 결과)'],
              ['label' => '호스트'],
              ['label' => 'CVE', 'width' => '11.5rem', 'nowrap' => true],
              ['label' => '패키지'],
              ['label' => '등급 · 노출', 'width' => '11rem'],
              ['label' => '수집 시각', 'width' => '9rem', 'nowrap' => true],
          ],
          $trendResolvedPaged,
          [
              'empty' => [
                  'icon'  => '📉',
                  'title' => '이 구간엔 해결된 항목이 없습니다.',
                  'hint'  => '구간(호스트·최근 N회차)을 넓혀 보세요.',
              ],
              'row_class' => fn($r) => vg_sev_row((string) $r['severity']),
              'cell' => [
                  0 => fn($r) => (string) $r['round'],
                  1 => fn($r) => vg_change_type_cell($r),
                  2 => fn($r) => '<a href="/host.php?id=' . (int) $r['host_id'] . '">' . vg_h($r['fqdn']) . '</a>',
                  3 => fn($r) => '<a href="/cve.php?cve=' . urlencode($r['cve_id']) . '">' . vg_h($r['cve_id']) . '</a>'
                                . ($r['in_kev'] ? ' ' . vg_badge('KEV', 'crit') : ''),
                  4 => fn($r) => vg_change_package_cell($r),
                  5 => fn($r) => vg_change_severity_cell($r),
                  6 => fn($r) => vg_change_when_cell($r),
              ],
          ]
      );
      if ($trendResolvedPaged) { vg_page_nav($trendResolvedTotal, $perPage, $page); }
      ?>
    <?php endif; ?>
  <?php endif; ?>
<?php endif; ?>
<?php vg_footer();
