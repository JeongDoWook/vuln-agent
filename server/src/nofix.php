<?php
declare(strict_types=1);

/**
 * nofix.php — "벤더 미수정이 한 패키지에 몰려 있다" 는 **관측**과 그에 따른 제거·대체 권고.
 *
 * 왜 있나(실측): gpuServer 의 libqt5webkit5 한 패키지에서 CVE 43건이 전부 no_fix 였다
 *   (CVE-2025-24201 CVSS 10.0 포함). 화면은 이걸 개별 CVE 43줄로 흩어 보여줘서 사용자는
 *   "패치 대기 중" 으로 읽었지만, 실제 조치는 `apt purge libqt5webkit5` **한 번**이다.
 *   정보는 이미 tb_finding 에 다 있었다 — 보여주는 단위만 CVE 에서 (호스트×패키지) 로 바꾼다.
 *
 * 표현 원칙: **EOL 이라고 단정하지 않는다.** 우리가 아는 건 "벤더가 이 패키지의 CVE 를 안 고치고
 *   있다" 는 관측뿐이고, 그게 EOL 인지 정책적 미수정인지는 이 데이터로 못 가린다.
 *   그래서 문구는 언제나 **관측 + 권고** 다(못 채우는 걸 억지로 채우면 신뢰도만 깎인다).
 *
 * 심각도 판정(matcher.php vg_classify)은 건드리지 않는다 — 이 파일은 표시 계층 전용이다.
 */

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/format.php';
require_once __DIR__ . '/distro.php';   // vg_osv_ecosystem / vg_eco_matches — 생태계별 화면의 필터

/**
 * 권고 임계값 — 여기 한 곳에서만 정한다.
 *   min_cnt   : no_fix 가 이 건수 이상일 때만 "몰려 있다" 고 본다(1~2건은 그냥 개별 CVE 다).
 *   min_ratio : 그 패키지 CVE 중 no_fix 비율. 낮으면 아직 패치로 줄일 여지가 있다는 뜻이라
 *               "제거" 권고가 과하다.
 * ※ 설정 이관 예정(tb_setting) — 지금은 다른 워커가 그 테이블을 만드는 중이라 상수로 둔다.
 */
const VG_NOFIX_ADVICE = ['min_cnt' => 10, 'min_ratio' => 0.8];

/** 심각도·런타임 상태의 "위험한 순서". SQL 의 FIELD() 순서와 PHP 의 역변환이 이 배열 하나를 공유한다. */
const VG_NOFIX_SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const VG_NOFIX_STATUS_ORDER = ['EXTERNAL', 'LAN', 'FILTERED', 'LISTENING', 'RUNNING', 'LOADED', 'INSTALLED'];

/** SQL 의 FIELD(col,'A','B',…) 에 넣을 리터럴 목록. 값은 이 파일이 정하는 고정 어휘라 바인딩이 필요 없다. */
function vg_nofix_field_list(array $order): string {
    return "'" . implode("','", $order) . "'";
}

/** FIELD() 순위(1-base) → 원래 값. 0/NULL 은 목록에 없던 값이므로 null. */
function vg_nofix_rank_value(array $order, $rank): ?string {
    $i = (int) $rank;
    return $i >= 1 && $i <= count($order) ? $order[$i - 1] : null;
}

/**
 * 호스트별 최신 스캔 [scan_id => ['host_id'=>…, 'fqdn'=>…, 'os_id'=>…, 'os_version'=>…]].
 *   삭제된 호스트·스캔은 제외. os_* 는 생태계 필터(vg_nofix_filter_eco)가 쓴다.
 *   집계 쿼리에 tb_scan/tb_host 를 JOIN 하지 않기 위해 미리 뽑아 둔다 —
 *   findings 계열 쿼리는 `scan_id IN (리터럴 목록)` 으로 idx_find_* 를 타는 게 전제라,
 *   조인으로 얽으면 옵티마이저가 전체스캔으로 떨어진다(findings.php 주석의 실측 근거).
 */
function vg_nofix_latest_scans(PDO $pdo): array {
    $rows = $pdo->query(
        'SELECT h.host_id, h.fqdn, h.os_id, h.os_version, t.mid AS scan_id
           FROM tb_host h
           JOIN ' . vg_latest_scan_subq() . ' t ON t.host_id = h.host_id
          WHERE h.is_deleted = 0
          ORDER BY h.fqdn'
    )->fetchAll();
    $out = [];
    foreach ($rows as $r) {
        $out[(int) $r['scan_id']] = [
            'host_id'    => (int) $r['host_id'],
            'fqdn'       => (string) $r['fqdn'],
            'os_id'      => $r['os_id'] ?? null,
            'os_version' => $r['os_version'] ?? null,
        ];
    }
    return $out;
}

/**
 * (스캔×컨테이너×패키지) 단위로 묶어, 임계값을 넘긴 "벤더 미수정 집중" 조합만 돌려준다.
 *   $scanIds  : 대상 스캔(보통 vg_nofix_latest_scans() 의 키). 비면 빈 배열.
 *   $pkg      : 패키지명 필터(없으면 전체). $exact=true 면 정확일치(패키지 상세가 쓴다).
 *
 * HAVING 이 걸러 낸 뒤 남는 행은 정의상 소수(권고 대상)라 전부 가져와 호출부가 잘라 쓴다 —
 *   그룹 개수를 세려고 파생테이블로 한 번 더 감싸는 쪽이 이 저장소에선 더 비쌌다.
 *   그래도 폭주를 막으려 상한을 둔다(도달하면 호출부가 안내한다).
 *
 * 실행계획(dev 실측, tb_finding 298,798행 · 대상 스캔 152개 = 27,491행): uq_find 로 range 스캔
 *   후 임시테이블+filesort, 0.13~0.14초. GROUP BY 키 그대로의 조합 인덱스
 *   (scan_id, container_id, package_name)를 따로 만들어 FORCE INDEX 로 재보아도 같은 실행계획에
 *   같은 시간이라(0.13~0.25초) **인덱스를 추가하지 않는다** — 안 쓰이는 인덱스는 스캔마다 대량
 *   INSERT 되는 이 테이블의 쓰기 비용만 늘린다(20260726151733_drop_redundant_indexes.sql 과 같은 판단).
 */
const VG_NOFIX_MAX_GROUPS = 500;

function vg_nofix_pkg_groups(PDO $pdo, array $scanIds, string $pkg = '', bool $exact = false): array {
    if (!$scanIds) { return []; }
    $in = implode(',', array_fill(0, count($scanIds), '?'));
    $params = array_values($scanIds);
    $where = "f.scan_id IN ($in)";
    if ($pkg !== '') {
        $where .= $exact ? ' AND f.package_name = ?' : ' AND f.package_name LIKE ?';
        $params[] = $exact ? $pkg : '%' . $pkg . '%';
    }
    $sevList = vg_nofix_field_list(VG_NOFIX_SEV_ORDER);
    $stList  = vg_nofix_field_list(VG_NOFIX_STATUS_ORDER);
    // NULLIF(FIELD(...),0): 목록에 없는 값(NULL runtime_status 등)은 0 이 되는데,
    //   그대로 MIN() 하면 "가장 위험한 상태" 자리를 0 이 차지해 버린다.
    $sql = "SELECT f.scan_id, f.container_id, f.package_name,
                   COUNT(*) AS cve_cnt,
                   SUM(f.no_fix) AS nofix_cnt,
                   SUM(f.in_kev) AS kev_cnt,
                   MIN(NULLIF(FIELD(f.severity, $sevList), 0)) AS sev_rank,
                   MIN(NULLIF(FIELD(f.runtime_status, $stList), 0)) AS status_rank
              FROM tb_finding f
             WHERE $where
             GROUP BY f.scan_id, f.container_id, f.package_name
            HAVING nofix_cnt >= ? AND nofix_cnt >= cve_cnt * ?
             ORDER BY nofix_cnt DESC, kev_cnt DESC, sev_rank ASC, f.package_name
             LIMIT " . VG_NOFIX_MAX_GROUPS;
    $params[] = VG_NOFIX_ADVICE['min_cnt'];
    $params[] = VG_NOFIX_ADVICE['min_ratio'];
    $st = $pdo->prepare($sql);
    $st->execute($params);

    $rows = [];
    foreach ($st->fetchAll() as $r) {
        $r['cve_cnt']        = (int) $r['cve_cnt'];
        $r['nofix_cnt']      = (int) $r['nofix_cnt'];
        $r['kev_cnt']        = (int) $r['kev_cnt'];
        $r['severity']       = vg_nofix_rank_value(VG_NOFIX_SEV_ORDER, $r['sev_rank']);
        $r['runtime_status'] = vg_nofix_rank_value(VG_NOFIX_STATUS_ORDER, $r['status_rank']);
        $rows[] = $r;
    }
    return $rows;
}

/**
 * 컨테이너 id → ['cid'=>짧은 id, 'os_id'=>…, 'os_version'=>…].
 *   집계 결과에 실제로 나온 것만 뒤늦게 채운다(집계 쿼리는 조인 없이 유지).
 *   컨테이너는 호스트와 배포판이 다를 수 있어(우분투 호스트의 알파인 이미지) os 도 함께 본다.
 */
function vg_nofix_containers(PDO $pdo, array $rows): array {
    $ids = [];
    foreach ($rows as $r) {
        $cid = (int) $r['container_id'];
        if ($cid > 0) { $ids[$cid] = true; }
    }
    if (!$ids) { return []; }
    $ids = array_keys($ids);
    $in = implode(',', array_fill(0, count($ids), '?'));
    $st = $pdo->prepare("SELECT container_id, cid, os_id, os_version FROM tb_container WHERE container_id IN ($in)");
    $st->execute($ids);
    $out = [];
    foreach ($st->fetchAll() as $r) {
        $out[(int) $r['container_id']] = [
            'cid'        => (string) $r['cid'],
            'os_id'      => $r['os_id'] ?? null,
            'os_version' => $r['os_version'] ?? null,
        ];
    }
    return $out;
}

/**
 * 관측 그룹을 **그 화면의 생태계**로 거른다. package.php 는 (패키지명 × 생태계) 화면이라,
 *   이름만 같고 배포판이 다른 자산의 관측을 얹으면 데비안 페이지에 RHEL 호스트가 뜬다.
 *   $pageEco 는 tb_package_summary 에 저장된 값(접미사가 붙어 있을 수 있다) —
 *   비교 기준은 매처와 같은 vg_eco_matches(접두 일치)다.
 *
 * 대상의 OS 를 모르면(에이전트가 안 보냈거나 컨테이너 정보가 없다) **뺀다.** vg_eco_matches 의
 *   "정보 없음 → 통과" 는 매칭 누락을 막으려는 규칙이지만, 여기서 통과시키면 남의 배포판 화면에
 *   근거 없는 권고를 얹게 된다 — 못 채우는 걸 억지로 채우지 않는다.
 */
function vg_nofix_filter_eco(PDO $pdo, array $rows, array $scans, string $pageEco): array {
    if ($pageEco === '' || !$rows) { return $rows; }
    $ctrs = vg_nofix_containers($pdo, $rows);
    $out = [];
    foreach ($rows as $r) {
        $cid = (int) $r['container_id'];
        $src = $cid > 0 ? ($ctrs[$cid] ?? null) : ($scans[(int) $r['scan_id']] ?? null);
        $eco = $src === null ? null : vg_osv_ecosystem($src['os_id'] ?? null, $src['os_version'] ?? null);
        if ($eco !== null && vg_eco_matches($pageEco, $eco, '')) { $out[] = $r; }
    }
    return $out;
}

/**
 * 권고의 근거 한 줄 — 「CVE 43건 중 43건이 벤더 미수정 · KEV 39건 · 설치만」.
 *   숫자를 먼저 보여주고 판단은 사용자에게 남긴다. 반환값은 이스케이프된 HTML 이 아니라 순수 문자열
 *   (호출부가 vg_h 하거나 vg_alert 처럼 스스로 이스케이프하는 컴포넌트에 넘긴다).
 */
function vg_nofix_reason(array $r): string {
    $parts = [sprintf('CVE %s건 중 %s건이 벤더 미수정', number_format($r['cve_cnt']), number_format($r['nofix_cnt']))];
    if (($r['kev_cnt'] ?? 0) > 0) { $parts[] = 'KEV ' . number_format((int) $r['kev_cnt']) . '건'; }
    if (!empty($r['severity'])) { $parts[] = '최고 등급 ' . $r['severity']; }
    if (!empty($r['runtime_status'])) { $parts[] = vg_status_label($r['runtime_status']); }
    return implode(' · ', $parts);
}

/** 권고 배지. "EOL 확정" 이 아니라 관측이라는 걸 title 에서 한 번 더 못박는다. */
function vg_nofix_badge(): string {
    return vg_badge(
        '제거·대체 검토',
        'high',
        '벤더 미수정 CVE 가 이 패키지에 몰려 있습니다 — 관측이지 EOL 확정이 아닙니다. '
        . '패치로는 해소되지 않으므로 제거 또는 대체를 검토하세요.'
    );
}

/** 화면 상단에 공통으로 붙이는 안내(관측 + 권고 + 한계). vg_alert() 스펙 배열. */
function vg_nofix_notice(): array {
    return [
        'type'  => 'warn',
        'title' => '조치는 패치가 아니라 제거 또는 대체 검토입니다',
        'hints' => [
            '아래 패키지들은 CVE 대부분이 벤더 미수정(no_fix)입니다 — 기다려도 패치가 오지 않습니다.',
            '이건 "벤더가 안 고치고 있다" 는 관측이지 EOL(지원 종료) 확정이 아닙니다. '
            . '제거·대체 여부는 실제 사용 여부를 확인하고 판단하세요.',
            '런타임 상태가 "설치만" 이면 위험은 낮지만, 쓰는 프로세스가 없다는 뜻이라 제거는 오히려 쉽습니다.',
            sprintf(
                '권고 기준: 벤더 미수정 %d건 이상이면서 그 패키지 CVE 의 %d%% 이상.',
                VG_NOFIX_ADVICE['min_cnt'],
                (int) round(VG_NOFIX_ADVICE['min_ratio'] * 100)
            ),
        ],
    ];
}
