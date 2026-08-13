<?php
declare(strict_types=1);

/**
 * suppression.php — **억제 근거를 화면 어휘로 옮기는 한 곳**(SSOT).
 *
 * 왜 필요한가: CONTEXT.md §7 은 "억제된 건은 위험 집계에서 빠지되 **근거는 호스트 상세에
 *   그대로 노출된다(숨기지 않는다)**" 를 이 제품의 차별점으로 못박아 놨다. 그런데 화면은
 *   tb_suppressed_finding.suppress_reason 한 줄을 90자로 잘라 회색 글씨로 보여줄 뿐이라,
 *   **어느 겹이 왜 억제했는지**(버전 비교인지, 배포판 트래커인지, 벤더 권고인지, changelog 인지)를
 *   읽을 수 없었다. 근거 테이블(tb_debsecan·tb_applied_errata·tb_pkg_changelog_cve)은
 *   server/public/** 어디서도 참조되지 않았다 — 차별점이 코드에만 있고 화면엔 없는 상태였다.
 *
 * 무엇을 하지 않나: **판정을 다시 하지 않는다.** 억제 판정의 정본은 matcher.php 의
 *   vg_match_decide_cve() 하나뿐이고, 여기는 그것이 남긴 근거 문구를 읽어 분류만 한다.
 *   판정 로직을 두 벌 두면 화면과 집계가 조용히 갈린다.
 *
 * 왜 문구 매칭인가: 억제 겹은 DB 에 코드로 남지 않는다(suppress_reason 문자열 하나뿐).
 *   컬럼을 새로 만들면 **이미 쌓인 스캔은 전부 미분류**가 되고 재매칭을 강제하게 된다.
 *   그래서 각 겹이 반드시 포함하는 **고정 문구**를 여기 한 곳에 모아 두고, 화면·집계가
 *   같은 표를 쓴다. 문구를 바꾸려면 matcher.php 와 이 표를 같이 고쳐야 한다
 *   (tests/suppression_test.php 가 둘의 일치를 검증한다).
 */

/**
 * 억제 근거 겹(layer) 표 — **순서가 곧 우선순위**다. matcher.php 의 판정 순서와 같게 두어야
 *   한 건이 여러 문구를 담아도 실제로 억제한 겹으로 분류된다(예: 벤더 OVAL 근거에도
 *   '≥ 조치' 가 들어 있어, 버전 겹보다 먼저 검사해야 한다).
 *
 *   match  : suppress_reason 에 반드시 들어가는 고정 문구(matcher.php 의 reason 조립부와 1:1).
 *   label  : 화면 뱃지 글자.  tone: app.css 의 .badge.tone-*.
 *   desc   : "왜 이 겹이 억제했나" 한 줄 — 표마다 다시 적지 않는다(DRY).
 *   source : 근거의 출처 테이블(사람이 원 데이터를 찾아갈 수 있게 이름을 그대로 적는다).
 */
const VG_SUPPRESS_LAYERS = [
    'kernel_inactive' => [
        'match'  => '실행 중이 아닌 커널',
        'label'  => '커널 미실행',
        'tone'   => 'muted',
        'desc'   => '설치만 되어 있고 지금 부팅된 커널이 아니라 그 코드가 실행되지 않습니다. 그 커널로 부팅하면 다음 수집에서 다시 위험으로 올라옵니다.',
        'source' => 'tb_scan.running_kernel',
    ],
    'kernel_cna' => [
        'match'  => 'kernel.org CNA',
        'label'  => '커널 업스트림 판정',
        'tone'   => 'info',
        'desc'   => 'kernel.org CNA 가 구동 커널 버전에 수정본이 포함됐다고 판정했습니다(배포판 관할 밖 커널 전용).',
        'source' => 'tb_kernel_cve',
    ],
    'changelog' => [
        'match'  => 'changelog 에',
        'label'  => '④ changelog 백포트',
        'tone'   => 'purple',
        'desc'   => '이 빌드의 changelog 에 해당 CVE 수정 기록이 있습니다 — 버전이 낮아 보여도 패치된 빌드입니다.',
        'source' => 'tb_pkg_changelog_cve',
    ],
    'errata' => [
        'match'  => '적용된 벤더 보안권고가',
        'label'  => '③ 벤더 권고(에이전트)',
        'tone'   => 'info',
        'desc'   => '대상 서버의 dnf updateinfo 가 "이 CVE 는 설치된 빌드에서 고쳐졌다"고 확인해 준 건입니다.',
        'source' => 'tb_applied_errata',
    ],
    'vendor_oval' => [
        'match'  => '이 빌드에서 고침',
        'label'  => '③ 벤더 권고(중앙 OVAL)',
        'tone'   => 'info',
        'desc'   => '중앙이 받은 벤더 보안권고(OVAL)와 설치 EVR 을 대조해 이미 고쳐진 것으로 판정했습니다.',
        'source' => 'tb_vendor_errata',
    ],
    'tracker' => [
        'match'  => '해당 없음으로 판정',
        'label'  => '② 배포판 보안 트래커',
        'tone'   => 'info',
        'desc'   => '배포판 보안 트래커(데비안 트래커·우분투 OVAL·debsecan)가 이 버전에 해당하지 않는다고 판정했습니다 — 백포트로 이미 수정된 것입니다.',
        'source' => 'tb_debsecan · tb_debian_tracker · tb_ubuntu_oval',
    ],
    'version' => [
        'match'  => '→ 이미 패치됨',
        'label'  => '① 버전 비교',
        'tone'   => 'ok',
        'desc'   => '설치 버전이 피드가 알려준 조치 버전 이상입니다(배포판 EVR 규칙으로 비교).',
        'source' => 'tb_package · 피드 조치 버전',
    ],
];

/** 분류되지 않은 근거 — 새 억제 겹이 생겼는데 이 표를 안 고쳤을 때만 나온다. */
const VG_SUPPRESS_LAYER_UNKNOWN = [
    'label'  => '근거 미분류',
    'tone'   => 'med',
    'desc'   => '억제 근거 문구가 알려진 겹 어디에도 맞지 않습니다 — 원문을 펼쳐 확인하세요.',
    'source' => 'tb_suppressed_finding.suppress_reason',
];

/** 억제 근거 문구 → 겹 키. 못 맞추면 'other'. */
function vg_suppress_layer(?string $reason): string
{
    $reason = (string) $reason;
    foreach (VG_SUPPRESS_LAYERS as $key => $def) {
        if ($reason !== '' && mb_strpos($reason, $def['match']) !== false) { return $key; }
    }
    return 'other';
}

/** 겹 키 → 표시 정보(label·tone·desc·source). 모르는 키는 '근거 미분류'. */
function vg_suppress_layer_meta(string $key): array
{
    return VG_SUPPRESS_LAYERS[$key] ?? VG_SUPPRESS_LAYER_UNKNOWN;
}

/**
 * 이 스캔의 억제 건을 겹별로 센다 — "왜 이만큼이 위험에서 빠졌나" 를 한 줄로 읽게 한다.
 *   분류는 위 표 하나로만 하고(DRY), 집계는 DB 에서 한 번에 끝낸다(억제는 스캔당 수천 건이라
 *   전 행을 PHP 로 끌어오면 목록 한 페이지를 그리려고 4천 행을 읽게 된다).
 *
 * @return array<string,int> 겹 키 => 건수 (0건인 겹은 넣지 않는다)
 */
function vg_suppress_layer_counts(PDO $pdo, int $scanId): array
{
    $cases = '';
    $params = [];
    foreach (VG_SUPPRESS_LAYERS as $key => $def) {
        $cases .= ' WHEN suppress_reason LIKE ? THEN ?';
        $params[] = '%' . $def['match'] . '%';
        $params[] = $key;
    }
    $st = $pdo->prepare(
        "SELECT CASE$cases ELSE 'other' END AS layer, COUNT(*) AS c
           FROM tb_suppressed_finding WHERE scan_id = ?
          GROUP BY layer"
    );
    $params[] = $scanId;
    $st->execute($params);

    $out = [];
    foreach ($st->fetchAll() as $r) { $out[(string) $r['layer']] = (int) $r['c']; }
    // 표 순서대로 정렬한다 — 화면이 매번 다른 순서로 뜨면 같은 자산을 두 번 볼 때 비교가 안 된다.
    $sorted = [];
    foreach (array_keys(VG_SUPPRESS_LAYERS) as $key) {
        if (!empty($out[$key])) { $sorted[$key] = $out[$key]; }
    }
    if (!empty($out['other'])) { $sorted['other'] = $out['other']; }
    return $sorted;
}

/**
 * 화면에 **보이는 행들**의 원 근거 데이터를 한 번에 읽는다(N+1 금지 — 페이지당 3쿼리 고정).
 *
 *   errata·changelog 는 "이 CVE 를 고쳤다"는 행이 실제로 있으므로 그 행을 그대로 보여준다.
 *   debsecan 은 **반대**다 — 억제 근거가 "목록에 없음" 이라 보여줄 행이 없다. 대신 같은
 *   패키지에 **아직 남아 있는** CVE 건수를 보여준다: 그 수가 0 이 아니라는 사실이 곧
 *   "트래커 판정이 실제로 들어왔다(수집 실패가 아니다)"는 증거다(NA ≠ PASS 와 같은 원칙).
 *
 * @param list<array<string,mixed>> $rows 이 페이지의 억제 행(package_name·cve_id 를 쓴다)
 * @return array{errata:array<string,string>,changelog:array<string,string>,debsecan:array<string,int>}
 *         errata·changelog 키는 "패키지|CVE", debsecan 키는 패키지명.
 */
function vg_suppress_evidence_map(PDO $pdo, int $scanId, array $rows): array
{
    $out = ['errata' => [], 'changelog' => [], 'debsecan' => []];
    $pkgs = [];
    $cves = [];
    foreach ($rows as $r) {
        $p = (string) ($r['package_name'] ?? '');
        $c = (string) ($r['cve_id'] ?? '');
        if ($p !== '') { $pkgs[$p] = true; }
        if ($c !== '') { $cves[$c] = true; }
    }
    if (!$pkgs || !$cves) { return $out; }

    $pkgs = array_keys($pkgs);
    $cves = array_keys($cves);
    $pkgPh = implode(',', array_fill(0, count($pkgs), '?'));
    $cvePh = implode(',', array_fill(0, count($cves), '?'));
    // 페이지의 패키지×CVE 사각형으로 넉넉히 읽고 PHP 에서 정확한 쌍만 쓴다 — 쌍마다
    //   (?,?) 튜플을 나열하면 바인딩이 페이지 크기의 두 배로 늘고 인덱스 이점도 없다.
    $args = array_merge([$scanId], $pkgs, $cves);

    $st = $pdo->prepare(
        "SELECT package_name, cve_id, evidence FROM tb_applied_errata
          WHERE scan_id = ? AND package_name IN ($pkgPh) AND cve_id IN ($cvePh)"
    );
    $st->execute($args);
    foreach ($st->fetchAll() as $r) {
        $out['errata'][$r['package_name'] . '|' . $r['cve_id']] = (string) ($r['evidence'] ?? '');
    }

    $st = $pdo->prepare(
        "SELECT package_name, cve_id, evidence FROM tb_pkg_changelog_cve
          WHERE scan_id = ? AND package_name IN ($pkgPh) AND cve_id IN ($cvePh)"
    );
    $st->execute($args);
    foreach ($st->fetchAll() as $r) {
        $out['changelog'][$r['package_name'] . '|' . $r['cve_id']] = (string) ($r['evidence'] ?? '');
    }

    $st = $pdo->prepare(
        "SELECT package_name, COUNT(*) AS c FROM tb_debsecan
          WHERE scan_id = ? AND package_name IN ($pkgPh) GROUP BY package_name"
    );
    $st->execute(array_merge([$scanId], $pkgs));
    foreach ($st->fetchAll() as $r) {
        $out['debsecan'][(string) $r['package_name']] = (int) $r['c'];
    }

    return $out;
}

/**
 * 억제를 **취소하는** 신호: 패치는 됐지만 프로세스가 옛 라이브러리(.so)를 아직 물고 있는 것.
 *   오탐이 아니라 **미탐** 쪽이라 위험 축에 있어야 한다 — 대시보드엔 "패치됨"으로 보인다.
 *   프로세스·패키지 단위로 접어 보여준다(한 프로세스가 옛 .so 를 수십 개 물기도 한다).
 *
 * @return array{total:int,rows:list<array<string,mixed>>}
 */
function vg_stale_lib_summary(PDO $pdo, int $scanId, int $limit): array
{
    $st = $pdo->prepare(
        'SELECT COUNT(*) FROM (SELECT 1 FROM tb_stale_lib WHERE scan_id = ?
                                GROUP BY package_name, comm) AS g'
    );
    $st->execute([$scanId]);
    $total = (int) $st->fetchColumn();
    if ($total === 0) { return ['total' => 0, 'rows' => []]; }

    $st = $pdo->prepare(
        'SELECT package_name, comm, COUNT(*) AS libs, COUNT(DISTINCT pid) AS procs,
                MIN(pid) AS sample_pid, MIN(lib_path) AS sample_lib
           FROM tb_stale_lib WHERE scan_id = ?
          GROUP BY package_name, comm
          ORDER BY libs DESC, package_name, comm
          LIMIT ' . max(1, $limit)
    );
    $st->execute([$scanId]);
    return ['total' => $total, 'rows' => $st->fetchAll()];
}
