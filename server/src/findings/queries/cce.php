<?php
declare(strict_types=1);

/**
 * findings/queries/cce.php — 보안설정(CCE) 탭의 조회 하나.
 *   결과 분포(FAIL/PASS/NA)와 목록. NA 를 PASS 와 섞지 않는 규칙이 이 파일 안에 있다.
 */

/**
 * 보안설정(CCE) 탭 — 결과 분포 + 위반의 등급 구성 + 목록.
 *   $f: q sev res page perPage
 *   반환: resultCounts failSevCounts total page rows
 */
function vg_findings_load_cce(PDO $pdo, array $scanIds, array $f): array {
    $q = (string) $f['q']; $sev = (string) $f['sev']; $res = (string) $f['res'];
    $page = (int) $f['page']; $perPage = (int) $f['perPage'];

    $in = implode(',', array_fill(0, count($scanIds), '?'));
    $cceResultCounts = ['FAIL'=>0, 'PASS'=>0, 'NA'=>0];
    // 위반(FAIL)의 등급 구성 — 화면의 두 번째 카드가 쓴다. 등급 어휘는 cce 판정이 주는 셋뿐이다
    //   (CRITICAL 이 없다 — findings.php 의 $sevOptions 와 같은 사실).
    $failSevCounts = ['HIGH'=>0, 'MEDIUM'=>0, 'LOW'=>0];

    // 결과 분포는 필터 무관 — 대상 스캔 전체 기준(CVE 탭의 등급 KPI 와 같은 자리·같은 성격).
    //   NA 를 PASS 와 섞지 않는다: 위반 0건이 "준수" 로 읽히는 걸 이 제품은 반복해서 경계해 왔다.
    //   uq_cce(scan_id, code) 가 scan_id 선두라 IN 범위를 그대로 탄다.
    // GROUP BY 에 severity 를 **한 칸 더** 얹어 위반의 등급 구성까지 같은 쿼리에서 낸다 —
    //   쿼리를 새로 붙이지 않는다(훑는 행도 접근 경로도 그대로고, 결과 행만 3개 → 최대 9개다).
    $stmt = $pdo->prepare(
        "SELECT result, severity, COUNT(*) c FROM tb_cce_finding
          WHERE scan_id IN ($in) GROUP BY result, severity"
    );
    $stmt->execute($scanIds);
    foreach ($stmt->fetchAll() as $r) {
        $rk = (string) $r['result'];
        $sk = (string) $r['severity'];
        if (isset($cceResultCounts[$rk])) { $cceResultCounts[$rk] += (int) $r['c']; }
        if ($rk === 'FAIL' && isset($failSevCounts[$sk])) { $failSevCounts[$sk] += (int) $r['c']; }
    }

    $where  = "f.scan_id IN ($in)";
    $params = $scanIds;
    if ($res !== 'ALL') {
        $where .= ' AND f.result = ?';
        $params[] = $res;
    }
    if ($sev !== '') {
        $where .= ' AND f.severity = ?';
        $params[] = $sev;
    }
    if ($q !== '') {
        $where .= ' AND (f.code LIKE ? OR f.title LIKE ? OR f.ssg_rule_id LIKE ?)';
        $like = '%' . addcslashes($q, '%_\\') . '%';
        $params[] = $like; $params[] = $like; $params[] = $like;
    }

    $stmt = $pdo->prepare("SELECT COUNT(*) FROM tb_cce_finding f WHERE $where");
    $stmt->execute($params);
    $total = (int) $stmt->fetchColumn();
    if ($total > 0) { $page = min($page, (int) ceil($total / $perPage)); }
    $offset = ($page - 1) * $perPage;

    // 룰 상세는 compliance_rule.php 가 이미 갖고 있다 — 여기서는 기준 참조(CIS/NIST/STIG)만
    //   함께 읽어 근거를 인용하고 링크로 보낸다(host.php 의 CCE 탭과 같은 조인).
    $stmt = $pdo->prepare(
        "SELECT f.code, f.ssg_rule_id, f.title, f.result, f.severity, f.evidence, f.rationale,
                h.host_id, h.fqdn, r.refs_json
           FROM tb_cce_finding f
           JOIN tb_scan s ON s.scan_id = f.scan_id
           JOIN tb_host h ON h.host_id = s.host_id
           LEFT JOIN tb_compliance_rule r ON r.rule_id = f.ssg_rule_id AND r.is_deleted = 0
          WHERE $where
          ORDER BY FIELD(f.result,'FAIL','NA','PASS'), FIELD(f.severity,'HIGH','MEDIUM','LOW'), h.fqdn, f.code
          LIMIT $perPage OFFSET $offset"
    );
    $stmt->execute($params);
    $rows = $stmt->fetchAll();

    return ['resultCounts' => $cceResultCounts, 'failSevCounts' => $failSevCounts,
            'total' => $total, 'page' => $page, 'rows' => $rows];
}
