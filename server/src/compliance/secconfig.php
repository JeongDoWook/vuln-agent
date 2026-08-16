<?php
declare(strict_types=1);

/**
 * compliance/secconfig.php — 통제 3: 보안시스템 운영(ISMS-P 2.10.1).
 *   판정은 CCE(cce.php)가 이미 tb_cce_finding 에 내려 둔 것을 쓰고, 여기서는 집계만 한다 —
 *   설정 취약 판정을 여기서 다시 짜면 CCE 화면과 컴플라이언스가 다른 답을 낸다.
 *
 *   ※ compliance.php 가 로드한다. 세션·인가·출력은 여기 두지 않는다(CLI 에서도 로드된다).
 */

require_once __DIR__ . '/../db.php';        // vg_latest_scan_subq

/**
 * 통제 3: 보안시스템 운영(ISMS-P 2.10.1).
 *   판정: host.php 에 이미 있는 "설정 취약"(tb_cce_finding.result='FAIL') 판정을 최신 스캔
 *   기준으로 집계만 한다 — 판정 로직 자체는 새로 만들지 않는다(YAGNI).
 *
 *   checked 는 **표시용 분모**다(판정에는 안 쓴다). 위반 174건이 큰 수인지 작은 수인지는
 *   전체 점검 항목 수를 모르면 읽을 수 없어서, 같은 조인으로 FAIL 필터만 뺀 총건수를 함께 센다.
 * @return array{violations: array<int, array<string, mixed>>, total: int, checked: int}
 */
function vg_compliance_load_secconfig(PDO $pdo, int $limit): array {
    $latestSubq = vg_latest_scan_subq();
    $scopeSql = "FROM tb_cce_finding cf
           JOIN $latestSubq t ON t.mid = cf.scan_id
           JOIN tb_host h ON h.host_id = t.host_id AND h.is_deleted = 0
          WHERE cf.is_deleted = 0";
    $fromSql = $scopeSql . " AND cf.result = 'FAIL'";
    $total = (int) $pdo->query("SELECT COUNT(*) $fromSql")->fetchColumn();
    $checked = (int) $pdo->query("SELECT COUNT(*) $scopeSql")->fetchColumn();

    $st = $pdo->prepare(
        "SELECT t.host_id, h.fqdn, cf.code, cf.title, cf.severity, cf.rationale
           $fromSql
          ORDER BY FIELD(cf.severity,'HIGH','MEDIUM','LOW'), h.fqdn
          LIMIT ?"
    );
    $st->bindValue(1, $limit, PDO::PARAM_INT);
    $st->execute();
    $rows = $st->fetchAll();
    $violations = [];
    foreach ($rows as $r) {
        $violations[] = [
            'host_id'   => (int) $r['host_id'],
            'fqdn'      => (string) $r['fqdn'],
            'code'      => (string) $r['code'],
            'title'     => (string) $r['title'],
            'severity'  => (string) $r['severity'],
            'rationale' => (string) ($r['rationale'] ?? ''),
        ];
    }
    return ['violations' => $violations, 'total' => $total, 'checked' => $checked];
}
