<?php
declare(strict_types=1);

ini_set('memory_limit', '512M');

/**
 * enrich_osv.php — OSV 조치안(fixed_version) 지연 보강.
 *
 *   피드 수집은 querybatch(응답=id만, 메모리 안전)라 fixed_version 이 비어 있다.
 *   여기서는 "실제로 findings 에 뜬 취약 패키지"(취약 부분집합, 소수)만 골라
 *   단건 /v1/query 로 조회해 조치 버전을 채운다.
 *   - 커널 등 거대 응답은 바이트 상한(6MB)으로 건너뛴다(OOM 방지).
 *   - 패키지당 1회 조회로 그 패키지의 모든 CVE fixed 를 한꺼번에 갱신.
 *   재매칭 불필요: findings.php 는 cve_affected_packages 를 JOIN 해 조치를 표시한다.
 *
 *   사용: php bin/enrich_osv.php   (스케줄 없이 수동/후처리로 실행)
 */

require __DIR__ . '/../src/feeds.php';

$pdo = vg_pdo();
$MAX_BYTES = 6 * 1024 * 1024;                 // 6MB 초과 응답은 건너뜀
$SINGLE    = 'https://api.osv.dev/v1/query';

// 보강 대상 키: findings 에 실제로 뜬 패키지 중 조치 버전이 아직 빈 것.
$needFix = [];
$rows = $pdo->query(
    'SELECT DISTINCT a.package_name
       FROM tb_cve_affected_packages a
       JOIN tb_findings f ON f.package_name = a.package_name
      WHERE a.fixed_version IS NULL'
)->fetchAll(PDO::FETCH_COLUMN);
foreach ($rows as $k) { $needFix[$k] = true; }

if (!$needFix) {
    fwrite(STDOUT, '[' . date('c') . "] 보강할 패키지 없음(모두 조치 확보 또는 findings 없음)\n");
    exit(0);
}
fwrite(STDOUT, '[' . date('c') . '] 보강 대상 패키지 ' . count($needFix) . "종\n");

// 호스트별 최신 스캔에서 (ecosystem, key, version) 을 만들어 조회.
$scans = $pdo->query(
    'SELECT s.id, s.os_id, s.os_version
       FROM tb_scans s JOIN (SELECT host_id, MAX(id) mid FROM tb_scans GROUP BY host_id) t ON t.mid = s.id'
)->fetchAll();

$queried = 0; $filled = 0; $skipped = 0; $seen = [];
foreach ($scans as $sc) {
    $eco = vg_osv_ecosystem($sc['os_id'], $sc['os_version']);
    if ($eco === null || $eco === '') { continue; }
    $isDeb = stripos($eco, 'Debian') === 0 || stripos($eco, 'Ubuntu') === 0;

    $pk = $pdo->prepare('SELECT name, source_pkg, version FROM tb_packages WHERE scan_id = ?');
    $pk->execute([(int) $sc['id']]);
    foreach ($pk->fetchAll() as $p) {
        $key = $isDeb ? ($p['source_pkg'] ?: $p['name']) : $p['name'];   // 연결 커넥터와 동일한 키 규칙
        $ver = (string) $p['version'];
        if ($key === '' || $ver === '' || !isset($needFix[$key])) { continue; }

        $dk = $eco . '|' . $key . '|' . $ver;
        if (isset($seen[$dk])) { continue; }
        $seen[$dk] = true;

        $payload = ['package' => ['ecosystem' => $eco, 'name' => $key], 'version' => $ver];
        $r = vg_http_json('POST', $SINGLE, $payload, [], 90, $MAX_BYTES);
        $queried++;
        if ($r['code'] !== 200 || !isset($r['json']['vulns'])) {
            $skipped++;
            fwrite(STDOUT, "  - {$eco} {$key}@{$ver}: 건너뜀 ({$r['error']})\n");
            unset($r);
            continue;
        }
        foreach ($r['json']['vulns'] as $v) {
            $cve   = vg_osv_cve($v);
            $fixed = vg_osv_fixed($v, $key);
            if ($cve === null || $fixed === null) { continue; }
            vg_upsert_affected($pdo, $cve, $eco, $key, $fixed);   // fixed 채움(기존 행 UPDATE)
            $filled++;
        }
        unset($r); // 응답 즉시 해제
    }
}

fwrite(STDOUT, '[' . date('c') . "] 조회 {$queried}패키지 · 조치 {$filled}건 채움 · {$skipped}건 건너뜀\n");
