<?php
declare(strict_types=1);

/**
 * feeds.php — CVE 피드 커넥터 (4단계).
 *   claude-pipeline 의 Connector/ConnectorCollectionLog 패턴을 PHP 로 옮긴 것.
 *   커넥터 타입: kev(CISA KEV) / osv(OSV.dev) / nvd(NVD 2.0).
 *   결과는 cves / kev_catalog / cve_affected_packages 로 upsert.
 */

require_once __DIR__ . '/db.php';

// ─────────────────────────────────────────────────────────────────────────
// HTTP (curl)
// ─────────────────────────────────────────────────────────────────────────
function vg_http_json(string $method, string $url, $body = null, array $headers = [], int $timeout = 90): array {
    $ch = curl_init($url);
    $hdr = array_merge(['Accept: application/json'], $headers);
    $opt = [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_TIMEOUT        => $timeout,
        CURLOPT_CONNECTTIMEOUT => 20,
        CURLOPT_CUSTOMREQUEST  => $method,
        CURLOPT_USERAGENT      => 'vuln-agent-feed/1.0',
    ];
    if ($body !== null) {
        $opt[CURLOPT_POSTFIELDS] = is_string($body) ? $body : json_encode($body);
        $hdr[] = 'Content-Type: application/json';
    }
    $opt[CURLOPT_HTTPHEADER] = $hdr;
    curl_setopt_array($ch, $opt);
    $raw  = curl_exec($ch);
    $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err  = curl_error($ch);
    curl_close($ch);
    $decoded = is_string($raw) ? json_decode($raw, true) : null;
    return ['code' => $code, 'json' => is_array($decoded) ? $decoded : null, 'error' => $err];
}

// raw 응답 (XML/RSS 등 non-JSON 소스용)
function vg_http_raw(string $method, string $url, array $headers = [], int $timeout = 60): array {
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_TIMEOUT        => $timeout,
        CURLOPT_CONNECTTIMEOUT => 20,
        CURLOPT_CUSTOMREQUEST  => $method,
        CURLOPT_USERAGENT      => 'vuln-agent-feed/1.0',
        CURLOPT_HTTPHEADER     => $headers,
    ]);
    $raw  = curl_exec($ch);
    $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err  = curl_error($ch);
    curl_close($ch);
    return ['code' => $code, 'body' => is_string($raw) ? $raw : '', 'error' => $err];
}

// ─────────────────────────────────────────────────────────────────────────
// upsert 헬퍼 (수집 결과 저장)
// ─────────────────────────────────────────────────────────────────────────
function vg_upsert_cve(PDO $pdo, string $id, ?string $summary, ?float $cvss, ?string $published): void {
    $st = $pdo->prepare(
        'INSERT INTO cves (cve_id, summary, cvss, published) VALUES (?,?,?,?)
         ON DUPLICATE KEY UPDATE
           summary   = COALESCE(VALUES(summary), summary),
           cvss      = COALESCE(VALUES(cvss), cvss),
           published = COALESCE(VALUES(published), published)'
    );
    $st->execute([$id, $summary, $cvss, $published]);
}

function vg_upsert_kev(PDO $pdo, string $id, ?string $dateAdded, ?string $note): void {
    $st = $pdo->prepare(
        'INSERT INTO kev_catalog (cve_id, date_added, note) VALUES (?,?,?)
         ON DUPLICATE KEY UPDATE date_added = VALUES(date_added), note = VALUES(note)'
    );
    $st->execute([$id, $dateAdded ?: null, $note]);
}

// 국내 보안공지(KISA 등) upsert. url 기준 dedup. 신규면 true.
function vg_upsert_advisory(PDO $pdo, string $source, string $title, string $url, ?string $published, ?string $cveIds): bool {
    $chk = $pdo->prepare('SELECT id FROM advisories WHERE url = ? LIMIT 1');
    $chk->execute([$url]);
    if ($chk->fetchColumn()) {
        $pdo->prepare('UPDATE advisories SET title=?, published=?, cve_ids=? WHERE url=?')
            ->execute([$title, $published, $cveIds, $url]);
        return false;
    }
    $pdo->prepare('INSERT INTO advisories (source, title, url, published, cve_ids) VALUES (?,?,?,?,?)')
        ->execute([$source, $title, $url, $published, $cveIds]);
    return true;
}

function vg_upsert_affected(PDO $pdo, string $cve, ?string $eco, string $pkg, ?string $fixed): void {
    // (cve, package_name) 중복 방지: 존재하면 skip
    $chk = $pdo->prepare('SELECT id FROM cve_affected_packages WHERE cve_id=? AND package_name=? LIMIT 1');
    $chk->execute([$cve, $pkg]);
    if ($chk->fetchColumn()) {
        return;
    }
    $st = $pdo->prepare('INSERT INTO cve_affected_packages (cve_id, ecosystem, package_name, fixed_version) VALUES (?,?,?,?)');
    $st->execute([$cve, $eco, $pkg, $fixed]);
}

// ─────────────────────────────────────────────────────────────────────────
// 커넥터: 각 타입은 run(PDO,$conn) → ['fetched'=>N,'upserted'=>N] 반환
// ─────────────────────────────────────────────────────────────────────────
interface VgFeedConnector {
    public function run(PDO $pdo, array $conn): array;
}

// CISA KEV — 실제 악용 취약점 카탈로그(JSON, 무인증). kev_catalog + cves.
final class VgKevConnector implements VgFeedConnector {
    public function run(PDO $pdo, array $conn): array {
        $url = $conn['url'] ?? 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
        $r = vg_http_json('GET', $url);
        if ($r['code'] !== 200 || !isset($r['json']['vulnerabilities'])) {
            throw new RuntimeException("KEV fetch 실패 (HTTP {$r['code']}) {$r['error']}");
        }
        $vulns = $r['json']['vulnerabilities'];
        $up = 0;
        $pdo->beginTransaction();
        foreach ($vulns as $v) {
            $id = $v['cveID'] ?? '';
            if ($id === '') { continue; }
            $note = trim(($v['vendorProject'] ?? '') . ' ' . ($v['product'] ?? '') . ' — ' . ($v['vulnerabilityName'] ?? ''));
            vg_upsert_kev($pdo, $id, $v['dateAdded'] ?? null, mb_substr($note, 0, 250));
            vg_upsert_cve($pdo, $id, mb_substr((string) ($v['shortDescription'] ?? ''), 0, 2000), null, null);
            $up++;
        }
        $pdo->commit();
        return ['fetched' => count($vulns), 'upserted' => $up];
    }
}

// OSV.dev — 현재 수집된(최신 스캔) 패키지별로 조회 → cves + affected.
final class VgOsvConnector implements VgFeedConnector {
    public function run(PDO $pdo, array $conn): array {
        $url = $conn['url'] ?? 'https://api.osv.dev/v1/query';
        $eco = $conn['ecosystem'] ?? 'Rocky Linux';
        // 최신 스캔들의 distinct (name, version)
        $rows = $pdo->query(
            'SELECT DISTINCT p.name, p.version
             FROM packages p
             JOIN (SELECT host_id, MAX(id) mid FROM scans GROUP BY host_id) t ON t.mid = p.scan_id
             LIMIT 300'
        )->fetchAll();
        $fetched = 0; $up = 0;
        foreach ($rows as $p) {
            $q = ['package' => ['ecosystem' => $eco, 'name' => $p['name']]];
            if (!empty($p['version'])) { $q['version'] = $p['version']; }
            $r = vg_http_json('POST', $url, $q, [], 60);
            if ($r['code'] !== 200 || !isset($r['json']['vulns'])) { continue; }
            foreach ($r['json']['vulns'] as $v) {
                $id = $v['id'] ?? '';
                // OSV id 가 CVE 가 아니면 aliases 에서 CVE 추출
                if (strpos($id, 'CVE-') !== 0) {
                    foreach ($v['aliases'] ?? [] as $al) { if (strpos($al, 'CVE-') === 0) { $id = $al; break; } }
                }
                if (strpos($id, 'CVE-') !== 0) { continue; }
                vg_upsert_cve($pdo, $id, mb_substr((string) ($v['summary'] ?? ($v['details'] ?? '')), 0, 2000), null, null);
                vg_upsert_affected($pdo, $id, $eco, $p['name'], null);
                $up++;
            }
            $fetched++;
        }
        return ['fetched' => $fetched, 'upserted' => $up];
    }
}

// NVD 2.0 — 최근 N일 공개 CVE → cves (CVSS 포함).
final class VgNvdConnector implements VgFeedConnector {
    public function run(PDO $pdo, array $conn): array {
        $base = $conn['url'] ?? 'https://services.nvd.nist.gov/rest/json/cves/2.0';
        $days = (int) ($conn['days'] ?? 7);
        $key  = trim((string) ($conn['api_key'] ?? ''));
        $end   = gmdate('Y-m-d\TH:i:s.000');
        $start = gmdate('Y-m-d\TH:i:s.000', time() - $days * 86400);
        $url = $base . '?pubStartDate=' . rawurlencode($start) . '&pubEndDate=' . rawurlencode($end) . '&resultsPerPage=200';
        $headers = $key !== '' ? ['apiKey: ' . $key] : [];
        $r = vg_http_json('GET', $url, null, $headers, 90);
        if ($r['code'] !== 200 || !isset($r['json']['vulnerabilities'])) {
            throw new RuntimeException("NVD fetch 실패 (HTTP {$r['code']}) {$r['error']}");
        }
        $up = 0;
        $pdo->beginTransaction();
        foreach ($r['json']['vulnerabilities'] as $item) {
            $c = $item['cve'] ?? [];
            $id = $c['id'] ?? '';
            if ($id === '') { continue; }
            $desc = '';
            foreach ($c['descriptions'] ?? [] as $d) { if (($d['lang'] ?? '') === 'en') { $desc = $d['value']; break; } }
            $cvss = null;
            $metrics = $c['metrics'] ?? [];
            foreach (['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'] as $mk) {
                if (!empty($metrics[$mk][0]['cvssData']['baseScore'])) {
                    $cvss = (float) $metrics[$mk][0]['cvssData']['baseScore'];
                    break;
                }
            }
            $pub = !empty($c['published']) ? substr($c['published'], 0, 10) : null;
            vg_upsert_cve($pdo, $id, mb_substr($desc, 0, 2000), $cvss, $pub);
            $up++;
        }
        $pdo->commit();
        return ['fetched' => count($r['json']['vulnerabilities']), 'upserted' => $up];
    }
}

// KISA(보호나라) 국내 보안공지 RSS — 해외 도구가 안 하는 국내 특화.
//   RSS 는 title/link/pubDate 만 제공(CVE 없음) → 공지 자체를 advisories 로 수집.
//   제목에 CVE 가 있으면 best-effort 로 추출해 findings 에 국내공지 배지로 연계.
final class VgKisaConnector implements VgFeedConnector {
    public function run(PDO $pdo, array $conn): array {
        $url = $conn['url'] ?? 'https://www.boho.or.kr/kr/rss.do?bbsId=B0000133';
        $r = vg_http_raw('GET', $url);
        if ($r['code'] !== 200 || $r['body'] === '') {
            throw new RuntimeException("KISA RSS fetch 실패 (HTTP {$r['code']}) {$r['error']}");
        }
        $xml = @simplexml_load_string($r['body']);
        if ($xml === false || !isset($xml->channel->item)) {
            throw new RuntimeException('KISA RSS 파싱 실패(형식 오류)');
        }
        $items = $xml->channel->item;
        $up = 0;
        foreach ($items as $it) {
            $title = trim((string) $it->title);
            $link  = trim((string) $it->link);
            if ($title === '' || $link === '') { continue; }
            $pub = null;
            if (!empty($it->pubDate)) {
                $ts = strtotime((string) $it->pubDate);
                if ($ts !== false) { $pub = date('Y-m-d', $ts); }
            }
            preg_match_all('/CVE-[0-9]{4}-[0-9]{4,}/i', $title, $m);
            $cveIds = $m[0] ? implode(',', array_map('strtoupper', array_unique($m[0]))) : null;
            if (vg_upsert_advisory($pdo, 'kisa', mb_substr($title, 0, 500), $link, $pub, $cveIds)) {
                $up++;
            }
            // 제목에 CVE 가 있으면 cves 에도 등록(국내공지 근거 확보)
            foreach ($m[0] as $cve) {
                vg_upsert_cve($pdo, strtoupper($cve), null, null, null);
            }
        }
        return ['fetched' => count($items), 'upserted' => $up];
    }
}

function vg_feed_make(string $type): VgFeedConnector {
    switch ($type) {
        case 'kev': return new VgKevConnector();
        case 'osv': return new VgOsvConnector();
        case 'nvd': return new VgNvdConnector();
        case 'kisa': return new VgKisaConnector();
        default: throw new InvalidArgumentException("알 수 없는 커넥터 타입: $type");
    }
}

// ─────────────────────────────────────────────────────────────────────────
// 실행 + 스케줄
// ─────────────────────────────────────────────────────────────────────────
function vg_schedule_next(array $schedule, ?int $fromTs = null): ?string {
    $fromTs = $fromTs ?? time();
    $mode = $schedule['mode'] ?? 'manual';
    if ($mode === 'interval') {
        $min = max(1, (int) ($schedule['interval_minutes'] ?? 1440));
        return date('Y-m-d H:i:s', $fromTs + $min * 60);
    }
    return null; // manual → 스케줄러가 자동 실행하지 않음
}

/** 커넥터 1건 실행: 로그(running→success/error) + 커넥터 상태/다음실행 갱신. */
function vg_feed_run(PDO $pdo, int $connectorId, string $triggerBy = 'schedule'): array {
    $st = $pdo->prepare('SELECT * FROM feed_connectors WHERE id = ?');
    $st->execute([$connectorId]);
    $c = $st->fetch();
    if (!$c) {
        throw new RuntimeException("커넥터 없음: $connectorId");
    }
    $conn     = json_decode((string) $c['connection_json'], true) ?: [];
    $schedule = json_decode((string) $c['schedule_json'], true) ?: [];

    $lg = $pdo->prepare('INSERT INTO feed_collection_logs (connector_id, trigger_by, status) VALUES (?,?,?)');
    $lg->execute([$connectorId, $triggerBy, 'running']);
    $logId = (int) $pdo->lastInsertId();
    $pdo->prepare('UPDATE feed_connectors SET last_status=?, last_run_at=NOW() WHERE id=?')->execute(['running', $connectorId]);

    try {
        $res = vg_feed_make((string) $c['connector_type'])->run($pdo, $conn);
        $msg = "fetched={$res['fetched']} upserted={$res['upserted']}";
        $pdo->prepare('UPDATE feed_collection_logs SET status=?, finished_at=NOW(), items_fetched=?, items_upserted=?, message=? WHERE id=?')
            ->execute(['success', $res['fetched'], $res['upserted'], $msg, $logId]);
        $pdo->prepare('UPDATE feed_connectors SET last_status=?, last_message=?, next_run_at=? WHERE id=?')
            ->execute(['success', $msg, vg_schedule_next($schedule), $connectorId]);
        return ['ok' => true] + $res;
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) { $pdo->rollBack(); }
        $msg = mb_substr($e->getMessage(), 0, 480);
        $pdo->prepare('UPDATE feed_collection_logs SET status=?, finished_at=NOW(), message=? WHERE id=?')
            ->execute(['error', $msg, $logId]);
        $pdo->prepare('UPDATE feed_connectors SET last_status=?, last_message=?, next_run_at=? WHERE id=?')
            ->execute(['error', $msg, vg_schedule_next($schedule), $connectorId]);
        return ['ok' => false, 'error' => $msg];
    }
}

/** 스케줄러가 돌릴 대상: enabled=1 이고 (next_run_at NULL 또는 지금 이전). */
function vg_feed_due(PDO $pdo): array {
    return array_map('intval', $pdo->query(
        'SELECT id FROM feed_connectors
         WHERE enabled = 1 AND (next_run_at IS NULL OR next_run_at <= NOW())'
    )->fetchAll(PDO::FETCH_COLUMN));
}
