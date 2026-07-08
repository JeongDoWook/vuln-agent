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
        // SSRF/LFI 방어: http/https 만 허용(file://·gopher:// 등 차단), 리다이렉트도 동일 제한
        CURLOPT_PROTOCOLS       => CURLPROTO_HTTP | CURLPROTO_HTTPS,
        CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
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
        // SSRF/LFI 방어: http/https 만 허용(file://·gopher:// 등 차단), 리다이렉트도 동일 제한
        CURLOPT_PROTOCOLS       => CURLPROTO_HTTP | CURLPROTO_HTTPS,
        CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
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
    $chk = $pdo->prepare('SELECT id FROM cve_affected_packages WHERE cve_id=? AND package_name=? LIMIT 1');
    $chk->execute([$cve, $pkg]);
    $id = $chk->fetchColumn();
    if ($id) {
        // 존재하면 fixed_version 을 채워 넣는다(이전 batch 수집엔 없었음)
        if ($fixed !== null && $fixed !== '') {
            $pdo->prepare('UPDATE cve_affected_packages SET fixed_version=?, ecosystem=COALESCE(ecosystem,?) WHERE id=?')
                ->execute([$fixed, $eco, (int) $id]);
        }
        return;
    }
    $pdo->prepare('INSERT INTO cve_affected_packages (cve_id, ecosystem, package_name, fixed_version) VALUES (?,?,?,?)')
        ->execute([$cve, $eco, $pkg, $fixed]);
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

// 배포판(os_id + version) → OSV ecosystem 문자열. 미지원이면 null.
function vg_osv_ecosystem(?string $osId, ?string $osVer): ?string {
    $osId = strtolower(trim((string) $osId));
    $ver  = trim((string) $osVer);
    preg_match('/^\d+(\.\d+)?/', $ver, $m);
    $major = isset($m[0]) ? (int) $m[0] : 0;
    switch ($osId) {
        case 'debian':               return $major ? "Debian:$major" : null;
        case 'ubuntu':               return $ver !== '' ? "Ubuntu:$ver" : null;
        case 'rocky': case 'rockylinux': return $major ? "Rocky Linux:$major" : null;
        case 'almalinux':            return $major ? "AlmaLinux:$major" : null;
        case 'rhel': case 'redhat':  return $major ? "Red Hat:$major" : null;
        default:                     return null;
    }
}

// OSV vuln 에서 CVE ID 추출 (id → aliases 순)
function vg_osv_cve(array $vuln): ?string {
    if (preg_match('/CVE-\d{4}-\d+/i', (string) ($vuln['id'] ?? ''), $m)) { return strtoupper($m[0]); }
    foreach ($vuln['aliases'] ?? [] as $al) {
        if (preg_match('/CVE-\d{4}-\d+/i', (string) $al, $m)) { return strtoupper($m[0]); }
    }
    return null;
}

// OSV vuln 에서 해당 패키지의 "고쳐진 버전"(조치안) 추출 — 마지막 fixed 이벤트.
function vg_osv_fixed(array $vuln, string $key): ?string {
    $fixed = null;
    foreach ($vuln['affected'] ?? [] as $aff) {
        if (($aff['package']['name'] ?? '') !== $key) { continue; }
        foreach ($aff['ranges'] ?? [] as $rng) {
            foreach ($rng['events'] ?? [] as $ev) {
                if (!empty($ev['fixed'])) { $fixed = (string) $ev['fixed']; }
            }
        }
    }
    return $fixed;
}

// OSV.dev — 최신 스캔의 실제 패키지를 단건 /v1/query 로 조회해 취약 패키지 발굴 + 조치안.
//   배포판별 ecosystem 자동, deb/ubuntu 는 source_pkg 로 조회, 설치버전으로 필터.
//   단건 응답엔 summary·aliases·affected.ranges(고쳐진 버전) 가 있어 조치안까지 확보.
final class VgOsvConnector implements VgFeedConnector {
    public function run(PDO $pdo, array $conn): array {
        // querybatch: 응답이 {results:[{vulns:[{id}]}]} 로 작아 수백~수천 패키지도 메모리 안전.
        // (단건 query 는 커널 등 거대한 응답에서 OOM. fixed_version 은 batch 미제공 → null)
        $url = $conn['url'] ?? 'https://api.osv.dev/v1/querybatch';
        if (substr($url, -6) === '/query') { $url .= 'batch'; }
        $ecoOverride = trim((string) ($conn['ecosystem'] ?? ''));

        $scans = $pdo->query(
            'SELECT s.id, s.os_id, s.os_version
             FROM scans s JOIN (SELECT host_id, MAX(id) mid FROM scans GROUP BY host_id) t ON t.mid = s.id'
        )->fetchAll();

        $fetched = 0; $up = 0; $seen = [];
        foreach ($scans as $sc) {
            $eco = $ecoOverride !== '' ? $ecoOverride : vg_osv_ecosystem($sc['os_id'], $sc['os_version']);
            if ($eco === null || $eco === '') { continue; } // 미지원 배포판 스킵
            $isDeb = stripos($eco, 'Debian') === 0 || stripos($eco, 'Ubuntu') === 0;

            $pk = $pdo->prepare('SELECT name, source_pkg, version FROM packages WHERE scan_id = ?');
            $pk->execute([(int) $sc['id']]);

            // 쿼리 목록(배포판·패키지·버전 중복 제거). deb/ubuntu 는 source_pkg 로 조회.
            $queries = [];
            foreach ($pk->fetchAll() as $p) {
                $key = $isDeb ? ($p['source_pkg'] ?: $p['name']) : $p['name'];
                $ver = (string) $p['version'];
                if ($key === '' || $ver === '') { continue; }
                $dk = $eco . '|' . $key . '|' . $ver;
                if (isset($seen[$dk])) { continue; }
                $seen[$dk] = true;
                $queries[] = ['key' => $key, 'q' => ['package' => ['ecosystem' => $eco, 'name' => $key], 'version' => $ver]];
            }

            foreach (array_chunk($queries, 100) as $chunk) {
                $payload = ['queries' => array_map(static function ($x) { return $x['q']; }, $chunk)];
                $r = vg_http_json('POST', $url, $payload, [], 90);
                $fetched += count($chunk);
                if ($r['code'] === 200 && isset($r['json']['results'])) {
                    foreach ($r['json']['results'] as $i => $res) {
                        $key = $chunk[$i]['key'] ?? '';
                        foreach ($res['vulns'] ?? [] as $v) {
                            // batch 는 id 만 반환 → id 에서 CVE 추출(DEBIAN-CVE-…/UBUNTU-CVE-…/CVE-…)
                            if (!preg_match('/CVE-\d{4}-\d+/i', (string) ($v['id'] ?? ''), $m)) { continue; }
                            $cve = strtoupper($m[0]);
                            vg_upsert_cve($pdo, $cve, null, null, null);
                            vg_upsert_affected($pdo, $cve, $eco, $key, null);
                            $up++;
                        }
                    }
                }
                unset($r); // 응답 메모리 즉시 해제
            }
        }
        return ['fetched' => $fetched, 'upserted' => $up];
    }
}

// NVD 2.0 — 최근 N일 공개 CVE → cves (CVSS 포함). 증분 수집(전체 미러 아님).
//   기간 내 결과를 startIndex 로 끝까지 페이지네이션(무음 절단 방지, rate limit 준수).
final class VgNvdConnector implements VgFeedConnector {
    public function run(PDO $pdo, array $conn): array {
        $base = $conn['url'] ?? 'https://services.nvd.nist.gov/rest/json/cves/2.0';
        $days = max(1, (int) ($conn['days'] ?? 7));
        $key  = trim((string) ($conn['api_key'] ?? ''));
        $headers = $key !== '' ? ['apiKey: ' . $key] : [];
        $end   = gmdate('Y-m-d\TH:i:s.000');
        $start = gmdate('Y-m-d\TH:i:s.000', time() - $days * 86400);

        $perPage = 2000;              // NVD 최대
        $startIndex = 0; $total = 0; $fetched = 0; $up = 0;
        do {
            $qs = http_build_query([
                'pubStartDate'   => $start,
                'pubEndDate'     => $end,
                'resultsPerPage' => $perPage,
                'startIndex'     => $startIndex,
            ]);
            $r = vg_http_json('GET', "$base?$qs", null, $headers, 120);
            if ($r['code'] !== 200 || !isset($r['json']['vulnerabilities'])) {
                throw new RuntimeException("NVD fetch 실패 (HTTP {$r['code']}) {$r['error']}");
            }
            $total = (int) ($r['json']['totalResults'] ?? 0);
            $pdo->beginTransaction();
            foreach ($r['json']['vulnerabilities'] as $item) {
                if ($this->upsertItem($pdo, $item)) { $up++; }
                $fetched++;
            }
            $pdo->commit();
            $startIndex += $perPage;
            if ($startIndex < $total) {
                sleep($key !== '' ? 1 : 6);   // rate limit (키 없으면 5req/30s)
            }
        } while ($startIndex < $total);

        return ['fetched' => $fetched, 'upserted' => $up];
    }

    private function upsertItem(PDO $pdo, array $item): bool {
        $c = $item['cve'] ?? [];
        $id = $c['id'] ?? '';
        if ($id === '') { return false; }
        $desc = '';
        foreach ($c['descriptions'] ?? [] as $d) {
            if (($d['lang'] ?? '') === 'en') { $desc = (string) $d['value']; break; }
        }
        $cvss = null;
        foreach (['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'] as $mk) {
            if (!empty($c['metrics'][$mk][0]['cvssData']['baseScore'])) {
                $cvss = (float) $c['metrics'][$mk][0]['cvssData']['baseScore'];
                break;
            }
        }
        $pub = !empty($c['published']) ? substr((string) $c['published'], 0, 10) : null;
        vg_upsert_cve($pdo, $id, mb_substr($desc, 0, 2000), $cvss, $pub);
        return true;
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
        $xml = @simplexml_load_string($r['body'], 'SimpleXMLElement', LIBXML_NONET);
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

// FIRST EPSS — CVE별 악용확률(0~1) + 백분위. gzip CSV 를 받아 보유 CVE 만 갱신.
final class VgEpssConnector implements VgFeedConnector {
    public function run(PDO $pdo, array $conn): array {
        $url = $conn['url'] ?? 'https://epss.cyentia.com/epss_scores-current.csv.gz';
        $r = vg_http_raw('GET', $url, [], 120);
        if ($r['code'] !== 200 || $r['body'] === '') {
            throw new RuntimeException("EPSS fetch 실패 (HTTP {$r['code']}) {$r['error']}");
        }
        $txt = @gzdecode($r['body']);
        if ($txt === false) {
            throw new RuntimeException('EPSS gzip 해제 실패');
        }
        // 우리가 보유한 CVE 만 갱신(전체 34만건 삽입 안 함)
        $have = [];
        foreach ($pdo->query('SELECT cve_id FROM cves')->fetchAll(PDO::FETCH_COLUMN) as $c) {
            $have[strtoupper((string) $c)] = true;
        }
        if (!$have) {
            return ['fetched' => 0, 'upserted' => 0];
        }
        $upd = $pdo->prepare('UPDATE cves SET epss = ?, epss_percentile = ? WHERE cve_id = ?');
        $fetched = 0; $up = 0;
        $pdo->beginTransaction();
        foreach (explode("\n", $txt) as $line) {
            if ($line === '' || $line[0] === '#') { continue; }
            if (strncmp($line, 'cve,', 4) === 0) { continue; } // 헤더
            $f = explode(',', $line);
            if (count($f) < 3) { continue; }
            $fetched++;
            $cve = strtoupper($f[0]);
            if (!isset($have[$cve])) { continue; }
            $upd->execute([(float) $f[1], (float) $f[2], $cve]);
            $up++;
        }
        $pdo->commit();
        return ['fetched' => $fetched, 'upserted' => $up];
    }
}

function vg_feed_make(string $type): VgFeedConnector {
    switch ($type) {
        case 'kev':  return new VgKevConnector();
        case 'osv':  return new VgOsvConnector();
        case 'nvd':  return new VgNvdConnector();
        case 'kisa': return new VgKisaConnector();
        case 'epss': return new VgEpssConnector();
        default: throw new InvalidArgumentException("알 수 없는 커넥터 타입: $type");
    }
}

// ─────────────────────────────────────────────────────────────────────────
// 실행 + 스케줄
// ─────────────────────────────────────────────────────────────────────────
// cron 필드 한 개 매칭 (*, 숫자, a-b 범위, */n 스텝, 콤마 목록 지원)
function vg_cron_field_match(string $field, int $val, int $min, int $max): bool {
    foreach (explode(',', $field) as $part) {
        $step = 1;
        if (strpos($part, '/') !== false) {
            [$part, $s] = explode('/', $part, 2);
            $step = max(1, (int) $s);
        }
        if ($part === '*' || $part === '') { $lo = $min; $hi = $max; }
        elseif (strpos($part, '-') !== false) { [$a, $b] = explode('-', $part, 2); $lo = (int) $a; $hi = (int) $b; }
        else { $lo = $hi = (int) $part; }
        for ($i = $lo; $i <= $hi; $i += $step) {
            if ($i === $val) { return true; }
        }
    }
    return false;
}

// 표준 5필드 cron(분 시 일 월 요일)이 주어진 시각과 일치하는가. 요일 0=일요일(7도 일요일).
function vg_cron_match(string $expr, int $ts): bool {
    $f = preg_split('/\s+/', trim($expr));
    if (count($f) !== 5) { return false; }
    $dow = (int) date('w', $ts);
    return vg_cron_field_match($f[0], (int) date('i', $ts), 0, 59)
        && vg_cron_field_match($f[1], (int) date('G', $ts), 0, 23)
        && vg_cron_field_match($f[2], (int) date('j', $ts), 1, 31)
        && vg_cron_field_match($f[3], (int) date('n', $ts), 1, 12)
        && (vg_cron_field_match($f[4], $dow, 0, 6) || ($dow === 0 && vg_cron_field_match($f[4], 7, 0, 7)));
}

// 지금 실행 대상인가 (스케줄러가 매 tick 마다 판정). last_run 기준 중복 방지.
function vg_schedule_due(array $schedule, ?string $lastRun, ?int $now = null): bool {
    $now = $now ?? time();
    $lastTs = $lastRun ? strtotime($lastRun) : null;
    switch ($schedule['mode'] ?? 'manual') {
        case 'interval':
            $min = max(1, (int) ($schedule['interval_minutes'] ?? 1440));
            return $lastTs === null || ($now - $lastTs) >= $min * 60;
        case 'daily':
            [$h, $m] = array_map('intval', array_pad(explode(':', (string) ($schedule['time'] ?? '03:00')), 2, 0));
            $sched = strtotime(date('Y-m-d', $now) . sprintf(' %02d:%02d:00', $h, $m));
            return $now >= $sched && ($lastTs === null || $lastTs < $sched);
        case 'cron':
            $expr = (string) ($schedule['expr'] ?? '');
            if ($expr === '' || !vg_cron_match($expr, $now)) { return false; }
            return $lastTs === null || $lastTs < $now - ($now % 60); // 같은 분 중복 방지
        default: // manual
            return false;
    }
}

// 다음 실행 예정 시각(표시용).
function vg_schedule_next(array $schedule, ?int $fromTs = null): ?string {
    $fromTs = $fromTs ?? time();
    switch ($schedule['mode'] ?? 'manual') {
        case 'interval':
            $min = max(1, (int) ($schedule['interval_minutes'] ?? 1440));
            return date('Y-m-d H:i:s', $fromTs + $min * 60);
        case 'daily':
            [$h, $m] = array_map('intval', array_pad(explode(':', (string) ($schedule['time'] ?? '03:00')), 2, 0));
            $next = strtotime(date('Y-m-d', $fromTs) . sprintf(' %02d:%02d:00', $h, $m));
            if ($next <= $fromTs) { $next += 86400; }
            return date('Y-m-d H:i:s', $next);
        case 'cron':
            $expr = (string) ($schedule['expr'] ?? '');
            if ($expr === '') { return null; }
            $t = $fromTs - ($fromTs % 60) + 60;
            for ($i = 0; $i < 527040; $i++) { // 최대 366일 앞으로 스캔
                if (vg_cron_match($expr, $t)) { return date('Y-m-d H:i:s', $t); }
                $t += 60;
            }
            return null;
        default: // manual
            return null;
    }
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

/**
 * 미리보기: 소스에서 최대 10건을 가져와 그대로 보여준다(저장 안 함).
 *   커넥터 설정 전에 URL/응답 형태를 눈으로 확인하는 용도.
 */
function vg_feed_preview(string $type, array $conn, PDO $pdo): array {
    $limit = 10;
    switch ($type) {
        case 'kev':
            $r = vg_http_json('GET', $conn['url'] ?? '');
            if ($r['code'] !== 200 || !isset($r['json']['vulnerabilities'])) {
                return ['ok' => false, 'error' => "HTTP {$r['code']} {$r['error']}"];
            }
            $all = $r['json']['vulnerabilities'];
            return ['ok' => true, 'count' => count($all), 'sample' => array_slice($all, 0, $limit)];

        case 'nvd':
            $base = $conn['url'] ?? 'https://services.nvd.nist.gov/rest/json/cves/2.0';
            $days = max(1, (int) ($conn['days'] ?? 7));
            $qs = http_build_query([
                'pubStartDate'   => gmdate('Y-m-d\TH:i:s.000', time() - $days * 86400),
                'pubEndDate'     => gmdate('Y-m-d\TH:i:s.000'),
                'resultsPerPage' => $limit,
            ]);
            $h = !empty($conn['api_key']) ? ['apiKey: ' . $conn['api_key']] : [];
            $r = vg_http_json('GET', "$base?$qs", null, $h, 60);
            if ($r['code'] !== 200 || !isset($r['json']['vulnerabilities'])) {
                return ['ok' => false, 'error' => "HTTP {$r['code']} {$r['error']}"];
            }
            return ['ok' => true, 'count' => (int) ($r['json']['totalResults'] ?? 0), 'sample' => $r['json']['vulnerabilities']];

        case 'kisa':
            $r = vg_http_raw('GET', $conn['url'] ?? '');
            $xml = $r['code'] === 200 ? @simplexml_load_string($r['body'], 'SimpleXMLElement', LIBXML_NONET) : false;
            if ($xml === false || !isset($xml->channel->item)) {
                return ['ok' => false, 'error' => "RSS 파싱 실패 (HTTP {$r['code']})"];
            }
            $out = []; $n = 0;
            foreach ($xml->channel->item as $it) {
                if ($n++ >= $limit) { break; }
                $out[] = ['title' => (string) $it->title, 'link' => (string) $it->link, 'pubDate' => (string) $it->pubDate];
            }
            return ['ok' => true, 'count' => count($xml->channel->item), 'sample' => $out];

        case 'osv':
            $sc = $pdo->query(
                'SELECT s.id, s.os_id, s.os_version FROM scans s
                 JOIN (SELECT host_id, MAX(id) mid FROM scans GROUP BY host_id) t ON t.mid = s.id
                 ORDER BY s.id DESC LIMIT 1'
            )->fetch();
            if (!$sc) {
                return ['ok' => false, 'error' => '수집된 스캔이 없어 미리보기 불가(에이전트 먼저 실행).'];
            }
            $eco = trim((string) ($conn['ecosystem'] ?? '')) ?: vg_osv_ecosystem($sc['os_id'], $sc['os_version']);
            if (!$eco) {
                return ['ok' => false, 'error' => "OSV ecosystem 판정 불가(os_id={$sc['os_id']}). 커넥터에 ecosystem 지정."];
            }
            $isDeb = stripos($eco, 'Debian') === 0 || stripos($eco, 'Ubuntu') === 0;
            $pk = $pdo->prepare('SELECT name, source_pkg, version FROM packages WHERE scan_id=? LIMIT 1');
            $pk->execute([(int) $sc['id']]);
            $pkg = $pk->fetch();
            $key = $isDeb ? ($pkg['source_pkg'] ?: $pkg['name']) : $pkg['name'];
            $single = 'https://api.osv.dev/v1/query';
            $r = vg_http_json('POST', $single, ['package' => ['ecosystem' => $eco, 'name' => $key], 'version' => (string) $pkg['version']], [], 60);
            if ($r['code'] !== 200) {
                return ['ok' => false, 'error' => "HTTP {$r['code']} {$r['error']}"];
            }
            $vulns = $r['json']['vulns'] ?? [];
            return ['ok' => true, 'count' => count($vulns), 'note' => "ecosystem={$eco}, '{$key}'@{$pkg['version']} 조회", 'sample' => array_slice($vulns, 0, $limit)];

        default:
            return ['ok' => false, 'error' => "미리보기 미지원 타입: $type"];
    }
}

/** 스케줄러가 돌릴 대상: enabled=1 이고 스케줄(interval/daily/cron) 상 지금이 due. */
function vg_feed_due(PDO $pdo): array {
    $rows = $pdo->query('SELECT id, schedule_json, last_run_at FROM feed_connectors WHERE enabled = 1')->fetchAll();
    $due = [];
    foreach ($rows as $r) {
        $sch = json_decode((string) $r['schedule_json'], true) ?: [];
        if (vg_schedule_due($sch, $r['last_run_at'])) {
            $due[] = (int) $r['id'];
        }
    }
    return $due;
}
