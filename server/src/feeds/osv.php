<?php
declare(strict_types=1);

/**
 * feeds/osv.php — OSV.dev 커넥터. 최신 수집의 실제 패키지를 querybatch 로 조회해
 *   취약 패키지 발굴 + 조치안(fixed_version). 배포판별 ecosystem 자동, deb/ubuntu 는
 *   source_pkg 로 조회, 설치버전으로 필터. 조치안 지연 보강(vg_osv_enrich_fixed) 포함.
 *   미리보기는 run 과 같은 querybatch 로 앞 100개를 실제 조회한다(같은 소스·같은 기준).
 */

require_once __DIR__ . '/http.php';
require_once __DIR__ . '/upsert.php';
require_once __DIR__ . '/../db.php';      // vg_latest_scan_subq
require_once __DIR__ . '/../distro.php';
require_once __DIR__ . '/../vercmp.php';  // vg_osv_ecosystem / vg_pkg_ecosystem (매처와 공유)

// 커넥터 기본 소스 URL. 커넥터 레코드의 url 이 비어 있으면 이 값을 쓴다(run/미리보기 공용).
const VG_OSV_URL = 'https://api.osv.dev/v1/querybatch';

// vg_osv_ecosystem() 은 src/distro.php 로 옮겼다 — 매처도 같은 기준으로 읽어야 하기 때문.

// OSV vuln 에서 CVE ID 추출 (id → aliases 순)
function vg_osv_cve(array $vuln): ?string {
    if (preg_match('/CVE-\d{4}-\d+/i', (string) ($vuln['id'] ?? ''), $m)) { return strtoupper($m[0]); }
    foreach ($vuln['aliases'] ?? [] as $al) {
        if (preg_match('/CVE-\d{4}-\d+/i', (string) $al, $m)) { return strtoupper($m[0]); }
    }
    return null;
}

/**
 * OSV vuln 에서 해당 패키지의 "고쳐진 버전"(조치안) 추출 — 마지막 fixed 이벤트.
 *
 * $eco 를 주면 그 배포판의 affected 만 본다. 한 레코드가 여러 릴리스를 담기 때문이다
 * (USN-7786-1 은 14.04~24.04 의 openssl 을 한꺼번에 나열한다). 패키지명만으로 고르면
 * 24.04 호스트에 20.04 의 fixed 버전을 붙일 수 있다.
 * OSV 의 ecosystem 은 'Ubuntu:24.04:LTS' 처럼 접미사가 붙어 접두 일치로 비교한다.
 */
function vg_osv_manager(string $eco): string {
    $e = strtolower($eco);
    if (strpos($e, 'debian') === 0 || strpos($e, 'ubuntu') === 0) { return 'dpkg'; }
    if (strpos($e, 'red hat') === 0 || strpos($e, 'rocky linux') === 0 ||
        strpos($e, 'almalinux') === 0 || strpos($e, 'oracle linux') === 0) { return 'rpm'; }
    if (strpos($e, 'alpine') === 0) { return 'apk'; }
    $map = ['pypi' => 'pip', 'npm' => 'npm', 'rubygems' => 'gem',
            'packagist' => 'composer', 'go' => 'go'];
    return $map[$e] ?? 'upstream';
}

/** 설치 버전이 포함된 OSV 취약 구간의 fixed 경계만 반환한다. */
function vg_osv_range_fixed(array $range, string $installed, string $manager): ?string {
    if (strtoupper((string) ($range['type'] ?? '')) === 'GIT') { return null; }
    $vulnerable = false;
    foreach ($range['events'] ?? [] as $event) {
        if (isset($event['introduced'])) {
            $introduced = (string) $event['introduced'];
            if ($introduced === '0' || vg_ver_cmp($installed, $introduced, $manager) >= 0) { $vulnerable = true; }
            continue;
        }
        if (isset($event['fixed'])) {
            $fixed = (string) $event['fixed'];
            if ($vulnerable && vg_ver_cmp($installed, $fixed, $manager) < 0) { return $fixed; }
            if (vg_ver_cmp($installed, $fixed, $manager) >= 0) { $vulnerable = false; }
            continue;
        }
        if (isset($event['last_affected']) && vg_ver_cmp($installed, (string) $event['last_affected'], $manager) > 0) {
            $vulnerable = false;
            continue;
        }
        if (isset($event['limit']) && (string) $event['limit'] !== '*' &&
            vg_ver_cmp($installed, (string) $event['limit'], $manager) >= 0) { $vulnerable = false; }
    }
    return null;
}

function vg_osv_fixed(array $vuln, string $key, ?string $eco = null, ?string $installed = null): ?string {
    $fixed = null;
    foreach ($vuln['affected'] ?? [] as $aff) {
        if (($aff['package']['name'] ?? '') !== $key) { continue; }
        if ($eco !== null && strpos((string) ($aff['package']['ecosystem'] ?? ''), $eco) !== 0) { continue; }
        $manager = vg_osv_manager((string) ($aff['package']['ecosystem'] ?? $eco ?? ''));
        foreach ($aff['ranges'] ?? [] as $rng) {
            if ($installed !== null) {
                $candidate = vg_osv_range_fixed($rng, $installed, $manager);
                if ($candidate !== null) { return $candidate; }
                continue;
            }
            foreach ($rng['events'] ?? [] as $ev) {
                if (!empty($ev['fixed'])) { $fixed = (string) $ev['fixed']; }
            }
        }
    }
    return $fixed;
}

/** 전역 카탈로그에는 모든 설치본에 안전한 단일 fixed 경계만 저장한다. */
function vg_osv_global_fixed(array $vuln, string $key, string $eco, string $installed): ?string {
    $fixedEvents = [];
    foreach ($vuln['affected'] ?? [] as $aff) {
        if (($aff['package']['name'] ?? '') !== $key) { continue; }
        if (strpos((string) ($aff['package']['ecosystem'] ?? ''), $eco) !== 0) { continue; }
        foreach ($aff['ranges'] ?? [] as $range) {
            if (strtoupper((string) ($range['type'] ?? '')) === 'GIT') { continue; }
            foreach ($range['events'] ?? [] as $event) {
                if (isset($event['fixed'])) { $fixedEvents[(string) $event['fixed']] = true; }
            }
        }
    }
    // 스키마는 package/ecosystem당 fixed 하나만 표현한다. 여러 구간을 마지막 값으로
    // 덮으면 다른 브랜치가 패치된 것으로 오판되므로 보수적으로 미정(null) 처리한다.
    if (count($fixedEvents) !== 1) { return null; }
    return vg_osv_fixed($vuln, $key, $eco, $installed);
}
/** Debian 계열은 source_pkg와 source_version을 한 쌍으로 질의해야 한다. */
function vg_osv_package_query(array $pkg, string $eco): ?array {
    $isDeb = stripos($eco, 'Debian') === 0 || stripos($eco, 'Ubuntu') === 0;
    $source = trim((string) ($pkg['source_pkg'] ?? ''));
    $key = $isDeb && $source !== '' ? $source : trim((string) ($pkg['name'] ?? ''));
    $sourceVersion = trim((string) ($pkg['source_version'] ?? ''));
    $version = $isDeb && $source !== '' && $sourceVersion !== '' ? $sourceVersion : trim((string) ($pkg['version'] ?? ''));
    if ($key === '' || $version === '') { return null; }
    return ['key' => $key, 'eco' => $eco,
            'q' => ['package' => ['ecosystem' => $eco, 'name' => $key], 'version' => $version]];
}
/**
 * 보안공지 레코드(USN-*, DSA-* …)가 묶고 있는 CVE 목록.
 *   querybatch 는 id 만 준다. USN 은 id 에 CVE 가 없어 그대로 버리면 취약점을 놓친다:
 *   실측(Ubuntu:24.04, 4개 패키지) CVE 105건 저장 → USN 을 펼치면 133건(+27%).
 *   OSV 의 per-CVE 레코드(UBUNTU-CVE-*)가 불완전한 탓이다. 예: CVE-2025-5745 는
 *   per-CVE 레코드에 Ubuntu:25.04 만 있는데, USN-7634-1 은 24.04 glibc 를 고친다.
 *
 *   USN 의 CVE 목록은 USN 전체 기준이라 일부는 다른 릴리스·다른 패키지 몫일 수 있다.
 *   그래도 조치는 동일하다(그 fixed 버전으로 올리면 전부 해결) → 커버리지를 택했다.
 * @return list<string> 대문자 CVE ID
 */
function vg_osv_advisory_cves(array $doc): array {
    $out = [];
    foreach (array_merge($doc['upstream'] ?? [], $doc['aliases'] ?? []) as $ref) {
        if (preg_match('/CVE-\d{4}-\d+/i', (string) $ref, $m)) { $out[strtoupper($m[0])] = true; }
    }
    return array_keys($out);
}

/** 단건 조회 URL(/v1/vulns/<id>). 커넥터 URL 이 무엇이든 같은 호스트를 쓴다. */
function vg_osv_vuln_url(string $id): string {
    return 'https://api.osv.dev/v1/vulns/' . rawurlencode($id);
}

/** 커넥터에 /v1/query 가 저장돼 있어도 batch 엔드포인트로 보정한다(run·미리보기 공용). */
function vg_osv_batch_url(array $conn): string {
    $url = vg_conn_url($conn, VG_OSV_URL);
    return substr($url, -6) === '/query' ? $url . 'batch' : $url;
}

/**
 * 스캔 1건의 패키지를 OSV querybatch 질의 목록으로 바꾼다(패키지·버전 중복 제거).
 * deb/ubuntu 는 바이너리 패키지가 아니라 source_pkg 로 조회해야 매칭된다.
 *
 * @return list<array{key:string,q:array}>
 */
function vg_osv_queries(PDO $pdo, int $scanId, string $eco): array {
    // OS 패키지만. 언어 패키지는 vg_osv_lang_queries 가 자기 생태계로 따로 조회한다.
    $pk = $pdo->prepare("SELECT name, source_pkg, source_version, version FROM tb_package
                         WHERE scan_id = ? AND container_id = 0 AND manager IN ('rpm','dpkg')");
    $pk->execute([$scanId]);

    $out = []; $seen = [];
    foreach ($pk->fetchAll() as $p) {
        $query = vg_osv_package_query($p, $eco);
        if ($query === null) { continue; }
        $key = $query['key']; $ver = $query['q']['version'];
        if (isset($seen["$key|$ver"])) { continue; }
        $seen["$key|$ver"] = true;
        $out[] = $query;
    }
    return $out;
}

/**
 * 언어 패키지(pip/npm/gem/composer) → OSV 질의. 배포판과 무관하게 자기 생태계로 조회한다.
 * 에이전트는 예전부터 이걸 수집해 보냈는데 서버가 버려서 언어 패키지 CVE 가 전부 미탐이었다.
 *
 * @return list<array{key:string,eco:string,q:array}>
 */
function vg_osv_lang_queries(PDO $pdo, int $scanId): array {
    $pk = $pdo->prepare("SELECT manager, name, version FROM tb_package
                         WHERE scan_id = ? AND container_id = 0 AND manager NOT IN ('rpm','dpkg')");
    $pk->execute([$scanId]);

    $out = []; $seen = [];
    foreach ($pk->fetchAll() as $p) {
        $eco = vg_pkg_ecosystem((string) $p['manager'], null);
        $key = (string) $p['name'];
        $ver = (string) $p['version'];
        if ($eco === null || $key === '' || $ver === '' || isset($seen["$eco|$key|$ver"])) { continue; }
        $seen["$eco|$key|$ver"] = true;
        $out[] = ['key' => $key, 'eco' => $eco,
                  'q' => ['package' => ['ecosystem' => $eco, 'name' => $key], 'version' => $ver]];
    }
    return $out;
}

/**
 * 컨테이너 **내부** 패키지 → OSV 질의. 생태계는 그 컨테이너의 배포판이다(호스트와 다를 수 있다).
 * deb 계열은 호스트와 마찬가지로 source_pkg 로 조회해야 매칭된다.
 *
 * @return list<array{key:string,eco:string,q:array}>
 */
function vg_osv_container_queries(PDO $pdo, int $scanId): array {
    $st = $pdo->prepare(
        'SELECT c.os_id, c.os_version, p.manager, p.name, p.source_pkg, p.source_version, p.version
           FROM tb_package p JOIN tb_container c ON c.container_id = p.container_id
          WHERE p.scan_id = ? AND p.container_id > 0'
    );
    $st->execute([$scanId]);

    $out = []; $seen = [];
    foreach ($st->fetchAll() as $p) {
        // 컨테이너 안에도 **언어 패키지**가 있다(Go 바이너리에서 뽑은 의존 모듈 등).
        //   그건 컨테이너 배포판이 아니라 자기 생태계(Go/PyPI/npm…)로 물어야 한다.
        //   배포판으로 물으면 이름만 같은 엉뚱한 CVE 가 붙거나(오탐), 배포판이 OSV 미지원이면
        //   조회 자체를 건너뛰어 통째로 미탐이 된다 — Calico 컨테이너가 정확히 그 경우였다.
        $mgr = (string) $p['manager'];
        if (vg_is_os_manager($mgr)) {
            $eco = vg_osv_ecosystem($p['os_id'], $p['os_version']);
        } else {
            $eco = vg_pkg_ecosystem($mgr, null);
        }
        if ($eco === null) { continue; }                     // OSV 미지원 배포판 → 조회 불가
        $query = vg_osv_package_query($p, $eco);
        if ($query === null) { continue; }
        $key = $query['key']; $ver = $query['q']['version'];
        if (isset($seen["$eco|$key|$ver"])) { continue; }
        $seen["$eco|$key|$ver"] = true;
        $out[] = $query;
    }
    return $out;
}

// OSV.dev — 최신 수집의 실제 패키지를 단건 /v1/query 로 조회해 취약 패키지 발굴 + 조치안.
//   배포판별 ecosystem 자동, deb/ubuntu 는 source_pkg 로 조회, 설치버전으로 필터.
//   단건 응답엔 summary·aliases·affected.ranges(고쳐진 버전) 가 있어 조치안까지 확보.
final class VgOsvConnector implements VgFeedConnector {
    public function run(PDO $pdo, array $conn): array {
        // querybatch: 응답이 {results:[{vulns:[{id}]}]} 로 작아 수백~수천 패키지도 메모리 안전.
        // (단건 query 는 커널 등 거대한 응답에서 OOM. fixed_version 은 batch 미제공 → null)
        $url = vg_osv_batch_url($conn);
        $ecoOverride = trim((string) ($conn['ecosystem'] ?? ''));

        $scans = $pdo->query(
            'SELECT s.scan_id, s.os_id, s.os_version
             FROM tb_scan s JOIN ' . vg_latest_scan_subq() . ' t ON t.mid = s.scan_id'
        )->fetchAll();

        $fetched = 0; $up = 0; $seen = [];
        $direct  = [];   // [cve, eco, key] — id 에 CVE 가 있는 것. upsert 는 3-pass 트랜잭션에서.
        $advWork = [];   // [id, eco, key] — CVE 가 id 에 없는 보안공지. 3-pass 로 펼친다.
        $advIds  = [];   // id => true    — prefetch 할 고유 공지(같은 USN 이 여러 패키지에 걸린다)

        // ── 1-pass: querybatch(이미 100개 배치라 빠르다). 결과를 **모으기만** 한다 —
        //    HTTP 와 DB write 를 분리해, upsert 는 아래 트랜잭션에서 한꺼번에 커밋한다
        //    (예전엔 write 마다 autocommit fsync 라 1,646 write 가 76초였다). ──
        foreach ($scans as $sc) {
            $eco = $ecoOverride !== '' ? $ecoOverride : vg_osv_ecosystem($sc['os_id'], $sc['os_version']);

            // OS 패키지(배포판 생태계) + 언어 패키지(PyPI/npm/RubyGems/Packagist).
            //   배포판이 미지원(eco=null)이어도 언어 패키지는 조회할 수 있다.
            $cand = array_merge(vg_osv_lang_queries($pdo, (int) $sc['scan_id']),
                            vg_osv_container_queries($pdo, (int) $sc['scan_id']));   // 컨테이너 내부 패키지도 자기 배포판으로 조회
            if ($eco !== null && $eco !== '') {
                $cand = array_merge(vg_osv_queries($pdo, (int) $sc['scan_id'], $eco), $cand);
            }

            // 스캔 간 중복 조회 방지(호스트가 달라도 같은 생태계·패키지·버전이면 한 번만).
            $queries = [];
            foreach ($cand as $q) {
                $dk = $q['eco'] . '|' . $q['key'] . '|' . $q['q']['version'];
                if (isset($seen[$dk])) { continue; }
                $seen[$dk] = true;
                $queries[] = $q;
            }

            foreach (array_chunk($queries, 100) as $chunk) {
                $payload = ['queries' => array_map(static function ($x) { return $x['q']; }, $chunk)];
                $r = vg_http_json('POST', $url, $payload, [], 90);
                $fetched += count($chunk);
                if ($r['code'] === 200 && isset($r['json']['results'])) {
                    foreach ($r['json']['results'] as $i => $res) {
                        $key    = $chunk[$i]['key'] ?? '';
                        $qEco   = $chunk[$i]['eco'] ?? $eco;   // 질의마다 생태계가 다르다(배포판/PyPI/npm…)
                        foreach ($res['vulns'] ?? [] as $v) {
                            $id = (string) ($v['id'] ?? '');
                            if ($id === '') { continue; }
                            // batch 는 id 만 반환 → id 에서 CVE 추출(DEBIAN-CVE-…/UBUNTU-CVE-…/CVE-…)
                            if (preg_match('/CVE-\d{4}-\d+/i', $id, $m)) {
                                $dk = strtoupper($m[0]) . '|' . $qEco . '|' . $key;
                                if (!isset($seen[$dk])) {
                                    $seen[$dk] = true;
                                    $direct[]  = [strtoupper($m[0]), (string) $qEco, $key];
                                }
                                continue;
                            }
                            // CVE 없는 공지 → 3-pass 로. 같은 (공지,패키지) 중복은 여기서 걸러 GET 을 아낀다.
                            $wk = $id . '|' . $qEco . '|' . $key;
                            if (!isset($seen[$wk])) {
                                $seen[$wk]   = true;
                                $advWork[]   = [$id, (string) $qEco, $key];
                                $advIds[$id] = true;
                            }
                        }
                    }
                }
                unset($r); // 응답 메모리 즉시 해제
            }
        }

        // ── 2-pass: 고유 공지 문서를 **병렬로** 받아 캐시를 채운다(GHSA 가 많은 환경에서 순차 GET 을
        //    없앤다). HTTP 라 트랜잭션 밖에서 한다 — 트랜잭션을 HTTP 동안 열어두면 락을 오래 쥔다. ──
        $this->prefetchAdvisories(array_keys($advIds));

        // ── 3-pass: DB write 를 **한 트랜잭션으로** 묶어 커밋한다(개별 autocommit fsync 제거).
        //    2000건마다 끊어 락을 짧게 쥔다(rhoval·ubuntuoval 과 같은 방식). ──
        $pdo->beginTransaction();
        $w = 0;
        $tick = function () use ($pdo, &$w) {
            if (++$w % 2000 === 0) { $pdo->commit(); $pdo->beginTransaction(); }
        };
        foreach ($direct as [$cve, $qEco, $key]) {
            vg_upsert_cve($pdo, $cve, null, null, null);
            vg_upsert_affected($pdo, $cve, $qEco, $key, null);
            $up++;
            $tick();
        }
        // 공지 펼치기(전부 캐시 히트). 캐시 실패분만 expandAdvisory 가 순차 폴백한다(소수).
        foreach ($advWork as [$id, $qEco, $key]) {
            $up += $this->expandAdvisory($pdo, $id, $qEco, $key);
            $tick();
        }
        $pdo->commit();
        return ['fetched' => $fetched, 'upserted' => $up];
    }

    // 미리보기: run 과 같은 querybatch 로 최신 수집의 앞 100개를 실제 조회한다(같은 소스·같은 기준).
    //   패키지 1건만 단건 조회하면 대개 취약점이 없어 항상 "0건" 으로 보였다.
    public function preview(PDO $pdo, array $conn): array {
        $sc = $pdo->query(
            'SELECT s.scan_id, s.os_id, s.os_version FROM tb_scan s
             JOIN ' . vg_latest_scan_subq() . ' t ON t.mid = s.scan_id
             ORDER BY s.scan_id DESC LIMIT 1'
        )->fetch();
        if (!$sc) {
            return ['ok' => false, 'error' => '수집 이력이 없어 미리보기 불가(에이전트 먼저 실행).'];
        }
        $eco = trim((string) ($conn['ecosystem'] ?? '')) ?: vg_osv_ecosystem($sc['os_id'], $sc['os_version']);
        if (!$eco) {
            return ['ok' => false, 'error' => "OSV ecosystem 판정 불가(os_id={$sc['os_id']}). 커넥터에 ecosystem 지정."];
        }
        $queries = array_slice(vg_osv_queries($pdo, (int) $sc['scan_id'], $eco), 0, 100);
        if (!$queries) {
            return ['ok' => false, 'error' => "최신 수집(id={$sc['scan_id']})에 패키지가 없어 미리보기 불가."];
        }
        $r = vg_http_json('POST', vg_osv_batch_url($conn),
            ['queries' => array_column($queries, 'q')], [], 90);
        if ($r['code'] !== 200 || !isset($r['json']['results'])) {
            return ['ok' => false, 'error' => "HTTP {$r['code']} {$r['error']}"];
        }
        $hits = [];
        foreach ($r['json']['results'] as $i => $res) {
            if (empty($res['vulns'])) { continue; }
            $hits[] = [
                'package' => $queries[$i]['key'],
                'version' => $queries[$i]['q']['version'],
                'vulns'   => array_column($res['vulns'], 'id'),
            ];
        }
        $note = sprintf('ecosystem=%s, 패키지 %d개 조회 → 취약 %d개', $eco, count($queries), count($hits));
        return ['ok' => true, 'count' => count($hits), 'note' => $note, 'sample' => array_slice($hits, 0, 10)];
    }

    /**
     * 공지 문서들을 **병렬로** 받아 advCache 를 채운다(expandAdvisory 가 이 캐시를 그대로 쓴다).
     *   그래서 판정 로직은 한 줄도 안 바뀌고, 순차 GET 만 사라진다.
     *   거대 응답(커널 등)은 상한으로 그 건만 건너뛰고 캐시에 null 을 남긴다 → expandAdvisory 가
     *   순차 폴백(4MB 제한 GET)으로 다시 시도한다(기존 동작과 동일).
     * @param string[] $ids
     */
    private function prefetchAdvisories(array $ids): void {
        $ids = array_values(array_filter($ids, fn(string $id) => !array_key_exists($id, $this->advCache)));
        if (!$ids) { return; }

        $urlOf = [];
        foreach ($ids as $id) { $urlOf[vg_osv_vuln_url($id)] = $id; }
        // OSV advisory 는 대개 수 KB — 4MB 상한이면 커널류 거대 문서만 걸러진다(expandAdvisory 와 동일).
        $resp = vg_http_get_many(array_keys($urlOf), 8, 30, [], 4 * 1024 * 1024);

        foreach ($urlOf as $u => $id) {
            $body = ($resp[$u]['code'] ?? 0) === 200 ? ($resp[$u]['body'] ?? '') : '';
            $doc  = $body !== '' ? json_decode($body, true) : null;
            // 실패·거대응답은 캐시하지 않는다 → expandAdvisory 가 순차로 한 번 더 시도한다(멱등).
            if (is_array($doc)) { $this->advCache[$id] = $doc; }
        }
    }

    /**
     * 보안공지 1건을 펼쳐 CVE 를 등록한다. 같은 공지가 여러 패키지에서 나오므로 문서를 캐시한다.
     * 공지 레코드엔 우리 배포판의 fixed 버전이 들어 있어 조치안까지 여기서 확보된다.
     * @return int upsert 한 CVE 수
     */
    private function expandAdvisory(PDO $pdo, string $id, string $eco, string $key): int {
        if (!array_key_exists($id, $this->advCache)) {
            $r = vg_http_json('GET', vg_osv_vuln_url($id), null, [], 30, 4 * 1024 * 1024);
            // 실패해도 수집 전체를 접지 않는다. 다음 실행에서 다시 시도한다.
            $this->advCache[$id] = ($r['code'] === 200 && is_array($r['json'] ?? null)) ? $r['json'] : null;
        }
        $doc = $this->advCache[$id];
        if ($doc === null) { return 0; }

        $fixed = vg_osv_fixed($doc, $key, $eco);
        $n = 0;
        foreach (vg_osv_advisory_cves($doc) as $cve) {
            vg_upsert_cve($pdo, $cve, null, null, null);
            vg_upsert_affected($pdo, $cve, $eco, $key, $fixed);
            $n++;
        }
        return $n;
    }

    /** @var array<string, array|null> 보안공지 문서 캐시(같은 USN 이 여러 패키지에 걸린다) */
    private array $advCache = [];
}

/**
 * OSV 조치안(fixed_version) 지연 보강.
 *   querybatch 응답엔 fixed 가 없다. 보안공지(USN)로 들어온 CVE 는 커넥터가 조치안까지 채우지만,
 *   per-CVE 레코드(UBUNTU-CVE-*)로 들어온 CVE 는 여전히 비어 있다. 여기서 "실제로 findings 에
 *   뜬 취약 패키지"(소수)만 골라 단건 /v1/query 로 조회해 채운다.
 *   커널 등 거대 응답은 바이트 상한으로 건너뛴다(OOM 방지).
 *
 *   findings 를 읽으므로 반드시 재매칭 뒤에 부른다.
 *   fixed 가 이미 있으면 대상에서 빠지므로 몇 번을 돌려도 멱등하다.
 *
 * @param callable|null $log 진행 로그(문자열 1줄). CLI 에서만 쓴다.
 * @return array{targets:int,queried:int,filled:int,skipped:int}
 */
function vg_osv_enrich_fixed(PDO $pdo, ?callable $log = null): array {
    $maxBytes = 6 * 1024 * 1024;
    $single   = 'https://api.osv.dev/v1/query';
    $stat     = ['targets' => 0, 'queried' => 0, 'filled' => 0, 'skipped' => 0];

    // 보강 대상: findings 에 실제로 뜬 패키지 중 조치 버전이 아직 빈 것.
    $needFix = [];
    foreach ($pdo->query(
        'SELECT DISTINCT a.package_name
           FROM tb_cve_affected_package a
           JOIN tb_finding f ON f.package_name = a.package_name
          WHERE a.fixed_version IS NULL'
    )->fetchAll(PDO::FETCH_COLUMN) as $k) {
        $needFix[$k] = true;
    }
    $stat['targets'] = count($needFix);
    if (!$needFix) { return $stat; }

    $scans = $pdo->query(
        'SELECT s.scan_id, s.os_id, s.os_version
           FROM tb_scan s JOIN ' . vg_latest_scan_subq() . ' t ON t.mid = s.scan_id'
    )->fetchAll();

    $seen = [];
    foreach ($scans as $sc) {
        $eco = vg_osv_ecosystem($sc['os_id'], $sc['os_version']);

        // OS 패키지 + 언어 패키지 둘 다 보강한다(생태계는 질의마다 다르다).
        $cand = array_merge(vg_osv_lang_queries($pdo, (int) $sc['scan_id']),
                            vg_osv_container_queries($pdo, (int) $sc['scan_id']));   // 컨테이너 내부 패키지도 자기 배포판으로 조회
        if ($eco !== null && $eco !== '') {
            $cand = array_merge(vg_osv_queries($pdo, (int) $sc['scan_id'], $eco), $cand);
        }

        foreach ($cand as $q) {
            $key  = $q['key'];
            $qEco = (string) $q['eco'];
            $ver  = $q['q']['version'];
            if (!isset($needFix[$key])) { continue; }
            $dk = "$qEco|$key|$ver";
            if (isset($seen[$dk])) { continue; }
            $seen[$dk] = true;

            $r = vg_http_json('POST', $single, $q['q'], [], 90, $maxBytes);
            $stat['queried']++;
            if ($r['code'] !== 200 || !isset($r['json']['vulns'])) {
                $stat['skipped']++;
                if ($log) { $log("  - {$qEco} {$key}@{$ver}: 건너뜀 ({$r['error']})"); }
                unset($r);
                continue;
            }
            foreach ($r['json']['vulns'] as $v) {
                $cve   = vg_osv_cve($v);
                $fixed = vg_osv_global_fixed($v, $key, $qEco, (string) $ver);
                if ($cve === null || $fixed === null) { continue; }
                vg_upsert_affected($pdo, $cve, $qEco, $key, $fixed);   // fixed 채움(기존 행 UPDATE)
                $stat['filled']++;
            }
            unset($r); // 응답 즉시 해제
        }
    }
    return $stat;
}
