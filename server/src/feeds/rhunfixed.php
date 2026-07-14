<?php
declare(strict_types=1);

/**
 * feeds/rhunfixed.php — Red Hat "아직 안 고친" CVE 수집(조치 불가 취약점).
 *
 * 왜: OVAL(rhoval)은 **수정본이 나온 것(RHSA)만** 담는다. Red Hat 이 "영향받음 / 고치지 않겠다 /
 *   조사 중 / 지원 종료" 로 표시한 CVE 는 거기 없어서 우리가 통째로 못 봤다(미탐).
 *   실측(redhat/ubi8): Trivy 523건 중 514건이 이것 — 수정본이 있는 9건은 우리도 정확히 9건 잡았다.
 *
 * 소스: Red Hat Security Data API
 *   목록  https://access.redhat.com/hydra/rest/securitydata/cve.json?package=<컴포넌트>&per_page=1000
 *   상세  https://access.redhat.com/hydra/rest/securitydata/cve/<CVE>.json   (약 3KB)
 *   CSAF VEX 는 CVE 하나당 587KB 라 못 쓴다(수천 건이면 GB 단위).
 *
 * 조회 단위는 **컴포넌트(소스 패키지)** 다 — Red Hat 은 bzip2 로 상태를 매기고, 우리는 그걸
 *   설치된 바이너리(bzip2-libs …)에 펼친다(Trivy 도 같은 방식). 바이너리 이름으로 물으면 0건이다.
 *
 * 비용 관리(실측으로 다듬었다 — 처음엔 상세 조회의 93%가 낭비였다):
 *   · 대상은 **실제로 설치된 컴포넌트**만(수백 개). 전체 CVE 를 긁지 않는다.
 *   · 목록을 **product 로 릴리스까지 좁힌다** — 안 좁히면 그 컴포넌트의 전 제품 CVE 가 다 온다.
 *   · 목록에 **이 릴리스·이 컴포넌트의 수정본**이 있으면 상세를 안 받는다(이미 판정 가능).
 *   · 한 번 확인한 (컴포넌트, CVE) 는 'Not affected' 까지 저장해 다시 받지 않는다.
 *   · 한 실행의 상세 조회 상한(기본 20000). 걸리면 **로그를 남긴다** — 조용한 미완성은 곧 미탐이다.
 */

require_once __DIR__ . '/http.php';
require_once __DIR__ . '/upsert.php';            // vg_is_cve_id / vg_upsert_cve
require_once __DIR__ . '/../vendorerrata.php';   // vg_errata_vendor / vg_rpm_component

const VG_RHCVE_LIST   = 'https://access.redhat.com/hydra/rest/securitydata/cve.json';
const VG_RHCVE_DETAIL = 'https://access.redhat.com/hydra/rest/securitydata/cve/';

/**
 * 목록의 affected_packages 에 **이 릴리스·이 컴포넌트의 수정본**이 있는가(있으면 상세를 안 받는다).
 *
 * 두 가지를 다 봐야 한다 — 하나라도 빠뜨리면 남의 제품 수정본을 우리 것으로 오인해 CVE 를
 * 통째로 건너뛴다(미탐):
 *   · 이름:   "jbcs-httpd24-curl-0:8.0.1-1.el8jbcs" 는 curl 이 아니라 JBoss Core Services 다.
 *   · dist태그: ".el8jbcs" 는 RHEL8 이 아니다. .el8 / .el8_10 처럼 **경계가 끝나야** 한다.
 * 실제로 이 둘 때문에 curl CVE-2023-27534 를 놓쳤다(Trivy 는 잡았다).
 */
function vg_rhcve_fixed_in_release(array $affectedPackages, string $component, string $major): bool {
    foreach ($affectedPackages as $ap) {
        $ap = (string) $ap;
        if (strncmp($ap, $component . '-', strlen($component) + 1) !== 0) { continue; }   // 다른 컴포넌트
        if (preg_match('/\.el' . preg_quote($major, '/') . '(_\d+)?(\.|$)/', $ap) === 1) { return true; }
    }
    return false;
}

/** 이 릴리스에서 "아직 안 고쳐진" 상태인가. 'Not affected' 는 아니다(캐시용으로만 저장한다). */
function vg_rhcve_is_unfixed(string $fixState): bool {
    return in_array($fixState, [
        'Affected', 'Fix deferred', 'Will not fix', 'Under investigation', 'Out of support scope',
    ], true);
}

/**
 * CVE 상세 → 이 (릴리스, 컴포넌트) 의 fix_state. 해당 항목이 없으면 null(= 이 릴리스와 무관).
 *   package_state 예: {product_name: "Red Hat Enterprise Linux 8", package_name: "bzip2",
 *                      fix_state: "Fix deferred"}
 */
function vg_rhcve_fix_state(array $detail, string $major, string $component): ?string {
    foreach ($detail['package_state'] ?? [] as $ps) {
        $prod = (string) ($ps['product_name'] ?? '');
        $pkg  = (string) ($ps['package_name'] ?? '');
        if ($pkg !== $component) { continue; }
        // "Red Hat Enterprise Linux 8" — 메이저까지만 본다(8.x EUS 표기가 섞여 온다).
        if (preg_match('/Enterprise Linux\s+' . preg_quote($major, '/') . '(\D|$)/', $prod) === 1) {
            return (string) ($ps['fix_state'] ?? '');
        }
    }
    return null;
}

/** 스캔에 실제로 설치된 RHEL 계열 컴포넌트 목록: [ [vendor, major, component] … ] */
function vg_rhcve_targets(PDO $pdo): array {
    $rows = $pdo->query(
        "SELECT DISTINCT s.os_id AS host_os, s.os_version AS host_ver,
                c.os_id AS ctr_os, c.os_version AS ctr_ver,
                p.container_id, p.source_pkg, p.name
           FROM tb_packages p
           JOIN tb_scans s      ON s.id = p.scan_id AND s.is_deleted = 0
           LEFT JOIN tb_containers c ON c.id = p.container_id AND c.scan_id = p.scan_id
          WHERE p.manager = 'rpm'
            AND p.scan_id IN (SELECT MAX(id) FROM tb_scans WHERE is_deleted = 0 GROUP BY host_id)"
    )->fetchAll();

    $out = [];
    foreach ($rows as $r) {
        $isCtr  = (int) $r['container_id'] !== 0;
        $osId   = (string) ($isCtr ? $r['ctr_os']  : $r['host_os']);
        $osVer  = (string) ($isCtr ? $r['ctr_ver'] : $r['host_ver']);
        $vendor = vg_errata_vendor($osId);
        if ($vendor !== 'redhat') { continue; }              // 지금은 Red Hat 만(알마는 OVAL 로 충분)
        if (preg_match('/^(\d+)/', $osVer, $m) !== 1) { continue; }

        $comp = vg_rpm_component((string) $r['source_pkg'], (string) $r['name']);
        if ($comp === '') { continue; }
        $out[$vendor . '|' . $m[1] . '|' . $comp] = [$vendor, $m[1], $comp];
    }
    return array_values($out);
}

// Red Hat 미수정 CVE — OVAL 이 못 담는 "수정본 없는 취약점".
final class VgRhunfixedConnector implements VgFeedConnector {
    public function run(PDO $pdo, array $conn): array {
        // 한 실행의 상세 조회 상한. 첫 동기화는 커서 여러 번 나눠 도는데, **중간에 멈추면
        //   그만큼 미탐이 남는다** — 그래서 멈췄다는 사실을 반드시 로그로 남긴다(조용한 미완성 금지).
        //   한 번 확인한 (컴포넌트, CVE) 는 캐시되므로 다음 실행이 이어서 채운다.
        $maxDetail = (int) ($conn['max_detail'] ?? 20000);
        $fetched   = 0;
        $upserted  = 0;
        $details   = 0;
        $failed    = 0;
        $stopped   = false;

        // 이미 알고 있는 것(다시 받지 않는다): OVAL 의 수정본 + 지난 실행에서 확인한 상태.
        $known = [];   // "벤더|메이저|컴포넌트|CVE" => true
        foreach ($pdo->query('SELECT vendor, release_major, component, cve_id FROM tb_vendor_unfixed') as $r) {
            $known[$r['vendor'] . '|' . $r['release_major'] . '|' . $r['component'] . '|' . $r['cve_id']] = true;
        }

        $ins = $pdo->prepare(
            'INSERT INTO tb_vendor_unfixed (vendor, release_major, component, cve_id, fix_state, severity, cvss)
             VALUES (?,?,?,?,?,?,?)
             ON DUPLICATE KEY UPDATE fix_state = VALUES(fix_state), severity = VALUES(severity),
                                     cvss = VALUES(cvss), checked_at = NOW()'
        );
        // 예전엔 여기서 "OVAL 에 이 CVE 의 수정본이 있으면 건너뛴다" 를 했다. **틀렸다** —
        //   그 검사가 CVE 만 보고 컴포넌트를 안 봐서, 남의 컴포넌트 수정본을 우리 것으로 오인했다.
        //   실측: CVE-2024-11053 은 OVAL 에 mecab(PHP 모듈) 수정본으로 들어 있는데, 그걸 보고
        //   curl 을 "이미 고쳐짐" 으로 건너뛰었다 → curl 의 진짜 취약점을 놓쳤다(미탐).
        //   목록의 affected_packages 검사(vg_rhcve_fixed_in_release)가 컴포넌트까지 보므로 그걸로 충분하다.

        foreach (vg_rhcve_targets($pdo) as [$vendor, $major, $comp]) {
            $list = $this->fetchList($comp, $major);
            $fetched += count($list);

            foreach ($list as $c) {
                if ($details >= $maxDetail) { $stopped = true; break 2; }

                $cve = (string) ($c['CVE'] ?? '');
                if (!vg_is_cve_id($cve)) { continue; }

                $key = "$vendor|$major|$comp|$cve";
                if (isset($known[$key])) { continue; }              // 이미 확인함

                // 목록에 이미 **이 릴리스·이 컴포넌트의 수정본**이 실려 있으면 상세를 받을 이유가 없다.
                //   남의 제품(jbcs-httpd24-curl … .el8jbcs)을 우리 것으로 오인하면 CVE 를 통째로
                //   건너뛴다 — 실제로 curl CVE-2023-27534 를 그렇게 놓쳤다.
                if (vg_rhcve_fixed_in_release((array) ($c['affected_packages'] ?? []), $comp, $major)) {
                    continue;
                }

                $detail = $this->fetchDetail($cve);
                $details++;
                if ($detail === null) { $failed++; continue; }   // 실패는 캐시 안 함 → 다음 실행이 재시도

                $state = vg_rhcve_fix_state($detail, $major, $comp);
                if ($state === null || $state === '') { continue; }  // 이 릴리스와 무관

                $sev  = (string) ($detail['threat_severity'] ?? ($c['severity'] ?? ''));
                $cvss = $c['cvss3_score'] ?? null;

                $ins->execute([
                    $vendor, $major, mb_substr($comp, 0, 255), mb_substr($cve, 0, 32),
                    mb_substr($state, 0, 32), mb_substr($sev, 0, 16),
                    $cvss !== null ? (float) $cvss : null,
                ]);
                $known[$key] = true;
                $upserted++;

                // CVE 상세(요약·CVSS)는 NVD 가 채우지만, 없을 수 있으니 껍데기는 만들어 둔다.
                if (vg_rhcve_is_unfixed($state)) {
                    vg_upsert_cve($pdo, $cve, null, $cvss !== null ? (float) $cvss : null, null);
                }
            }
        }
        // 조용히 끝내지 않는다 — 미완성인 채로 "성공" 이라고 하면 그 차이가 곧 미탐이다.
        if ($stopped) {
            error_log("[rhunfixed] 상세 조회 상한($maxDetail)에 걸려 중단 — 다음 실행이 이어서 채운다");
        }
        if ($failed > 0) {
            error_log("[rhunfixed] CVE 상세 조회 실패 {$failed}건 — 캐시하지 않았으니 다음 실행이 재시도한다");
        }
        return ['fetched' => $fetched, 'upserted' => $upserted];
    }

    public function preview(PDO $pdo, array $conn): array {
        $t = vg_rhcve_targets($pdo)[0] ?? ['redhat', '9', 'openssl'];
        [$vendor, $major, $comp] = $t;
        $list  = array_slice($this->fetchList($comp), 0, 10);
        $items = [];
        foreach ($list as $c) {
            $items[] = [
                'cve'       => $c['CVE'] ?? '',
                'component' => $comp,
                'severity'  => $c['severity'] ?? '',
                'advisories' => count($c['advisories'] ?? []),   // 0 이면 수정본 없음(우리 대상)
            ];
        }
        return ['ok' => true, 'target' => "$vendor:$major/$comp", 'count' => count($list), 'items' => $items];
    }

    /**
     * 컴포넌트의 CVE 목록(페이지네이션). **product 로 릴리스를 먼저 좁힌다.**
     *   안 좁히면 그 컴포넌트의 전 제품·전 릴리스 CVE 가 다 와서, 상세를 받아 보고서야
     *   "이 릴리스와 무관" 임을 알게 된다 — 실측 폐기율 93%(1,279건 중 1,076건)였다.
     */
    private function fetchList(string $component, string $major = ''): array {
        $out  = [];
        $page = 1;
        $prod = $major !== '' ? '&product=' . rawurlencode("Red Hat Enterprise Linux $major") : '';
        while ($page <= 10) {                                       // 안전 상한(컴포넌트당 1만 건)
            $url = VG_RHCVE_LIST . '?per_page=1000&page=' . $page . $prod . '&package=' . rawurlencode($component);
            try {
                // 목록도 예외를 흡수한다 — 컴포넌트 하나의 일시적 실패로 수집 전체를 죽이지 않는다.
                //   그 컴포넌트는 이번 실행에서 비워지고, 다음 실행이 다시 시도한다.
                $r = vg_http_raw('GET', $url, [], 60);
            } catch (Throwable $e) {
                error_log("[rhunfixed] 목록 조회 예외($component): " . $e->getMessage());
                break;
            }
            if ($r['code'] !== 200 || $r['body'] === '') { break; }
            $rows = json_decode($r['body'], true);
            if (!is_array($rows) || !$rows) { break; }
            $out = array_merge($out, $rows);
            if (count($rows) < 1000) { break; }
            $page++;
        }
        return $out;
    }

    /**
     * CVE 상세(약 3KB). 실패하면 null — 한 건 때문에 수집 전체를 멈추지 않는다.
     *   **한 번 재시도한다.** 수천 건을 연속으로 받다 보면 간헐적으로 실패하는데(레이트리밋 추정),
     *   그냥 넘기면 그 CVE 가 조용히 사라진다 — 실제로 zstd CVE-2022-4899 를 그렇게 놓쳤다.
     *   실패는 캐시하지 않으므로 다음 실행이 다시 시도한다(수렴한다).
     */
    private function fetchDetail(string $cve): ?array {
        for ($try = 1; $try <= 2; $try++) {
            try {
                // 예외까지 흡수한다 — DNS 가 한 번 흔들리면(SSRF 가드가 resolve 실패로 던진다)
                //   20분짜리 수집이 통째로 죽는다. 실제로 그렇게 4차 수집이 날아갔다.
                $r = vg_http_raw('GET', VG_RHCVE_DETAIL . rawurlencode($cve) . '.json', [], 30);
                if ($r['code'] === 200 && $r['body'] !== '') {
                    $d = json_decode($r['body'], true);
                    if (is_array($d)) { return $d; }
                }
            } catch (Throwable $e) {
                error_log('[rhunfixed] 상세 조회 예외(' . $cve . '): ' . $e->getMessage());
            }
            if ($try === 1) { usleep(500000); }   // 0.5초 쉬고 한 번 더
        }
        return null;
    }
}
