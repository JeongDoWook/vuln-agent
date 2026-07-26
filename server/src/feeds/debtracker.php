<?php
declare(strict_types=1);

/**
 * feeds/debtracker.php — 데비안 보안 트래커 **수집** 커넥터.
 *   판정(vg_debtracker_is_vulnerable · vg_debtracker_evidence)은 src/debtracker.php 가 갖는다 —
 *   매처가 HTTP 계층을 끌고 오지 않도록 책임을 갈랐다(SRP).
 *
 * 소스: https://security-tracker.debian.org/tracker/debsecan/release/1/<코드명>  (zlib, 약 1.6MB)
 *   전체 트래커 JSON 은 79MB 라 PHP 로 통째 파싱하면 메모리가 위험하다. debsecan 이 실제로
 *   받아 쓰는 이 압축 포맷은 가볍고, 필요한 것(릴리스별 "아직 취약")만 정확히 담고 있다.
 *
 * 포맷 (원본 파서 /usr/bin/debsecan 과 대조해 확인):
 *   VERSION 1
 *   <CVE 섹션>   CVE-ID,플래그,설명           ← 줄 순서가 곧 인덱스
 *   (빈 줄)
 *   <취약 섹션>  패키지,CVE인덱스,플래그4자,수정버전,예외버전들(공백구분)
 *                  flags[0]=='B' → 패키지명이 **바이너리**(아니면 소스)
 *                  flags[1]      → 긴급도(' '|L|M|H)
 *                  flags[3]=='F' → 수정본 있음
 *   (빈 줄)
 *   <소스→바이너리 매핑>  ← 쓰지 않는다. 실제 설치 목록은 에이전트가 보낸다.
 */

require_once __DIR__ . '/http.php';
require_once __DIR__ . '/../debtracker.php';   // 판정 규칙(매처와 공유)

const VG_DEBTRACKER_BASE = 'https://security-tracker.debian.org/tracker/debsecan/release/1/';

/** 릴리스 데이터를 받아 zlib 을 푼다(run·미리보기 공용). */
function vg_debtracker_fetch(string $baseUrl, string $codename): string {
    $r = vg_http_raw('GET', rtrim($baseUrl, '/') . '/' . $codename, [], 120);
    if ($r['code'] !== 200 || $r['body'] === '') {
        throw new RuntimeException("데비안 트래커 fetch 실패 ({$codename}, HTTP {$r['code']}) {$r['error']}");
    }
    $txt = @gzuncompress($r['body']);   // zlib(RFC1950) — gzip 이 아니다
    if ($txt === false) {
        throw new RuntimeException("데비안 트래커 압축 해제 실패 ({$codename})");
    }
    return $txt;
}

/**
 * 릴리스 데이터 → 행 목록. 네트워크·DB 없이 도는 순수 함수(그래서 단위 테스트가 가능하다).
 * @return list<array{pkg:string,is_binary:int,cve:string,fixed:string,others:string,urgency:string,has_fix:int}>
 */
function vg_debtracker_parse(string $raw): array {
    $lines = explode("\n", $raw);
    if (($lines[0] ?? '') !== 'VERSION 1') {
        throw new RuntimeException('데비안 트래커: 알 수 없는 포맷(VERSION 1 아님)');
    }
    $urgencyMap = [' ' => '', 'L' => 'low', 'M' => 'medium', 'H' => 'high'];
    $n = count($lines);

    // 1) CVE 섹션 — 줄 순서가 인덱스다.
    $cves = [];
    $i = 1;
    for (; $i < $n; $i++) {
        if ($lines[$i] === '') { $i++; break; }
        $cves[] = explode(',', $lines[$i], 2)[0];
    }

    // 2) 취약 섹션.
    $rows = [];
    for (; $i < $n; $i++) {
        if ($lines[$i] === '') { break; }
        $f = explode(',', $lines[$i], 5);
        if (count($f) < 5) { continue; }
        [$pkg, $vnum, $flags, $fixed, $others] = $f;
        $cve = $cves[(int) $vnum] ?? '';
        if ($cve === '' || $pkg === '') { continue; }
        $rows[] = [
            'pkg'       => $pkg,
            'is_binary' => (($flags[0] ?? ' ') === 'B') ? 1 : 0,
            'cve'       => $cve,
            'fixed'     => $fixed,
            'others'    => $others,
            'urgency'   => $urgencyMap[$flags[1] ?? ' '] ?? '',
            'has_fix'   => (($flags[3] ?? ' ') === 'F') ? 1 : 0,
        ];
    }
    return $rows;
}

/**
 * 수집할 릴리스 — 설정에 없으면 **수집된 데비안 호스트와 컨테이너**에서 뽑는다.
 *
 * 컨테이너를 빠뜨렸다가 실제로 당했다: 호스트는 데비안 13(trixie)인데 그 위에서 도는
 * 컨테이너는 데비안 12(bookworm) 였다. trixie 만 받아오니 컨테이너엔 억제 근거가 하나도
 * 없었고, 컨테이너 오탐 850건이 그대로 남았다(억제 0건). 판정 대상이 곧 수집 대상이다.
 */
function vg_debtracker_releases(PDO $pdo, array $conn): array {
    $cfg = array_values(array_filter(array_map('strval', (array) ($conn['releases'] ?? []))));
    if ($cfg) { return $cfg; }

    $rel  = [];
    $rows = $pdo->query(
        "SELECT DISTINCT os_version FROM tb_scan
          WHERE LOWER(os_id) = 'debian' AND os_version IS NOT NULL AND is_deleted = 0
         UNION
         SELECT DISTINCT os_version FROM tb_container
          WHERE LOWER(os_id) = 'debian' AND os_version IS NOT NULL"
    )->fetchAll(PDO::FETCH_COLUMN);
    foreach ($rows as $v) {
        $c = vg_debian_codename((string) $v);
        if ($c !== '') { $rel[$c] = true; }
    }
    return $rel ? array_keys($rel) : ['bookworm', 'trixie'];
}

// 데비안 보안 트래커 — 릴리스별 "아직 취약" 목록. 대상 서버에 debsecan 을 깔지 않아도 된다.
final class VgDebtrackerConnector implements VgFeedConnector {
    public function run(PDO $pdo, array $conn): array {
        $base     = vg_conn_url($conn, VG_DEBTRACKER_BASE);
        $fetched  = 0;
        $upserted = 0;

        foreach (vg_debtracker_releases($pdo, $conn) as $codename) {
            $rows     = vg_debtracker_parse(vg_debtracker_fetch($base, $codename));
            $fetched += count($rows);

            // 릴리스 단위 통째 교체 — 트래커에서 빠진 항목(=고쳐진 것)이 남아 있으면
            //   "아직 취약" 으로 계속 잡혀 억제가 안 된다(오탐이 되살아난다).
            $pdo->beginTransaction();
            $pdo->prepare('DELETE FROM tb_debian_tracker WHERE release_codename = ?')->execute([$codename]);

            $ins = $pdo->prepare(
                'INSERT INTO tb_debian_tracker
                   (release_codename, pkg_name, is_binary, cve_id, fixed_version, other_versions, urgency, has_fix)
                 VALUES (?,?,?,?,?,?,?,?)
                 ON DUPLICATE KEY UPDATE fixed_version = VALUES(fixed_version),
                   other_versions = VALUES(other_versions), urgency = VALUES(urgency), has_fix = VALUES(has_fix)'
            );
            foreach ($rows as $r) {
                $ins->execute([
                    $codename,
                    mb_substr($r['pkg'], 0, 255),
                    $r['is_binary'],
                    mb_substr($r['cve'], 0, 32),
                    mb_substr($r['fixed'], 0, 255),
                    mb_substr($r['others'], 0, 512),
                    $r['urgency'],
                    $r['has_fix'],
                ]);
                $upserted++;
            }
            $pdo->commit();
        }
        return ['fetched' => $fetched, 'upserted' => $upserted];
    }

    public function preview(PDO $pdo, array $conn): array {
        $base     = vg_conn_url($conn, VG_DEBTRACKER_BASE);
        $codename = vg_debtracker_releases($pdo, $conn)[0] ?? 'trixie';
        $rows     = vg_debtracker_parse(vg_debtracker_fetch($base, $codename));

        $items = [];
        foreach (array_slice($rows, 0, 10) as $r) {
            $items[] = [
                'cve'     => $r['cve'],
                'package' => $r['pkg'] . ($r['is_binary'] ? ' (바이너리)' : ''),
                'fixed'   => $r['fixed'] !== '' ? $r['fixed'] : '(수정본 없음)',
                'urgency' => $r['urgency'],
            ];
        }
        return ['ok' => true, 'release' => $codename, 'count' => count($rows), 'items' => $items];
    }
}
