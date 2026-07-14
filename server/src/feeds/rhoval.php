<?php
declare(strict_types=1);

/**
 * feeds/rhoval.php — RHEL 계열 벤더 권고(OVAL) **수집** 커넥터.
 *   판정(vg_vendor_errata_evidence)은 src/vendorerrata.php 가 갖는다 — 매처가 HTTP·XML 계층을
 *   끌고 오지 않도록 책임을 갈랐다(SRP). 데비안 트래커와 같은 구조다.
 *
 * 소스:
 *   redhat    https://security.access.redhat.com/data/oval/v2/RHEL{N}/rhel-{N}.oval.xml.bz2  (bz2 전용)
 *   almalinux https://security.almalinux.org/oval/org.almalinux.alsa-{N}.xml                  (평문)
 *   Rocky 는 OSV(Rocky Linux:N)가 조치 버전을 이미 준다 → 중복 수집하지 않는다.
 *
 * OVAL 구조(실물 대조: rhel-9.oval.xml, 압축 해제 25MB):
 *   <definition>  <reference source="RHSA" ref_id="RHSA-2024:1234"/>
 *                 <reference source="CVE"  ref_id="CVE-2024-0001"/>
 *                 <advisory><severity>Important</severity></advisory>
 *                 <criteria>… <criterion test_ref="oval:…:tst:1"/> …
 *   <rpminfo_test id="…:tst:1"> <object object_ref="…:obj:1"/> <state state_ref="…:ste:1"/>
 *   <rpminfo_object id="…:obj:1"> <name>openssl</name>
 *   <rpminfo_state  id="…:ste:1"> <evr operation="less than">0:3.0.7-24.el9_2</evr>
 *
 * **comment 속성을 파싱하지 않는다.** "openssl is earlier than 0:3.0.7-24.el9_2" 로 적혀 있어
 *   유혹적이지만, 그건 사람이 읽으라고 만든 문자열이다. object/state 를 정식으로 따라가야
 *   포맷이 바뀌어도 조용히 틀리지 않는다(억제가 틀리면 미탐이다).
 *
 * 메모리: XMLReader 로 스트리밍하고, bz2 는 compress.bzip2:// 래퍼로 바로 읽는다
 *   (25MB XML 을 통째로 문자열에 올리지 않는다).
 */

require_once __DIR__ . '/http.php';
require_once __DIR__ . '/../vendorerrata.php';   // 판정 규칙(매처와 공유)

const VG_RHOVAL_SOURCES = [
    'redhat'    => 'https://security.access.redhat.com/data/oval/v2/RHEL{N}/rhel-{N}.oval.xml.bz2',
    'almalinux' => 'https://security.almalinux.org/oval/org.almalinux.alsa-{N}.xml',
];

/** OVAL 을 받아 임시파일로 저장하고, XMLReader 가 열 수 있는 경로(bz2 면 스트림 래퍼)를 준다. */
function vg_rhoval_fetch(string $url): array {
    $r = vg_http_raw('GET', $url, [], 180);
    if ($r['code'] !== 200 || $r['body'] === '') {
        throw new RuntimeException("OVAL fetch 실패 (HTTP {$r['code']}) {$r['error']} — $url");
    }
    $tmp = tempnam(sys_get_temp_dir(), 'vgoval');
    if ($tmp === false || file_put_contents($tmp, $r['body']) === false) {
        throw new RuntimeException('OVAL 임시파일 저장 실패');
    }
    $isBz2 = substr($url, -4) === '.bz2';
    if ($isBz2 && !extension_loaded('bz2')) {
        @unlink($tmp);
        throw new RuntimeException('bz2 확장이 없습니다 — Red Hat OVAL 은 bz2 로만 배포된다(이미지 재빌드 필요)');
    }
    return ['path' => $tmp, 'uri' => $isBz2 ? 'compress.bzip2://' . $tmp : $tmp];
}

/**
 * OVAL → 권고 행 목록. 네트워크·DB 없이 도는 순수 함수(경로만 받는다 → 픽스처로 단위 테스트).
 * @return list<array{pkg:string,cve:string,evr:string,advisory:string,severity:string}>
 */
function vg_rhoval_parse(string $uri): array {
    $doc = new DOMDocument();
    $rd  = new XMLReader();
    if (!@$rd->open($uri)) {
        throw new RuntimeException("OVAL 열기 실패: $uri");
    }

    $defs    = [];   // [ [cves[], testRefs[], advisory, severity] … ]
    $tests   = [];   // testId  => ['obj' => objId, 'ste' => steId]
    $objects = [];   // objId   => 패키지명
    $states  = [];   // steId   => 조치 EVR ('less than' 인 것만)

    while ($rd->read()) {
        if ($rd->nodeType !== XMLReader::ELEMENT) { continue; }

        switch ($rd->localName) {
            case 'definition':
                $node = $rd->expand($doc);
                if ($node instanceof DOMElement) {
                    $cves = []; $adv = ''; $sev = '';
                    foreach ($node->getElementsByTagNameNS('*', 'reference') as $ref) {
                        $src = strtoupper($ref->getAttribute('source'));
                        $rid = $ref->getAttribute('ref_id');
                        if ($src === 'CVE')  { $cves[] = $rid; }
                        if ($src === 'RHSA' && $adv === '') { $adv = $rid; }   // 알마도 이 source 를 쓴다
                    }
                    $sevNode = $node->getElementsByTagNameNS('*', 'severity')->item(0);
                    if ($sevNode !== null) { $sev = trim($sevNode->textContent); }

                    $refs = [];
                    foreach ($node->getElementsByTagNameNS('*', 'criterion') as $cr) {
                        $t = $cr->getAttribute('test_ref');
                        if ($t !== '') { $refs[] = $t; }
                    }
                    if ($cves && $refs) { $defs[] = [$cves, $refs, $adv, $sev]; }
                }
                $rd->next();   // 자식은 이미 읽었다
                break;

            case 'rpminfo_test':
                $node = $rd->expand($doc);
                if ($node instanceof DOMElement) {
                    $id  = $node->getAttribute('id');
                    $o   = $node->getElementsByTagNameNS('*', 'object')->item(0);
                    $s   = $node->getElementsByTagNameNS('*', 'state')->item(0);
                    if ($id !== '' && $o instanceof DOMElement && $s instanceof DOMElement) {
                        $tests[$id] = ['obj' => $o->getAttribute('object_ref'), 'ste' => $s->getAttribute('state_ref')];
                    }
                }
                $rd->next();
                break;

            case 'rpminfo_object':
                $node = $rd->expand($doc);
                if ($node instanceof DOMElement) {
                    $id = $node->getAttribute('id');
                    $nm = $node->getElementsByTagNameNS('*', 'name')->item(0);
                    if ($id !== '' && $nm !== null) { $objects[$id] = trim($nm->textContent); }
                }
                $rd->next();
                break;

            case 'rpminfo_state':
                $node = $rd->expand($doc);
                if ($node instanceof DOMElement) {
                    $id  = $node->getAttribute('id');
                    $evr = $node->getElementsByTagNameNS('*', 'evr')->item(0);
                    // 'less than' 인 EVR 만 조치안이다. arch·서명 검사 상태는 버린다.
                    if ($id !== '' && $evr instanceof DOMElement
                        && strtolower($evr->getAttribute('operation')) === 'less than') {
                        $states[$id] = trim($evr->textContent);
                    }
                }
                $rd->next();
                break;
        }
    }
    $rd->close();

    // 정의 × 테스트 → (패키지, 조치 EVR, CVE) 로 펼친다.
    $rows = [];
    $seen = [];
    foreach ($defs as [$cves, $refs, $adv, $sev]) {
        foreach ($refs as $t) {
            $test = $tests[$t] ?? null;
            if ($test === null) { continue; }
            $pkg = $objects[$test['obj']] ?? '';
            $evr = $states[$test['ste']] ?? '';        // 조치안이 없는 테스트(플랫폼·아키)는 여기서 걸러진다
            if ($pkg === '' || $evr === '') { continue; }

            foreach ($cves as $cve) {
                $k = "$pkg|$cve|$evr";
                if (isset($seen[$k])) { continue; }
                $seen[$k] = true;
                $rows[] = ['pkg' => $pkg, 'cve' => $cve, 'evr' => $evr, 'advisory' => $adv, 'severity' => $sev];
            }
        }
    }
    return $rows;
}

/** 수집 대상 — 설정에 없으면 수집된 RHEL 계열 **호스트·컨테이너**에서 뽑는다. */
function vg_rhoval_targets(PDO $pdo, array $conn): array {
    $cfg = (array) ($conn['releases'] ?? []);
    if ($cfg) {
        $out = [];
        foreach ($cfg as $c) {                        // "redhat:9" 형식
            $p = explode(':', (string) $c, 2);
            if (count($p) === 2) { $out[] = [$p[0], $p[1]]; }
        }
        return $out;
    }

    $rows = $pdo->query(
        "SELECT DISTINCT os_id, os_version FROM tb_scans WHERE os_id IS NOT NULL AND is_deleted = 0
         UNION
         SELECT DISTINCT os_id, os_version FROM tb_containers WHERE os_id IS NOT NULL"
    )->fetchAll();

    $out = [];
    foreach ($rows as $r) {
        $vendor = vg_errata_vendor((string) $r['os_id']);
        if ($vendor === null) { continue; }
        if (preg_match('/^(\d+)/', (string) $r['os_version'], $m) !== 1) { continue; }
        $out[$vendor . ':' . $m[1]] = [$vendor, $m[1]];
    }
    return array_values($out);
}

// RHEL 계열 벤더 권고(OVAL). 대상 서버에서 dnf updateinfo 를 긁지 않아도 된다.
final class VgRhovalConnector implements VgFeedConnector {
    public function run(PDO $pdo, array $conn): array {
        $fetched = 0; $upserted = 0;

        foreach (vg_rhoval_targets($pdo, $conn) as [$vendor, $major]) {
            $tpl = VG_RHOVAL_SOURCES[$vendor] ?? null;
            if ($tpl === null) { continue; }
            $src = vg_rhoval_fetch(str_replace('{N}', $major, $tpl));

            try {
                $rows     = vg_rhoval_parse($src['uri']);
                $fetched += count($rows);

                // 벤더·릴리스 단위 통째 교체 — 철회된 권고가 남아 있으면 잘못 억제한다(미탐).
                $pdo->beginTransaction();
                $pdo->prepare('DELETE FROM tb_vendor_errata WHERE vendor = ? AND release_major = ?')
                    ->execute([$vendor, $major]);

                $ins = $pdo->prepare(
                    'INSERT INTO tb_vendor_errata (vendor, release_major, pkg_name, cve_id, fixed_evr, advisory, severity)
                     VALUES (?,?,?,?,?,?,?)
                     ON DUPLICATE KEY UPDATE advisory = VALUES(advisory), severity = VALUES(severity)'
                );
                $maxFix = [];   // "패키지|CVE" => 가장 높은 조치 EVR (카탈로그에 넣을 값)
                foreach ($rows as $r) {
                    $ins->execute([
                        $vendor, $major,
                        mb_substr($r['pkg'], 0, 255),
                        mb_substr($r['cve'], 0, 32),
                        mb_substr($r['evr'], 0, 128),
                        mb_substr($r['advisory'], 0, 64),
                        mb_substr($r['severity'], 0, 16),
                    ]);
                    $upserted++;

                    $k = $r['pkg'] . '|' . $r['cve'];
                    if (!isset($maxFix[$k]) || vg_ver_cmp($r['evr'], $maxFix[$k], 'rpm') > 0) {
                        $maxFix[$k] = $r['evr'];
                    }
                }

                // **취약 후보도 여기서 나온다.** RHEL 계열은 OSV 에 조치안이 없어(실측: UBI9 스캔의
                //   findings 가 0 이었다) OVAL 이 유일한 소스다. 그래서 카탈로그(tb_cves +
                //   tb_cve_affected_packages)에도 넣어 매처가 후보를 찾을 수 있게 한다.
                //   생태계 표기는 매처·OSV 와 같은 기준(vg_osv_ecosystem): 'Red Hat:9' / 'AlmaLinux:9'.
                //
                //   카탈로그의 조치버전은 **가장 높은 EVR** 을 넣는다. 같은 (패키지,CVE)가 마이너
                //   스트림마다 다른 EVR 로 고쳐지는데(el9_2 · el9_4) 자연키는 하나뿐이라 하나만 남는다.
                //   낮은 EVR 을 넣으면 다른 스트림에서 "이미 패치됨" 으로 잘못 억제한다(미탐).
                //   높은 쪽은 보수적이다 — 억제를 덜 할 뿐이고, 정밀한 스트림 판정은
                //   tb_vendor_errata 를 보는 vg_vendor_errata_evidence 가 따로 한다.
                $eco = $vendor === 'almalinux' ? "AlmaLinux:$major" : "Red Hat:$major";
                foreach ($maxFix as $k => $evr) {
                    [$pkg, $cve] = explode('|', $k, 2);
                    vg_upsert_cve($pdo, $cve, null, null, null);   // 상세(요약·CVSS)는 NVD 가 채운다
                    vg_upsert_affected($pdo, $cve, $eco, mb_substr($pkg, 0, 255), mb_substr($evr, 0, 128));
                }
                $pdo->commit();
            } finally {
                @unlink($src['path']);
            }
        }
        return ['fetched' => $fetched, 'upserted' => $upserted];
    }

    public function preview(PDO $pdo, array $conn): array {
        $t = vg_rhoval_targets($pdo, $conn)[0] ?? ['redhat', '9'];
        [$vendor, $major] = $t;
        $src = vg_rhoval_fetch(str_replace('{N}', $major, VG_RHOVAL_SOURCES[$vendor]));
        try {
            $rows  = vg_rhoval_parse($src['uri']);
            $items = [];
            foreach (array_slice($rows, 0, 10) as $r) {
                $items[] = [
                    'cve'      => $r['cve'],
                    'package'  => $r['pkg'],
                    'fixed'    => $r['evr'],
                    'advisory' => $r['advisory'],
                    'severity' => $r['severity'],
                ];
            }
            return ['ok' => true, 'target' => "$vendor:$major", 'count' => count($rows), 'items' => $items];
        } finally {
            @unlink($src['path']);
        }
    }
}
