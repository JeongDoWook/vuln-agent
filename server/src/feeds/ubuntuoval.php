<?php
declare(strict_types=1);

/**
 * feeds/ubuntuoval.php — 우분투 보안 OVAL **수집** 커넥터.
 *   판정(vg_ubuntu_evidence)은 src/ubuntuoval.php 가 갖는다 — 데비안 트래커·RHEL OVAL 과 같은 구조.
 *
 * 왜: 우분투만 벤더 판정이 없었다. 우분투도 백포트를 하므로(1.2-3ubuntu0.1) 버전만 보면 오탐이
 *   남고, "벤더가 아직 안 고쳤나"(조치 불가)도 알 수 없었다.
 *   실측(deskmini-x300, Ubuntu 24.04): 억제 765건 — 같은 규모의 데비안 호스트는 4,135건이었다.
 *
 * 소스: https://security-metadata.canonical.com/oval/com.ubuntu.<코드명>.cve.oval.xml.bz2
 *   (noble 7.4MB bz2 → 129MB XML. XMLReader 로 스트리밍한다.)
 *
 * OVAL 구조(실물 대조):
 *   <definition class="vulnerability">
 *     <reference source="CVE" ref_id="CVE-2024-56406"/>  <severity>Medium</severity>
 *     <criterion test_ref="…:tst:2024564060000000"/>
 *   <dpkginfo_test id="…:tst:…"> <object object_ref="…:obj:…"/> <state state_ref="…:ste:…"/>
 *   <dpkginfo_object id="…:obj:…"> <name var_ref="…:var:…"/>        ← 변수에 바이너리 이름들이 들어 있다
 *   <dpkginfo_state  id="…:ste:…"> <evr operation="less than">0:5.38.2-3.2ubuntu0.1</evr>
 *   <constant_variable id="…:var:…"> <value>perl</value><value>perl-base</value>…
 *
 * **state 가 없는 테스트가 핵심이다** — "그 패키지가 존재하면 취약"(아직 수정본이 없다).
 *   RHEL 의 OVAL 은 수정본만 담아서 미수정 CVE 를 따로 받아야 했는데(rhunfixed), 우분투는
 *   한 파일에 둘 다 있다. 그러니 state 없는 테스트를 **버리면 조치 불가가 통째로 미탐이 된다.**
 *
 * comment 속성은 파싱하지 않는다(사람이 읽는 문자열이다). object/state/variable 을 정식으로 따라간다.
 */

require_once __DIR__ . '/http.php';
require_once __DIR__ . '/upsert.php';        // vg_is_cve_id
require_once __DIR__ . '/../ubuntuoval.php'; // 판정 규칙(매처와 공유) + vg_ubuntu_codename

const VG_UBUNTU_OVAL_URL = 'https://security-metadata.canonical.com/oval/com.ubuntu.{C}.cve.oval.xml.bz2';

/** OVAL 을 받아 임시파일로 저장하고 XMLReader 용 경로(bz2 스트림 래퍼)를 준다. */
function vg_ubuntu_oval_fetch(string $url): array {
    $r = vg_http_raw('GET', $url, [], 300);
    if ($r['code'] !== 200 || $r['body'] === '') {
        throw new RuntimeException("우분투 OVAL fetch 실패 (HTTP {$r['code']}) {$r['error']} — $url");
    }
    $tmp = tempnam(sys_get_temp_dir(), 'vgubu');
    if ($tmp === false || file_put_contents($tmp, $r['body']) === false) {
        throw new RuntimeException('우분투 OVAL 임시파일 저장 실패');
    }
    if (!extension_loaded('bz2')) {
        @unlink($tmp);
        throw new RuntimeException('bz2 확장이 없습니다 — 우분투 OVAL 은 bz2 로만 배포된다');
    }
    return ['path' => $tmp, 'uri' => 'compress.bzip2://' . $tmp];
}

/**
 * OVAL → 행 목록. 네트워크·DB 없이 도는 순수 함수(경로만 받는다 → 픽스처로 단위 테스트).
 * @return list<array{pkg:string,cve:string,evr:?string,severity:string}>   evr=null → 아직 수정본 없음
 */
function vg_ubuntu_oval_parse(string $uri): array {
    $doc = new DOMDocument();
    $rd  = new XMLReader();
    if (!@$rd->open($uri)) {
        throw new RuntimeException("우분투 OVAL 열기 실패: $uri");
    }

    $defs   = [];   // [ [cve, testRefs[], severity] … ]
    $tests  = [];   // tstId => ['obj' => objId, 'ste' => steId|null]
    $objs   = [];   // objId => ['var' => varId|null, 'name' => 이름|null]
    $states = [];   // steId => 조치 EVR ('less than' 인 것만)
    $vars   = [];   // varId => [바이너리 이름 …]

    while ($rd->read()) {
        if ($rd->nodeType !== XMLReader::ELEMENT) { continue; }

        switch ($rd->localName) {
            case 'definition':
                $node = $rd->expand($doc);
                if ($node instanceof DOMElement && $node->getAttribute('class') === 'vulnerability') {
                    $cve = '';
                    foreach ($node->getElementsByTagNameNS('*', 'reference') as $ref) {
                        if (strtoupper($ref->getAttribute('source')) === 'CVE') {
                            $cve = $ref->getAttribute('ref_id');
                            break;
                        }
                    }
                    $sevNode = $node->getElementsByTagNameNS('*', 'severity')->item(0);
                    $sev     = $sevNode !== null ? trim($sevNode->textContent) : '';

                    $refs = [];
                    foreach ($node->getElementsByTagNameNS('*', 'criterion') as $cr) {
                        $t = $cr->getAttribute('test_ref');
                        if ($t !== '') { $refs[] = $t; }
                    }
                    if ($cve !== '' && $refs) { $defs[] = [$cve, $refs, $sev]; }
                }
                $rd->next();
                break;

            case 'dpkginfo_test':
                $node = $rd->expand($doc);
                if ($node instanceof DOMElement) {
                    $id = $node->getAttribute('id');
                    $o  = $node->getElementsByTagNameNS('*', 'object')->item(0);
                    $s  = $node->getElementsByTagNameNS('*', 'state')->item(0);
                    if ($id !== '' && $o instanceof DOMElement) {
                        // state 가 없는 테스트 = "패키지가 있으면 취약"(아직 수정본 없음) → 버리지 않는다.
                        $tests[$id] = [
                            'obj' => $o->getAttribute('object_ref'),
                            'ste' => $s instanceof DOMElement ? $s->getAttribute('state_ref') : null,
                        ];
                    }
                }
                $rd->next();
                break;

            case 'dpkginfo_object':
                $node = $rd->expand($doc);
                if ($node instanceof DOMElement) {
                    $id = $node->getAttribute('id');
                    $nm = $node->getElementsByTagNameNS('*', 'name')->item(0);
                    if ($id !== '' && $nm instanceof DOMElement) {
                        $var = $nm->getAttribute('var_ref');
                        $objs[$id] = [
                            'var'  => $var !== '' ? $var : null,
                            'name' => $var === '' ? trim($nm->textContent) : null,
                        ];
                    }
                }
                $rd->next();
                break;

            case 'dpkginfo_state':
                $node = $rd->expand($doc);
                if ($node instanceof DOMElement) {
                    $id  = $node->getAttribute('id');
                    $evr = $node->getElementsByTagNameNS('*', 'evr')->item(0);
                    if ($id !== '' && $evr instanceof DOMElement
                        && strtolower($evr->getAttribute('operation')) === 'less than') {
                        $states[$id] = trim($evr->textContent);
                    }
                }
                $rd->next();
                break;

            case 'constant_variable':
                $node = $rd->expand($doc);
                if ($node instanceof DOMElement) {
                    $id   = $node->getAttribute('id');
                    $vals = [];
                    foreach ($node->getElementsByTagNameNS('*', 'value') as $v) {
                        $t = trim($v->textContent);
                        if ($t !== '') { $vals[] = $t; }
                    }
                    if ($id !== '' && $vals) { $vars[$id] = $vals; }
                }
                $rd->next();
                break;
        }
    }
    $rd->close();

    // 정의 × 테스트 → (바이너리 패키지, CVE, 조치 EVR|null)
    $rows = [];
    $seen = [];
    foreach ($defs as [$cve, $refs, $sev]) {
        if (!vg_is_cve_id($cve)) { continue; }
        foreach ($refs as $t) {
            $test = $tests[$t] ?? null;                 // 커널 uname 테스트 등 dpkg 가 아닌 것은 여기서 걸러진다
            if ($test === null) { continue; }
            $obj = $objs[$test['obj']] ?? null;
            if ($obj === null) { continue; }

            $pkgs = $obj['var'] !== null ? ($vars[$obj['var']] ?? []) : [$obj['name']];
            $evr  = $test['ste'] !== null ? ($states[$test['ste']] ?? null) : null;

            foreach ($pkgs as $pkg) {
                if (!is_string($pkg) || $pkg === '') { continue; }
                $k = "$pkg|$cve";
                if (isset($seen[$k])) { continue; }
                $seen[$k] = true;
                $rows[] = ['pkg' => $pkg, 'cve' => $cve, 'evr' => $evr, 'severity' => $sev];
            }
        }
    }
    return $rows;
}

/** 수집 대상 코드명 — 설정에 없으면 수집된 우분투 **호스트·컨테이너**에서 뽑는다. */
function vg_ubuntu_oval_releases(PDO $pdo, array $conn): array {
    $cfg = array_values(array_filter(array_map('strval', (array) ($conn['releases'] ?? []))));
    if ($cfg) { return $cfg; }

    $rows = $pdo->query(
        "SELECT DISTINCT os_version FROM tb_scans
          WHERE LOWER(os_id) = 'ubuntu' AND os_version IS NOT NULL AND is_deleted = 0
         UNION
         SELECT DISTINCT os_version FROM tb_containers
          WHERE LOWER(os_id) = 'ubuntu' AND os_version IS NOT NULL"
    )->fetchAll(PDO::FETCH_COLUMN);

    $rel = [];
    foreach ($rows as $v) {
        $c = vg_ubuntu_codename((string) $v);
        if ($c !== '') { $rel[$c] = true; }
    }
    return array_keys($rel);   // 우분투 호스트가 없으면 빈 배열 → 받을 게 없다
}

// 우분투 보안 OVAL — 릴리스별 조치 EVR + "아직 수정본 없음"(조치 불가) 판정.
final class VgUbuntuOvalConnector implements VgFeedConnector {
    public function run(PDO $pdo, array $conn): array {
        $base     = (string) ($conn['url'] ?? VG_UBUNTU_OVAL_URL);
        $fetched  = 0;
        $upserted = 0;

        // bz2 확장 체크는 대상마다 반복할 필요 없다 — 병렬 다운로드 전에 한 번만.
        if (!extension_loaded('bz2')) {
            throw new RuntimeException('bz2 확장이 없습니다 — 우분투 OVAL 은 bz2 로만 배포된다');
        }

        // 중복 코드명(설정 오류)이 있으면 같은 임시파일을 두 번째 순회에서 이미 지운 뒤 열게 된다 —
        //   여기서 걷어낸다(원래도 같은 릴리스를 두 번 처리할 이유가 없다).
        $codes = array_values(array_unique(vg_ubuntu_oval_releases($pdo, $conn)));
        $urlOf = [];
        foreach ($codes as $code) { $urlOf[$code] = str_replace('{C}', $code, $base); }
        $downloads = vg_http_download_many(array_values($urlOf));

        foreach ($codes as $code) {
            $url = $urlOf[$code];
            $dl  = $downloads[$url] ?? ['path' => null, 'code' => 0, 'error' => '다운로드 안 됨'];
            if ($dl['path'] === null) {
                // 기존 시맨틱 유지: 다운로드 실패는 RuntimeException 으로 전체 run() 을 중단한다.
                throw new RuntimeException("우분투 OVAL fetch 실패 (HTTP {$dl['code']}) {$dl['error']} — $url");
            }
            $uri = 'compress.bzip2://' . $dl['path'];
            try {
                $rows     = vg_ubuntu_oval_parse($uri);
                $fetched += count($rows);
                if (!$rows) { continue; }   // 빈 결과로 기존 데이터를 지우지 않는다(수집 실패 = 억제 전멸)

                // 릴리스 단위 통째 교체 — 벤더가 뺀 항목(=해당 없음으로 정정)이 남아 있으면 계속 취약으로 잡힌다.
                $pdo->beginTransaction();
                $pdo->prepare('DELETE FROM tb_ubuntu_oval WHERE release_codename = ?')->execute([$code]);
                $pdo->commit();

                $batch = [];
                $flush = static function (array $b) use ($pdo): void {
                    if (!$b) { return; }
                    $ph = implode(',', array_fill(0, count($b), '(?,?,?,?,?)'));
                    $pdo->prepare(
                        "INSERT INTO tb_ubuntu_oval (release_codename, pkg_name, cve_id, fixed_evr, severity)
                         VALUES $ph
                         ON DUPLICATE KEY UPDATE fixed_evr = VALUES(fixed_evr), severity = VALUES(severity)"
                    )->execute(array_merge(...$b));
                };

                // 배치 INSERT + 주기적 커밋 — 한 트랜잭션에 수십만 행을 담으면 락 대기로 죽는다(OVAL 때 겪었다).
                $pdo->beginTransaction();
                foreach ($rows as $i => $r) {
                    $batch[] = [
                        $code,
                        mb_substr($r['pkg'], 0, 255),
                        mb_substr($r['cve'], 0, 32),
                        $r['evr'] !== null ? mb_substr($r['evr'], 0, 128) : null,
                        mb_substr($r['severity'], 0, 16),
                    ];
                    $upserted++;
                    if (count($batch) >= 500) {
                        $flush($batch);
                        $batch = [];
                        if (($i % 10000) < 500) { $pdo->commit(); $pdo->beginTransaction(); }
                    }
                }
                $flush($batch);
                $pdo->commit();

                // **취약 후보도 여기서 나온다.** 지금까지 우분투 후보는 OSV 에만 의존했다.
                //   실측: dev 에서 ubuntu:24.04 를 판정했더니 findings 0 이었다(Trivy 는 34건).
                //   OSV 의 우분투 수록이 우리 커버리지의 상한이 되는 구조였다 — 벤더 데이터가
                //   "어느 패키지가 영향받나" 의 정본인데 그걸 억제에만 쓰고 후보엔 안 썼다.
                //   그래서 카탈로그(tb_cves + tb_cve_affected_packages)에도 넣는다. 생태계 표기는
                //   OSV·매처와 같은 기준('Ubuntu:24.04').
                //   미수정 CVE 는 fixed_version=NULL 로 넣는다 — 버전 억제가 안 걸리고(조치안이 없으니
                //   당연하다), 판정 맵이 no_fix 로 표시한다.
                $eco = 'Ubuntu:' . vg_ubuntu_version_of($code);
                if (vg_ubuntu_version_of($code) === '') { continue; }   // 모르는 코드명은 후보를 만들지 않는다

                $cveB   = [];
                $affB   = [];
                $flushC = static function (array $cveB, array $affB) use ($pdo): void {
                    if ($cveB) {
                        $ph = implode(',', array_fill(0, count($cveB), '(?)'));
                        $pdo->prepare("INSERT IGNORE INTO tb_cves (cve_id) VALUES $ph")->execute($cveB);
                    }
                    if ($affB) {
                        $ph = implode(',', array_fill(0, count($affB), '(?,?,?,?)'));
                        $pdo->prepare(
                            "INSERT INTO tb_cve_affected_packages (cve_id, ecosystem, package_name, fixed_version)
                             VALUES $ph
                             ON DUPLICATE KEY UPDATE fixed_version = VALUES(fixed_version)"
                        )->execute(array_merge(...$affB));
                    }
                };

                $pdo->beginTransaction();
                $n = 0;
                foreach ($rows as $r) {
                    $cveB[] = $r['cve'];
                    $affB[] = [
                        $r['cve'], $eco, mb_substr($r['pkg'], 0, 255),
                        $r['evr'] !== null ? mb_substr($r['evr'], 0, 128) : null,
                    ];
                    if (++$n % 500 === 0) {
                        $flushC($cveB, $affB);
                        $cveB = []; $affB = [];
                        if ($n % 10000 === 0) { $pdo->commit(); $pdo->beginTransaction(); }
                    }
                }
                $flushC($cveB, $affB);
                $pdo->commit();
            } finally {
                @unlink($dl['path']);
            }
        }
        return ['fetched' => $fetched, 'upserted' => $upserted];
    }

    public function preview(PDO $pdo, array $conn): array {
        $code = vg_ubuntu_oval_releases($pdo, $conn)[0] ?? 'noble';
        $src  = vg_ubuntu_oval_fetch(str_replace('{C}', $code, (string) ($conn['url'] ?? VG_UBUNTU_OVAL_URL)));
        try {
            $rows  = vg_ubuntu_oval_parse($src['uri']);
            $items = [];
            foreach (array_slice($rows, 0, 10) as $r) {
                $items[] = [
                    'cve'      => $r['cve'],
                    'package'  => $r['pkg'],
                    'fixed'    => $r['evr'] ?? '(아직 수정본 없음 → 조치 불가)',
                    'severity' => $r['severity'],
                ];
            }
            return ['ok' => true, 'release' => $code, 'count' => count($rows), 'items' => $items];
        } finally {
            @unlink($src['path']);
        }
    }
}
