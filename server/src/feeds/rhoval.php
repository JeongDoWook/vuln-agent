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
 *   oracle    https://linux.oracle.com/security/oval/com.oracle.elsa-all.xml.bz2              (전 릴리스 한 파일)
 *   Rocky 는 OSV(Rocky Linux:N)가 조치 버전을 이미 준다 → 중복 수집하지 않는다.
 *
 * Oracle Linux 는 **OSV 에 아예 없다** → 이 OVAL 이 유일한 판정 소스다(억제 + 취약 후보 둘 다).
 *   실측(deskmini): ol 9.7 컨테이너의 패키지 117개에 findings 가 0 이었다 — 통째로 미탐이었다.
 *   전 릴리스가 한 파일이라 정의의 <platform>Oracle Linux 9</platform> 로 릴리스를 갈라야 한다.
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
require_once __DIR__ . '/upsert.php';   // vg_is_cve_id
require_once __DIR__ . '/../vendorerrata.php';   // 판정 규칙(매처와 공유)

const VG_RHOVAL_SOURCES = [
    'redhat'    => 'https://security.access.redhat.com/data/oval/v2/RHEL{N}/rhel-{N}.oval.xml.bz2',
    'almalinux' => 'https://security.almalinux.org/oval/org.almalinux.alsa-{N}.xml',
    // Oracle 은 **전 릴리스가 한 파일**이다(11MB bz2 → 236MB XML, 정의 9,272개).
    //   그래서 정의의 <platform>Oracle Linux 9</platform> 로 릴리스를 갈라야 한다 —
    //   안 가르면 OL8 의 조치 EVR(el8_10)로 OL9 를 판정하게 된다.
    'oracle'    => 'https://linux.oracle.com/security/oval/com.oracle.elsa-all.xml.bz2',
];

/** 이 벤더의 OVAL 파일이 여러 릴리스를 한꺼번에 담는가(→ platform 으로 걸러야 한다). */
function vg_rhoval_is_combined(string $vendor): bool {
    return $vendor === 'oracle';
}

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

/** 이미 다운로드된 임시파일 경로 → XMLReader 가 열 수 있는 uri(bz2 면 스트림 래퍼). vg_rhoval_fetch 의 후반부만 뽑았다. */
function vg_rhoval_uri(string $path, string $url): string {
    $isBz2 = substr($url, -4) === '.bz2';
    if ($isBz2 && !extension_loaded('bz2')) {
        throw new RuntimeException('bz2 확장이 없습니다 — Red Hat OVAL 은 bz2 로만 배포된다(이미지 재빌드 필요)');
    }
    return $isBz2 ? 'compress.bzip2://' . $path : $path;
}

/**
 * OVAL → 권고 행 목록. 네트워크·DB 없이 도는 순수 함수(경로만 받는다 → 픽스처로 단위 테스트).
 *
 * $onlyMajor 를 주면 **그 릴리스의 정의만** 붙잡는다(Oracle 처럼 전 릴리스가 한 파일인 경우).
 *   전부 메모리에 이고 가면 죽는다 — 실측: Oracle 파일(236MB XML)에서 PHP 512MB 를 넘겨 사망.
 *   OVAL 은 정의 → 테스트 → 오브젝트 → 상태 순이라, 남긴 정의가 참조하는 것만 이어서 담으면 된다.
 *
 * @return list<array{pkg:string,cve:string,evr:string,advisory:string,severity:string,majors:list<string>}>
 */
function vg_rhoval_parse(string $uri, string $onlyMajor = ''): array {
    $doc = new DOMDocument();
    $rd  = new XMLReader();
    if (!@$rd->open($uri)) {
        throw new RuntimeException("OVAL 열기 실패: $uri");
    }

    $defs    = [];   // [ [cves[], testRefs[], advisory, severity, majors[]] … ]
    $tests   = [];   // testId  => ['obj' => objId, 'ste' => steId]
    $objects = [];   // objId   => 패키지명
    $states  = [];   // steId   => 조치 EVR ('less than' 인 것만)
    $needTst = [];   // 남긴 정의가 참조하는 테스트 id (필터가 있을 때만 채운다)
    $needObj = [];
    $needSte = [];

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
                        // 권고 ID: RHSA(레드햇·알마) · ELSA(오라클)
                        if (($src === 'RHSA' || $src === 'ELSA') && $adv === '') { $adv = $rid; }
                    }
                    $sevNode = $node->getElementsByTagNameNS('*', 'severity')->item(0);
                    if ($sevNode !== null) { $sev = trim($sevNode->textContent); }

                    // 릴리스 귀속 — <platform>Oracle Linux 9</platform> / <platform>Red Hat … 9</platform>.
                    //   한 파일에 여러 릴리스가 섞인 소스(Oracle)에서 이걸 안 보면 OL8 의 조치 EVR 로
                    //   OL9 를 판정한다. 릴리스별 파일(Red Hat·Alma)에선 그냥 비어 있어도 무해하다.
                    $majors = [];
                    foreach ($node->getElementsByTagNameNS('*', 'platform') as $pf) {
                        if (preg_match('/(\d+)/', $pf->textContent, $pm) === 1) { $majors[$pm[1]] = true; }
                    }

                    $refs = [];
                    foreach ($node->getElementsByTagNameNS('*', 'criterion') as $cr) {
                        $t = $cr->getAttribute('test_ref');
                        if ($t !== '') { $refs[] = $t; }
                    }
                    // 대상 릴리스가 아니면 여기서 버린다(그 정의가 참조하는 테스트도 안 담는다).
                    //   isset 으로 본다 — PHP 는 '9' 같은 숫자 문자열 키를 **정수로 캐스팅**하므로
                    //   in_array('9', array_keys($majors), true) 는 항상 false 다(실측: 전 행이 사라졌다).
                    if ($onlyMajor !== '' && !isset($majors[$onlyMajor])) {
                        $cves = [];
                    }
                    if ($cves && $refs) {
                        $defs[] = [$cves, $refs, $adv, $sev, array_map('strval', array_keys($majors))];
                        foreach ($refs as $t) { $needTst[$t] = true; }
                    }
                }
                $rd->next();   // 자식은 이미 읽었다
                break;

            case 'rpminfo_test':
                $node = $rd->expand($doc);
                if ($node instanceof DOMElement) {
                    $id  = $node->getAttribute('id');
                    $o   = $node->getElementsByTagNameNS('*', 'object')->item(0);
                    $s   = $node->getElementsByTagNameNS('*', 'state')->item(0);
                    if ($id !== '' && ($onlyMajor === '' || isset($needTst[$id]))
                        && $o instanceof DOMElement && $s instanceof DOMElement) {
                        $obj = $o->getAttribute('object_ref');
                        $ste = $s->getAttribute('state_ref');
                        $tests[$id]    = ['obj' => $obj, 'ste' => $ste];
                        $needObj[$obj] = true;
                        $needSte[$ste] = true;
                    }
                }
                $rd->next();
                break;

            case 'rpminfo_object':
                $node = $rd->expand($doc);
                if ($node instanceof DOMElement) {
                    $id = $node->getAttribute('id');
                    $nm = $node->getElementsByTagNameNS('*', 'name')->item(0);
                    if ($id !== '' && ($onlyMajor === '' || isset($needObj[$id])) && $nm !== null) {
                        $objects[$id] = trim($nm->textContent);
                    }
                }
                $rd->next();
                break;

            case 'rpminfo_state':
                $node = $rd->expand($doc);
                if ($node instanceof DOMElement) {
                    $id  = $node->getAttribute('id');
                    $evr = $node->getElementsByTagNameNS('*', 'evr')->item(0);
                    // 'less than' 인 EVR 만 조치안이다. arch·서명 검사 상태는 버린다.
                    if ($id !== '' && ($onlyMajor === '' || isset($needSte[$id]))
                        && $evr instanceof DOMElement
                        && strtolower($evr->getAttribute('operation')) === 'less than') {
                        $states[$id] = trim($evr->textContent);
                    }
                }
                $rd->next();
                break;
        }
    }
    $rd->close();

    // 정의 × 테스트 → (패키지, 조치 EVR, CVE) 로 펼친다. majors 는 그 정의가 적용되는 릴리스다.
    $rows = [];
    $seen = [];
    foreach ($defs as [$cves, $refs, $adv, $sev, $majors]) {
        foreach ($refs as $t) {
            $test = $tests[$t] ?? null;
            if ($test === null) { continue; }
            $pkg = $objects[$test['obj']] ?? '';
            $evr = $states[$test['ste']] ?? '';        // 조치안이 없는 테스트(플랫폼·아키)는 여기서 걸러진다
            if ($pkg === '' || $evr === '') { continue; }

            // **별도 제품 계보의 EVR 은 조치안이 아니다** — Oracle 이 같은 파일에 섞어 낸다.
            //   · Ksplice 사용자공간: glibc 2:2.28-151.0.1.ksplice2.el8   (epoch 2, 실측 10,528행)
            //   · FIPS 검증 빌드   : gnutls 10:3.6.16-8.el8_9.3_fips      (epoch 10)
            //   일반 설치본은 epoch 0 이라, 이걸 조치안으로 쓰면 **정상 최신 시스템이 통째로 취약**해진다
            //   (epoch 가 우선하므로 0:… < 2:… < 10:…). 실측 oraclelinux:8 — glibc·gnutls 계열이
            //   전부 오탐으로 남았다. Trivy 도 같은 이유로 제외한다.
            if (stripos($evr, 'ksplice') !== false || stripos($evr, '_fips') !== false) { continue; }

            // 한 권고가 여러 릴리스를 함께 다루면(ELSA-2023-12788 은 OL8·OL9) 그 안에 el8·el9 EVR 이
            //   섞여 있다. 릴리스 필터를 켰으면 **그 릴리스의 EVR 만** 남긴다 — 안 그러면 OL8 행에
            //   el9 EVR(11.3.1)이 들어가 설치본(8.5.0)이 영원히 "미조치" 가 된다(실측: libgcc 오탐).
            //   릴리스 태그는 두 모양이다: `-24.el8_10` 과 모듈러의 `-7.module+el8.10.0+…`.
            //   `\.el8` 로만 보면 모듈러 패키지(python39·nodejs …)를 통째로 버린다(실측 22만→7.5만행).
            if ($onlyMajor !== '' && preg_match('/el' . preg_quote($onlyMajor, '/') . '([._+]|$)/', $evr) !== 1) {
                continue;
            }

            foreach ($cves as $cve) {
                $k = "$pkg|$cve|$evr";
                if (isset($seen[$k])) { continue; }
                $seen[$k] = true;
                $rows[] = [
                    'pkg' => $pkg, 'cve' => $cve, 'evr' => $evr,
                    'advisory' => $adv, 'severity' => $sev, 'majors' => $majors,
                ];
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
        "SELECT DISTINCT os_id, os_version FROM tb_scan WHERE os_id IS NOT NULL AND is_deleted = 0
         UNION
         SELECT DISTINCT os_id, os_version FROM tb_container WHERE os_id IS NOT NULL"
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

        $targets = vg_rhoval_targets($pdo, $conn);

        // 다운로드만 먼저 동시에 한다(파싱·DB 로직은 그대로 순차). Oracle 처럼 같은 URL(전체릴리스
        //   파일 하나)을 메이저마다 중복 요청하면(현재도 그렇다, 캐싱은 범위 밖) 여러 대상이 같은
        //   임시파일을 참조하게 된다 — refs 로 참조수를 세어 그 URL 을 쓰는 모든 대상의 파싱이
        //   끝난 뒤에만 unlink 한다(파싱 중간에 지우면 다른 대상이 못 연다).
        $urls = [];
        $refs = [];
        foreach ($targets as [$vendor, $major]) {
            $tpl = VG_RHOVAL_SOURCES[$vendor] ?? null;
            if ($tpl === null) { continue; }
            $url = str_replace('{N}', $major, $tpl);
            $urls[] = $url;
            $refs[$url] = ($refs[$url] ?? 0) + 1;
        }
        // 기존 vg_rhoval_fetch 의 개별 타임아웃(180초)을 유지한다 — 병렬화 자체가 목적이라
        //   타임아웃까지 늘릴 이유는 없다(기본값 300은 이 커넥터엔 과하다).
        $downloads = vg_http_download_many(array_values(array_unique($urls)), 3, 180);

        try {
            foreach ($targets as [$vendor, $major]) {
                $tpl = VG_RHOVAL_SOURCES[$vendor] ?? null;
                if ($tpl === null) { continue; }
                $url = str_replace('{N}', $major, $tpl);
                $dl  = $downloads[$url] ?? ['path' => null, 'code' => 0, 'error' => '다운로드 안 됨'];
                if ($dl['path'] === null) {
                    // 기존 시맨틱 유지: 다운로드 실패는 RuntimeException 으로 전체 run() 을 중단한다.
                    throw new RuntimeException("OVAL fetch 실패 (HTTP {$dl['code']}) {$dl['error']} — $url");
                }
                $uri = vg_rhoval_uri($dl['path'], $url);

                try {
                    // 한 파일에 여러 릴리스가 섞인 소스(Oracle)는 **이 릴리스 것만** 파싱한다.
                    //   안 거르면 (1) OL8 의 조치 EVR 이 OL9 행으로 들어가 판정이 틀어지고,
                    //   (2) 전 릴리스를 메모리에 이고 가다 죽는다(실측: 512MB 초과).
                    $rows = vg_rhoval_parse($uri, vg_rhoval_is_combined($vendor) ? $major : '');
                    if (vg_rhoval_is_combined($vendor) && !$rows) {
                        throw new RuntimeException("$vendor OVAL 에 릴리스 $major 정의가 없다(플랫폼 표기 변경?)");
                    }
                    $fetched += count($rows);

                    // 24만 행을 한 트랜잭션에 넣었더니 **운영에서 Lock wait timeout** 이 났다 —
                    //   락을 수 분간 쥐고 있는 동안 스케줄러(재매칭·다른 피드)와 부딪혔다.
                    //   그래서 (1) 여러 행을 한 INSERT 로 묶고 (2) 배치마다 커밋해 락을 짧게 쥔다.
                    //   중간에 죽으면 권고가 일부만 남는데, 그건 "억제를 덜 함"(오탐이 남을 뿐)이라
                    //   안전한 방향이다 — 다음 수집이 다시 통째로 교체한다.
                    $pdo->beginTransaction();
                    $pdo->prepare('DELETE FROM tb_vendor_errata WHERE vendor = ? AND release_major = ?')
                        ->execute([$vendor, $major]);
                    $pdo->commit();

                    $maxFix = [];   // "패키지|CVE" => 가장 높은 조치 EVR (카탈로그에 넣을 값)
                    $batch  = [];
                    $flush  = static function (array $b) use ($pdo): void {
                        if (!$b) { return; }
                        $ph  = implode(',', array_fill(0, count($b), '(?,?,?,?,?,?,?)'));
                        $st  = $pdo->prepare(
                            "INSERT INTO tb_vendor_errata
                               (vendor, release_major, pkg_name, cve_id, fixed_evr, advisory, severity)
                             VALUES $ph
                             ON DUPLICATE KEY UPDATE
                               advisory = COALESCE(VALUES(advisory), advisory),
                               severity = COALESCE(VALUES(severity), severity)"
                        );
                        $st->execute(array_merge(...$b));
                    };

                    $pdo->beginTransaction();
                    foreach ($rows as $i => $r) {
                        $batch[] = [
                            $vendor, $major,
                            mb_substr($r['pkg'], 0, 255),
                            mb_substr($r['cve'], 0, 32),
                            mb_substr($r['evr'], 0, 128),
                            mb_substr($r['advisory'], 0, 64),
                            mb_substr($r['severity'], 0, 16),
                        ];
                        $upserted++;

                        $k = $r['pkg'] . '|' . $r['cve'];
                        if (!isset($maxFix[$k]) || vg_ver_cmp($r['evr'], $maxFix[$k], 'rpm') > 0) {
                            $maxFix[$k] = $r['evr'];
                        }

                        if (count($batch) >= 500) {
                            $flush($batch);
                            $batch = [];
                            if (($i % 10000) < 500) { $pdo->commit(); $pdo->beginTransaction(); }
                        }
                    }
                    $flush($batch);
                    $pdo->commit();

                    // **취약 후보도 여기서 나온다.** RHEL 계열은 OSV 에 조치안이 없어(실측: UBI9 스캔의
                    //   findings 가 0 이었다) OVAL 이 유일한 소스다. 그래서 카탈로그(tb_cve +
                    //   tb_cve_affected_package)에도 넣어 매처가 후보를 찾을 수 있게 한다.
                    //   생태계 표기는 매처·OSV 와 같은 기준(vg_osv_ecosystem): 'Red Hat:9' / 'AlmaLinux:9'.
                    //
                    //   카탈로그의 조치버전은 **가장 높은 EVR** 을 넣는다. 같은 (패키지,CVE)가 마이너
                    //   스트림마다 다른 EVR 로 고쳐지는데(el9_2 · el9_4) 자연키는 하나뿐이라 하나만 남는다.
                    //   낮은 EVR 을 넣으면 다른 스트림에서 "이미 패치됨" 으로 잘못 억제한다(미탐).
                    //   높은 쪽은 보수적이다 — 억제를 덜 할 뿐이고, 정밀한 스트림 판정은
                    //   tb_vendor_errata 를 보는 vg_vendor_errata_evidence 가 따로 한다.
                    //   카탈로그도 배치로 넣는다(행마다 upsert 하면 8만 번 왕복 + 락 유지 시간이 길다).
                    $eco    = ['almalinux' => "AlmaLinux:$major", 'oracle' => "Oracle Linux:$major"][$vendor]
                              ?? "Red Hat:$major";
                    $cveB   = [];
                    $affB   = [];
                    $flushC = static function (array $cveB, array $affB) use ($pdo): void {
                        if ($cveB) {
                            // 상세(요약·CVSS)는 NVD 가 채운다 — 여기선 CVE 존재만 보장한다(INSERT IGNORE).
                            $ph = implode(',', array_fill(0, count($cveB), '(?)'));
                            $pdo->prepare("INSERT IGNORE INTO tb_cve (cve_id) VALUES $ph")->execute($cveB);
                        }
                        if ($affB) {
                            $ph = implode(',', array_fill(0, count($affB), '(?,?,?,?)'));
                            $pdo->prepare(
                                "INSERT INTO tb_cve_affected_package (cve_id, ecosystem, package_name, fixed_version)
                                 VALUES $ph
                                 ON DUPLICATE KEY UPDATE fixed_version = COALESCE(VALUES(fixed_version), fixed_version)"
                            )->execute(array_merge(...$affB));
                        }
                    };

                    $pdo->beginTransaction();
                    $n = 0;
                    foreach ($maxFix as $k => $evr) {
                        [$pkg, $cve] = explode('|', $k, 2);
                        if (!vg_is_cve_id($cve)) { continue; }
                        $cveB[] = $cve;
                        $affB[] = [$cve, $eco, mb_substr($pkg, 0, 255), mb_substr($evr, 0, 128)];

                        if (++$n % 500 === 0) {
                            $flushC($cveB, $affB);
                            $cveB = []; $affB = [];
                            if ($n % 10000 === 0) { $pdo->commit(); $pdo->beginTransaction(); }
                        }
                    }
                    $flushC($cveB, $affB);
                    $pdo->commit();
                } finally {
                    // 이 URL 을 쓰는 마지막 대상의 파싱이 끝났을 때만 지운다(Oracle 공유 파일 대비).
                    if (--$refs[$url] <= 0) {
                        @unlink($dl['path']);
                    }
                }
            }
        } finally {
            // 다운로드 실패·파싱 예외로 run() 이 중간에 끊겨도, 아직 처리 차례가 오지 않은
            //   다른 대상의 다운로드 파일(수십~수백MB)이 /tmp 에 남지 않게 한다.
            foreach ($downloads as $d) {
                if ($d['path'] !== null) { @unlink($d['path']); }
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
