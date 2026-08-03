<?php
declare(strict_types=1);

/**
 * feeds/ssg.php — SCAP Security Guide(ComplianceAsCode) 룰셋 수집.
 *
 * 왜: 보안설정 점검(CCE) 룰을 그동안 **우리가 코드에 지어 써 넣었다**(cce.php 385줄).
 *   "이 항목이 왜 중요한가 / 어느 기준에 근거하나" 를 우리가 정하는 셈이라 신뢰도가 낮다.
 *   SSG 는 오픈소스 룰셋이고 룰마다 **CIS·NIST 800-53·STIG·PCI-DSS 참조**와 근거를 갖고 있다.
 *   그걸 카탈로그로 받아 우리 점검을 그 룰에 묶는다 — 룰의 정체·근거·기준 매핑은 검증된
 *   소스가 갖고, 우리는 에이전트가 보낸 값으로 판정만 한다.
 *
 * 소스: github.com/ComplianceAsCode/content 릴리스 tarball (약 9MB, bz2)
 *   빌드된 데이터스트림(ssg-*-ds.xml)은 릴리스 자산에 없다 — 소스에서 rule.yml 을 읽는다.
 *
 * 파싱을 YAML 파서로 하지 않는 이유: rule.yml 의 **3분의 1에 Jinja 블록**({{% if %}})이 섞여 있어
 *   표준 YAML 파서가 깨진다(실측: 표본 400개 중 130개). 우리가 쓰는 필드는 몇 개뿐이라
 *   그 필드만 정규식으로 뽑는다 — 깨지는 파서보다 낫다.
 *
 * 한계(솔직히): 판정 로직(OVAL)까지 중앙에서 돌리진 못한다. OVAL 은 살아 있는 파일시스템을
 *   프로브하는데 우리는 수집된 사실만 갖고 있고, 대상 서버엔 아무것도 설치하지 않는다.
 *   그래서 **우리가 판정 가능한 룰만** 묶고, 나머지는 화면에서 "수집 항목 없음" 으로 드러낸다.
 */

require_once __DIR__ . '/http.php';

const VG_SSG_LATEST = 'https://api.github.com/repos/ComplianceAsCode/content/releases/latest';

/** 최신 릴리스의 tarball URL + 버전. */
function vg_ssg_latest(string $apiUrl = VG_SSG_LATEST): array {
    $r = vg_http_raw('GET', $apiUrl, ['Accept: application/vnd.github+json'], 60);
    if ($r['code'] !== 200 || $r['body'] === '') {
        throw new RuntimeException("SSG 릴리스 조회 실패 (HTTP {$r['code']}) {$r['error']}");
    }
    $d = json_decode($r['body'], true);
    if (!is_array($d)) { throw new RuntimeException('SSG 릴리스 응답 파싱 실패'); }

    $ver = (string) ($d['tag_name'] ?? '');
    foreach ($d['assets'] ?? [] as $a) {
        $name = (string) ($a['name'] ?? '');
        if (str_ends_with($name, '.tar.bz2')) {
            return ['version' => $ver, 'url' => (string) $a['browser_download_url']];
        }
    }
    throw new RuntimeException('SSG 릴리스에 tar.bz2 자산이 없다');
}

/**
 * rule.yml 한 개 → 룰 정보. 필요한 필드만 뽑는다(Jinja 가 섞여 있어 YAML 파서는 못 쓴다).
 * @return array{title:string,severity:string,rationale:string,refs:array<string,string>}|null
 */
function vg_ssg_parse_rule(string $yaml): ?array {
    // title: 'Disable SSH Access via Empty Passwords'   또는   title: |- 다음 줄
    $title = '';
    if (preg_match("/^title:\s*['\"]?(.+?)['\"]?\s*$/m", $yaml, $m) === 1) {
        $title = trim($m[1]);
    }
    if ($title === '' || $title === '|-' || $title === '|') {
        if (preg_match('/^title:\s*\|-?\s*\n\s+(.+)$/m', $yaml, $m) === 1) { $title = trim($m[1]); }
    }
    if ($title === '') { return null; }

    $severity = 'unknown';
    if (preg_match('/^severity:\s*(\w+)/m', $yaml, $m) === 1) { $severity = strtolower($m[1]); }

    // rationale: |-  (들여쓴 블록) — 첫 문단만 쓴다(설명은 길다).
    $rationale = '';
    if (preg_match('/^rationale:\s*\|-?\s*\n((?:[ \t]+.*\n?)+)/m', $yaml, $m) === 1) {
        $rationale = trim(preg_replace('/\s+/', ' ', $m[1]) ?? '');
    }

    // references:
    //     cis@rhel9: 5.2.11
    //     nist: AC-17(a)
    $refs = [];
    if (preg_match('/^references:\s*\n((?:[ \t]+\S.*\n?)+)/m', $yaml, $m) === 1) {
        foreach (preg_split('/\r?\n/', $m[1]) as $line) {
            if (preg_match('/^\s+([\w@.\-]+):\s*(.+?)\s*$/', $line, $mm) === 1) {
                $refs[$mm[1]] = trim($mm[2], " '\"");
            }
        }
    }

    return ['title' => $title, 'severity' => $severity, 'rationale' => $rationale, 'refs' => $refs];
}

/**
 * tarball 에서 rule.yml 들을 읽어 룰 목록으로. 룰 ID 는 디렉터리명이다.
 *   .tar.bz2 를 PharData 에 바로 물리면 **압축을 통째로 메모리에 푼다**(실측: 128MB 초과로 사망).
 *   그래서 bz2 스트림으로 디스크에 먼저 풀고, 평문 tar 를 연다(메모리 상수).
 */
function vg_ssg_parse_tarball(string $path): array {
    $tar = $path;
    if (str_ends_with($path, '.bz2')) {
        $tar = preg_replace('/\.bz2$/', '', $path) ?? ($path . '.tar');
        $in  = fopen('compress.bzip2://' . $path, 'rb');
        $out = fopen($tar, 'wb');
        if ($in === false || $out === false) { throw new RuntimeException('SSG bz2 해제 실패'); }
        stream_copy_to_stream($in, $out);
        fclose($in);
        fclose($out);
    }

    $phar = new PharData($tar);
    $out  = [];

    foreach (new RecursiveIteratorIterator($phar) as $file) {
        /** @var PharFileInfo $file */
        $p = $file->getPathname();
        if (!str_ends_with($p, '/rule.yml')) { continue; }
        // .../linux_os/guide/services/ssh/ssh_server/sshd_disable_empty_passwords/rule.yml
        if (preg_match('#/([^/]+)/rule\.yml$#', $p, $m) !== 1) { continue; }
        $ruleId = $m[1];

        $r = vg_ssg_parse_rule((string) file_get_contents($p));
        if ($r === null) { continue; }
        $out[$ruleId] = $r;
    }
    return $out;
}

// SCAP Security Guide — 보안설정 점검 룰의 정체·근거·기준 매핑(CIS/NIST/STIG)을 제공한다.
final class VgSsgConnector implements VgFeedConnector {
    public function run(PDO $pdo, array $conn): array {
        $rel = vg_ssg_latest((string) ($conn['url'] ?? VG_SSG_LATEST));

        $r = vg_http_raw('GET', $rel['url'], [], 300);
        if ($r['code'] !== 200 || $r['body'] === '') {
            throw new RuntimeException("SSG tarball 다운로드 실패 (HTTP {$r['code']}) {$r['error']}");
        }
        $tmp = tempnam(sys_get_temp_dir(), 'vgssg') . '.tar.bz2';   // PharData 는 확장자로 형식을 안다
        file_put_contents($tmp, $r['body']);

        try {
            $rules = vg_ssg_parse_tarball($tmp);
            if (!$rules) { throw new RuntimeException('SSG tarball 에서 룰을 하나도 읽지 못했다'); }

            $ins = $pdo->prepare(
                'INSERT INTO tb_compliance_rule (rule_id, title, severity, rationale, refs_json, ssg_version)
                 VALUES (?,?,?,?,?,?)
                 ON DUPLICATE KEY UPDATE
                   title = COALESCE(VALUES(title), title),
                   severity = COALESCE(VALUES(severity), severity),
                   rationale = COALESCE(VALUES(rationale), rationale),
                   refs_json = COALESCE(VALUES(refs_json), refs_json),
                   ssg_version = COALESCE(VALUES(ssg_version), ssg_version), is_deleted = 0'
            );

            $n = 0;
            $pdo->beginTransaction();
            foreach ($rules as $id => $x) {
                $ins->execute([
                    mb_substr((string) $id, 0, 191),
                    mb_substr($x['title'], 0, 255),
                    mb_substr($x['severity'], 0, 16),
                    mb_substr($x['rationale'], 0, 2000),
                    json_encode($x['refs'], JSON_UNESCAPED_UNICODE),
                    mb_substr((string) $rel['version'], 0, 16),
                ]);
                if (++$n % 500 === 0) { $pdo->commit(); $pdo->beginTransaction(); }
            }
            $pdo->commit();

            return ['fetched' => count($rules), 'upserted' => $n];
        } finally {
            @unlink($tmp);
        }
    }

    public function preview(PDO $pdo, array $conn): array {
        $rel = vg_ssg_latest((string) ($conn['url'] ?? VG_SSG_LATEST));
        return [
            'ok'      => true,
            'version' => $rel['version'],
            'items'   => [['소스' => $rel['url'], '내용' => 'rule.yml → 제목·근거·심각도 + CIS/NIST/STIG 참조']],
        ];
    }
}
