<?php
declare(strict_types=1);

/**
 * feeds/kcve.php — 리눅스 커널 CNA(kernel.org vulns.git) 수집.
 *
 * 왜: 커널만은 배포판이 아니라 **업스트림이 정본 판정자**다. 라즈베리·우분투 HWE·자체 빌드처럼
 *   배포판 버전 체계 밖의 커널은 트래커·OVAL 에 아예 없어서 "자동 판정 불가" 로 남는다
 *   (실측 raspberrypi5-00: LOW 2,069건 중 702건이 커널 하나. 커널 6.18 에 2004년 CVE 까지 붙었다).
 *   kernel.org CNA 는 CVE 마다 **stable 시리즈별 수정 버전**을 준다 → uname 버전과 바로 대조된다.
 *
 * 소스: git.kernel.org vulns.git 의 cgit **스냅샷 tarball**(약 20MB, gz).
 *   CVE 당 JSON 을 개별로 받으면 12,000번 넘게 요청해야 한다 — tarball 하나로 끝낸다.
 *
 * tar 를 직접 읽는 이유: PharData 는 .tar.gz 를 평문 tar 로 **디스크에 통째로 풀어야** 하는데
 *   그게 326MB 다(대부분 우리가 안 쓰는 mbox·sha1). tar 는 512바이트 헤더의 단순 포맷이라,
 *   gz 스트림 위에서 필요한 항목(cve/published 아래의 CVE JSON)만 읽고 나머지는 건너뛴다.
 */

require_once __DIR__ . '/http.php';

const VG_KCVE_SNAPSHOT = 'https://git.kernel.org/pub/scm/linux/security/vulns.git/snapshot/vulns-master.tar.gz';

/**
 * CVE 레코드(JSON) → 업스트림 판정 축.
 *   CNA 레코드의 semver 블록(defaultStatus=affected)만 본다. git 커밋 해시 블록은 우리 소관이 아니다.
 *     {"version":"6.5","status":"affected"}                                  → 6.5 부터 취약
 *     {"version":"6.1.78","lessThanOrEqual":"6.1.*","status":"unaffected"}   → 6.1.y 는 6.1.78 에서 수정
 *     {"version":"6.8","lessThanOrEqual":"*","status":"unaffected"}          → 메인라인 6.8 에서 수정
 * @return array{cve:string,introduced:?string,mainline:?string,streams:array<string,string>}|null
 */
function vg_kcve_parse_record(string $json): ?array {
    $d = json_decode($json, true);
    if (!is_array($d)) { return null; }

    $cve = (string) ($d['cveMetadata']['cveId'] ?? '');
    if (!preg_match('/^CVE-\d{4}-\d{4,}$/', $cve)) { return null; }

    $introduced = null;
    $mainline   = null;
    $streams    = [];

    foreach ($d['containers']['cna']['affected'] ?? [] as $aff) {
        if (($aff['defaultStatus'] ?? '') !== 'affected') { continue; }   // git 해시 블록(unaffected)은 건너뛴다
        foreach ($aff['versions'] ?? [] as $v) {
            $ver = trim((string) ($v['version'] ?? ''));
            $st  = (string) ($v['status'] ?? '');
            $lte = trim((string) ($v['lessThanOrEqual'] ?? ''));
            if ($ver === '' || $ver === '0') { continue; }

            if ($st === 'affected' && $lte === '') {
                $introduced ??= $ver;
            } elseif ($st === 'unaffected' && str_ends_with($lte, '.*')) {
                $streams[substr($lte, 0, -2)] = $ver;
            } elseif ($st === 'unaffected' && $lte === '*') {
                $mainline ??= $ver;
            }
        }
    }
    if ($introduced === null && $mainline === null && !$streams) { return null; }

    return ['cve' => $cve, 'introduced' => $introduced, 'mainline' => $mainline, 'streams' => $streams];
}

/**
 * gz tar 를 스트림으로 훑어 cve/published 아래의 CVE JSON 만 $onFile 로 넘긴다.
 *   tar: 512바이트 헤더(이름 100 · 크기 124@12 8진수 · 타입 156) + 데이터(512 배수 패딩).
 *   압축 스트림이라 fseek 가 비싸다 → 건너뛸 때도 읽어서 버린다(메모리는 상수).
 * @return int 넘긴 파일 수
 */
function vg_kcve_scan_tar(string $gzPath, callable $onFile): int {
    $fp = fopen('compress.zlib://' . $gzPath, 'rb');
    if ($fp === false) { throw new RuntimeException('커널 CNA tarball 을 열지 못했다'); }

    $skip = static function ($fp, int $n): void {
        while ($n > 0) {
            $c = fread($fp, min($n, 262144));
            if ($c === false || $c === '') { return; }
            $n -= strlen($c);
        }
    };

    $n = 0;
    try {
        while (!feof($fp)) {
            $hdr = '';
            while (strlen($hdr) < 512 && !feof($fp)) {          // 압축 스트림은 짧게 끊어 준다
                $c = fread($fp, 512 - strlen($hdr));
                if ($c === false || $c === '') { break; }
                $hdr .= $c;
            }
            if (strlen($hdr) < 512 || trim($hdr, "\0") === '') { break; }   // 끝(NUL 블록 2개)

            $name = trim(substr($hdr, 0, 100), " \0");
            $size = (int) octdec(trim(substr($hdr, 124, 12), " \0"));
            $type = substr($hdr, 156, 1);
            $pad  = (512 - ($size % 512)) % 512;

            $want = ($type === '0' || $type === "\0")
                && preg_match('#/cve/published/\d{4}/CVE-\d{4}-\d+\.json$#', $name) === 1;

            if ($want && $size > 0 && $size < 4194304) {
                $data = '';
                while (strlen($data) < $size && !feof($fp)) {
                    $c = fread($fp, min($size - strlen($data), 262144));
                    if ($c === false || $c === '') { break; }
                    $data .= $c;
                }
                $onFile($data);
                $n++;
            } else {
                $skip($fp, $size);
            }
            $skip($fp, $pad);
        }
    } finally {
        fclose($fp);
    }
    return $n;
}

// 리눅스 커널 CNA — CVE 별 stable 시리즈 수정 버전(커널 판정의 정본).
final class VgKcveConnector implements VgFeedConnector {
    public function run(PDO $pdo, array $conn): array {
        $url = (string) ($conn['url'] ?? VG_KCVE_SNAPSHOT);

        $tmp = tempnam(sys_get_temp_dir(), 'vgkcve') . '.tar.gz';
        $r   = vg_http_raw('GET', $url, [], 600);
        if ($r['code'] !== 200 || $r['body'] === '') {
            throw new RuntimeException("커널 CNA 스냅샷 다운로드 실패 (HTTP {$r['code']}) {$r['error']}");
        }
        file_put_contents($tmp, $r['body']);
        unset($r);

        $insCve = $pdo->prepare(
            'INSERT INTO tb_kernel_cves (cve_id, introduced_version, mainline_fixed) VALUES (?,?,?)
             ON DUPLICATE KEY UPDATE introduced_version = VALUES(introduced_version),
                                     mainline_fixed = VALUES(mainline_fixed)'
        );
        $insFix = $pdo->prepare(
            'INSERT INTO tb_kernel_cve_fixes (cve_id, stream, fixed_version) VALUES (?,?,?)
             ON DUPLICATE KEY UPDATE fixed_version = VALUES(fixed_version)'
        );

        $upserted = 0;
        $pdo->beginTransaction();
        try {
            $fetched = vg_kcve_scan_tar($tmp, function (string $json) use ($pdo, $insCve, $insFix, &$upserted): void {
                $rec = vg_kcve_parse_record($json);
                if ($rec === null) { return; }

                $insCve->execute([$rec['cve'], $rec['introduced'], $rec['mainline']]);
                foreach ($rec['streams'] as $stream => $fixed) {
                    $insFix->execute([$rec['cve'], mb_substr((string) $stream, 0, 16), mb_substr($fixed, 0, 32)]);
                }
                // 커밋을 끊어 준다 — 12,000건을 한 트랜잭션에 담으면 락 대기로 죽는다(OVAL 때 겪었다).
                if (++$upserted % 500 === 0) { $pdo->commit(); $pdo->beginTransaction(); }
            });
            $pdo->commit();
        } catch (Throwable $e) {
            if ($pdo->inTransaction()) { $pdo->rollBack(); }
            throw $e;
        } finally {
            @unlink($tmp);
        }

        if ($upserted === 0) { throw new RuntimeException('커널 CNA 스냅샷에서 레코드를 하나도 읽지 못했다'); }
        return ['fetched' => $fetched, 'upserted' => $upserted];
    }

    public function preview(PDO $pdo, array $conn): array {
        return [
            'ok'    => true,
            'items' => [[
                '소스' => (string) ($conn['url'] ?? VG_KCVE_SNAPSHOT),
                '내용' => 'CVE 별 stable 시리즈 수정 버전(예: 6.1.y → 6.1.78) + 최초 취약 버전',
                '쓰임' => 'uname 으로 잡은 구동 커널 버전과 대조해 커널 CVE 를 판정(배포판 무관)',
            ]],
        ];
    }
}
