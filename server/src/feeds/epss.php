<?php
declare(strict_types=1);

/**
 * feeds/epss.php — FIRST EPSS 커넥터. CVE별 악용확률(0~1) + 백분위. gzip CSV 를 받아
 *   우리가 보유한 CVE 만 갱신(전체 34만건 삽입 안 함). 미리보기는 앞 10행(점수 내림차순).
 */

require_once __DIR__ . '/http.php';

// 커넥터 기본 소스 URL. 커넥터 레코드의 url 이 비어 있으면 이 값을 쓴다(run/미리보기 공용).
const VG_EPSS_URL = 'https://epss.cyentia.com/epss_scores-current.csv.gz';

/** EPSS gzip CSV 를 받아 평문으로 돌려준다(run·미리보기 공용). */
function vg_epss_fetch(string $url): string {
    $r = vg_http_raw('GET', $url, [], 120);
    if ($r['code'] !== 200 || $r['body'] === '') {
        throw new RuntimeException("EPSS fetch 실패 (HTTP {$r['code']}) {$r['error']}");
    }
    $txt = @gzdecode($r['body']);
    if ($txt === false) {
        throw new RuntimeException('EPSS gzip 해제 실패');
    }
    return $txt;
}

// FIRST EPSS — CVE별 악용확률(0~1) + 백분위. gzip CSV 를 받아 보유 CVE 만 갱신.
final class VgEpssConnector implements VgFeedConnector {
    public function run(PDO $pdo, array $conn): array {
        $txt = vg_epss_fetch(vg_conn_url($conn, VG_EPSS_URL));
        // 우리가 보유한 CVE 만 갱신(전체 34만건 삽입 안 함)
        $have = [];
        foreach ($pdo->query('SELECT cve_id FROM tb_cve')->fetchAll(PDO::FETCH_COLUMN) as $c) {
            $have[strtoupper((string) $c)] = true;
        }
        if (!$have) {
            return ['fetched' => 0, 'upserted' => 0];
        }
        $upd = $pdo->prepare('UPDATE tb_cve SET epss = ?, epss_percentile = ? WHERE cve_id = ?');
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

    // 미리보기: 34만 행 CSV 라 앞쪽 10행만 보여준다(점수 내림차순 정렬본이라 상위권이 나온다).
    public function preview(PDO $pdo, array $conn): array {
        $txt = vg_epss_fetch(vg_conn_url($conn, VG_EPSS_URL));
        $out = []; $rows = 0;
        foreach (explode("\n", $txt) as $line) {
            if ($line === '' || $line[0] === '#' || strncmp($line, 'cve,', 4) === 0) { continue; }
            $f = explode(',', $line);
            if (count($f) < 3) { continue; }
            $rows++;
            if (count($out) < 10) {
                $out[] = ['cve' => strtoupper($f[0]), 'epss' => (float) $f[1], 'percentile' => (float) $f[2]];
            }
        }
        return ['ok' => true, 'count' => $rows, 'note' => '보유 중인 CVE 만 갱신된다(전체 삽입 안 함)', 'sample' => $out];
    }
}
