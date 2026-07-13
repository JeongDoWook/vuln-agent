<?php
declare(strict_types=1);

/**
 * feeds/kev.php — CISA KEV 커넥터. 실제 악용 취약점 카탈로그(JSON, 무인증).
 *   tb_kev_catalog + tb_cves 로 upsert. 미리보기는 앞 10건을 그대로 보여준다.
 */

require_once __DIR__ . '/http.php';
require_once __DIR__ . '/upsert.php';

// 커넥터 기본 소스 URL. 커넥터 레코드의 url 이 비어 있으면 이 값을 쓴다(run/미리보기 공용).
const VG_KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

// CISA KEV — 실제 악용 취약점 카탈로그(JSON, 무인증). kev_catalog + cves.
final class VgKevConnector implements VgFeedConnector {
    public function run(PDO $pdo, array $conn): array {
        $url = vg_conn_url($conn, VG_KEV_URL);
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
            // knownRansomwareCampaignUse 는 "Known" / "Unknown" 문자열로 온다(불리언이 아니다).
            $ransom = strcasecmp((string) ($v['knownRansomwareCampaignUse'] ?? ''), 'Known') === 0;
            vg_upsert_kev($pdo, $id, $v['dateAdded'] ?? null, mb_substr($note, 0, VG_TEXT_MAX),
                $v['dueDate'] ?? null, $ransom);
            vg_upsert_cve($pdo, $id, mb_substr((string) ($v['shortDescription'] ?? ''), 0, VG_TEXT_MAX), null, null);
            $up++;
        }
        $pdo->commit();
        return ['fetched' => count($vulns), 'upserted' => $up];
    }

    // 미리보기: 소스에서 앞 10건을 그대로 보여준다(저장 안 함). run 과 같은 URL 을 본다.
    public function preview(PDO $pdo, array $conn): array {
        $r = vg_http_json('GET', vg_conn_url($conn, VG_KEV_URL));
        if ($r['code'] !== 200 || !isset($r['json']['vulnerabilities'])) {
            return ['ok' => false, 'error' => "HTTP {$r['code']} {$r['error']}"];
        }
        $all = $r['json']['vulnerabilities'];
        return ['ok' => true, 'count' => count($all), 'sample' => array_slice($all, 0, 10)];
    }
}
