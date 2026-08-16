<?php
declare(strict_types=1);

/**
 * matcher/catalog.php — CVE 카탈로그 적재(KEV 집합 + 이 스캔의 패키지에 걸린 영향 인덱스).
 *   **이름 단위 캐시가 이 파일의 핵심**이다 — 재매칭이 같은 패키지를 스캔마다 다시 보므로
 *   static 캐시가 그대로 남아 있어야 한다. 캐시를 비우는 경로(reset)를 스케줄러·sync·
 *   커넥터가 직접 부르므로(vg_load_cve_catalog($pdo, [], true)) 시그니처는 고정이다.
 *
 * matcher.php 가 require 한다.
 */

if (!function_exists('vg_load_cve_catalog')) {
    /**
     * CVE 카탈로그: KEV 등재 집합 + **이 스캔에 실제로 있는 패키지**의 영향 인덱스.
     *
     * 예전엔 tb_cve_affected_package 를 통째로 읽었다. RHEL OVAL 이 들어오며 그 표가 50만 행이
     * 되자 두 번 터졌다 — 스캔마다 다시 읽어 30초 실행제한(재매칭 사망), 그리고 전부 배열에 올려
     * 512MB 메모리 초과(운영에서 실제로 죽었다). 스캔 하나가 보는 패키지는 수백 개뿐인데
     * 수십만 행을 들고 있을 이유가 없다.
     *
     * 그래서 **필요한 패키지 이름만** 질의하고, 이름 단위로 캐시한다(재매칭은 같은 패키지를
     * 스캔마다 다시 보므로 캐시 적중률이 높다). KEV 는 작아서 통째로 캐시한다.
     */
    function vg_load_cve_catalog(PDO $pdo, array $pkgNames, bool $reset = false): array {
        static $kev = null;
        static $cache = [];        // package name => cached catalog rows, including empty results

        if ($reset) { $kev = null; $cache = []; return ['kev' => [], 'affected' => []]; }

        if ($kev === null) {
            $kev = [];
            foreach ($pdo->query('SELECT cve_id FROM tb_kev_catalog')->fetchAll() as $r) {
                $kev[$r['cve_id']] = true;
            }
        }

        $need = [];
        foreach ($pkgNames as $n) {
            $n = (string) $n;
            if ($n !== '' && !array_key_exists($n, $cache)) { $need[$n] = true; }
        }
        $need = array_keys($need);

        // 영향 패키지 인덱스: package_name => [ {cve, eco, fixed, cvss} … ]
        //   ecosystem/fixed_version 을 함께 읽는다. 예전엔 이름만 보고 CVE 를 매달아
        //   (1) 다른 배포판의 행이 붙고 (2) 이미 상위 버전인데도 취약으로 떴다.
        foreach (array_chunk($need, 500) as $chunk) {
            foreach ($chunk as $n) { $cache[$n] = []; }   // 결과 없음도 기록(재질의 방지)
            $in = implode(',', array_fill(0, count($chunk), '?'));
            $st = $pdo->prepare(
                "SELECT a.cve_id, a.package_name, a.ecosystem, a.fixed_version, c.cvss
                   FROM tb_cve_affected_package a
                   LEFT JOIN tb_cve c ON c.cve_id = a.cve_id
                  WHERE a.package_name IN ($in)"
            );
            $st->execute($chunk);
            foreach ($st->fetchAll() as $r) {
                $cache[$r['package_name']][] = [
                    'cve'   => $r['cve_id'],
                    'eco'   => $r['ecosystem'],
                    'fixed' => $r['fixed_version'],
                    'cvss'  => $r['cvss'],
                ];
            }
        }

        $affected = [];
        foreach ($pkgNames as $n) {
            $n = (string) $n;
            if ($n !== '' && !empty($cache[$n])) { $affected[$n] = $cache[$n]; }
        }
        return ['kev' => $kev, 'affected' => $affected];
    }
}
