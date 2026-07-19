<?php
declare(strict_types=1);

/**
 * package_summary.php — packages.php 용 사전집계 요약(tb_package_summary)을 재구성한다.
 *   원본 tb_cve_affected_packages(92만 행)를 (package_name,ecosystem)로 집계해 화면이
 *   매 로드마다 전체를 재집계하지 않고 이 요약 테이블만 읽게 한다. OSV 커넥터 실행
 *   직후(재매칭·조치안 보강 뒤)에만 호출된다.
 */

require_once __DIR__ . '/db.php';

/**
 * packages.php 용 사전집계 요약(tb_package_summary)을 통째로 다시 만든다.
 *   원본 tb_cve_affected_packages(92만 행)를 (package_name,ecosystem)로 집계한 결과를 담아,
 *   화면이 매 로드마다 전체를 재집계(~8초)하지 않고 이 40K행만 읽게 한다.
 *   affected_packages 는 OSV 커넥터만 쓰므로 OSV 실행 직후(재매칭·조치안 보강 뒤)에만 부른다.
 *
 * 트랜잭션 안에서 DELETE→INSERT 한다: InnoDB MVCC 로 읽는 쪽은 커밋 전까지 옛 요약을 그대로
 * 보다 커밋 순간 새 값으로 전환된다(빈 창이 없다). OSV 실행 뒤라 affected_packages 로의 동시
 * 쓰기도 없다.
 */
/**
 * 이 패키지를 전부 고치려면 올려야 할 버전 = 조치 버전 중 가장 높은 것.
 *
 * SQL MAX() 는 사전순이라 '3.0.13-0ubuntu3.9' > '3.0.13-0ubuntu3.11' 로 뒤집힌다.
 * strnatcmp 는 숫자 덩어리를 수로 비교해 11 > 9 를 지킨다. epoch('2:9.1...')도 앞자리
 * 숫자로 먼저 비교돼 일관된다. dpkg 완전 호환은 아니지만 표시용으로 충분하다.
 */
if (!function_exists('vg_pkg_max_fixed')) {
    function vg_pkg_max_fixed(array $versions): ?string {
        $max = null;
        foreach ($versions as $v) {
            if ($v === null || $v === '') { continue; }
            if ($max === null || strnatcmp($v, $max) > 0) { $max = $v; }
        }
        return $max;
    }
}

if (!function_exists('vg_rebuild_package_summary')) {
    function vg_rebuild_package_summary(PDO $pdo): void {
        vg_with_tx($pdo, function () use ($pdo) {
            $pdo->exec('DELETE FROM tb_package_summary');
            $pdo->exec(
                "INSERT INTO tb_package_summary (package_name, ecosystem, cve_cnt, max_epss, fix_cnt)
                 SELECT a.package_name, a.ecosystem,
                        COUNT(DISTINCT a.cve_id), MAX(c.epss), SUM(a.fixed_version IS NOT NULL)
                   FROM tb_cve_affected_packages a
                   LEFT JOIN tb_cves c ON c.cve_id = a.cve_id AND c.is_deleted = 0
                  WHERE a.is_deleted = 0
                  GROUP BY a.package_name, a.ecosystem"
            );

            // 조치 버전 최댓값은 자연순 비교가 필요해 SQL MAX() 로 못 구한다 — PHP 에서 계산해
            //   별도로 갱신한다. DISTINCT 로 (패키지,배포판,조치버전) 조합만 읽어 92만 원본 행보다
            //   훨씬 적은 수만 순회한다.
            $fx = $pdo->query(
                "SELECT DISTINCT package_name, ecosystem, fixed_version
                   FROM tb_cve_affected_packages
                  WHERE is_deleted = 0 AND fixed_version IS NOT NULL"
            );
            $byPkg = [];
            foreach ($fx as $row) {
                $byPkg[$row['package_name']][$row['ecosystem']][] = $row['fixed_version'];
            }
            if ($byPkg) {
                $upd = $pdo->prepare(
                    'UPDATE tb_package_summary SET max_fixed = ? WHERE package_name = ? AND ecosystem = ?'
                );
                foreach ($byPkg as $name => $byEco) {
                    foreach ($byEco as $eco => $versions) {
                        $upd->execute([vg_pkg_max_fixed($versions), $name, $eco]);
                    }
                }
            }
        });
    }
}
