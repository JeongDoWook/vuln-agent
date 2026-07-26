<?php
declare(strict_types=1);

/**
 * package_summary.php — packages.php 용 사전집계 요약(tb_package_summary)을 재구성한다.
 *   원본 tb_cve_affected_package(92만 행)를 (package_name,ecosystem)로 집계해 화면이
 *   매 로드마다 전체를 재집계하지 않고 이 요약 테이블만 읽게 한다. OSV 커넥터 실행
 *   직후(재매칭·조치안 보강 뒤)에만 호출된다.
 */

require_once __DIR__ . '/db.php'; // vg_with_tx — 트랜잭션 래퍼

if (!function_exists('vg_pkg_max_fixed')) {
    /**
     * 이 패키지를 전부 고치려면 올려야 할 버전 = 조치 버전 중 가장 높은 것.
     *
     * SQL MAX() 는 사전순이라 '3.0.13-0ubuntu3.9' > '3.0.13-0ubuntu3.11' 로 뒤집힌다.
     * strnatcmp 는 숫자 덩어리를 수로 비교해 11 > 9 를 지킨다. epoch('2:9.1...')도 앞자리
     * 숫자로 먼저 비교돼 일관된다. dpkg 완전 호환은 아니지만 표시용으로 충분하다.
     */
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
    /**
     * tb_package_summary 를 통째로 다시 만든다(DELETE→INSERT, 트랜잭션 안).
     *
     * InnoDB MVCC 로 읽는 쪽은 커밋 전까지 옛 요약을 그대로 보다 커밋 순간 새 값으로 전환된다
     * (빈 창이 없다). OSV 실행 직후에만 불리므로 affected_packages 로의 동시 쓰기도 없다.
     */
    function vg_rebuild_package_summary(PDO $pdo): void {
        vg_with_tx($pdo, function () use ($pdo) {
            $pdo->exec('DELETE FROM tb_package_summary');
            $pdo->exec(
                "INSERT INTO tb_package_summary (package_name, ecosystem, cve_cnt, max_epss, fix_cnt)
                 SELECT a.package_name, a.ecosystem,
                        COUNT(DISTINCT a.cve_id), MAX(c.epss), SUM(a.fixed_version IS NOT NULL)
                   FROM tb_cve_affected_package a
                   LEFT JOIN tb_cve c ON c.cve_id = a.cve_id AND c.is_deleted = 0
                  WHERE a.is_deleted = 0
                  GROUP BY a.package_name, a.ecosystem"
            );

            // 조치 버전 최댓값은 자연순 비교가 필요해 SQL MAX() 로 못 구한다 — PHP 에서 계산해
            //   별도로 갱신한다. DISTINCT 로 (패키지,배포판,조치버전) 조합만 읽어 92만 원본 행보다
            //   훨씬 적은 수만 순회한다.
            $fx = $pdo->query(
                "SELECT DISTINCT package_name, ecosystem, fixed_version
                   FROM tb_cve_affected_package
                  WHERE is_deleted = 0 AND fixed_version IS NOT NULL"
            );
            $byPkg = [];
            foreach ($fx as $row) {
                // ecosystem 은 스키마상 NOT NULL DEFAULT '' 라(02-matcher.sql) PHP 배열 키로
                //   안전하다 — NULL 이 ''로 강제변환돼 아래 UPDATE 의 WHERE ecosystem = ? 와
                //   어긋나는 경우가 없다.
                $byPkg[$row['package_name']][$row['ecosystem']][] = $row['fixed_version'];
            }
            if ($byPkg) {
                $upd = $pdo->prepare(
                    'UPDATE tb_package_summary SET max_fixed = ? WHERE package_name = ? AND ecosystem = ?'
                );
                foreach ($byPkg as $name => $byEco) {
                    foreach ($byEco as $eco => $versions) {
                        // PHP 는 '2048' 같은 순수 숫자 문자열을 배열 키에서 int 로 강제변환한다
                        //   (패키지명 '2048' 실존) — 그대로 바인딩하면 varchar 비교가 암묵 형변환을
                        //   타 PK 인덱스를 못 쓸 수 있어 명시적으로 문자열로 되돌린다.
                        $upd->execute([vg_pkg_max_fixed($versions), (string) $name, (string) $eco]);
                    }
                }
            }
        });
    }
}
