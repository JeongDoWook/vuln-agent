<?php
declare(strict_types=1);

/**
 * license_summary.php — language-packages.php 용 사전집계(tb_package_license_summary)를
 *   재구성한다. package_summary.php(tb_package_summary)와 같은 패턴: 매 로드마다 tb_package를
 *   재집계하지 않고 이 요약 테이블만 읽게 한다. OSV 커넥터 실행 직후에만 호출된다.
 *   tb_package 는 스캔마다 누적되는 원본이라, 여기 무인덱스 필터/KPI 를 직접 걸면
 *   packages 40초 사고(사전집계 없이 92만 행 재집계)가 재현된다 — 반드시 이 요약을 거친다.
 */

require_once __DIR__ . '/db.php';            // vg_with_tx, vg_latest_scan_subq
require_once __DIR__ . '/license_risk.php';  // vg_license_classify

// 언어 패키지 생태계 — OS 패키지(rpm/dpkg/apk) 라이선스는 이번 라운드 scope_out.
const VG_LANG_MANAGERS = ['pip', 'npm', 'gem', 'composer', 'maven', 'nuget', 'cargo', 'go'];

if (!function_exists('vg_rebuild_license_summary')) {
    /**
     * tb_package_license_summary 를 통째로 다시 만든다(DELETE→INSERT, 트랜잭션 안).
     *   각 호스트의 "최신 스캔"만 집계 대상이다(vg_latest_scan_subq) — 과거 스캔까지 다 더하면
     *   같은 패키지가 스캔 횟수만큼 중복 집계된다. 컨테이너 패키지도 호스트와 같은 scan_id 를
     *   쓰므로 별도 조인 없이 함께 잡힌다.
     */
    function vg_rebuild_license_summary(PDO $pdo): void {
        vg_with_tx($pdo, function () use ($pdo) {
            $pdo->exec('DELETE FROM tb_package_license_summary');

            // package_summary.php 와 같은 패턴: 벌크 INSERT...SELECT 로 만들고, risk 는 자연어
            // 판정(vg_license_classify, PHP 순수함수)이 필요해 distinct license 값만 순회 UPDATE
            // 한다 — 예전엔 GROUP BY 결과 행마다 PHP 루프로 단건 INSERT 를 돌려 웹 요청 경로에서
            // 느렸다. tb_host.is_deleted=0 도 걸어야 한다 — 화면 목록(language-packages.php)엔
            // 있는데 여기 없으면 삭제된 호스트의 패키지가 KPI 집계에 섞여 들어간다.
            $mgrPlaceholders = implode(',', array_fill(0, count(VG_LANG_MANAGERS), '?'));
            $pdo->prepare(
                "INSERT INTO tb_package_license_summary (manager, name, license, risk, pkg_count)
                 SELECT p.manager, p.name, p.license, 'unknown', COUNT(*)
                   FROM tb_package p
                   JOIN " . vg_latest_scan_subq() . " latest ON latest.mid = p.scan_id
                   JOIN tb_host h ON h.host_id = latest.host_id
                  WHERE p.is_deleted = 0 AND h.is_deleted = 0
                    AND p.license IS NOT NULL AND p.license <> ''
                    AND p.manager IN ($mgrPlaceholders)
                  GROUP BY p.manager, p.name, p.license"
            )->execute(VG_LANG_MANAGERS);

            $licenses = $pdo->query('SELECT DISTINCT license FROM tb_package_license_summary')
                ->fetchAll(PDO::FETCH_COLUMN);
            if ($licenses) {
                $upd = $pdo->prepare('UPDATE tb_package_license_summary SET risk = ? WHERE license = ?');
                foreach ($licenses as $license) {
                    $upd->execute([vg_license_classify($license), $license]);
                }
            }
        });
    }
}
