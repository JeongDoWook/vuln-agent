<?php
declare(strict_types=1);

/**
 * matcher.php — 수집된 packages + exposures 를 CVE 와 조인해 우선순위를 매긴다.
 *   규칙(CONTEXT §7): 외부노출(EXTERNAL) + 로드됨 + KEV = CRITICAL.
 *   설치만 됨 → LOW, 로드·내부 → MEDIUM, 외부노출 → HIGH, +KEV 시 한 단계 상향.
 *   각 판정에 "왜"(근거)를 남긴다(설명가능성).
 *
 *   이 파일이 갖는 것은 **스캔 1건의 실행 흐름**뿐이다(vg_match_scan): 신호·카탈로그·근거를
 *   순서대로 불러 판정 결과를 배열로 모으고 → 지문을 비교해 → 달라졌을 때만 통째 재작성한다.
 *   판정 자체는 server/src/matcher/ 아래로 나눠 뒀다(아래 require 블록의 주석 참고).
 *   외부 호출부(scheduler·sync·connectors·ingest·host)는 예전처럼 이 파일만 require 하면 된다.
 */

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/vercmp.php';   // vg_ver_cmp — dpkg/rpm 버전 비교
require_once __DIR__ . '/distro.php';   // vg_osv_ecosystem — 수집과 동일 기준
require_once __DIR__ . '/debtracker.php';   // vg_debtracker_evidence — 데비안 백포트 판정(중앙)
require_once __DIR__ . '/vendorerrata.php'; // vg_vendor_errata_evidence — RHEL 계열 백포트 판정(중앙)
require_once __DIR__ . '/ubuntuoval.php';   // vg_ubuntu_evidence — 우분투 벤더 판정(중앙)
require_once __DIR__ . '/kernelcve.php';
require_once __DIR__ . '/finding_evidence.php'; // 구조화 판정 근거 생성·저장
require_once __DIR__ . '/package_summary.php'; // vg_rebuild_package_summary — 하위호환 재노출(신규 호출부는 직접 require)

// 재매칭 결과 지문의 **알고리즘 버전**. 판정 로직이나 저장 컬럼을 바꾸면 이 값을 올린다.
//   안 올리면 입력(피드·수집물)이 그대로인 스캔은 지문도 그대로라 "결과가 같다"고 판단해
//   **새 코드로 재계산한 결과가 영영 저장되지 않는다.** 올리면 전 스캔이 한 번씩 다시 쓰인다.
//   2 — changelog 백포트 억제가 서드파티 저장소 패키지에도 적용된다(서드파티 가드에서 분리).
if (!defined('VG_MATCH_FP_VERSION')) { define('VG_MATCH_FP_VERSION', 2); }

// 책임 단위로 나눈 판정 층(순수 이동 — 함수 이름·시그니처·본문 불변).
//   순서가 의존 방향이다: classify(등급) → signals(원시 신호) → catalog(CVE) → evidence(억제 근거)
//   → candidates(패키지 단위 후보·맥락) → decide(억제 게이트). 아래 vg_match_scan 이 이 순서로 부른다.
//   각 파일은 자기 첫 함수로 function_exists 가드를 갖는다(원본 가드의 보호를 파일마다 유지).
require_once __DIR__ . '/matcher/classify.php';   // vg_scope_rank · vg_classify
require_once __DIR__ . '/matcher/signals.php';    // vg_load_scan_signals
require_once __DIR__ . '/matcher/catalog.php';    // vg_load_cve_catalog
require_once __DIR__ . '/matcher/evidence.php';   // vg_load_suppression_evidence · vg_match_load_kernel_context
require_once __DIR__ . '/matcher/candidates.php'; // vg_match_pkg_candidates · vg_match_pkg_context
require_once __DIR__ . '/matcher/decide.php';     // vg_match_decide_cve

if (!function_exists('vg_match_fingerprint')) {
    /**
     * 판정 결과의 지문. **같은 결과면 같은 지문**이어야 한다(쓰기를 건너뛰는 근거).
     *   · 행이 담기는 순서에 흔들리지 않게 유니크키(container_id|cve_id|package_name)로 정렬한다.
     *   · 스칼라는 전부 문자열로 통일한다 — cvss 는 float 이라 표현이 흔들릴 수 있다.
     *   · feed_updated_at 은 NOW() 라 매 실행 달라지므로 넣지 않는다(저장만 되고 읽는 코드가 없다).
     *   · 알고리즘 버전(VG_MATCH_FP_VERSION)을 섞는다 — 그 상수 옆 주석 참고.
     */
    function vg_match_fingerprint(array $findRows, array $suppRows): string {
        $norm = function (array $rows): array {
            $out = [];
            foreach ($rows as $r) {
                $out[$r['key']] = [
                    array_map(function ($v) { return $v === null ? null : (string) $v; }, $r['row']),
                    $r['evidence'] ?? null,
                ];
            }
            ksort($out);
            return $out;
        };
        return sha1((string) json_encode(
            ['v' => VG_MATCH_FP_VERSION, 'f' => $norm($findRows), 's' => $norm($suppRows)],
            JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
        ));
    }

    /**
     * 한 스캔에 대해 매칭 수행 → findings 재계산. 반환: 등급별 카운트.
     *   판정은 매번 전부 다시 하지만, 결과 지문이 `tb_scan.match_fingerprint` 와 같으면
     *   **한 줄도 쓰지 않는다.** 피드가 갱신돼도 특정 스캔의 판정 결과는 대부분 그대로인데,
     *   지금까지는 1비트도 안 바뀐 경우에도 findings 를 통째 삭제·재삽입해 binlog 만
     *   하루 20GB 넘게 쌓였다(운영 실측: 105G 중 76G 가 binlog).
     */
    function vg_match_scan(PDO $pdo, int $scanId): array {
        $sig = vg_load_scan_signals($pdo, $scanId);
        $scan            = $sig['scan'];
        $hostEco         = $sig['hostEco'];
        $family          = $sig['family'];
        $ctrs            = $sig['ctrs'];
        $packages        = $sig['packages'];
        $loadMap         = $sig['loadMap'];
        $procRunningPkgs = $sig['procRunningPkgs'];
        $procLoadedPkgs  = $sig['procLoadedPkgs'];

        // 카탈로그는 **이 스캔이 실제로 가진 패키지**만 읽는다(이름 + 소스패키지 둘 다 조회한다).
        //   전부 읽으면 RHEL OVAL 이 들어온 뒤 50만 행이라 메모리가 터진다(운영에서 실제로 죽었다).
        $pkgNames = [];
        foreach ($packages as $pp) {
            $pkgNames[(string) $pp['name']] = true;
            if (!empty($pp['source_pkg'])) { $pkgNames[(string) $pp['source_pkg']] = true; }
        }
        $catalog  = vg_load_cve_catalog($pdo, array_keys($pkgNames));
        $kev      = $catalog['kev'];
        $affected = $catalog['affected'];

        // backport·debsecan·useDebsecan·trackerLabel·errata·vendorErrata 는 개별로 뽑지 않고
        //   $sup 를 통째로 vg_match_decide_cve() 에 넘긴다(그 함수의 억제 겹 ②~④가 쓴다).
        //   stale·unfixed 만 여기서 따로 쓴다(패키지 단위 헬퍼 vg_match_pkg_context/candidates 의 인자).
        $sup     = vg_load_suppression_evidence($pdo, $scanId, $scan['os_id'] ?? null, $scan['os_version'] ?? null);
        $stale   = $sup['stale'];
        $unfixed = $sup['unfixed'];

        // 커널 판정의 정본은 **업스트림(kernel.org CNA)** 이다 — 배포판 EVR 이 아니라 uname 버전으로 본다.
        //   라즈베리·자체빌드 커널은 배포판 트래커/OVAL 관할 밖이라 "서드파티 → 자동 판정 불가" 로
        //   전부 남았다(실측 raspberrypi5-00: LOW 2,069 중 702건이 커널 하나. 6.18 커널에 2004년 CVE 까지).
        $kernelCtx            = vg_match_load_kernel_context($pdo, $packages, $affected, $scan);
        $runningKernel        = $kernelCtx['runningKernel'];
        $runningKernelPresent = $kernelCtx['runningKernelPresent'];
        $kernelFixed          = $kernelCtx['kernelFixed'];

        // ── 1단계: 계산. 여기선 DB 에 한 줄도 쓰지 않고 결과를 배열로만 모은다.
        //   쓸지 말지는 아래 지문 비교가 정하므로, 판정과 쓰기가 붙어 있으면 안 된다.
        //   메모리: 스캔당 최대 2.5만 행(운영 실측)이라 수 MB 수준이다.
        $findRows = [];  // ['key'=>유니크키, 'row'=>tb_finding INSERT 파라미터, 'evidence'=>증거 payload]
        $suppRows = [];  // ['key'=>유니크키, 'row'=>tb_suppressed_finding INSERT 파라미터]

        // NOFIX 는 등급이 아니라 **별도 축**이다(조치 불가). CRITICAL~LOW 와 겹쳐서 센다.
        $counts = ['CRITICAL' => 0, 'HIGH' => 0, 'MEDIUM' => 0, 'LOW' => 0, 'SUPPRESSED' => 0, 'NOFIX' => 0];
        $seen = [];

        foreach ($packages as $p) {
            $mgr   = (string) ($p['manager'] ?? 'dpkg');
            $ctrId = (int) ($p['container_id'] ?? 0);
            $ctr   = $ctrId > 0 ? ($ctrs[$ctrId] ?? null) : null;

            $cands = vg_match_pkg_candidates($p, $ctr, $mgr, $ctrId, $hostEco, $family, $affected, $unfixed);

            if (!$cands) {
                continue;
            }

            $ctx = vg_match_pkg_context(
                $p, $ctr, $ctrId, $mgr, $scan, $runningKernel, $runningKernelPresent,
                $loadMap, $procRunningPkgs, $procLoadedPkgs, $stale
            );
            $staleEv          = $ctx['staleEv'];
            $kernelPending    = $ctx['kernelPending'];
            $exposed          = $ctx['exposed'];
            $loaded           = $ctx['loaded'];
            $scope            = $ctx['scope'];

            foreach ($cands as $cveId => $cand) {
                // 컨테이너별로 따로 센다 — 호스트의 openssl 과 컨테이너의 openssl 은 별개 취약점이다.
                $key = $ctrId . '|' . $cveId . '|' . $p['name'];
                if (isset($seen[$key])) { continue; }
                $seen[$key] = true;

                $decision = vg_match_decide_cve($cveId, $cand, $p, $mgr, $ctr, $ctrId, $scan, $ctx, $kev, $kernelFixed, $sup);

                if ($decision['suppress']) {
                    // 억제(백포트)된 건은 tb_finding 이 아니라 tb_suppressed_finding 으로 — 위험 집계에서 자동 제외.
                    $suppRows[] = ['key' => $key, 'row' => [
                        $scanId, $ctrId, $cveId, $p['name'], $p['version'],
                        $decision['inKev'] ? 1 : 0, $decision['cvss'], $decision['sev'], $decision['reason'],
                    ]];
                    $counts['SUPPRESSED']++;
                    continue;
                }

                if ($decision['noFix'] !== '') { $counts['NOFIX']++; }
                $counts[$decision['sev']]++;
                $findRows[] = [
                    'key' => $key,
                    'row' => [
                        $scanId, $ctrId, $cveId, $p['name'], $p['version'],
                        $loaded ? 1 : 0, $exposed ? 1 : 0, $scope, $decision['status'], $decision['inKev'] ? 1 : 0,
                        ($staleEv !== null || $kernelPending) ? 1 : 0, $decision['noFix'] !== '' ? 1 : 0,
                        $decision['cvss'], $decision['sev'], $decision['why'],
                    ],
                    'evidence' => vg_build_finding_evidence($scan, $p, $mgr, $ctr, $cand, $ctx, $decision),
                ];
            }
        }

        // ── 2단계: 지문 비교. 결과가 그대로면 DELETE·INSERT·증거 기록을 전부 건너뛴다
        //   (트랜잭션도 열지 않는다).
        //   지문이 NULL(최초·신규 스캔)이면 당연히 다르므로 항상 쓴다.
        $fingerprint = vg_match_fingerprint($findRows, $suppRows);
        $fpSt = $pdo->prepare('SELECT match_fingerprint FROM tb_scan WHERE scan_id = ?');
        $fpSt->execute([$scanId]);
        $prevFp = $fpSt->fetchColumn();
        if (is_string($prevFp) && hash_equals($prevFp, $fingerprint)) {
            return $counts;
        }

        // ── 3단계: 쓰기. 결과가 달라졌으므로 **통째 재작성**한다(행 단위 diff 로 하지 않는다 —
        //   비교 컬럼을 하나 빠뜨리면 stale 값이 영구히 남는다).
        //
        // 재계산은 원자적으로(자체 트랜잭션). 스케줄러 사이드카와 동시 재매칭 시
        // DELETE↔INSERT 경합으로 유니크키 충돌이 나던 것을 방지.
        //
        // 이 트랜잭션만 READ COMMITTED 로 내린다 — 기본 REPEATABLE READ 의 **갭락**이 동시 재매칭을
        //   데드락시킨다(1213). 실측한 사이클(SHOW ENGINE INNODB STATUS):
        //     아래 `DELETE ... WHERE scan_id = ?` 는 유니크키(uq_find·uq_supp) 선두가 scan_id 라
        //     그 범위를 스캔하는데, 새 스캔은 scan_id 가 가장 커서 스캔이 인덱스 끝까지 간다
        //     → **supremum 갭에 X 갭락**. 갭락끼리는 호환이라 동시 스캔 둘이 **둘 다** 잡는다.
        //     이어서 각자 자기 행을 INSERT 하면 그 갭에 **insert intention** 이 필요한데 이건
        //     상대의 갭락과 충돌 → 서로 대기 → 데드락. 행이 겹치지 않아도(스캔이 달라도) 걸린다.
        //   READ COMMITTED 는 이 스캔에 갭락을 걸지 않으므로 원인 자체가 사라진다.
        //   락 순서 통일로는 못 고친다 — 둘이 **같은 순서로 같은 갭**을 잡다 나는 사고다.
        // 정합성: 이 트랜잭션 안의 읽기는 **방금 자기가 쓴 행을 도로 보는 것뿐**이다 —
        //   finding id 재조회(SELECT finding_id FROM tb_finding)가 그것이고,
        //   판정 근거($packages·$affected 등)는 전부 이 시점 이전에 읽어 뒀다.
        //   남이 쓴 데이터를 다시 읽는 게 없으니 비반복읽기·팬텀이 성립할 여지가 없고,
        //   원자성은 격리수준과 무관하다.
        // 범위: SET TRANSACTION(SESSION/GLOBAL 없이)은 **다음 트랜잭션 하나에만** 걸린다 —
        //   vg_with_tx 가 새로 트랜잭션을 열 때만 적용된다(중첩 호출이면 참여만 하고 안 건다).
        return vg_with_tx($pdo, function () use ($pdo, $scanId, $findRows, $suppRows, $counts, $fingerprint) {

        // 기존 findings 삭제 후 재삽입. INSERT 는 멱등(동시성 대비).
        $pdo->prepare('DELETE FROM tb_finding WHERE scan_id = ?')->execute([$scanId]);
        $ins = $pdo->prepare(
            'INSERT INTO tb_finding
               (scan_id, container_id, cve_id, package_name, installed_version, loaded, exposed,
                exposure_scope, runtime_status, in_kev, needs_restart, no_fix, cvss, severity, rationale)
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
             ON DUPLICATE KEY UPDATE
               installed_version=VALUES(installed_version), loaded=VALUES(loaded),
               exposed=VALUES(exposed), exposure_scope=VALUES(exposure_scope),
               runtime_status=VALUES(runtime_status), in_kev=VALUES(in_kev),
               needs_restart=VALUES(needs_restart), no_fix=VALUES(no_fix), cvss=VALUES(cvss),
               severity=VALUES(severity), rationale=VALUES(rationale)'
        );
        $findId = $pdo->prepare('SELECT finding_id FROM tb_finding WHERE scan_id=? AND container_id=? AND cve_id=? AND package_name=?');

        // 억제(백포트)된 건은 tb_finding 이 아니라 여기로 — 위험 집계에서 자동 제외.
        $pdo->prepare('DELETE FROM tb_suppressed_finding WHERE scan_id = ?')->execute([$scanId]);
        $insSupp = $pdo->prepare(
            'INSERT INTO tb_suppressed_finding
               (scan_id, container_id, cve_id, package_name, installed_version, in_kev, cvss, base_severity, suppress_reason)
             VALUES (?,?,?,?,?,?,?,?,?)
             ON DUPLICATE KEY UPDATE
               installed_version=VALUES(installed_version), in_kev=VALUES(in_kev), cvss=VALUES(cvss),
               base_severity=VALUES(base_severity), suppress_reason=VALUES(suppress_reason)'
        );

        foreach ($suppRows as $r) {
            $insSupp->execute($r['row']);
        }

        foreach ($findRows as $r) {
            $ins->execute($r['row']);
            // 증거는 finding 의 id 를 참조하므로 삽입 뒤에야 쓸 수 있다.
            //   행 앞 4개(scan_id, container_id, cve_id, package_name)가 곧 유니크키다.
            $findId->execute(array_slice($r['row'], 0, 4));
            $findingId = (int) $findId->fetchColumn();
            if ($findingId > 0) {
                vg_store_finding_evidence($pdo, $findingId, $r['evidence']);
            }
        }

            // 지문은 **같은 트랜잭션 안에서** 갱신한다 — 밖에서 갱신하면 롤백 시
            //   "안 썼는데 썼다고 기록"이 남아 이후 재매칭이 영영 건너뛴다.
            $pdo->prepare('UPDATE tb_scan SET match_fingerprint = ? WHERE scan_id = ?')->execute([$fingerprint, $scanId]);
            return $counts;
        }, 'READ COMMITTED');
    }

    /**
     * 재매칭 대상 스캔 id — 호스트별 최신 N건(기본 2). changes.php 가 최신+직전을 비교하므로 2가 하한.
     *
     * 왜 전체가 아닌가: vg_match_scan() 은 스캔 1건마다 tb_finding·tb_suppressed_finding 을
     *   DELETE+INSERT 로 통째 재작성한다. 피드 수집마다 전체 스캔(운영 268건)을 돌리면
     *   binlog 가 하루 23GB 씩 불어난다(운영 실측 2026-07-26 — 디스크 105G 중 76G 가 binlog).
     *   옛 스캔의 findings 는 어느 화면도 최신 기준으로 읽지 않으므로 다시 계산할 이유가 없다.
     * 왜 1건이 아니라 2건인가: changes.php 의 변화 추적이 호스트마다 **최신 + 직전** 스캔의
     *   findings 를 비교한다. 최신 1건만 갱신하면 직전 스캔이 옛 피드 기준으로 남아
     *   "피드가 늘어서 생긴 차이"가 신규 취약점으로 오표시된다.
     *
     * 삭제된 스캔·호스트는 제외 — vg_latest_scan_subq()(db.php)·index.php 와 같은 기준.
     * @return list<int> 스캔 id 내림차순(최신부터)
     */
    function vg_rematch_scan_ids(PDO $pdo, int $perHost = 2): array {
        $st = $pdo->prepare(
            'SELECT t.scan_id FROM (
                 SELECT s.scan_id, ROW_NUMBER() OVER (PARTITION BY s.host_id ORDER BY s.scan_id DESC) AS rn
                   FROM tb_scan s
                   JOIN tb_host h ON h.host_id = s.host_id AND h.is_deleted = 0
                  WHERE s.is_deleted = 0
             ) t
             WHERE t.rn <= ?
             ORDER BY t.scan_id DESC'
        );
        $st->bindValue(1, max(1, $perHost), PDO::PARAM_INT);
        $st->execute();
        return array_map('intval', $st->fetchAll(PDO::FETCH_COLUMN));
    }
}
