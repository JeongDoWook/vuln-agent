<?php
declare(strict_types=1);

/**
 * ingest_store.php — ingest.php 가 파싱한 에이전트 페이로드를 중앙 DB 에 저장한다.
 *   호스트/스캔 upsert, 패키지·노출·컨테이너·changelog 등 벌크 INSERT, 변경이력(pkg_changes)
 *   계산까지 하나의 트랜잭션으로 묶는다. 인증·파싱·응답 조립은 ingest.php 에 남는다.
 *   트랜잭션의 시작(beginTransaction)과 끝(commit)만 갖고, 실패 시 롤백/오류응답은
 *   호출자(ingest.php)의 책임이다 — 예외를 그대로 위로 던진다.
 *
 *   이 파일이 갖는 것은 **저장 1회의 실행 흐름**뿐이다: 트랜잭션 경계와 스트림 실행 순서.
 *   실제 SQL 은 수집 스트림별로 server/src/ingest/store/ 아래에 나눠 뒀다(아래 require 블록).
 *   호출부(ingest.php)는 예전처럼 이 파일만 require 하면 된다.
 *
 *   ⚠ 트랜잭션은 여기 하나뿐이다. 스트림 함수는 절대 begin/commit 하지 않는다 —
 *     쪼개면 부분 저장이 생긴다. 실행 순서도 이 함수의 위→아래가 정본이다(선행 삽입 의존:
 *     host_id → scan_id → container_id 순으로 아래가 위에 매달린다).
 */

require_once __DIR__ . '/assetgrade_history.php';   // 최신 제안 + append-only 관찰 이력

// 수집 스트림별 저장(순수 이동 — SQL·실행 순서 불변). 서로를 부르지 않으므로 require 순서에
//   의존하지 않는다. 트랜잭션·분기·순서는 전부 아래 vg_ingest_store 가 갖는다.
require_once __DIR__ . '/ingest/store/host.php';        // 호스트 upsert · 직전 스냅샷 조회
require_once __DIR__ . '/ingest/store/scan.php';        // 스냅샷(tb_scan) · 실행 기록(scan_run·stage)
require_once __DIR__ . '/ingest/store/packages.php';    // 설치/언어 패키지 · 의존 그래프
require_once __DIR__ . '/ingest/store/containers.php';  // 컨테이너 목록 · 내부 패키지·프로세스·노출
require_once __DIR__ . '/ingest/store/runtime.php';     // 호스트 노출 · 실행 프로세스
require_once __DIR__ . '/ingest/store/evidence.php';    // changelog · 재시작 필요 · debsecan · errata
require_once __DIR__ . '/ingest/store/changes.php';     // 직전 스냅샷 대비 패키지 변경 이력
require_once __DIR__ . '/ingest/store/integrity.php';   // 패키지 무결성(두 분기 밖에서 항상 갱신)

// $host  : ['fqdn','vm','meta','sys','raw','collected_at']
// $parsed: 파싱된 각 섹션의 rows/count 및 manager·origin_map·커널 정보·content_hash
// 반환    : ['host_id','scan_id','unchanged','chg_count']
function vg_ingest_store(PDO $pdo, array $host, array $parsed): array
{
    $fqdn        = (string) $host['fqdn'];
    $vm          = $host['vm'];
    $meta        = $host['meta'];
    $sys         = $host['sys'];
    $raw         = (string) $host['raw'];
    $collectedAt = $host['collected_at'];
    $remoteIp    = $host['remote_ip'] ?? null;

    $manager   = (string) $parsed['manager'];
    $pkgRows   = $parsed['pkg_rows'];
    $pkgCount  = (int) $parsed['pkg_count'];
    $originMap = $parsed['origin_map'];

    $ctrRows     = $parsed['ctr_rows'];
    $ctrCount    = (int) $parsed['ctr_count'];
    $ctrPkgRows  = $parsed['ctr_pkg_rows'];
    $ctrPkgCount = (int) $parsed['ctr_pkg_count'];
    $ctrProcRows  = $parsed['ctr_proc_rows'];
    $ctrProcCount = (int) $parsed['ctr_proc_count'];
    $ctrExpRows   = $parsed['ctr_exp_rows'];
    $ctrExpCount  = (int) $parsed['ctr_exp_count'];

    $langRows  = $parsed['lang_rows'];
    $langCount = (int) $parsed['lang_count'];

    $expRows  = $parsed['exp_rows'];
    $expCount = (int) $parsed['exp_count'];

    $procRows  = $parsed['proc_rows'];
    $procCount = (int) $parsed['proc_count'];

    $clogRows  = $parsed['clog_rows'];
    $clogCount = (int) $parsed['clog_count'];

    $staleRows  = $parsed['stale_rows'];
    $staleCount = (int) $parsed['stale_count'];

    // 패키지 무결성 — 스냅샷 내용(content_hash)에는 안 들어간다. 같은 스냅샷을 재사용하는
    //   경우에도 최신 검사 결과로 덮어써야 하므로 아래에서 두 분기 밖에서 갱신한다
    //   (tb_collection_stage 와 같은 취급).
    $integChecked = !empty($parsed['integrity_checked']);
    $integPartial = !empty($parsed['integrity_partial']);
    $integTotal   = (int) ($parsed['integrity_total'] ?? 0);
    $integRows    = $parsed['integrity_rows'] ?? [];

    $debsecanRows  = $parsed['debsecan_rows'];
    $debsecanCount = (int) $parsed['debsecan_count'];

    $errataRows  = $parsed['errata_rows'];
    $errataCount = (int) $parsed['errata_count'];

    // 패키지 의존성 그래프 — pom.xml 최상위 직접 선언(container_id=0) + SBOM CycloneDX dependencies.
    //   [manager,name,version] 3필드.
    $pomDepRows  = $parsed['pom_dep_rows'] ?? [];
    // [cid, parent_manager|null, parent_name|null, parent_version|null, child_manager, child_name, child_version].
    $sbomDepRows = $parsed['sbom_dep_rows'] ?? [];

    $runningKernel = (string) $parsed['running_kernel'];
    $kernelLatest  = (string) $parsed['kernel_latest'];
    $kernelReboot  = $parsed['kernel_reboot'];

    $contentHash = (string) $parsed['content_hash'];
    $collectionStages = $parsed['collection_stages'] ?? [];

    $chgCount = 0;   // 이번에 기록한 패키지 변경 건수

    $pdo->beginTransaction();

    // 호스트 upsert (fqdn 유니크). LAST_INSERT_ID 트릭으로 기존 host_id 회수.
    $hostId = vg_ingest_store_host_upsert($pdo, $fqdn, $vm, $remoteIp);

    // 직전 스캔과 내용이 같으면 새 스냅샷을 만들지 않는다 — 수집시각만 갱신한다.
    //   호스트 생존 신호는 tb_host.last_seen 이 위에서 이미 갱신했으므로 잃는 정보가 없다.
    //   그 결과 스캔 목록 자체가 "변경 시점" 목록이 된다(changes.php 의 비교도 더 정확해진다).
    $prev = vg_ingest_store_prev_scan($pdo, $hostId);
    $unchanged = $prev !== null && (string) $prev['content_hash'] === $contentHash;

    if ($unchanged) {
        $scanId = (int) $prev['scan_id'];
        vg_ingest_store_scan_touch($pdo, $scanId, $collectedAt, $meta);
    } else {
        // 스캔 1행
        $scanId = vg_ingest_store_scan_insert(
            $pdo, $hostId, $collectedAt, $meta, $vm, $sys,
            $runningKernel, $kernelLatest, $kernelReboot,
            $contentHash, $pkgCount, $expCount, $raw
        );

        // 패키지 벌크
        if ($pkgCount > 0) {
            vg_ingest_store_packages($pdo, $scanId, $manager, $pkgRows, $originMap);
        }

        // 컨테이너 + 그 안의 패키지.
        //   컨테이너 목록이 먼저 들어가야 cid → container_id 지도가 생긴다(아래가 전부 이걸 쓴다).
        //   컨테이너가 하나도 없어도 예약 cid(`_host` → 0)는 항상 있다 — docker 가 없는
        //   호스트도 자기 SBOM(/opt/vuln-agent/sbom/_host.json)을 넣을 수 있어야 한다.
        $ctrIds = vg_ingest_ctr_ids_with_host(
            $ctrCount > 0 ? vg_ingest_store_containers($pdo, $scanId, $ctrRows) : []
        );   // cid => tb_container.container_id (0 = 호스트 자신)
        if ($ctrPkgCount > 0) {
            vg_ingest_store_container_packages($pdo, $scanId, $ctrPkgRows, $ctrIds);
        }

        // 컨테이너 런타임 증거 — 매처가 컨테이너 패키지에도 "로드됨/외부노출" 을 적용하는 근거.
        if ($ctrProcCount > 0) {
            vg_ingest_store_container_processes($pdo, $scanId, $ctrProcRows, $ctrIds);
        }
        if ($ctrExpCount > 0) {
            vg_ingest_store_container_exposures($pdo, $scanId, $ctrExpRows, $ctrIds);
        }

        // 패키지 의존성 그래프 벌크 — pom.xml 직접 선언(호스트) + SBOM 의존성 엣지.
        if ($pomDepRows || $sbomDepRows) {
            vg_ingest_store_package_deps($pdo, $scanId, $pomDepRows, $sbomDepRows, $ctrIds);
        }

        // 언어 패키지 벌크
        if ($langCount > 0) {
            vg_ingest_store_lang_packages($pdo, $scanId, $langRows);
        }

        // 노출 벌크
        if ($expCount > 0) {
            vg_ingest_store_exposures($pdo, $scanId, $expRows);
        }

        // 실행 프로세스 벌크
        if ($procCount > 0) {
            vg_ingest_store_processes($pdo, $scanId, $procRows);
        }

        // changelog CVE 벌크 (백포트 근거 — 매처가 억제 판정에 사용)
        if ($clogCount > 0) {
            vg_ingest_store_changelog_cves($pdo, $scanId, $clogRows);
        }

        // 재시작 필요 벌크 (옛 라이브러리 상주 — 매처가 억제를 막는 근거로 사용)
        if ($staleCount > 0) {
            vg_ingest_store_stale_libs($pdo, $scanId, $staleRows);
        }

        // debsecan 벌크 (데비안 트래커가 "아직 취약"이라 본 CVE)
        if ($debsecanCount > 0) {
            vg_ingest_store_debsecan($pdo, $scanId, $debsecanRows);
        }

        // errata CVE 벌크 (벤더가 "이 빌드에서 고쳤다"고 확인한 CVE)
        if ($errataCount > 0) {
            vg_ingest_store_errata($pdo, $scanId, $errataRows);
        }

        // 패키지 변경 이력 — 직전 스냅샷이 있을 때만(첫 수집은 기록하지 않는다).
        if ($prev !== null) {
            $chgCount = vg_ingest_store_pkg_changes(
                $pdo, $hostId, $scanId, (int) $prev['scan_id'], $manager, $pkgRows, $langRows
            );
        }
    }   // ← 변경 있음(새 스냅샷) 분기 끝

    // 패키지 무결성 — 스냅샷 재사용 여부와 무관하게 **이번 수집이 실제로 본 것**으로 덮어쓴다.
    vg_ingest_store_integrity($pdo, $scanId, $integChecked, $integPartial, $integTotal, $integRows);

    // 동일 스냅샷 재전송이어도 수집기 완전성은 최신 상태로 갱신한다.
    if ($collectionStages) {
        vg_ingest_store_stages($pdo, $scanId, $collectionStages);
    }

    // 수집 결과가 같아 기존 스냅샷을 재사용하더라도 실행 사실과 실행별 자원값은 항상 남긴다.
    vg_ingest_store_scan_run($pdo, $hostId, $scanId, $collectedAt, $unchanged, $pkgCount, $expCount, $meta);

    // 자산 등급 **초안 제안** 갱신 — 확정값(grade)은 건드리지 않는다("판정은 사람이, 초안은 시스템이").
    //   노출·프로세스가 이미 이 트랜잭션에 들어와 있으므로 여기서 계산해야 최신 데이터를 본다.
    //   동일 스냅샷 재전송(unchanged)이어도 기존 scan_id 의 행을 그대로 읽으므로 결과는 같다.
    vg_asset_grade_observe($pdo, $hostId, $scanId, $collectedAt, $collectionStages);

    $pdo->commit();

    return [
        'host_id'   => $hostId,
        'scan_id'   => $scanId,
        'unchanged' => $unchanged,
        'chg_count' => $chgCount,
    ];
}
