<?php
declare(strict_types=1);

/**
 * SBOM 호스트 임포트 단위 테스트 — SBOM 파일명(cid)이 어디에 붙는지 결정하는 순수 로직.
 *   · 예약 cid `_host`      → container_id = 0 (호스트 자신)
 *   · 실제 컨테이너 cid     → 그 컨테이너의 container_id (기존 동작 불변)
 *   · 어느 쪽도 아닌 cid    → 버리되 **드러낸다**(vg_ingest_sbom_dropped)
 * DB 는 건드리지 않는다 — 실제 저장은 tests/smoke.sh 의 e2e 가 본다.
 *
 * 실행:
 *   docker run --rm -v "$PWD:/w" -w /w php:8.3-cli php tests/sbom_host_import_test.php
 */

require_once __DIR__ . '/../server/src/ingest_parse.php';              // vg_ingest_parse_sbom · VG_SBOM_HOST_CID
require_once __DIR__ . '/../server/src/ingest/store/containers.php';   // vg_ingest_ctr_ids_with_host

$fail = 0;
$eq = static function (string $label, $got, $want) use (&$fail): void {
    if ($got !== $want) {
        printf("  ✗ [%s] 기대 %s, 실제 %s\n", $label, var_export($want, true), var_export($got, true));
        $fail++;
    }
};

// SBOM 한 줄(cid|format|base64)을 만든다 — express 가 lodash 를 끌어오는 최소 CycloneDX.
$sbomLine = static function (string $cid): string {
    $doc = [
        'bomFormat' => 'CycloneDX', 'specVersion' => '1.5',
        'metadata' => ['component' => ['bom-ref' => 'root', 'name' => 'app', 'version' => '1.0.0',
                                       'purl' => 'pkg:npm/app@1.0.0']],
        'components' => [
            ['bom-ref' => 'e', 'name' => 'express', 'version' => '4.18.2', 'purl' => 'pkg:npm/express@4.18.2'],
            ['bom-ref' => 'l', 'name' => 'lodash',  'version' => '4.17.21', 'purl' => 'pkg:npm/lodash@4.17.21'],
        ],
        'dependencies' => [['ref' => 'e', 'dependsOn' => ['l']]],
    ];
    return $cid . '|cyclonedx|' . base64_encode((string) json_encode($doc));
};

// 수집된 컨테이너 목록(vg_ingest_parse_container_list 의 반환 모양: cid 를 키로).
$ctrRows = ['abc123' => ['abc123', 'web', 'nginx:1.25', '', '', '', '0']];

// ── 1) 예약 cid → 호스트(container_id = 0) ─────────────────────────────────
$ctrIds = vg_ingest_ctr_ids_with_host(['abc123' => 42]);
$eq('예약 cid 는 호스트(0)로 매핑된다', $ctrIds[VG_SBOM_HOST_CID] ?? null, 0);
$eq('예약 cid 이름은 _host', VG_SBOM_HOST_CID, '_host');

$hostSbom = vg_ingest_parse_sbom($sbomLine(VG_SBOM_HOST_CID));
$eq('호스트 SBOM 패키지 2건 파싱', count($hostSbom['packages']), 2);
// 저장 단계의 가드(`isset($ctrIds[$cid])`)를 통과해야 패키지·엣지가 남는다.
$kept = array_filter($hostSbom['deps'], static fn($r) => isset($ctrIds[$r[0]]));
$eq('호스트 SBOM 엣지가 저장 가드를 통과', count($kept), count($hostSbom['deps']));
$eq('호스트 SBOM 엣지가 하나 이상', count($hostSbom['deps']) > 0, true);
$eq('호스트 SBOM 은 버려지지 않는다', vg_ingest_sbom_dropped($hostSbom, $ctrRows), []);

// ── 2) 실제 컨테이너 cid → 그 컨테이너 id (기존 동작 불변) ──────────────────
$eq('실제 컨테이너 cid 는 그 컨테이너 id', $ctrIds['abc123'] ?? null, 42);
$ctrSbom = vg_ingest_parse_sbom($sbomLine('abc123'));
$eq('컨테이너 SBOM 은 버려지지 않는다', vg_ingest_sbom_dropped($ctrSbom, $ctrRows), []);
// 예약 이름이 이긴다 — 조작된 페이로드가 `_host` 를 컨테이너로 주장해도 호스트 매핑을 못 덮는다.
$eq('예약 이름은 컨테이너에 뺏기지 않는다',
    vg_ingest_ctr_ids_with_host([VG_SBOM_HOST_CID => 99])[VG_SBOM_HOST_CID], 0);

// ── 3) 매칭 실패 cid → 버려지되 드러난다 ───────────────────────────────────
$ghostSbom = vg_ingest_parse_sbom($sbomLine('gone-ctr'));
$eq('매칭 실패 SBOM 은 저장 가드에서 전부 버려진다',
    count(array_filter($ghostSbom['deps'], static fn($r) => isset($ctrIds[$r[0]]))), 0);
$dropped = vg_ingest_sbom_dropped($ghostSbom, $ctrRows);
$eq('버려진 cid 가 드러난다', array_keys($dropped), ['gone-ctr']);
$eq('버려진 패키지 건수', $dropped['gone-ctr']['packages'], 2);
$eq('버려진 엣지 건수', $dropped['gone-ctr']['edges'], count($ghostSbom['deps']));
// 폴백 금지 — 매칭 실패가 호스트(0)로 둔갑하지 않는다.
$eq('매칭 실패는 호스트로 떨어지지 않는다', isset($ctrIds['gone-ctr']), false);

// 여러 문서가 섞여도 버려진 것만 집계한다.
$mixed = vg_ingest_parse_sbom(
    $sbomLine(VG_SBOM_HOST_CID) . "\n" . $sbomLine('abc123') . "\n" . $sbomLine('gone-ctr')
);
$eq('혼합 입력에서 버려진 것만 집계', array_keys(vg_ingest_sbom_dropped($mixed, $ctrRows)), ['gone-ctr']);

if ($fail === 0) {
    echo "sbom_host_import: 전체 통과\n";
    exit(0);
}
printf("sbom_host_import: %d건 실패\n", $fail);
exit(1);
