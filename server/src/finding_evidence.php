<?php
declare(strict_types=1);

/** Structured finding evidence used to explain vulnerability decisions. */

function vg_match_source(array $scan, string $manager, ?array $container): string {
    $os = strtolower((string) ($container['os_id'] ?? $container['os'] ?? $scan['os_id'] ?? ''));
    if ($os === 'ubuntu') return 'ubuntu_oval';
    if ($os === 'debian') return 'debian_tracker';
    if (in_array($os, ['rhel','rocky','almalinux','centos'], true)) return 'vendor_oval';
    if ($manager === 'kernel') return 'kernel_cna';
    return 'osv';
}

/**
 * 증거 payload 를 **계산만** 한다(DB 접근 없음). 기록은 vg_store_finding_evidence().
 *   매처가 "계산 → 지문 비교 → (다르면) 쓰기" 로 도는데, 계산 단계에선 아직 finding_id 가 없고
 *   결과가 같으면 아예 쓰지 않으므로 계산과 기록이 분리돼 있어야 한다.
 */
function vg_build_finding_evidence(array $scan, array $package, string $manager, ?array $container, array $candidate, array $context, array $decision): array {
    $process = ['running'=>(bool)($context['running']??false),'loaded'=>(bool)($context['pkgLoaded']??false),'restart_required'=>(($context['staleEv']??null)!==null)||(bool)($context['kernelPending']??false)];
    $network = ['scope'=>$context['scope']??null,'listener'=>$context['le']??null,'externally_reachable'=>(bool)($context['exposed']??false)];
    $details = ['manager'=>$manager,'container'=>$container['cid']??null,'installed_version'=>$package['version']??null,'comparison_version'=>$candidate['cmpver']??null,'runtime_status'=>$decision['status']??null,'rationale'=>$decision['why']??null];
    return [
        'match_source'     => vg_match_source($scan, $manager, $container),
        'fixed_version'    => $candidate['fixed'] ?? null,
        'source_package'   => $package['source_pkg'] ?? null,
        'source_version'   => $package['source_version'] ?? null,
        'process_evidence' => json_encode($process, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES),
        'network_evidence' => json_encode($network, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES),
        'evidence_json'    => json_encode($details, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES),
    ];
}

/** vg_build_finding_evidence() 가 만든 payload 를 기록한다. */
function vg_store_finding_evidence(PDO $pdo, int $findingId, array $payload): void {
    $sql = 'INSERT INTO tb_finding_evidence (finding_id,match_source,fixed_version,source_package,source_version,process_evidence,network_evidence,feed_updated_at,evidence_json) VALUES (?,?,?,?,?,?,?,NOW(),?) ON DUPLICATE KEY UPDATE match_source=VALUES(match_source),fixed_version=VALUES(fixed_version),source_package=VALUES(source_package),source_version=VALUES(source_version),process_evidence=VALUES(process_evidence),network_evidence=VALUES(network_evidence),feed_updated_at=VALUES(feed_updated_at),evidence_json=VALUES(evidence_json)';
    $pdo->prepare($sql)->execute([
        $findingId, $payload['match_source'], $payload['fixed_version'], $payload['source_package'],
        $payload['source_version'], $payload['process_evidence'], $payload['network_evidence'], $payload['evidence_json'],
    ]);
}
