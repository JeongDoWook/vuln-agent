<?php
declare(strict_types=1);

/** Internal remediation/SLA and structured finding evidence. */
const VG_REMEDIATION_STATUSES = ['OPEN', 'IN_PROGRESS', 'EXCEPTION', 'RESOLVED'];

function vg_match_source(array $scan, string $manager, ?array $container): string {
    $os = strtolower((string) ($container['os_id'] ?? $container['os'] ?? $scan['os_id'] ?? ''));
    if ($os === 'ubuntu') return 'ubuntu_oval';
    if ($os === 'debian') return 'debian_tracker';
    if (in_array($os, ['rhel','rocky','almalinux','centos'], true)) return 'vendor_oval';
    if ($manager === 'kernel') return 'kernel_cna';
    return 'osv';
}

function vg_store_finding_evidence(PDO $pdo, int $findingId, array $scan, array $package, string $manager, ?array $container, array $candidate, array $context, array $decision): void {
    $process = ['running'=>(bool)($context['running']??false),'loaded'=>(bool)($context['pkgLoaded']??false),'restart_required'=>(($context['staleEv']??null)!==null)||(bool)($context['kernelPending']??false)];
    $network = ['scope'=>$context['scope']??null,'listener'=>$context['le']??null,'externally_reachable'=>(bool)($context['exposed']??false)];
    $details = ['manager'=>$manager,'container'=>$container['cid']??null,'installed_version'=>$package['version']??null,'comparison_version'=>$candidate['cmpver']??null,'runtime_status'=>$decision['status']??null,'rationale'=>$decision['why']??null];
    $sql = 'INSERT INTO tb_finding_evidence (finding_id,match_source,fixed_version,source_package,source_version,process_evidence,network_evidence,feed_updated_at,evidence_json) VALUES (?,?,?,?,?,?,?,NOW(),?) ON DUPLICATE KEY UPDATE match_source=VALUES(match_source),fixed_version=VALUES(fixed_version),source_package=VALUES(source_package),source_version=VALUES(source_version),process_evidence=VALUES(process_evidence),network_evidence=VALUES(network_evidence),feed_updated_at=VALUES(feed_updated_at),evidence_json=VALUES(evidence_json)';
    $pdo->prepare($sql)->execute([$findingId,vg_match_source($scan,$manager,$container),$candidate['fixed']??null,$package['source_pkg']??null,$package['source_version']??null,json_encode($process,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES),json_encode($network,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES),json_encode($details,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES)]);
}

function vg_sla_due_days(PDO $pdo, string $severity, ?string $scope, bool $inKev): int {
    $st=$pdo->prepare("SELECT due_days FROM tb_sla_policies WHERE enabled=1 AND is_deleted=0 AND severity=? AND (exposure_scope='ANY' OR exposure_scope=?) AND (in_kev=0 OR in_kev=?) ORDER BY in_kev DESC,(exposure_scope<>'ANY') DESC,priority ASC LIMIT 1");
    $st->execute([$severity,$scope?:'NONE',$inKev?1:0]); $days=$st->fetchColumn();
    return $days===false?90:max(0,(int)$days);
}

function vg_sync_remediation_cases(PDO $pdo, int $scanId): void {
    $st=$pdo->prepare('SELECT host_id,collected_at FROM tb_scans WHERE id=?'); $st->execute([$scanId]); $scan=$st->fetch(); if(!$scan)return;
    $rows=$pdo->prepare("SELECT f.cve_id,f.package_name,f.severity,f.exposure_scope,f.in_kev,COALESCE(c.image_digest,c.cid,'') container_ref FROM tb_findings f LEFT JOIN tb_containers c ON c.id=f.container_id WHERE f.scan_id=?"); $rows->execute([$scanId]);
    $seen=[]; $up=$pdo->prepare("INSERT INTO tb_remediation_cases (host_id,container_ref,cve_id,package_name,status,due_at,due_source,first_seen_at,last_seen_at) VALUES (?,?,?,?, 'OPEN', ?, 'SLA', ?, ?) ON DUPLICATE KEY UPDATE status=IF(status='RESOLVED' AND last_seen_at<VALUES(last_seen_at),'OPEN',status),completed_at=IF(status='OPEN',NULL,completed_at),last_seen_at=VALUES(last_seen_at),is_deleted=0,deleted_at=NULL,due_at=due_at");
    $collected=(string)$scan['collected_at'];
    foreach($rows->fetchAll() as $r){$days=vg_sla_due_days($pdo,(string)$r['severity'],$r['exposure_scope'],(bool)$r['in_kev']);$due=(new DateTimeImmutable($collected))->modify("+{$days} days")->format('Y-m-d H:i:s');$ref=(string)$r['container_ref'];$up->execute([(int)$scan['host_id'],$ref,$r['cve_id'],$r['package_name'],$due,$collected,$collected]);$seen[$ref."\0".$r['cve_id']."\0".$r['package_name']]=true;}
    $open=$pdo->prepare("SELECT id,container_ref,cve_id,package_name FROM tb_remediation_cases WHERE host_id=? AND is_deleted=0 AND status IN ('OPEN','IN_PROGRESS')");$open->execute([(int)$scan['host_id']]);
    $resolve=$pdo->prepare("UPDATE tb_remediation_cases SET status='RESOLVED',completed_at=?,resolution_note='다음 수집에서 취약 판정이 사라져 자동 완료' WHERE id=?");
    foreach($open->fetchAll() as $case){$key=$case['container_ref']."\0".$case['cve_id']."\0".$case['package_name'];if(!isset($seen[$key]))$resolve->execute([$collected,$case['id']]);}
}