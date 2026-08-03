<?php
declare(strict_types=1);

/**
 * ingest_store.php — ingest.php 가 파싱한 에이전트 페이로드를 중앙 DB 에 저장한다.
 *   호스트/스캔 upsert, 패키지·노출·컨테이너·changelog 등 벌크 INSERT, 변경이력(pkg_changes)
 *   계산까지 하나의 트랜잭션으로 묶는다. 인증·파싱·응답 조립은 ingest.php 에 남는다.
 *   트랜잭션의 시작(beginTransaction)과 끝(commit)만 갖고, 실패 시 롤백/오류응답은
 *   호출자(ingest.php)의 책임이다 — 예외를 그대로 위로 던진다.
 */

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

    $debsecanRows  = $parsed['debsecan_rows'];
    $debsecanCount = (int) $parsed['debsecan_count'];

    $errataRows  = $parsed['errata_rows'];
    $errataCount = (int) $parsed['errata_count'];

    $runningKernel = (string) $parsed['running_kernel'];
    $kernelLatest  = (string) $parsed['kernel_latest'];
    $kernelReboot  = $parsed['kernel_reboot'];

    $contentHash = (string) $parsed['content_hash'];
    $collectionStages = $parsed['collection_stages'] ?? [];

    $chgCount = 0;   // 이번에 기록한 패키지 변경 건수

    $pdo->beginTransaction();

    // 호스트 upsert (fqdn 유니크). LAST_INSERT_ID 트릭으로 기존 host_id 회수.
    $stmt = $pdo->prepare(
        'INSERT INTO tb_host (fqdn, hostname, os_id, os_version, first_seen, last_seen, last_seen_ip)
         VALUES (:fqdn, :hn, :osid, :osver, NOW(), NOW(), :ip)
         ON DUPLICATE KEY UPDATE
            hostname     = VALUES(hostname),
            os_id        = VALUES(os_id),
            os_version   = VALUES(os_version),
            last_seen    = NOW(),
            last_seen_ip = VALUES(last_seen_ip),
            host_id      = LAST_INSERT_ID(host_id)'
    );
    $stmt->execute([
        ':fqdn'  => $fqdn,
        ':hn'    => $fqdn,
        ':osid'  => ($vm['distro_id'] ?? '') ?: null,
        ':osver' => ($vm['distro_version'] ?? '') ?: null,
        ':ip'    => $remoteIp,
    ]);
    $hostId = (int) $pdo->lastInsertId();

    // 직전 스캔과 내용이 같으면 새 스냅샷을 만들지 않는다 — 수집시각만 갱신한다.
    //   호스트 생존 신호는 tb_host.last_seen 이 위에서 이미 갱신했으므로 잃는 정보가 없다.
    //   그 결과 스캔 목록 자체가 "변경 시점" 목록이 된다(changes.php 의 비교도 더 정확해진다).
    $q = $pdo->prepare('SELECT scan_id, content_hash FROM tb_scan WHERE host_id = ? ORDER BY scan_id DESC LIMIT 1');
    $q->execute([$hostId]);
    $prev = $q->fetch() ?: null;
    $unchanged = $prev !== null && (string) $prev['content_hash'] === $contentHash;

    if ($unchanged) {
        $scanId = (int) $prev['scan_id'];
        $pdo->prepare(
            'UPDATE tb_scan SET collected_at = :ca, agent_version = :av, schedule = :sch,
                                 elapsed_seconds = :el,
                                 peak_rss_mb = :pk, cpu_seconds = :cpu,
                                 mem_total_mb = :mem, cpu_cores = :cores WHERE scan_id = :sid'
        )->execute([
            ':ca' => $collectedAt,
            ':av' => ($meta['agent_version'] ?? '') ?: null,
            ':sch' => ($meta['schedule'] ?? '') ?: null,
            ':el' => isset($meta['elapsed_seconds']) ? (int) $meta['elapsed_seconds'] : null,
            ':pk' => isset($meta['peak_rss_mb']) ? (float) $meta['peak_rss_mb'] : null,
            ':cpu' => isset($meta['cpu_seconds']) ? (float) $meta['cpu_seconds'] : null,
            ':mem' => isset($meta['mem_total_mb']) ? (float) $meta['mem_total_mb'] : null,
            ':cores' => isset($meta['nproc']) ? (int) $meta['nproc'] : null,
            ':sid' => $scanId,
        ]);
    } else {
    // 스캔 1행
    $stmt = $pdo->prepare(
        'INSERT INTO tb_scan
            (host_id, collected_at, agent_version, schedule, elapsed_seconds, peak_rss_mb, cpu_seconds,
             mem_total_mb, cpu_cores,
             os_id, os_version, kernel, running_kernel, kernel_latest, kernel_reboot_needed,
             cpe, package_family, content_hash,
             package_count, exposure_count, raw_json)
         VALUES
            (:h, :ca, :av, :sch, :el, :pk, :cpu, :mem, :cores, :osid, :osver, :kern, :rk, :kl, :krn, :cpe, :fam, :hash, :pc, :ec, :raw)'
    );
    $stmt->execute([
        ':h'     => $hostId,
        ':ca'    => $collectedAt,
        ':av'    => ($meta['agent_version'] ?? '') ?: null,
        ':sch'   => ($meta['schedule'] ?? '') ?: null,
        ':el'    => isset($meta['elapsed_seconds']) ? (int) $meta['elapsed_seconds'] : null,
        ':pk'    => isset($meta['peak_rss_mb']) ? (float) $meta['peak_rss_mb'] : null,
        ':cpu'   => isset($meta['cpu_seconds']) ? (float) $meta['cpu_seconds'] : null,
        ':mem'   => isset($meta['mem_total_mb']) ? (float) $meta['mem_total_mb'] : null,
        ':cores' => isset($meta['nproc']) ? (int) $meta['nproc'] : null,
        ':osid'  => ($vm['distro_id'] ?? '') ?: null,
        ':osver' => ($vm['distro_version'] ?? '') ?: null,
        ':kern'  => ($sys['kernel_release'] ?? ($sys['kernel'] ?? '')) ?: null,
        ':rk'    => $runningKernel ?: null,
        ':kl'    => $kernelLatest ?: null,
        ':krn'   => $kernelReboot,
        ':cpe'   => ($vm['cpe_name'] ?? '') ?: null,
        ':fam'   => ($vm['package_family'] ?? '') ?: null,
        ':hash'  => $contentHash,
        ':pc'    => $pkgCount,
        ':ec'    => $expCount,
        ':raw'   => $raw,
    ]);
    $scanId = (int) $pdo->lastInsertId();

    // 패키지 벌크
    if ($pkgCount > 0) {
        $ins = $pdo->prepare(
            'INSERT INTO tb_package (scan_id, manager, name, version, arch, source_pkg, source_version, vendor, origin)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
        );
        foreach ($pkgRows as $r) {
            // 출처: dpkg 는 apt Origin 라벨, rpm 은 VENDOR($r[5]).
            $origin = $manager === 'rpm'
                ? (($r[5] ?? '') !== '' ? $r[5] : null)
                : ($originMap[$r[0]] ?? null);
            $ins->execute([$scanId, $manager, $r[0], $r[1], $r[2], $r[3], $r[4], $r[5], $origin]);
        }
    }

    // 컨테이너 + 그 안의 패키지.
    //   컨테이너는 호스트와 OS 가 다를 수 있어(호스트 Rocky + 컨테이너 Debian) os 를 따로 갖는다.
    //   패키지는 같은 tb_package 에 container_id 를 달아 넣는다(0 = 호스트).
    $ctrIds = [];   // cid => tb_container.container_id
    if ($ctrCount > 0) {
        $insC = $pdo->prepare(
            'INSERT INTO tb_container (scan_id,cid,name,image,image_digest,k8s_namespace,k8s_pod,k8s_container,workload_ref,runtime_state,sbom_format,sbom_hash,os_id,os_version,manager,pkg_count)
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'
        );
        foreach ($ctrRows as $cid => $f) {
            $insC->execute([
                $scanId, $cid,
                ($f[1] !== '' ? $f[1] : null), ($f[2] !== '' ? $f[2] : null),
                (($f[7] ?? '') !== '' ? $f[7] : null), (($f[8] ?? '') !== '' ? $f[8] : null),
                (($f[9] ?? '') !== '' ? $f[9] : null), (($f[10] ?? '') !== '' ? $f[10] : null),
                (($f[11] ?? '') !== '' ? $f[11] : null), (($f[12] ?? '') !== '' ? $f[12] : 'running'),
                (($f[13] ?? '') !== '' ? $f[13] : null), (($f[14] ?? '') !== '' ? $f[14] : null),
                ($f[3] !== '' ? $f[3] : null), ($f[4] !== '' ? $f[4] : null),
                ($f[5] !== '' ? $f[5] : null), (int) $f[6],
            ]);
            $ctrIds[$cid] = (int) $pdo->lastInsertId();
        }
    }
    if ($ctrPkgCount > 0) {
        $ins = $pdo->prepare(
            'INSERT INTO tb_package (scan_id, container_id, manager, name, version, source_pkg)
             VALUES (?, ?, ?, ?, ?, ?)'
        );
        foreach ($ctrPkgRows as $r) {
            $cidKey = $r[0];
            if (!isset($ctrIds[$cidKey])) { continue; }   // 목록에 없는 컨테이너의 패키지는 버린다
            $ins->execute([
                $scanId, $ctrIds[$cidKey], $r[1], $r[2], $r[3],
                (($r[4] ?? '') !== '' ? $r[4] : null),
            ]);
        }
    }

    // 컨테이너 런타임 증거 — 호스트와 같은 테이블에 container_id 를 달아 넣는다(0 = 호스트).
    //   이게 있어야 매처가 컨테이너 패키지에도 "로드됨/외부노출" 을 적용해 등급을 매길 수 있다.
    if ($ctrProcCount > 0) {
        $ins = $pdo->prepare(
            'INSERT INTO tb_process (scan_id, container_id, pid, comm, username, exe_pkg, loaded_pkgs)
             VALUES (?, ?, ?, ?, ?, ?, ?)'
        );
        foreach ($ctrProcRows as $f) {
            if (!isset($ctrIds[$f[0]])) { continue; }   // 목록에 없는 컨테이너 것은 버린다
            $ins->execute([
                $scanId, $ctrIds[$f[0]],
                ($f[1] !== '' ? (int) $f[1] : null),
                $f[2], $f[3], $f[4], $f[5],
            ]);
        }
    }
    if ($ctrExpCount > 0) {
        $ins = $pdo->prepare(
            'INSERT INTO tb_exposure
                (scan_id, container_id, pid, proc, proto, bind_addr, port, scope, exe_pkg, loaded_pkgs)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
        );
        foreach ($ctrExpRows as $f) {
            if (!isset($ctrIds[$f[0]])) { continue; }
            $ins->execute([
                $scanId, $ctrIds[$f[0]],
                ($f[1] !== '' ? (int) $f[1] : null),
                $f[2], $f[3], $f[4],
                ($f[5] !== '' ? (int) $f[5] : null),
                $f[6], $f[7], $f[8],
            ]);
        }
    }

    // 언어 패키지 벌크 — 같은 tb_package 에 manager=pip|npm|gem|composer 로 넣는다.
    //   매처가 manager 로 생태계(PyPI/npm/…)를 정해 OS 패키지와 섞이지 않게 매칭한다.
    if ($langCount > 0) {
        $ins = $pdo->prepare(
            'INSERT INTO tb_package (scan_id, manager, name, version) VALUES (?, ?, ?, ?)'
        );
        foreach ($langRows as $r) {
            $ins->execute([$scanId, $r[0], $r[1], $r[2]]);
        }
    }

    // 노출 벌크
    if ($expCount > 0) {
        $ins = $pdo->prepare(
            'INSERT INTO tb_exposure
                (scan_id, pid, proc, proto, bind_addr, port, scope, exe_pkg, loaded_pkgs)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
        );
        foreach ($expRows as $f) {
            $ins->execute([
                $scanId,
                ($f[0] !== '' ? (int) $f[0] : null),
                $f[1], $f[2], $f[3],
                ($f[4] !== '' ? (int) $f[4] : null),
                $f[5], $f[6], $f[7],
            ]);
        }
    }

    // 실행 프로세스 벌크
    if ($procCount > 0) {
        $ins = $pdo->prepare(
            'INSERT INTO tb_process (scan_id, pid, comm, username, exe_pkg, loaded_pkgs)
             VALUES (?, ?, ?, ?, ?, ?)'
        );
        foreach ($procRows as $f) {
            $ins->execute([
                $scanId,
                ($f[0] !== '' ? (int) $f[0] : null),
                $f[1], $f[2], $f[3], $f[4],
            ]);
        }
    }

    // changelog CVE 벌크 (백포트 근거 — 매처가 억제 판정에 사용)
    if ($clogCount > 0) {
        $ins = $pdo->prepare(
            'INSERT INTO tb_pkg_changelog_cve (scan_id, package_name, cve_id, evidence)
             VALUES (?, ?, ?, ?)'
        );
        foreach ($clogRows as $r) {
            $ins->execute([$scanId, $r[0], $r[1], $r[2]]);
        }
    }

    // 재시작 필요 벌크 (옛 라이브러리 상주 — 매처가 억제를 막는 근거로 사용)
    if ($staleCount > 0) {
        $ins = $pdo->prepare(
            'INSERT INTO tb_stale_lib (scan_id, pid, comm, package_name, lib_path)
             VALUES (?, ?, ?, ?, ?)'
        );
        foreach ($staleRows as $r) {
            $ins->execute([$scanId, (int) $r[0], $r[1], $r[2], mb_strimwidth((string) $r[3], 0, 512, '')]);
        }
    }

    // debsecan 벌크 (데비안 트래커가 "아직 취약"이라 본 CVE — 매처가 나머지를 억제하는 근거)
    if ($debsecanCount > 0) {
        $ins = $pdo->prepare(
            'INSERT INTO tb_debsecan (scan_id, cve_id, package_name) VALUES (?, ?, ?)'
        );
        foreach ($debsecanRows as $r) {
            $ins->execute([$scanId, $r[0], $r[1]]);
        }
    }

    // errata CVE 벌크 (벤더가 "이 빌드에서 고쳤다"고 확인한 CVE — 매처가 억제 판정에 사용)
    if ($errataCount > 0) {
        $ins = $pdo->prepare(
            'INSERT INTO tb_applied_errata (scan_id, package_name, cve_id, evidence)
             VALUES (?, ?, ?, ?)'
        );
        foreach ($errataRows as $r) {
            $ins->execute([$scanId, $r[0], $r[1], $r[2]]);
        }
    }

    // 패키지 변경 이력 — 직전 스냅샷과 무엇이 달라졌나(설치/제거/업그레이드/다운그레이드).
    //   첫 수집(직전 스냅샷 없음)은 전부 "설치"로 기록하지 않는다 — 의미 없는 폭증만 만든다.
    if ($prev !== null) {
        // 호스트 패키지만 비교한다(container_id=0). 컨테이너 것까지 섞으면 컨테이너 패키지가
        // 전부 "제거됨"으로 잘못 기록된다 — $curPkgs 에는 호스트·언어 패키지만 담기기 때문이다.
        $q = $pdo->prepare('SELECT manager, name, version FROM tb_package WHERE scan_id = ? AND container_id = 0');
        $q->execute([(int) $prev['scan_id']]);
        $prevPkgs = [];
        foreach ($q->fetchAll() as $r) {
            $prevPkgs[$r['manager'] . '|' . $r['name']] = (string) $r['version'];
        }
        $curPkgs = vg_ingest_build_pkg_map($manager, $pkgRows, $langRows);
        // 배포판 규칙으로 비교해야 승강을 정확히 가른다(1:1.1 > 2.0 같은 epoch 사례).
        $pkgChanges = vg_ingest_diff_packages($prevPkgs, $curPkgs, 'vg_ver_cmp');

        $insChg = $pdo->prepare(
            'INSERT INTO tb_pkg_change (host_id, scan_id, manager, package_name, change_type, old_version, new_version)
             VALUES (?, ?, ?, ?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE change_type=VALUES(change_type),
               old_version=VALUES(old_version), new_version=VALUES(new_version)'
        );
        foreach ($pkgChanges as [$key, $type, $old, $new]) {
            [$mgr, $name] = explode('|', $key, 2);
            $insChg->execute([$hostId, $scanId, $mgr, $name, $type, $old, $new]);
            $chgCount++;
        }
    }

    }   // ← 변경 있음(새 스냅샷) 분기 끝

    // 동일 스냅샷 재전송이어도 수집기 완전성은 최신 상태로 갱신한다.
    if ($collectionStages) {
        $stage = $pdo->prepare('INSERT INTO tb_collection_stage (scan_id,stage_code,status,item_count) VALUES (?,?,?,?) ON DUPLICATE KEY UPDATE status=VALUES(status),item_count=VALUES(item_count),created_at=NOW()');
        foreach ($collectionStages as $r) { $stage->execute([$scanId, $r[0], $r[1], $r[2]]); }
    }

    $pdo->commit();

    return [
        'host_id'   => $hostId,
        'scan_id'   => $scanId,
        'unchanged' => $unchanged,
        'chg_count' => $chgCount,
    ];
}
