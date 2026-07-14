<?php
declare(strict_types=1);

/**
 * ingest.php — 수집 에이전트가 보낸 JSON 을 받아 중앙 DB 에 저장한다.
 *   인증 : 공유 토큰 (헤더 X-Agent-Token 또는 Authorization: Bearer)
 *   본문 : vuln-inventory-agent.sh (jq 모드) 가 만든 JSON
 *   저장 : hosts → scans → packages / exposures  (하나의 트랜잭션)
 */

header('Content-Type: application/json; charset=utf-8');

$cfg = require __DIR__ . '/../src/config.php';
require __DIR__ . '/../src/db.php';
require __DIR__ . '/../src/matcher.php';
require __DIR__ . '/../src/cce.php';          // vg_evaluate_cce (보안설정 점검)
require __DIR__ . '/../src/rpmdb.php';        // vg_ingest_rpmdb_rows (컨테이너 rpm DB 를 중앙이 파싱)
require_once __DIR__ . '/../src/audit.php';   // vg_log_activity
require_once __DIR__ . '/../src/agenttoken.php';  // vg_agent_token_verify (호스트 바인딩)
require_once __DIR__ . '/../src/ingest_parse.php';  // vg_ingest_parse_* (순수 변환, DB 비의존)

// 통일 에러 포맷: {ok:false,error,code,ts(ISO8601)}
function respond_fail(int $httpCode, string $msg, string $code): void {
    http_response_code($httpCode);
    echo json_encode(['ok' => false, 'error' => $msg, 'code' => $code, 'ts' => date('c')], JSON_UNESCAPED_UNICODE);
    exit;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    respond_fail(405, 'POST only', 'method_not_allowed');
}

// ── 인증 : 개별 토큰(호스트 바인딩) 우선, 없으면 공유 토큰(하위호환) ──────────
//   1) 개별 토큰이면 그 토큰에 묶인 fqdn 만 갱신할 수 있다 → 본문 fqdn 이 다르면 아래에서 403.
//   2) 개별 토큰이 아니면 공유 토큰(cfg['ingest_token'])을 상수시간 비교로 받는다(기존 배포 이행용).
//      공유 토큰은 deprecated — 본문 fqdn 을 그대로 믿으므로 위조에 취약하다. 수신마다 경고를 남긴다.
$provided  = vg_auth_token('X-Agent-Token');   // 커스텀 헤더 우선, 없으면 Authorization: Bearer
$pdoAuth   = vg_pdo();
$boundFqdn = null;      // 개별 토큰이면 강제할 fqdn
$sharedTok = false;     // 공유 토큰(하위호환)으로 인증됐나

$agentTok = vg_agent_token_verify($pdoAuth, (string) $provided);
if ($agentTok !== null) {
    $boundFqdn = $agentTok['fqdn'];
} else {
    $expected = (string) ($cfg['ingest_token'] ?? '');
    if ($expected !== '' && $provided !== '' && hash_equals($expected, (string) $provided)) {
        $sharedTok = true;
    } else {
        respond_fail(401, 'unauthorized', 'unauthorized');
    }
}

// ── 본문 파싱 ─────────────────────────────────────────────────
$raw = file_get_contents('php://input');
if ($raw === false || $raw === '') {
    respond_fail(400, 'empty body', 'empty_body');
}
$data = json_decode($raw, true);
if (!is_array($data)) {
    respond_fail(400, 'invalid json', 'invalid_json');
}

$meta = $data['meta']         ?? [];
$vm   = $data['vuln_mapping'] ?? [];
$sys  = $data['system']       ?? [];
$pkg  = $data['pkg']          ?? [];
$exp  = $data['exposure']     ?? [];
$upd  = $data['updates']      ?? [];

$fqdn = trim((string) ($meta['hostname_fqdn'] ?? '')) ?: 'unknown';

// ── 호스트 바인딩 강제 ───────────────────────────────────────
//   개별 토큰: 바인딩된 fqdn 만 갱신 가능. 본문이 다른 호스트를 주장하면 스푸핑 → 거부(403) + 감사.
//   공유 토큰: 본문 fqdn 을 그대로 쓰되(하위호환), 이행 추적용 경고를 남긴다.
if ($boundFqdn !== null) {
    if ($fqdn !== 'unknown' && $fqdn !== $boundFqdn) {
        vg_log_activity($pdoAuth, 'HOST', null, 'ingest_spoof_blocked',
            "토큰 바인딩 위반: 토큰은 [{$boundFqdn}] 에 묶였는데 본문은 [{$fqdn}] 주장 → 거부",
            ['bound' => $boundFqdn, 'claimed' => $fqdn], null, 'SYSTEM');
        respond_fail(403, 'token is bound to a different host', 'host_binding_violation');
    }
    $fqdn = $boundFqdn;   // 본문이 비었거나 일치 → 바인딩 값으로 강제.
} elseif ($sharedTok) {
    vg_log_activity($pdoAuth, 'HOST', null, 'ingest_shared_token',
        "공유 토큰으로 수신(개별 토큰 이행 권장): {$fqdn}",
        ['fqdn' => $fqdn], null, 'SYSTEM');
}

// collected_at (ISO-8601) → MySQL DATETIME
$collectedAt = vg_ingest_parse_collected_at($meta['collected_at'] ?? null);

// ── 패키지 목록 파싱 (매니저별 TSV) ──────────────────────────
//   dpkg 상태가 'ii'(설치됨)가 아닌 행은 버린다. 'rc' 는 **제거됐고 설정만 남은** 패키지라
//   실제로 설치돼 있지 않다 — 예전엔 이것도 설치로 저장해 없는 패키지의 CVE 가 떴다.
//   source_version 은 OSV 의 deb 조치안(소스 버전 기준)과 비교하는 데 쓴다.
$manager = (string) ($pkg['manager'] ?? '');
$pkgRows = !empty($pkg['list']) ? vg_ingest_parse_packages($manager, (string) $pkg['list']) : [];
$pkgCount = count($pkgRows);

// ── 패키지 출처(Origin 라벨) — 서드파티 저장소 식별 ──
//   형식: "docker-ce-cli\tDocker" / "curl\tDebian" / "foo\tLOCAL"(수동 .deb)
//   rpm 은 VENDOR 를 이미 보내므로 그걸 출처로 쓴다(아래 저장부).
$originMap = vg_ingest_parse_origins((string) ($pkg['origins'] ?? ''));

// ── 언어 패키지 파싱 (pip/npm/gem/composer) ────────────────────
//   에이전트가 수집해 보내는데 지금까지 서버가 버리고 있었다 → 언어 패키지 CVE 가 전부 미탐.
//   OSV 는 PyPI/npm/RubyGems/Packagist 생태계를 그대로 지원한다.
$lang = $data['langpkg'] ?? [];
$langRows  = vg_ingest_parse_langpkgs($lang);
$langCount = count($langRows);

// ── 노출 상관 파싱 (pipe 구분, 첫 줄은 헤더) ─────────────────
$expRows = !empty($exp['correlation']) ? vg_ingest_parse_exposures((string) $exp['correlation']) : [];
$expCount = count($expRows);

// ── 실행 프로세스 파싱 (pipe, 첫 줄 헤더) — 실행중/사용중 구분용 ──
$rt = $data['runtime'] ?? [];
$procRows = !empty($rt['processes']) ? vg_ingest_parse_processes((string) $rt['processes']) : [];
$procCount = count($procRows);

// ── 재시작 필요 파싱 (pipe, 첫 줄 헤더) ──
//   업데이트로 교체된 옛 라이브러리를 아직 물고 있는 프로세스. 패키지는 패치됐어도
//   그 프로세스는 여전히 옛 코드를 실행한다 → 매처가 "이미 패치됨" 억제를 막는 근거.
$staleRows = !empty($rt['stale']) ? vg_ingest_parse_stale((string) $rt['stale']) : [];
$staleCount = count($staleRows);

// ── changelog CVE 파싱 — 패키지별 changelog 에 나온 CVE(백포트 근거) ──
//   에이전트가 --no-changelog 로 돌면 이 섹션이 비어 clogCount=0 → 무해(억제 없음).
$clog = $data['changelog'] ?? [];
$clogRows  = is_array($clog) ? vg_ingest_parse_changelog($clog) : [];
$clogCount = count($clogRows);

// ── errata CVE 파싱 — 이미 적용된 벤더 보안권고가 고친 CVE (백포트 근거, 시스템 전체) ──
$errataText  = (string) ($upd['errata_cves'] ?? '');
$errataRows  = vg_ingest_parse_errata($errataText);
$errataCount = count($errataRows);

// ── debsecan 파싱 — 데비안 보안 트래커가 "아직 취약하다"고 판정한 CVE (데비안 전용) ──
//   errata 와 방향이 반대다: errata 는 고쳐진 CVE, debsecan 은 남아 있는 CVE 를 준다.
//   → 매처는 "여기 없는 deb CVE = 백포트로 이미 수정됨"으로 억제한다.
$debsecanRows  = vg_ingest_parse_debsecan((string) ($upd['debsecan'] ?? ''));
$debsecanCount = count($debsecanRows);

// ── 컨테이너 파싱 (내부 패키지 — 호스트 스캔에서 빠져 통째로 미탐이던 영역) ──
//   컨테이너 런타임 증거(processes/exposure)가 없으면 컨테이너 취약점은 근거가
//   "설치만 됨" 뿐이라 전부 LOW 다.
$ctr = $data['containers'] ?? [];
$ctrRows     = vg_ingest_parse_container_list((string) ($ctr['list'] ?? ''));
$ctrPkgRows  = vg_ingest_parse_container_packages((string) ($ctr['packages'] ?? ''));
$ctrProcRows = vg_ingest_parse_container_processes((string) ($ctr['processes'] ?? ''));
$ctrExpRows  = vg_ingest_parse_container_exposures((string) ($ctr['exposure'] ?? ''));

// rpm DB 파일을 받은 컨테이너 — **중앙이 직접 파싱**해 패키지 행으로 펼친다.
//   컨테이너 안에 rpm 바이너리가 없고 호스트에도 rpm 이 없으면 에이전트는 DB 를 읽을 수 없다
//   (실측: 데비안 호스트 + calico UBI8 컨테이너 → 패키지가 통째로 안 보였다 = 미탐).
//   에이전트가 DB 파일을 그대로 올리고 여기서 해석한다 — 결과 행 모양이 같아 아래 저장 경로를
//   그대로 탄다(Trivy·Grype 와 같은 방식).
$ctrPkgRows = array_merge($ctrPkgRows, vg_ingest_rpmdb_rows((string) ($ctr['rpmdb'] ?? '')));

$ctrCount     = count($ctrRows);
$ctrPkgCount  = count($ctrPkgRows);
$ctrProcCount = count($ctrProcRows);
$ctrExpCount  = count($ctrExpRows);

// ── 커널: 실행 중인 커널 vs 설치된 최신 커널 ─────────────────────
//   커널을 패치해도 **재부팅 전까지는 옛 커널이 돈다.** 설치 버전만 보면 "패치됨"이라
//   커널 CVE 가 억제되는데 실제로는 취약하다(미탐). 에이전트는 예전부터 이 둘을 보냈는데
//   서버가 버리고 있었다.
$runningKernel = trim((string) ($upd['running_kernel'] ?? ''));
$kernelInfo    = vg_ingest_parse_kernel($manager, $runningKernel, (string) ($upd['installed_kernels'] ?? ''));
$kernelLatest  = $kernelInfo['latest'];
$kernelReboot  = $kernelInfo['reboot_needed'];

// ── 내용 해시 — "바뀔 때만 스냅샷" 판정 ────────────────────────
//   수집 내용이 직전과 같으면 새 스캔을 만들지 않는다(대부분의 수집이 여기 해당한다).
$contentHash = vg_ingest_content_hash(
    $pkgRows, $manager, $langRows, $expRows, $staleRows,
    $ctrPkgRows, $ctrRows, $ctrExpRows,
    $runningKernel, $kernelLatest, $kernelReboot,
    $vm, $sys, $originMap
);
$chgCount = 0;   // 이번에 기록한 패키지 변경 건수

// ── 저장 (트랜잭션) ──────────────────────────────────────────
try {
    $pdo = vg_pdo();
    $pdo->beginTransaction();

    // 호스트 upsert (fqdn 유니크). LAST_INSERT_ID 트릭으로 기존 id 회수.
    $stmt = $pdo->prepare(
        'INSERT INTO tb_hosts (fqdn, hostname, os_id, os_version, first_seen, last_seen)
         VALUES (:fqdn, :hn, :osid, :osver, NOW(), NOW())
         ON DUPLICATE KEY UPDATE
            hostname   = VALUES(hostname),
            os_id      = VALUES(os_id),
            os_version = VALUES(os_version),
            last_seen  = NOW(),
            id         = LAST_INSERT_ID(id)'
    );
    $stmt->execute([
        ':fqdn'  => $fqdn,
        ':hn'    => $fqdn,
        ':osid'  => ($vm['distro_id'] ?? '') ?: null,
        ':osver' => ($vm['distro_version'] ?? '') ?: null,
    ]);
    $hostId = (int) $pdo->lastInsertId();

    // 직전 스캔과 내용이 같으면 새 스냅샷을 만들지 않는다 — 수집시각만 갱신한다.
    //   호스트 생존 신호는 tb_hosts.last_seen 이 위에서 이미 갱신했으므로 잃는 정보가 없다.
    //   그 결과 스캔 목록 자체가 "변경 시점" 목록이 된다(changes.php 의 비교도 더 정확해진다).
    $q = $pdo->prepare('SELECT id, content_hash FROM tb_scans WHERE host_id = ? ORDER BY id DESC LIMIT 1');
    $q->execute([$hostId]);
    $prev = $q->fetch() ?: null;
    $unchanged = $prev !== null && (string) $prev['content_hash'] === $contentHash;

    if ($unchanged) {
        $scanId = (int) $prev['id'];
        $pdo->prepare(
            'UPDATE tb_scans SET collected_at = :ca, agent_version = :av, elapsed_seconds = :el,
                                 peak_rss_mb = :pk, cpu_seconds = :cpu WHERE id = :id'
        )->execute([
            ':ca' => $collectedAt,
            ':av' => ($meta['agent_version'] ?? '') ?: null,
            ':el' => isset($meta['elapsed_seconds']) ? (int) $meta['elapsed_seconds'] : null,
            ':pk' => isset($meta['peak_rss_mb']) ? (float) $meta['peak_rss_mb'] : null,
            ':cpu' => isset($meta['cpu_seconds']) ? (float) $meta['cpu_seconds'] : null,
            ':id' => $scanId,
        ]);
    } else {
    // 스캔 1행
    $stmt = $pdo->prepare(
        'INSERT INTO tb_scans
            (host_id, collected_at, agent_version, elapsed_seconds, peak_rss_mb, cpu_seconds,
             os_id, os_version, kernel, running_kernel, kernel_latest, kernel_reboot_needed,
             cpe, package_family, content_hash,
             package_count, exposure_count, raw_json)
         VALUES
            (:h, :ca, :av, :el, :pk, :cpu, :osid, :osver, :kern, :rk, :kl, :krn, :cpe, :fam, :hash, :pc, :ec, :raw)'
    );
    $stmt->execute([
        ':h'     => $hostId,
        ':ca'    => $collectedAt,
        ':av'    => ($meta['agent_version'] ?? '') ?: null,
        ':el'    => isset($meta['elapsed_seconds']) ? (int) $meta['elapsed_seconds'] : null,
        ':pk'    => isset($meta['peak_rss_mb']) ? (float) $meta['peak_rss_mb'] : null,
        ':cpu'   => isset($meta['cpu_seconds']) ? (float) $meta['cpu_seconds'] : null,
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
            'INSERT INTO tb_packages (scan_id, manager, name, version, arch, source_pkg, source_version, vendor, origin)
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
    //   패키지는 같은 tb_packages 에 container_id 를 달아 넣는다(0 = 호스트).
    $ctrIds = [];   // cid => tb_containers.id
    if ($ctrCount > 0) {
        $insC = $pdo->prepare(
            'INSERT INTO tb_containers (scan_id, cid, name, image, os_id, os_version, manager, pkg_count)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
        );
        foreach ($ctrRows as $cid => $f) {
            $insC->execute([
                $scanId, $cid,
                ($f[1] !== '' ? $f[1] : null), ($f[2] !== '' ? $f[2] : null),
                ($f[3] !== '' ? $f[3] : null), ($f[4] !== '' ? $f[4] : null),
                ($f[5] !== '' ? $f[5] : null), (int) $f[6],
            ]);
            $ctrIds[$cid] = (int) $pdo->lastInsertId();
        }
    }
    if ($ctrPkgCount > 0) {
        $ins = $pdo->prepare(
            'INSERT INTO tb_packages (scan_id, container_id, manager, name, version, source_pkg)
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
            'INSERT INTO tb_processes (scan_id, container_id, pid, comm, username, exe_pkg, loaded_pkgs)
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
            'INSERT INTO tb_exposures
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

    // 언어 패키지 벌크 — 같은 tb_packages 에 manager=pip|npm|gem|composer 로 넣는다.
    //   매처가 manager 로 생태계(PyPI/npm/…)를 정해 OS 패키지와 섞이지 않게 매칭한다.
    if ($langCount > 0) {
        $ins = $pdo->prepare(
            'INSERT INTO tb_packages (scan_id, manager, name, version) VALUES (?, ?, ?, ?)'
        );
        foreach ($langRows as $r) {
            $ins->execute([$scanId, $r[0], $r[1], $r[2]]);
        }
    }

    // 노출 벌크
    if ($expCount > 0) {
        $ins = $pdo->prepare(
            'INSERT INTO tb_exposures
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
            'INSERT INTO tb_processes (scan_id, pid, comm, username, exe_pkg, loaded_pkgs)
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
            'INSERT INTO tb_pkg_changelog_cves (scan_id, package_name, cve_id, evidence)
             VALUES (?, ?, ?, ?)'
        );
        foreach ($clogRows as $r) {
            $ins->execute([$scanId, $r[0], $r[1], $r[2]]);
        }
    }

    // 재시작 필요 벌크 (옛 라이브러리 상주 — 매처가 억제를 막는 근거로 사용)
    if ($staleCount > 0) {
        $ins = $pdo->prepare(
            'INSERT INTO tb_stale_libs (scan_id, pid, comm, package_name, lib_path)
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
        $q = $pdo->prepare('SELECT manager, name, version FROM tb_packages WHERE scan_id = ? AND container_id = 0');
        $q->execute([(int) $prev['id']]);
        $prevPkgs = [];
        foreach ($q->fetchAll() as $r) {
            $prevPkgs[$r['manager'] . '|' . $r['name']] = (string) $r['version'];
        }
        $curPkgs = vg_ingest_build_pkg_map($manager, $pkgRows, $langRows);
        // 배포판 규칙으로 비교해야 승강을 정확히 가른다(1:1.1 > 2.0 같은 epoch 사례).
        $pkgChanges = vg_ingest_diff_packages($prevPkgs, $curPkgs, 'vg_ver_cmp');

        $insChg = $pdo->prepare(
            'INSERT INTO tb_pkg_changes (host_id, scan_id, manager, package_name, change_type, old_version, new_version)
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

    $pdo->commit();
} catch (Throwable $e) {
    if (isset($pdo) && $pdo->inTransaction()) {
        $pdo->rollBack();
    }
    // 내부 오류 상세는 서버 로그로만. 클라이언트에는 일반 메시지(정보노출 방지).
    error_log('[ingest] ' . $e->getMessage());
    respond_fail(500, 'internal error', 'internal_error');
}

// 스캔 수신 감사로그(에이전트발 → SYSTEM).
vg_log_activity($pdo, 'HOST', $hostId, 'ingest', '스캔 수신',
    ['packages' => $pkgCount, 'exposures' => $expCount, 'processes' => $procCount], null, 'SYSTEM');

// 저장 성공 → 즉시 매칭(우선순위 산출). 실패해도 수집 자체는 성공으로 응답.
$findings = null;
try {
    $findings = vg_match_scan($pdo, $scanId);
} catch (Throwable $e) {
    $findings = ['error' => $e->getMessage()];
}

// 보안설정 점검(CCE) — 이미 수신한 security/users 섹션으로 판정. 실패해도 수집은 성공.
$cce = null;
try {
    $cce = vg_evaluate_cce($pdo, $scanId, $data);
} catch (Throwable $e) {
    $cce = ['error' => $e->getMessage()];
}

echo json_encode([
    'ok'        => true,
    'host_id'   => $hostId,
    'scan_id'   => $scanId,
    'fqdn'      => $fqdn,
    'packages'  => $pkgCount,
    'langpkgs'  => $langCount,
    'debsecan'  => $debsecanCount,
    // 피드 미지원 배포판이면 매칭이 0건이다 — 에이전트 로그에서 바로 보이도록 응답에 싣는다.
    //   (matcher.php 가 distro.php 를 로드하므로 vg_distro_unsupported 를 여기서 쓸 수 있다.)
    'warning'       => vg_distro_unsupported($vm['distro_id'] ?? null, $vm['distro_version'] ?? null),
    'containers'    => $ctrCount,
    'ctr_packages'  => $ctrPkgCount,
    'ctr_processes' => $ctrProcCount,
    'ctr_exposures' => $ctrExpCount,
    // 직전 수집과 내용이 같으면 새 스냅샷을 만들지 않는다(changed=false). 바뀐 패키지 수도 알려준다.
    'changed'     => !$unchanged,
    'pkg_changes' => $chgCount,
    'exposures' => $expCount,
    'processes' => $procCount,
    'findings'  => $findings,
    'cce'       => $cce,
], JSON_UNESCAPED_UNICODE);
