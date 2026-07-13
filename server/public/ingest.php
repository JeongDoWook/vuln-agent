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
require_once __DIR__ . '/../src/audit.php';   // vg_log_activity

// 통일 에러 포맷: {ok:false,error,code,ts(ISO8601)}
function respond_fail(int $httpCode, string $msg, string $code): void {
    http_response_code($httpCode);
    echo json_encode(['ok' => false, 'error' => $msg, 'code' => $code, 'ts' => date('c')], JSON_UNESCAPED_UNICODE);
    exit;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    respond_fail(405, 'POST only', 'method_not_allowed');
}

// ── 인증 : 공유 토큰 상수시간 비교 ─────────────────────────────
$expected = (string) ($cfg['ingest_token'] ?? '');
$provided = vg_auth_token('X-Agent-Token');   // 커스텀 헤더 우선, 없으면 Authorization: Bearer
if ($expected === '' || !hash_equals($expected, (string) $provided)) {
    respond_fail(401, 'unauthorized', 'unauthorized');
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

// collected_at (ISO-8601) → MySQL DATETIME
$collectedAt = null;
if (!empty($meta['collected_at'])) {
    $ts = strtotime((string) $meta['collected_at']);
    if ($ts !== false) {
        $collectedAt = date('Y-m-d H:i:s', $ts);
    }
}

// ── 패키지 목록 파싱 (매니저별 TSV) ──────────────────────────
$manager = (string) ($pkg['manager'] ?? '');
$pkgRows = [];
if (!empty($pkg['list'])) {
    foreach (preg_split('/\r?\n/', (string) $pkg['list']) as $line) {
        if ($line === '') { continue; }
        $f    = explode("\t", $line);
        $name = trim($f[0] ?? '');
        if ($name === '') { continue; }
        if ($manager === 'rpm') {
            // name \t epoch:version-release \t arch \t sourcerpm \t vendor
            $pkgRows[] = [$name, $f[1] ?? '', $f[2] ?? '', $f[3] ?? '', '', $f[4] ?? ''];
        } else {
            // dpkg: name \t version \t arch \t source_pkg \t source_version \t status
            //   상태가 'ii'(설치됨)가 아닌 행은 버린다. 'rc' 는 **제거됐고 설정만 남은** 패키지라
            //   실제로 설치돼 있지 않다 — 예전엔 이것도 설치로 저장해 없는 패키지의 CVE 가 떴다.
            $st = trim($f[5] ?? '');
            if ($st !== '' && substr($st, 1, 1) !== 'i') { continue; }
            // source_version 은 OSV 의 deb 조치안(소스 버전 기준)과 비교하는 데 쓴다.
            $pkgRows[] = [$name, $f[1] ?? '', $f[2] ?? '', $f[3] ?? '', $f[4] ?? '', ''];
        }
    }
}
$pkgCount = count($pkgRows);

// ── 언어 패키지 파싱 (pip/npm/gem/composer) ────────────────────
//   에이전트가 수집해 보내는데 지금까지 서버가 버리고 있었다 → 언어 패키지 CVE 가 전부 미탐.
//   OSV 는 PyPI/npm/RubyGems/Packagist 생태계를 그대로 지원한다.
//   실제 출력 형식(컨테이너에서 확인):
//     pip      : "requests==2.31.0"                       (pip3 list --format=freeze)
//     npm      : "+-- corepack@0.34.6" / "`-- npm@10.8.2" (npm ls -g --depth=0, 트리)
//     gem      : "abbrev (default: 0.1.1)" / "rails (7.0.4, 6.1.7)"
//     composer : "psr/log 3.0.2 설명"
$langRows = [];
$addLang = static function (string $mgr, string $name, string $ver) use (&$langRows): void {
    $name = trim($name); $ver = trim($ver);
    if ($name === '' || $ver === '') { return; }
    $langRows["$mgr|$name"] = [$mgr, mb_strimwidth($name, 0, 255, ''), mb_strimwidth($ver, 0, 255, '')];
};
$lang = $data['langpkg'] ?? [];
foreach (preg_split('/\r?\n/', (string) ($lang['pip'] ?? '')) as $line) {
    if (preg_match('/^([A-Za-z0-9._-]+)==(\S+)$/', trim($line), $m)) { $addLang('pip', $m[1], $m[2]); }
}
foreach (preg_split('/\r?\n/', (string) ($lang['npm_global'] ?? '')) as $line) {
    // 트리 장식(├──, └──, +--, `--)을 걷어내고 name@version. 스코프 패키지는 @scope/name@1.2.3.
    $t = trim(preg_replace('/^[\s|`+\x{2500}-\x{257F}-]+/u', '', $line) ?? '');
    if (preg_match('/^(@?[^@\s]+(?:\/[^@\s]+)?)@(\S+)$/', $t, $m)) { $addLang('npm', $m[1], $m[2]); }
}
foreach (preg_split('/\r?\n/', (string) ($lang['gem'] ?? '')) as $line) {
    // "rails (7.0.4, 6.1.7)" → 첫 버전만. "abbrev (default: 0.1.1)" 의 default: 도 제거.
    if (preg_match('/^(\S+)\s+\((?:default:\s*)?([^,)]+)/', trim($line), $m)) { $addLang('gem', $m[1], $m[2]); }
}
foreach (preg_split('/\r?\n/', (string) ($lang['composer'] ?? '')) as $line) {
    if (preg_match('#^(\S+/\S+)\s+(\S+)#', trim($line), $m)) { $addLang('composer', $m[1], $m[2]); }
}
$langRows  = array_values($langRows);
$langCount = count($langRows);

// ── 노출 상관 파싱 (pipe 구분, 첫 줄은 헤더) ─────────────────
$expRows = [];
if (!empty($exp['correlation'])) {
    foreach (preg_split('/\r?\n/', (string) $exp['correlation']) as $line) {
        if ($line === '') { continue; }
        if (strncmp($line, 'pid|proc|proto', 14) === 0) { continue; } // 헤더 스킵
        $f = explode('|', $line);
        if (count($f) < 8) { continue; }
        $expRows[] = $f; // pid,proc,proto,bind,port,scope,exe_pkg,loaded_pkgs
    }
}
$expCount = count($expRows);

// ── 실행 프로세스 파싱 (pipe, 첫 줄 헤더) — 실행중/사용중 구분용 ──
$procRows = [];
$rt = $data['runtime'] ?? [];
if (!empty($rt['processes'])) {
    foreach (preg_split('/\r?\n/', (string) $rt['processes']) as $line) {
        if ($line === '') { continue; }
        if (strncmp($line, 'pid|comm|user', 13) === 0) { continue; } // 헤더
        $f = explode('|', $line);
        if (count($f) < 5) { continue; }
        $procRows[] = $f; // pid, comm, user, exe_pkg, loaded_pkgs
    }
}
$procCount = count($procRows);

// ── 재시작 필요 파싱 (pipe, 첫 줄 헤더) ──
//   업데이트로 교체된 옛 라이브러리를 아직 물고 있는 프로세스. 패키지는 패치됐어도
//   그 프로세스는 여전히 옛 코드를 실행한다 → 매처가 "이미 패치됨" 억제를 막는 근거.
$staleRows = [];
if (!empty($rt['stale'])) {
    foreach (preg_split('/\r?\n/', (string) $rt['stale']) as $line) {
        if ($line === '') { continue; }
        if (strncmp($line, 'pid|comm|pkg', 12) === 0) { continue; } // 헤더
        $f = explode('|', $line);
        if (count($f) < 4 || trim($f[2]) === '') { continue; }
        $staleRows[] = $f; // pid, comm, pkg, lib
    }
}
$staleCount = count($staleRows);

// ── changelog CVE 파싱 — 패키지별 changelog 에 나온 CVE(백포트 근거) ──
//   에이전트가 --no-changelog 로 돌면 이 섹션이 비어 clogCount=0 → 무해(억제 없음).
$clogRows = [];
$clog = $data['changelog'] ?? [];
if (is_array($clog)) {
    foreach ($clog as $pkgName => $text) {
        $pkgName = trim((string) $pkgName);
        if ($pkgName === '' || !is_string($text) || $text === '') { continue; }
        foreach (preg_split('/\r?\n/', $text) as $line) {
            if (!preg_match_all('/CVE-\d{4}-\d{4,}/i', $line, $m)) { continue; }
            foreach (array_unique($m[0]) as $cve) {
                $cve = strtoupper($cve);
                $k = $pkgName . '|' . $cve;
                if (isset($clogRows[$k])) { continue; }   // (패키지,CVE)당 첫 근거 줄만
                $clogRows[$k] = [$pkgName, $cve, mb_strimwidth(trim($line), 0, 255, '')];
            }
        }
    }
}
$clogCount = count($clogRows);

// ── errata CVE 파싱 — 이미 적용된 벤더 보안권고가 고친 CVE (백포트 근거, 시스템 전체) ──
//   `dnf updateinfo list installed --with-cve` 형식:
//     "CVE-2022-3715  Moderate/Sec.  bash-5.1.8-6.el9_1.x86_64"
//   같은 목록에 권고 ID 줄(RLSA-2023:0340 …)도 섞여 오지만 CVE 줄만 취한다.
//   NEVRA 에서 패키지명만 뽑는다: 뒤의 .arch 를 떼고 -version-release 둘을 떼면 name.
$errataRows = [];
$errataText = (string) ($upd['errata_cves'] ?? '');
foreach (preg_split('/\r?\n/', $errataText) as $line) {
    if (!preg_match('/^\s*(CVE-\d{4}-\d{4,})\s+\S+\s+(\S+)\s*$/i', $line, $m)) { continue; }
    $cve   = strtoupper($m[1]);
    $nevra = $m[2];
    $base  = preg_replace('/\.(x86_64|i686|aarch64|noarch|ppc64le|s390x)$/', '', $nevra);
    // name-version-release → 뒤에서 두 조각(version, release)을 떼면 name
    $parts = explode('-', (string) $base);
    if (count($parts) < 3) { continue; }
    array_pop($parts); array_pop($parts);
    $pkgName = implode('-', $parts);
    if ($pkgName === '') { continue; }
    $k = $pkgName . '|' . $cve;
    if (isset($errataRows[$k])) { continue; }
    $errataRows[$k] = [$pkgName, $cve, mb_strimwidth(trim($nevra), 0, 255, '')];
}
$errataCount = count($errataRows);

// ── debsecan 파싱 — 데비안 보안 트래커가 "아직 취약하다"고 판정한 CVE (데비안 전용) ──
//   형식: "CVE-2026-13595 bsdutils" (debsecan --format simple)
//   errata 와 방향이 반대다: errata 는 고쳐진 CVE, debsecan 은 남아 있는 CVE 를 준다.
//   → 매처는 "여기 없는 deb CVE = 백포트로 이미 수정됨"으로 억제한다.
$debsecanRows = [];
foreach (preg_split('/\r?\n/', (string) ($upd['debsecan'] ?? '')) as $line) {
    if (!preg_match('/^\s*(CVE-\d{4}-\d{4,})\s+(\S+)\s*$/i', $line, $m)) { continue; }
    $k = strtoupper($m[1]) . '|' . $m[2];
    $debsecanRows[$k] = [strtoupper($m[1]), mb_strimwidth($m[2], 0, 255, '')];
}
$debsecanRows  = array_values($debsecanRows);
$debsecanCount = count($debsecanRows);

// ── 내용 해시 — "바뀔 때만 스냅샷" 판정 ────────────────────────
//   수집 내용이 직전과 같으면 새 스캔을 만들지 않는다(대부분의 수집이 여기 해당한다).
//   **PID 는 넣지 않는다** — 재부팅·프로세스 재시작마다 바뀌어서, 넣으면 매번 "변경됨"이 되어
//   스냅샷을 매번 찍게 된다. 의미 있는 인벤토리(패키지·언어패키지·OS/커널·노출 포트·재시작필요)만 본다.
$hashParts = [];
foreach ($pkgRows as $r)  { $hashParts[] = "p|$manager|{$r[0]}|{$r[1]}"; }
foreach ($langRows as $r) { $hashParts[] = "l|{$r[0]}|{$r[1]}|{$r[2]}"; }
foreach ($expRows as $f)  {   // pid($f[0]) 제외: proc|proto|bind|port|scope|exe_pkg|loaded_pkgs
    $hashParts[] = 'e|' . implode('|', array_slice($f, 1, 7));
}
foreach ($staleRows as $r) { $hashParts[] = "s|{$r[2]}|{$r[3]}"; }
$hashParts[] = 'o|' . ($vm['distro_id'] ?? '') . '|' . ($vm['distro_version'] ?? '')
             . '|' . ($sys['kernel_release'] ?? ($sys['kernel'] ?? ''));
sort($hashParts);
$contentHash = hash('sha256', implode("\n", $hashParts));
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
            'UPDATE tb_scans SET collected_at = :ca, agent_version = :av, elapsed_seconds = :el WHERE id = :id'
        )->execute([
            ':ca' => $collectedAt,
            ':av' => ($meta['agent_version'] ?? '') ?: null,
            ':el' => isset($meta['elapsed_seconds']) ? (int) $meta['elapsed_seconds'] : null,
            ':id' => $scanId,
        ]);
    } else {
    // 스캔 1행
    $stmt = $pdo->prepare(
        'INSERT INTO tb_scans
            (host_id, collected_at, agent_version, elapsed_seconds,
             os_id, os_version, kernel, cpe, package_family, content_hash,
             package_count, exposure_count, raw_json)
         VALUES
            (:h, :ca, :av, :el, :osid, :osver, :kern, :cpe, :fam, :hash, :pc, :ec, :raw)'
    );
    $stmt->execute([
        ':h'     => $hostId,
        ':ca'    => $collectedAt,
        ':av'    => ($meta['agent_version'] ?? '') ?: null,
        ':el'    => isset($meta['elapsed_seconds']) ? (int) $meta['elapsed_seconds'] : null,
        ':osid'  => ($vm['distro_id'] ?? '') ?: null,
        ':osver' => ($vm['distro_version'] ?? '') ?: null,
        ':kern'  => ($sys['kernel_release'] ?? ($sys['kernel'] ?? '')) ?: null,
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
            'INSERT INTO tb_packages (scan_id, manager, name, version, arch, source_pkg, source_version, vendor)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
        );
        foreach ($pkgRows as $r) {
            $ins->execute([$scanId, $manager, $r[0], $r[1], $r[2], $r[3], $r[4], $r[5]]);
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
        $q = $pdo->prepare('SELECT manager, name, version FROM tb_packages WHERE scan_id = ?');
        $q->execute([(int) $prev['id']]);
        $prevPkgs = [];
        foreach ($q->fetchAll() as $r) {
            $prevPkgs[$r['manager'] . '|' . $r['name']] = (string) $r['version'];
        }
        $curPkgs = [];
        foreach ($pkgRows as $r)  { $curPkgs[$manager . '|' . $r[0]] = (string) $r[1]; }
        foreach ($langRows as $r) { $curPkgs[$r[0] . '|' . $r[1]]    = (string) $r[2]; }

        $insChg = $pdo->prepare(
            'INSERT INTO tb_pkg_changes (host_id, scan_id, manager, package_name, change_type, old_version, new_version)
             VALUES (?, ?, ?, ?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE change_type=VALUES(change_type),
               old_version=VALUES(old_version), new_version=VALUES(new_version)'
        );
        $emit = static function (string $key, string $type, ?string $old, ?string $new)
                use ($insChg, $hostId, $scanId, &$chgCount): void {
            [$mgr, $name] = explode('|', $key, 2);
            $insChg->execute([$hostId, $scanId, $mgr, $name, $type, $old, $new]);
            $chgCount++;
        };
        foreach ($curPkgs as $k => $v) {
            if (!isset($prevPkgs[$k])) {
                $emit($k, 'installed', null, $v);
            } elseif ($prevPkgs[$k] !== $v) {
                [$mgr] = explode('|', $k, 2);
                // 배포판 규칙으로 비교해야 승강을 정확히 가른다(1:1.1 > 2.0 같은 epoch 사례).
                $up = vg_ver_cmp($v, $prevPkgs[$k], $mgr) >= 0;
                $emit($k, $up ? 'upgraded' : 'downgraded', $prevPkgs[$k], $v);
            }
        }
        foreach ($prevPkgs as $k => $v) {
            if (!isset($curPkgs[$k])) { $emit($k, 'removed', $v, null); }
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
    // 직전 수집과 내용이 같으면 새 스냅샷을 만들지 않는다(changed=false). 바뀐 패키지 수도 알려준다.
    'changed'     => !$unchanged,
    'pkg_changes' => $chgCount,
    'exposures' => $expCount,
    'processes' => $procCount,
    'findings'  => $findings,
    'cce'       => $cce,
], JSON_UNESCAPED_UNICODE);
