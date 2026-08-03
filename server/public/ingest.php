<?php
declare(strict_types=1);

/**
 * ingest.php — 수집 에이전트가 보낸 JSON 을 받아 중앙 DB 에 저장한다.
 *   인증 : 호스트 바인딩 토큰 (헤더 X-Agent-Token 또는 Authorization: Bearer)
 *   본문 : vuln-inventory-agent.sh (jq 모드) 가 만든 JSON
 *   저장 : hosts → scans → packages / exposures  (하나의 트랜잭션)
 */

header('Content-Type: application/json; charset=utf-8');

require __DIR__ . '/../src/config.php';
require __DIR__ . '/../src/db.php';
require __DIR__ . '/../src/matcher.php';
require __DIR__ . '/../src/cce.php';          // vg_evaluate_cce (보안설정 점검)
require __DIR__ . '/../src/rpmdb.php';        // vg_ingest_rpmdb_rows (컨테이너 rpm DB 를 중앙이 파싱)
require_once __DIR__ . '/../src/audit.php';   // vg_log_activity
require_once __DIR__ . '/../src/agenttoken.php';  // vg_agent_token_verify (호스트 바인딩)
require_once __DIR__ . '/../src/ingest_parse.php';  // vg_ingest_parse_* (순수 변환, DB 비의존)
require_once __DIR__ . '/../src/ingest_store.php';  // vg_ingest_store (트랜잭션 저장)

// 통일 에러 포맷: {ok:false,error,code,ts(ISO8601)}
function respond_fail(int $httpCode, string $msg, string $code): void {
    http_response_code($httpCode);
    echo json_encode(['ok' => false, 'error' => $msg, 'code' => $code, 'ts' => date('c')], JSON_UNESCAPED_UNICODE);
    exit;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    respond_fail(405, 'POST only', 'method_not_allowed');
}

// ── 인증 : 호스트 바인딩 개별 토큰만 허용 ───────────────────────────────────
// 토큰에 묶인 fqdn 만 갱신할 수 있다. 본문 fqdn 이 다르면 아래에서 403.
$provided  = vg_auth_token('X-Agent-Token');   // 커스텀 헤더 우선, 없으면 Authorization: Bearer
$pdoAuth   = vg_pdo();

$agentTok = vg_agent_token_verify($pdoAuth, (string) $provided);
if ($agentTok === null) {
    respond_fail(401, 'unauthorized', 'unauthorized');
}
$boundFqdn = $agentTok['fqdn'];
$nonce = trim((string) ($_SERVER['HTTP_X_AGENT_NONCE'] ?? ''));
$sentAt = (int) ($_SERVER['HTTP_X_AGENT_TIMESTAMP'] ?? 0);
if ($nonce !== '' || $sentAt > 0) {
    if (!vg_agent_nonce_accept($pdoAuth, (int) $agentTok['id'], $nonce, $sentAt)) {
        respond_fail(409, 'stale or replayed request', 'replay_rejected');
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
// 바인딩된 fqdn 만 갱신 가능. 본문이 다른 호스트를 주장하면 스푸핑 → 거부(403) + 감사.
if ($fqdn !== 'unknown' && $fqdn !== $boundFqdn) {
    vg_log_activity($pdoAuth, 'HOST', null, 'ingest_spoof_blocked',
        "토큰 바인딩 위반: 토큰은 [{$boundFqdn}] 에 묶였는데 본문은 [{$fqdn}] 주장 → 거부",
        ['bound' => $boundFqdn, 'claimed' => $fqdn], null, 'SYSTEM');
    respond_fail(403, 'token is bound to a different host', 'host_binding_violation');
}
$fqdn = $boundFqdn;   // 본문이 비었거나 일치 → 바인딩 값으로 강제.

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
$ctrExpRows  = vg_ingest_parse_container_exposures((string) ($ctr['exposure'] ?? ''));$sbom = vg_ingest_parse_sbom((string) ($ctr['sbom'] ?? ''));
$ctrPkgRows = array_merge($ctrPkgRows, $sbom['packages']);
foreach ($sbom['meta'] as $cid => $sm) {
    if (isset($ctrRows[$cid])) { $ctrRows[$cid][13]=$sm[0]; $ctrRows[$cid][14]=$sm[1]; }
}

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
// 수집 완전성은 취약점 0건과 별개다. 섹션이 없으면 "안전"이 아니라 누락으로 저장한다.
$collectionStages = [
    ['packages', $pkgCount > 0 ? 'COMPLETE' : 'MISSING', $pkgCount],
    ['language_packages', $langCount > 0 ? 'COMPLETE' : 'EMPTY', $langCount],
    ['runtime_processes', $procCount > 0 ? 'COMPLETE' : 'MISSING', $procCount],
    ['network_exposure', $expCount > 0 ? 'COMPLETE' : 'EMPTY', $expCount],
    ['containers', $ctrCount > 0 ? 'COMPLETE' : 'EMPTY', $ctrCount],
];

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
// ── 저장 (트랜잭션) ── 실 로직은 vg_ingest_store() 로 분리(server/src/ingest_store.php) ──
try {
    $pdo = vg_pdo();
    $store = vg_ingest_store(
        $pdo,
        [
            'fqdn'         => $fqdn,
            'vm'           => $vm,
            'meta'         => $meta,
            'sys'          => $sys,
            'raw'          => $raw,
            'collected_at' => $collectedAt,
            'remote_ip'    => $_SERVER['REMOTE_ADDR'] ?? null,
        ],
        [
            'manager'        => $manager,
            'pkg_rows'       => $pkgRows,
            'pkg_count'      => $pkgCount,
            'origin_map'     => $originMap,
            'ctr_rows'       => $ctrRows,
            'ctr_count'      => $ctrCount,
            'ctr_pkg_rows'   => $ctrPkgRows,
            'ctr_pkg_count'  => $ctrPkgCount,
            'ctr_proc_rows'  => $ctrProcRows,
            'ctr_proc_count' => $ctrProcCount,
            'ctr_exp_rows'   => $ctrExpRows,
            'ctr_exp_count'  => $ctrExpCount,
            'lang_rows'      => $langRows,
            'lang_count'     => $langCount,
            'exp_rows'       => $expRows,
            'exp_count'      => $expCount,
            'proc_rows'      => $procRows,
            'proc_count'     => $procCount,
            'clog_rows'      => $clogRows,
            'clog_count'     => $clogCount,
            'stale_rows'     => $staleRows,
            'stale_count'    => $staleCount,
            'debsecan_rows'  => $debsecanRows,
            'debsecan_count' => $debsecanCount,
            'errata_rows'    => $errataRows,
            'errata_count'   => $errataCount,
            'running_kernel' => $runningKernel,
            'kernel_latest'  => $kernelLatest,
            'kernel_reboot'  => $kernelReboot,
            'content_hash'   => $contentHash,
            'collection_stages' => $collectionStages,
        ]
    );
    $hostId    = $store['host_id'];
    $scanId    = $store['scan_id'];
    $unchanged = $store['unchanged'];
    $chgCount  = $store['chg_count'];
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

// ── 명령 큐 완료 처리 (optional) ─────────────────────────────
//   agent-poll.php 가 알려준 명령을 수행한 뒤 이 ingest 로 결과를 보고할 때 온다.
//   host_id 소유 확인 실패(다른 호스트의 command_id 주장) · 이미 done/failed 는 조용히 무시(멱등).
$commandId = $data['command_id'] ?? null;
if (is_int($commandId) || (is_string($commandId) && ctype_digit($commandId))) {
    $pdo->prepare(
        "UPDATE tb_agent_command SET status = 'done', executed_at = NOW()
          WHERE agent_command_id = ? AND host_id = ? AND status = 'pending' AND is_deleted = 0"
    )->execute([(int) $commandId, $hostId]);
}

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
