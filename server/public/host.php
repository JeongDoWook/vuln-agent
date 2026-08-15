<?php
declare(strict_types=1);

/**
 * host.php — 호스트 상세(자산 상세). 로그인 필요.
 *   ?id=<host_id> 의 최신 스캔을 하나의 자산 화면으로 보여준다.
 *   상단: 자산 식별 + 최고 위험도 히어로 + KPI.
 *   그 아래 섹션 탭(취약점 / 런타임 / 보안설정 / 억제 / 스캔이력) — 각 탭이 자기 데이터를
 *   서버 페이지네이션한다. ?tab= 이 활성 탭, ?page= 는 그 활성 탭에만 적용된다.
 */

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require __DIR__ . '/../src/distro.php';   // vg_distro_unsupported — 피드 미지원 배포판 경고
require_once __DIR__ . '/../src/audit.php';   // vg_log_activity
require_once __DIR__ . '/../src/matcher.php';
require_once __DIR__ . '/../src/finding_history.php';   // vg_finding_history_url — 이력 링크 조립
require_once __DIR__ . '/../src/finding_status.php';    // 조치 상태(사람이 정하는 값) 조회·저장
require_once __DIR__ . '/../src/agentcommand.php';   // 수집 제어(즉시/예약 실행·주기 변경)
require_once __DIR__ . '/../src/agentspeedtier.php';   // 속도 티어 라벨(agent-poll.php 와 공유 정의)
require_once __DIR__ . '/../src/assetgrade.php';       // 자산 중요도·N2SF 등급 어휘와 초안 제안
require_once __DIR__ . '/../src/assetgrade_history.php'; // 시스템 제안 관찰 이력 조회·표시
require_once __DIR__ . '/../src/asset_grade_review.php'; // 단일 자산의 구조화된 사람 검토 정보
require_once __DIR__ . '/../src/account_inventory.php';   // 계정 인벤토리 판정(vg_account_judgments)
require_once __DIR__ . '/../src/packagedep.php';   // 의존성 그래프 — 취약점의 직접/전이 판정
require_once __DIR__ . '/../src/suppression.php';  // 억제 근거 겹 분류·원근거 조회·재시작 필요 목록
vg_require_menu_any('assets', 'findings');   // 자산 상세: 자산 목록·탐지 결과에서 함께 열린다

/* '리소스' 탭은 '스캔 이력' 탭으로 흡수됐다 — 둘 다 tb_scan_run 하나를 읽었고(회차별 메모리·CPU),
 *   한쪽은 표, 다른 쪽은 같은 값의 추이 차트였다. 탭을 나눠 두면 "이 자산의 수집이 어땠나"를
 *   두 군데서 이어 붙여 읽어야 한다. 기존 링크·북마크를 살리려고 302 로 넘긴다(나머지 쿼리는 유지). */
if (($_GET['tab'] ?? '') === 'resources') {
    header('Location: /host.php' . vg_qs(['tab' => 'scans', 'page' => null]), true, 302);
    exit;
}

// --- 수집 제어 POST 처리 (즉시실행/예약실행/주기변경) — GET 렌더보다 먼저, 헤더 출력 전 ---
//   자산관리(assets)와 같은 인가 범위를 쓴다 — 새 메뉴 코드를 만들지 않는다(YAGNI).
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $agentMsg = null; $agentErr = null;
    $postHostId = (int) ($_GET['id'] ?? $_POST['id'] ?? 0);
    $action = (string) ($_POST['action'] ?? '');
    // 수집 제어·자산 등급·삭제는 자산관리(assets) 권한이고, 탐지 결과의 조치 상태는 이 화면과
    //   같은 findings 권한이다 — 축이 다른 작업을 한 메뉴 권한에 묶지 않는다.
    $postMenu = $action === 'finding_set_status' ? 'findings' : 'assets';
    if (!vg_csrf_check($_POST['csrf'] ?? null)) {
        $agentErr = '세션이 만료되었습니다.';
    } elseif (!vg_can($postMenu)) {
        http_response_code(403);
        echo 'forbidden';
        exit;
    } else {
        $pdo = vg_pdo();
        $me = vg_current_user();
        try {
            if ($action === 'agent_run_now') {
                vg_agent_command_create($pdo, $postHostId, null, $me['id'] ?? null);
                $agentMsg = '즉시 실행 명령을 등록했습니다. 에이전트가 다음 poll 에서 실행합니다.';
            } elseif ($action === 'agent_cancel') {
                vg_agent_command_cancel($pdo, $postHostId, (int) ($_POST['command_id'] ?? 0), $me['id'] ?? null);
                $agentMsg = '수집 중단을 요청했습니다.';
            } elseif ($action === 'agent_schedule') {
                $runAtRaw = trim((string) ($_POST['run_at'] ?? ''));
                if ($runAtRaw === '') {
                    throw new RuntimeException('예약 시각을 입력하세요.');
                }
                // <input type="datetime-local"> 은 'YYYY-MM-DDTHH:MM' 을 준다 — DB 포맷으로 변환.
                $runAt = str_replace('T', ' ', $runAtRaw) . ':00';
                vg_agent_command_create($pdo, $postHostId, $runAt, $me['id'] ?? null);
                $agentMsg = '예약 실행 명령을 등록했습니다.';
            } elseif ($action === 'agent_set_schedule') {
                // 화면은 분 단위로 받고 저장은 초로 환산한다(사람이 시간을 셀 때는 분이 더 익숙하다).
                $minutes = (int) ($_POST['schedule_minutes'] ?? 0);
                vg_agent_command_set_schedule($pdo, $postHostId, $minutes * 60);
                $agentMsg = "수집 주기를 {$minutes}분으로 변경했습니다.";
            } elseif ($action === 'agent_set_speed_tier') {
                if (!vg_has_role('admin', 'operator')) {
                    throw new RuntimeException('속도 티어를 변경할 권한이 없습니다.');
                }
                $tier = (string) ($_POST['agent_speed_tier'] ?? '');
                vg_agent_command_set_speed_tier($pdo, $postHostId, $tier);
                $agentMsg = '속도 티어를 변경했습니다. 다음 poll/다음 수집 시작부터 반영됩니다.';
            } elseif ($action === 'host_set_grade') {
                /* 자산 등급 **확정** — 사람의 판정이다. 시스템 제안(grade_suggested)은 여기서
                 * 건드리지 않고, 확정값만 별도 컬럼에 쓴다. 확정은 관리자만 할 수 있다
                 * (인가는 클라이언트 숨김이 아니라 여기 서버측에서 정해진다). */
                if (!vg_has_role('admin')) {
                    throw new RuntimeException('자산 등급을 확정할 권한이 없습니다.');
                }
                // 등급 검증·기록은 assetgrade.php 의 공통 함수를 재사용하고, 전용 모듈이 구조화
                // 검토 정보까지 같은 트랜잭션으로 묶는다. 일괄 확정은 호스트별 검토 정보에 손대지 않는다.
                //   이 폼은 중요도를 늘 함께 보내므로 빈 값이면 "미지정으로 지움"이 맞다(null 이 아니다).
                $newGrade = (string) ($_POST['grade'] ?? '');
                vg_asset_grade_review_confirm(
                    $pdo,
                    $postHostId,
                    $newGrade,
                    (string) ($_POST['criticality'] ?? ''),
                    (string) ($_POST['grade_reason'] ?? ''),
                    $_POST,
                    $me['id'] ?? null
                );
                $agentMsg = $newGrade === ''
                    ? '자산 등급 확정을 해제했습니다.'
                    : "자산 등급을 {$newGrade} 로 확정했습니다.";
            } elseif ($action === 'finding_set_status') {
                /* 탐지 결과 한 건의 조치 상태. 상태 4개와 메모 한 줄이 전부다 —
                 * 담당자·결재선·재점검 확인은 만들지 않는다(마이그레이션 머리주석 참조).
                 * 쓰기 작업이므로 역할을 서버측에서 확정한다(모달에서 폼을 숨긴 것은 통제가 아니다). */
                if (!vg_has_role('admin', 'operator')) {
                    throw new RuntimeException('조치 상태를 변경할 권한이 없습니다.');
                }
                $fsCve = trim((string) ($_POST['cve_id'] ?? ''));
                $fsPkg = trim((string) ($_POST['package_name'] ?? ''));
                if ($fsCve === '' || $fsPkg === '') {
                    throw new RuntimeException('대상 취약점을 확인할 수 없습니다.');
                }
                $fsRef    = (string) ($_POST['container_ref'] ?? '');
                $fsStatus = (string) ($_POST['status'] ?? '');
                $fsNote   = (string) ($_POST['note'] ?? '');
                vg_finding_status_save($pdo, $postHostId, $fsRef, $fsCve, $fsPkg, $fsStatus, $fsNote, $me['id'] ?? null);
                // 누가 무엇을 어떤 상태로 바꿨는지 남긴다. 메모 원문은 메시지에 싣지 않는다 —
                //   사람이 쓴 문장이라 길이를 예측할 수 없다(남긴 사실은 data 로 충분하다).
                vg_log_activity($pdo, 'HOST', $postHostId, 'finding_set_status',
                    "조치 상태 변경: $fsCve · $fsPkg → " . vg_finding_status_label($fsStatus),
                    ['cve_id' => $fsCve, 'package_name' => $fsPkg, 'container_ref' => $fsRef,
                     'status' => $fsStatus, 'note_len' => mb_strlen(trim($fsNote))],
                    $me['id'] ?? null, subject: $fsCve, action: 'UPDATE');
                $agentMsg = $fsCve . ' 의 조치 상태를 ' . vg_finding_status_label($fsStatus) . ' 로 저장했습니다.';
            } elseif ($action === 'host_delete') {
                if (!vg_has_role('admin', 'operator')) {
                    throw new RuntimeException('자산을 삭제할 권한이 없습니다.');
                }
                $st = $pdo->prepare('SELECT fqdn FROM tb_host WHERE host_id = ? AND is_deleted = 0');
                $st->execute([$postHostId]);
                $fqdn = $st->fetchColumn();
                if ($fqdn === false) {
                    throw new RuntimeException('호스트를 찾을 수 없습니다.');
                }
                vg_soft_delete($pdo, 'tb_host', $postHostId);
                vg_log_activity($pdo, 'HOST', $postHostId, 'host_delete', "자산 삭제: $fqdn",
                    subject: (string) $fqdn, action: 'DELETE');
                $_SESSION['vg_flash'] = [
                    'assetMsg' => "자산 '$fqdn' 을(를) 삭제했습니다. 해당 호스트가 다시 수집을 보내면 재등록됩니다.",
                ];
                header('Location: /assets.php', true, 303);
                exit;
            }
        } catch (Throwable $e) {
            error_log('[host-agent-command] ' . $e->getMessage());
            $agentErr = $e instanceof RuntimeException ? $e->getMessage() : '처리 중 오류가 발생했습니다.';
        }
    }
    vg_redirect_flash(['agentMsg' => $agentMsg, 'agentErr' => $agentErr]);
}
$agentFlash = vg_flash_take();
$agentMsg = $agentFlash['agentMsg'] ?? null;
$agentErr = $agentFlash['agentErr'] ?? null;
$agentCsrf = vg_csrf_token();

$err = null; $host = null; $scan = null; $scanAge = null; $pollAge = null; $approver = null; $gradeReview = [];
$unsupContainers = [];   // 피드 미지원 배포판 컨테이너
$missingStages = [];     // 최신 스캔에서 수집 자체가 실패한 단계(한글 라벨)
$missingStageCodes = []; // 같은 것의 원본 코드 — 화면이 "이 항목이 미수집인가"를 물을 때 쓴다
$integrityRows = [];     // 패키지 원본과 다른 파일(상위 일부만 — 전체 건수는 tb_scan 에 있다)
$suppEvidence = ['errata' => [], 'changelog' => [], 'debsecan' => []];   // 억제 근거 원 데이터
$suppLayers = [];        // 억제 근거 겹별 건수(스캔 전체)
$staleLibs = ['total' => 0, 'rows' => []];   // 재시작 필요(옛 라이브러리를 물고 있는 프로세스)
$gradeSignals = [];      // 등급 제안 근거 신호(자산 설정 탭에서만 계산한다)

// 무결성 목록은 "상태를 알리는 미리보기"다. 전체 목록 화면은 만들지 않는다(YAGNI).
const VG_HOST_INTEGRITY_TOP = 20;

// 재시작 필요 목록도 같은 성격의 미리보기다(프로세스·패키지로 묶은 상위 일부 + 전체 건수).
const VG_HOST_STALE_TOP = 20;

// --- 탭별 데이터 조회 (?tab= 에 따라 갈리는 SQL). 각자 {total, rows, ...} 형태의 배열을 반환한다. ---

function vg_host_load_vuln_tab(PDO $pdo, int $sid, int $critHighTotal, int $perPage, int $offset, ?string $q = null): array {
    /* 성격이 다른 두 부류를 한 목록에 섞고 페이지를 나누면, 어느 한쪽은 반드시 뒤로 밀린다.
     *   - 등급순으로 정렬했더니: 커널 재부팅 건(등급이 낮다)이 2페이지로 밀려 사라졌다.
     *   - 그래서 needs_restart 를 맨 위로 올렸더니: 이번엔 **CRITICAL 이 안 보였다**
     *     (실측: web01 은 재시작 필요 건이 앞을 다 채워 CRITICAL 2건이 44페이지 뒤로 갔다).
     * 정렬로는 못 푼다 — 표를 둘로 나눈다. 각자 자기 기준으로 정렬하고, 둘 다 첫 화면에 있다.
     *   표1(주 목록·페이지네이션): CRITICAL·HIGH — 등급 → EPSS 순
     *   표2(상위 N건 + 전체보기):  재시작·재부팅 필요 — 등급이 낮아도 놓치면 안 되는 부류
     *                              (이미 패치됐는데 옛 코드가 상주해 "패치됨"으로 사라진다)
     * 검색(q)은 표1(주 목록)에만 적용한다 — 표2는 "상위 N건은 놓치지 않는다"가 목적이라
     *   필터링하면 그 의도와 충돌한다.
     */
    /* 컨테이너 **이름**(cid)까지 함께 읽는다 — 조치 상태는 스캔이 바뀌어도 유지되는 자연키
     *   (host_id, 컨테이너 이름, cve_id, 패키지명)로 붙기 때문이다. 숫자 container_id 는
     *   스캔마다 새로 발급돼 그 키로 쓸 수 없다(finding_history.php 머리주석). */
    $sel = "SELECT f.severity, f.runtime_status, f.cve_id, f.package_name, f.installed_version, f.rationale,
                   f.needs_restart, f.container_id, f.in_kev, c.epss, c.epss_percentile, c.ref_urls_json,
                   IFNULL(ctr.cid, '') AS container_cid,
               " . VG_FIXED_VERSION_SUBQ . "
              FROM tb_finding f
              LEFT JOIN tb_cve c ON c.cve_id = f.cve_id
              LEFT JOIN tb_container ctr ON ctr.container_id = f.container_id";

    $where = "f.scan_id = ? AND f.severity IN ('CRITICAL','HIGH')";
    $params = [$sid];
    if ($q !== null && $q !== '') {
        $where .= ' AND (f.cve_id LIKE ? OR f.package_name LIKE ?)';
        $params[] = '%' . $q . '%';
        $params[] = '%' . $q . '%';
    }

    if ($q !== null && $q !== '') {
        $cnt = $pdo->prepare("SELECT COUNT(*) FROM tb_finding f WHERE $where");
        $cnt->execute($params);
        $total = (int) $cnt->fetchColumn();
    } else {
        $total = $critHighTotal;
    }

    $st = $pdo->prepare(
        "$sel WHERE $where
         ORDER BY FIELD(f.severity,'CRITICAL','HIGH'), c.epss DESC, f.cve_id
         LIMIT $perPage OFFSET $offset"
    );
    $st->execute($params);
    $rows = $st->fetchAll();

    $st = $pdo->prepare(
        "$sel WHERE f.scan_id = ? AND f.needs_restart = 1
         ORDER BY FIELD(f.severity,'CRITICAL','HIGH','MEDIUM','LOW'), c.epss DESC, f.cve_id
         LIMIT " . vg_ui_detail_preview_limit()
    );
    $st->execute([$sid]);
    $restartRows = $st->fetchAll();

    return ['total' => $total, 'rows' => $rows, 'restartRows' => $restartRows];
}

/**
 * 같은 패키지에서 나온 CRITICAL·HIGH 묶음 — "이 하나를 올리면 N건 해결".
 *
 *   왜 필요한가: 표를 행 단위로만 보면 libc6 하나가 만든 CVE 5건이 "서로 다른 다섯 문제"처럼
 *   보인다. 근거 문장까지 사실상 같아서 화면이 반복으로 채워진다. 손댈 대상 기준으로 먼저
 *   묶어 두면 "무엇부터 올리나"에 한 줄로 답한다.
 *   의존성 부모별 묶음(vg_pkgdep_scan_rollup)과 같은 질문에 답하지만 대상이 다르다 —
 *   저쪽은 **전이 의존성이 있는 자산**(언어 패키지), 이쪽은 **모든 자산**의 OS 패키지다.
 *
 *   집계는 스캔 전체 기준이라 페이지·검색을 넘겨도 값이 변하지 않는다.
 *   2건 이상 묶이는 것만 남긴다(1건짜리는 묶음이 아니라 그냥 그 행이다).
 */
function vg_host_load_pkg_rollup(PDO $pdo, int $sid, int $limit): array {
    // FIELD() 는 CRITICAL=1, HIGH=2 — MIN 이 그 묶음의 최고 등급이다.
    //   상한+1 을 읽어 "더 있다"를 알 수 있게 한다 — 조용히 자르면 이게 전부처럼 보인다.
    $st = $pdo->prepare(
        "SELECT package_name, installed_version, COUNT(*) AS cnt,
                MIN(FIELD(severity,'CRITICAL','HIGH')) AS sev_rank,
                MAX(in_kev) AS kev, MAX(needs_restart) AS needs_restart
           FROM tb_finding
          WHERE scan_id = ? AND severity IN ('CRITICAL','HIGH')
          GROUP BY package_name, installed_version
         HAVING cnt > 1
          ORDER BY cnt DESC, sev_rank, package_name
          LIMIT " . ($limit + 1)
    );
    $st->execute([$sid]);
    $rows = $st->fetchAll();
    $truncated = count($rows) > $limit;
    if ($truncated) { $rows = array_slice($rows, 0, $limit); }
    foreach ($rows as &$r) {
        $r['severity'] = ((int) $r['sev_rank']) === 1 ? 'CRITICAL' : 'HIGH';
    }
    unset($r);
    return ['rows' => $rows, 'truncated' => $truncated];
}

/** 취약점 행 → 의존성 판정 캐시의 키. 형식의 정본은 packagedep.php 다(집계도 같은 키를 쓴다). */
function vg_host_dep_key(array $f): string {
    return vg_pkgdep_finding_key(
        (int) ($f['container_id'] ?? 0),
        (string) ($f['package_name'] ?? ''),
        (string) ($f['installed_version'] ?? '')
    );
}

/** 손댈 대상(부모) 라벨 — "이름 버전 이 끌어옴 [외 N개]". 이스케이프 전의 평문이다. */
function vg_host_dep_parent_label(array $o): string {
    $p = vg_pkgdep_parts((string) $o['parents'][0]);
    $more = count($o['parents']) - 1;
    return $p['name'] . ' ' . $p['version'] . ' 이 끌어옴' . ($more > 0 ? ' 외 ' . $more . '개' : '');
}

/**
 * 전이 의존성일 때의 조치 셀 — "직접 조치 불가" + 손댈 대상 + 의존성 경로 링크.
 *   **버전은 제안하지 않는다.** 설치되지 않은 부모 버전이 무엇을 끌어오는지 우리는 모른다
 *   (그걸 알려면 업스트림 버전별 의존성 DB 가 필요하다). 틀린 조치 제안은 없는 것보다 나쁘다.
 */
function vg_host_dep_origin_cell(array $o, int $hostId): string {
    $t = vg_pkgdep_parts((string) $o['key']);
    $url = '/depgraph.php?id=' . $hostId . '&cid=' . (int) $o['container_id']
         . '&mgr=' . urlencode($t['manager']) . '&name=' . urlencode($t['name'])
         . '&ver=' . urlencode($t['version']) . '&tab=from';
    return '<span class="pill">직접 조치 불가</span>'
        . '<div class="why">' . vg_h(vg_host_dep_parent_label($o))
        . ' · <a href="' . vg_h($url) . '">의존성 경로</a></div>';
}

/**
 * 손댈 대상(부모) 요약 표의 한 행 → 이름·버전 + 의존성 그래프 링크.
 *   링크는 "무엇을 끌어오나"(tab=to) 로 건다 — 이 부모를 올리면 무엇이 함께 바뀌는지가
 *   여기서 궁금한 것이다(행 단위 셀의 링크는 반대로 "무엇이 끌어왔나"였다).
 */
function vg_host_dep_rollup_target(array $p, int $hostId): string {
    $t = vg_pkgdep_parts((string) $p['key']);
    $url = '/depgraph.php?id=' . $hostId . '&cid=' . (int) $p['container_id']
         . '&mgr=' . urlencode($t['manager']) . '&name=' . urlencode($t['name'])
         . '&ver=' . urlencode($t['version']) . '&tab=to';
    return '<strong>' . vg_h($t['name']) . '</strong> <span class="why">' . vg_h($t['version']) . '</span>'
        . ' <a class="pill" href="' . vg_h($url) . '">의존성 그래프</a>';
}

function vg_host_load_runtime_tab(PDO $pdo, int $sid, int $perPage, int $offset, int $ePage, ?string $q = null): array {
    // 노출·프로세스 모두 건수가 늘 수 있어 각자 페이지네이션한다(노출은 ?epage=, 프로세스는 ?page=).
    // 컨테이너 안의 프로세스·포트도 여기 함께 있다(container_id > 0).
    //   출처를 표시하지 않으면 컨테이너의 nginx 가 호스트의 nginx 처럼 보인다 → "위치" 열.
    $q = ($q !== null && $q !== '') ? $q : null;

    $eWhere = 'e.scan_id = ?';
    $eParams = [$sid];
    if ($q !== null) {
        $eWhere .= ' AND (e.proc LIKE ? OR e.exe_pkg LIKE ?)';
        $eParams[] = '%' . $q . '%';
        $eParams[] = '%' . $q . '%';
    }
    $cnt = $pdo->prepare("SELECT COUNT(*) FROM tb_exposure e WHERE $eWhere");
    $cnt->execute($eParams);
    $exposureTotal = (int) $cnt->fetchColumn();

    // vg_toolbar() 의 기본 "초기화" 링크는 page 만 지우고 epage 는 모른다(공용 컴포넌트, 이번
    //   범위에서 손 안 댐) — 검색 초기화 후에도 epage 가 URL 에 남을 수 있다. 그 값을 신뢰해
    //   그대로 OFFSET 에 쓰면 총건수를 넘겨 빈 표가 뜬다. 여기서 유효 범위로 접어 방어한다.
    $eMaxPage = max(1, (int) ceil($exposureTotal / $perPage));
    if ($ePage > $eMaxPage) { $ePage = $eMaxPage; }
    $eOffset = ($ePage - 1) * $perPage;

    $st = $pdo->prepare("SELECT e.proc, e.proto, e.bind_addr, e.port, e.scope, e.exe_pkg, e.loaded_pkgs,
                                IFNULL(c.cid, '') AS ctr
                           FROM tb_exposure e LEFT JOIN tb_container c ON c.container_id = e.container_id
                          WHERE $eWhere
                          ORDER BY FIELD(e.scope,'EXTERNAL','LAN','BOUND','FILTERED','LOCAL','-'), e.port
                          LIMIT $perPage OFFSET $eOffset");
    $st->execute($eParams);
    $exposures = $st->fetchAll();

    $pWhere = 'p.scan_id = ?';
    $pParams = [$sid];
    if ($q !== null) {
        $pWhere .= ' AND (p.comm LIKE ? OR p.username LIKE ? OR p.exe_pkg LIKE ?)';
        $pParams[] = '%' . $q . '%';
        $pParams[] = '%' . $q . '%';
        $pParams[] = '%' . $q . '%';
    }
    $cnt = $pdo->prepare("SELECT COUNT(*) FROM tb_process p WHERE $pWhere");
    $cnt->execute($pParams);
    $total = (int) $cnt->fetchColumn();

    $st = $pdo->prepare("SELECT p.pid, p.comm, p.username, p.exe_pkg, p.loaded_pkgs,
                                IFNULL(c.cid, '') AS ctr
                           FROM tb_process p LEFT JOIN tb_container c ON c.container_id = p.container_id
                          WHERE $pWhere ORDER BY p.comm LIMIT $perPage OFFSET $offset");
    $st->execute($pParams);
    $rows = $st->fetchAll();

    // 재시작 필요(옛 .so 를 물고 있는 프로세스)는 **억제를 취소하는** 신호라 런타임 축에 세운다.
    //   검색어와 무관하게 상태를 보여준다 — "지금 재시작이 필요한가" 는 목록 필터의 결과가 아니다.
    $stale = vg_stale_lib_summary($pdo, $sid, VG_HOST_STALE_TOP);

    return ['total' => $total, 'exposures' => $exposures, 'exposureTotal' => $exposureTotal,
            'rows' => $rows, 'ePage' => $ePage, 'stale' => $stale];
}

function vg_host_load_cce_tab(PDO $pdo, int $sid, int $perPage, int $offset, ?string $q = null): array {
    $where = 'f.scan_id = ?';
    $params = [$sid];
    if ($q !== null && $q !== '') {
        $where .= ' AND (f.code LIKE ? OR f.title LIKE ? OR f.ssg_rule_id LIKE ?)';
        $params[] = '%' . $q . '%';
        $params[] = '%' . $q . '%';
        $params[] = '%' . $q . '%';
    }
    $st = $pdo->prepare("SELECT COUNT(*) FROM tb_cce_finding f WHERE $where");
    $st->execute($params); $total = (int) $st->fetchColumn();
    // 점검 항목을 **검증된 룰셋(SSG)** 에 묶어 두었으므로, 그 룰의 기준 참조(CIS/NIST/STIG)를
    //   함께 읽어 화면이 근거를 인용할 수 있게 한다. 묶이지 않은 항목은 refs 가 비어 있다.
    $st = $pdo->prepare(
        "SELECT f.code, f.ssg_rule_id, f.title, f.result, f.severity, f.evidence, f.rationale,
                r.refs_json, r.title AS ssg_title
           FROM tb_cce_finding f
           LEFT JOIN tb_compliance_rule r ON r.rule_id = f.ssg_rule_id AND r.is_deleted = 0
          WHERE $where
          ORDER BY FIELD(f.result,'FAIL','NA','PASS'), FIELD(f.severity,'HIGH','MEDIUM','LOW'), f.code
          LIMIT $perPage OFFSET $offset"
    );
    $st->execute($params);
    $rows = $st->fetchAll();

    return ['total' => $total, 'rows' => $rows];
}

function vg_host_load_suppressed_tab(PDO $pdo, int $sid, int $suppressedCount, int $perPage, int $offset, ?string $q = null): array {
    $where = 'sf.scan_id = ?';
    $params = [$sid];
    if ($q !== null && $q !== '') {
        $where .= ' AND (sf.cve_id LIKE ? OR sf.package_name LIKE ?)';
        $params[] = '%' . $q . '%';
        $params[] = '%' . $q . '%';
    }

    if ($q !== null && $q !== '') {
        $cnt = $pdo->prepare("SELECT COUNT(*) FROM tb_suppressed_finding sf WHERE $where");
        $cnt->execute($params);
        $total = (int) $cnt->fetchColumn();
    } else {
        $total = $suppressedCount;
    }

    $st = $pdo->prepare(
        "SELECT cve_id, package_name, installed_version, base_severity, in_kev, suppress_reason,
                CASE WHEN sf.container_id = 0 THEN 'HOST'
                     ELSE COALESCE((SELECT c.name FROM tb_container c WHERE c.container_id = sf.container_id), CONCAT('container #', sf.container_id)) END AS target
           FROM tb_suppressed_finding sf WHERE $where
          ORDER BY FIELD(base_severity,'CRITICAL','HIGH','MEDIUM','LOW'), cve_id
          LIMIT $perPage OFFSET $offset"
    );
    $st->execute($params);
    $rows = $st->fetchAll();

    // 근거를 **행마다** 읽을 수 있게 한다: 어느 겹이 억제했는지(분류) + 그 겹의 원 데이터.
    //   원 데이터는 이 페이지의 행들만 한 번에 읽는다(N+1 금지 — suppression.php 참고).
    foreach ($rows as $i => $r) {
        $rows[$i]['layer'] = vg_suppress_layer($r['suppress_reason'] ?? null);
    }

    return [
        'total'    => $total,
        'rows'     => $rows,
        'evidence' => vg_suppress_evidence_map($pdo, $sid, $rows),
        'layers'   => vg_suppress_layer_counts($pdo, $sid),
    ];
}

/**
 * 수집 제어 카드 — 즉시실행/예약실행/주기변경 폼 + 예약된 명령 미니 목록.
 *   agent-command-queue-api 워커가 만드는 명령 큐(tb_agent_command)에 등록만 한다.
 *   실제 poll·실행은 데몬화된 에이전트 쪽 책임.
 */
function vg_host_render_agent_control(
    int $hostId, array $host, string $csrf, array $agentCommands, ?string $msg, ?string $err
): void {
    $curMinutes = (int) round(((int) ($host['poll_schedule_seconds'] ?? 3600)) / 60);
    $curSpeedTier = (string) ($host['agent_speed_tier'] ?? 'normal');
    $speedTierLabels = [];
    foreach (VG_AGENT_SPEED_TIERS as $t) { $speedTierLabels[$t] = vg_agent_speed_tier_label($t); }
    ?>
    <section class="card agent-control" aria-labelledby="agent-control-title">
      <div class="agent-control__heading">
        <div>
          <strong id="agent-control-title">수집 제어</strong>
        </div>
        <span class="agent-control__status"><span aria-hidden="true"></span>다음 poll 반영</span>
      </div>
      <div class="card__body">
        <?php vg_alert($msg, 'ok'); vg_alert($err); ?>
        <div class="agent-control__facts">
          <span><b>통신 경로</b> <?= vg_h((string)($_SERVER['HTTP_HOST'] ?? '중앙 서버')) ?> · poll 10초</span>
          <span><b>정기 수집</b> <?= number_format($curMinutes) ?>분마다 · 에이전트 로컬 스케줄 기준</span>
        </div>
        <?php $activeCommand = $agentCommands[0] ?? null; ?>
        <?php if ($activeCommand): ?>
          <?php
            $isRunning = $activeCommand['status'] === 'running';
            $pct = $isRunning ? (int) ($activeCommand['progress_percent'] ?? 0) : 0;
            $stageMessage = $isRunning
                ? ((string) ($activeCommand['progress_message'] ?: '수집을 진행하고 있습니다.'))
                : ($activeCommand['run_at'] ? '예약 시각이 되면 다음 poll에서 시작합니다.' : '에이전트의 다음 poll을 기다리고 있습니다.');
          ?>
          <div class="agent-progress" data-agent-progress data-host-id="<?= $hostId ?>" data-command-id="<?= (int)$activeCommand['agent_command_id'] ?>" data-state="<?= vg_h((string)$activeCommand['status']) ?>">
            <div class="agent-progress__top">
              <strong data-progress-title><?= $isRunning ? '수집 진행 중' : '명령 대기 중' ?></strong>
              <span data-progress-percent><?= $pct ?>%</span>
            </div>
            <progress class="agent-progress__track" data-progress-bar max="100" value="<?= $pct ?>"><?= $pct ?>%</progress>
            <div class="agent-progress__meta">
              <span data-progress-message><?= vg_h($stageMessage) ?></span>
              <span data-progress-time><?= $isRunning && $activeCommand['heartbeat_at'] ? '마지막 통신 ' . vg_h((string)$activeCommand['heartbeat_at']) : 'poll 주기 10초 이내' ?></span>
            </div>
            <form method="post" data-confirm="이 수집 작업을 중단할까요?">
              <input type="hidden" name="csrf" value="<?= vg_h($csrf) ?>">
              <input type="hidden" name="action" value="agent_cancel">
              <input type="hidden" name="id" value="<?= (int)$hostId ?>">
              <input type="hidden" name="command_id" value="<?= (int)$activeCommand['agent_command_id'] ?>">
              <button class="btn btn--sm btn--ghost" type="submit"><?= $isRunning ? '수집 중단' : '명령 취소' ?></button>
            </form>
          </div>
        <?php endif; ?>
        <div class="actions actions--stack">
          <form class="agent-control__row" method="post" data-confirm="지금 이 호스트의 스캔을 실행할까요?">
            <input type="hidden" name="csrf" value="<?= vg_h($csrf) ?>">
            <input type="hidden" name="action" value="agent_run_now">
            <input type="hidden" name="id" value="<?= (int) $hostId ?>">
            <?php /* 각 조작의 반영 시점은 카드 머리의 '다음 poll 반영' 배지가 한 번에 말한다 —
                     줄마다 되풀이하면 정작 다른 제약(최소 1분 등)이 묻힌다. */ ?>
            <label><strong>즉시 실행</strong></label>
            <button class="btn btn--sm btn--primary">지금 실행</button>
          </form>

          <form class="agent-control__row" method="post">
            <input type="hidden" name="csrf" value="<?= vg_h($csrf) ?>">
            <input type="hidden" name="action" value="agent_schedule">
            <input type="hidden" name="id" value="<?= (int) $hostId ?>">
            <label for="agent-run-at"><strong>예약 실행</strong></label>
            <input id="agent-run-at" type="datetime-local" name="run_at" min="<?= date('Y-m-d\TH:i') ?>" required>
            <button class="btn btn--sm btn--ghost">등록</button>
          </form>

          <form class="agent-control__row" method="post">
            <input type="hidden" name="csrf" value="<?= vg_h($csrf) ?>">
            <input type="hidden" name="action" value="agent_set_schedule">
            <input type="hidden" name="id" value="<?= (int) $hostId ?>">
            <label for="agent-schedule-minutes"><strong>수집 주기</strong><span>최소 1분</span></label>
            <div class="agent-control__number"><input id="agent-schedule-minutes" type="number" name="schedule_minutes" min="1" value="<?= $curMinutes ?>" required><span>분</span></div>
            <button class="btn btn--sm btn--ghost">저장</button>
          </form>

          <form class="agent-control__row" method="post">
            <input type="hidden" name="csrf" value="<?= vg_h($csrf) ?>">
            <input type="hidden" name="action" value="agent_set_speed_tier">
            <input type="hidden" name="id" value="<?= (int) $hostId ?>">
            <label for="agent-speed-tier"><strong>속도 티어</strong></label>
            <select id="agent-speed-tier" name="agent_speed_tier">
              <?php foreach ($speedTierLabels as $v => $label): ?>
                <option value="<?= vg_h($v) ?>"<?= $curSpeedTier === $v ? ' selected' : '' ?>><?= vg_h($label) ?></option>
              <?php endforeach; ?>
            </select>
            <button class="btn btn--sm btn--ghost">저장</button>
          </form>
        </div>

        <?php if ($agentCommands): ?>
          <div class="mt-lg">
            <strong class="why">예약된 명령</strong>
            <ul class="hint-list">
              <?php foreach ($agentCommands as $c): ?>
                <li>
                  <?= $c['status'] === 'running' ? '수집 실행 중' : ($c['run_at'] === null ? '즉시 실행 대기중' : vg_h((string) $c['run_at']) . ' 예약') ?>
                  <span class="why">(등록 <?= vg_h((string) $c['created_at']) ?>)</span>
                </li>
              <?php endforeach; ?>
            </ul>
          </div>
        <?php endif; ?>
      </div>
    </section>
    <?php
}

/**
 * 자산 등급 카드 — 중요도(상/중/하)와 N2SF 등급(C/S/O)을 **사람이 확정**하는 폼.
 *
 *   이 화면이 지키는 경계: 시스템 제안(grade_suggested)은 "참고" 자리에만 두고, 확정 입력의
 *   기본 선택으로 미리 채우지 않는다. 미리 채우면 사람이 그대로 저장하게 되어 사실상
 *   시스템이 등급을 정한 것이 된다. 등급 판정은 「정보공개법」 제9조 호 매핑에 따른 기관의
 *   법적 처분이므로 시스템이 대신할 수 없다.
 *
 *   $canEdit=false 면 읽기 전용으로 현재 값만 보여준다(확정은 관리자만).
 */
function vg_host_render_grade(int $hostId, array $host, array $review, string $csrf, ?string $approver, bool $canEdit, array $signals = []): void {
    $curGrade = (string) ($host['grade'] ?? '');
    $curCrit  = (string) ($host['criticality'] ?? '');
    $sugGrade = $host['grade_suggested'] ?? null;
    $sugReason = (string) ($host['grade_suggested_reason'] ?? '');
    $missingReview = vg_asset_grade_review_missing($review);
    ?>
    <section class="card mt-lg" aria-labelledby="asset-grade-title">
      <strong id="asset-grade-title">자산 등급</strong>
      <span class="why"> · N2SF 보안등급 <?= vg_h(vg_asset_grade_legend()) ?></span>
      <div class="card__body">
        <?php /* 여섯 항목 모두 "이 자산 등급의 현재 사실" 이다 — 뒤에 산문 문단으로 매달지 않고
                 같은 정의목록 안에 둔다. 제안값은 여기서도 '제안' 꼬리표를 달아 확정과 갈라 둔다. */ ?>
        <dl class="fact-grid">
          <div><dt>확정 등급</dt><dd><?= vg_asset_grade_badge($curGrade !== '' ? $curGrade : null, false, (string) ($host['grade_reason'] ?? '')) ?></dd></div>
          <div><dt>중요도</dt><dd><?= $curCrit !== '' ? vg_h(VG_ASSET_CRITICALITY[$curCrit] ?? $curCrit) : '<span class="why">–</span>' ?></dd></div>
          <div><dt>확정자</dt><dd><?= $approver !== null ? vg_h($approver) : '<span class="why">–</span>' ?></dd></div>
          <div><dt>확정 시각</dt><dd><?= !empty($host['approved_at']) ? vg_h((string) $host['approved_at']) : '<span class="why">–</span>' ?></dd></div>
          <div><dt>확정 근거</dt><dd><?= $curGrade !== '' && !empty($host['grade_reason'])
              ? vg_h((string) $host['grade_reason'])
              : '<span class="why">–</span>' ?></dd></div>
          <div><dt>시스템 초안</dt><dd><?= $sugGrade !== null
              ? vg_asset_grade_badge((string) $sugGrade, true, $sugReason) . ' <span class="why">' . vg_h($sugReason) . '</span>'
              : '<span class="why">근거 부족 — 제안 없음</span>' ?></dd></div>
        </dl>

        <?php /* 제안 근거를 한 줄 문자열로만 두면 사람이 "무엇 때문에 S 인가"를 못 읽는다 —
                 등급을 만든 신호와, 등급을 만들지는 않지만 확정 회의에서 볼 신호를 갈라 보여준다.
                 목록의 정본은 assetgrade.php 의 상수다(화면에 분류표를 늘리지 않는다). */ ?>
        <?php if ($signals): ?>
          <p class="why mt-lg">시스템이 본 신호 — 이 근거들 때문에 위 초안이 나왔습니다. 확정은 사람이 합니다.</p>
          <div class="badge-set">
            <?php foreach ($signals as $sig): ?>
              <?= vg_badge(
                    ($sig['grade'] !== null ? $sig['grade'] . ' · ' : '검토 · ') . $sig['label'],
                    (string) $sig['tone'],
                    $sig['evidence'] . ' ' . $sig['note']
                  ) ?>
            <?php endforeach; ?>
          </div>
          <ul class="hint-list">
            <?php foreach ($signals as $sig): ?>
              <li><span class="why"><?= vg_h(($sig['grade'] !== null ? '[' . $sig['grade'] . ' 근거] ' : '[검토 신호] ')
                  . $sig['evidence'] . ' ' . $sig['note']) ?></span></li>
            <?php endforeach; ?>
          </ul>
        <?php elseif ($host['grade_suggested'] ?? null): ?>
          <p class="why mt-lg">이 스캔에서는 제안 근거 신호를 다시 읽지 못했습니다 — 위 초안은 이전 관찰 결과입니다.</p>
        <?php endif; ?>

        <p class="why mt-lg">정보공개법 제9조 해당 여부는 C/S/O 판단 근거 중 하나이며, 법률이 C/S/O 등급을 정의하는 것은 아닙니다.</p>
        <?php if ($canEdit && !empty($review['is_stale'])): ?>
          <p class="why">⚠ 일괄 등급 변경 뒤 구조화 검토 정보가 재확인되지 않았습니다. 현재 등급에 맞게 다시 검토해 저장하세요.</p>
        <?php elseif ($canEdit && vg_asset_grade_review_overdue($review)): ?>
          <p class="why">⚠ 다음 검토일이 지났습니다. 현재 등급과 구조화 검토 정보를 다시 확인하세요.</p>
        <?php elseif ($canEdit && $curGrade !== '' && $missingReview): ?>
          <p class="why">⚠ 검토 정보 누락: <?= vg_h(implode(', ', $missingReview)) ?></p>
        <?php endif; ?>
        <?php if ($canEdit): ?>
        <dl class="fact-grid">
          <div><dt>제9조 해당 호</dt><dd><?= vg_h(VG_ASSET_REVIEW_ARTICLE9_ITEMS[(string) ($review['article9_item'] ?? '')] ?? '–') ?></dd></div>
          <div><dt>조문·판단 참조</dt><dd><?= vg_h((string) ($review['article9_reference'] ?? '–')) ?></dd></div>
          <div><dt>업무 유형</dt><dd><?= vg_h((string) ($review['business_category'] ?? '–')) ?></dd></div>
          <div><dt>데이터 유형</dt><dd><?= vg_h((string) ($review['data_category'] ?? '–')) ?></dd></div>
          <div><dt>소유 부서</dt><dd><?= vg_h((string) ($review['owning_department'] ?? '–')) ?></dd></div>
          <div><dt>외부 공개 상태</dt><dd><?= vg_h(VG_ASSET_REVIEW_PUBLICATION_STATES[(string) ($review['external_publication_state'] ?? '')] ?? '–') ?></dd></div>
          <div><dt>검토 문서·티켓</dt><dd><?= vg_h((string) ($review['review_reference'] ?? '–')) ?></dd></div>
          <div><dt>다음 검토일</dt><dd><?= vg_h((string) ($review['next_review_date'] ?? '–')) ?></dd></div>
        </dl>
        <?php endif; ?>

        <?php if ($canEdit): ?>
          <form class="setting-form mt-lg" method="post"
                data-confirm="이 자산의 등급을 확정할까요? 확정자와 시각이 감사로그에 기록됩니다.">
            <input type="hidden" name="csrf" value="<?= vg_h($csrf) ?>">
            <input type="hidden" name="action" value="host_set_grade">
            <input type="hidden" name="id" value="<?= (int) $hostId ?>">
            <input type="hidden" name="review_version" value="<?= (int) ($review['review_version'] ?? 0) ?>">
            <input type="hidden" name="grade_version" value="<?= (int) ($host['grade_version'] ?? 0) ?>">

            <label class="field" for="asset-criticality">중요도
              <select id="asset-criticality" name="criticality">
                <option value="">미지정</option>
                <?php foreach (VG_ASSET_CRITICALITY as $v => $label): ?>
                  <option value="<?= vg_h($v) ?>"<?= $curCrit === $v ? ' selected' : '' ?>><?= vg_h($label) ?></option>
                <?php endforeach; ?>
              </select>
            </label>

            <label class="field" for="asset-grade">보안등급 (N2SF)
              <select id="asset-grade" name="grade">
                <option value="">미지정(확정 해제)</option>
                <?php foreach (VG_ASSET_GRADES as $v => $label): ?>
                  <option value="<?= vg_h($v) ?>"<?= $curGrade === $v ? ' selected' : '' ?>><?= vg_h($label) ?></option>
                <?php endforeach; ?>
              </select>
            </label>

            <label class="field" for="asset-grade-reason">확정 근거
              <input id="asset-grade-reason" type="text" name="grade_reason" maxlength="255"
                     placeholder="예: 「정보공개법」 제9조 제6호 해당 업무정보 보유"
                     value="<?= vg_h((string) ($host['grade_reason'] ?? '')) ?>">
            </label>

            <label class="field" for="asset-article9-item">정보공개법 제9조 해당 호
              <select id="asset-article9-item" name="article9_item">
                <option value="">미지정</option>
                <?php foreach (VG_ASSET_REVIEW_ARTICLE9_ITEMS as $v => $label): ?>
                  <option value="<?= vg_h((string) $v) ?>"<?= ($review['article9_item'] ?? null) === (string) $v ? ' selected' : '' ?>><?= vg_h($label) ?></option>
                <?php endforeach; ?>
              </select>
            </label>
            <label class="field" for="asset-article9-reference">조문·판단 참조
              <input id="asset-article9-reference" name="article9_reference" maxlength="255" value="<?= vg_h((string) ($review['article9_reference'] ?? '')) ?>">
            </label>
            <label class="field" for="asset-business-category">업무 유형
              <input id="asset-business-category" name="business_category" maxlength="100" value="<?= vg_h((string) ($review['business_category'] ?? '')) ?>">
            </label>
            <label class="field" for="asset-data-category">데이터 유형
              <input id="asset-data-category" name="data_category" maxlength="100" value="<?= vg_h((string) ($review['data_category'] ?? '')) ?>">
            </label>
            <label class="field" for="asset-owning-department">소유 부서
              <input id="asset-owning-department" name="owning_department" maxlength="120" value="<?= vg_h((string) ($review['owning_department'] ?? '')) ?>">
            </label>
            <label class="field" for="asset-publication-state">외부 공개 상태
              <select id="asset-publication-state" name="external_publication_state">
                <option value="">미지정</option>
                <?php foreach (VG_ASSET_REVIEW_PUBLICATION_STATES as $v => $label): ?>
                  <option value="<?= vg_h($v) ?>"<?= ($review['external_publication_state'] ?? null) === $v ? ' selected' : '' ?>><?= vg_h($label) ?></option>
                <?php endforeach; ?>
              </select>
            </label>
            <label class="field" for="asset-review-reference">검토 문서·티켓 참조
              <input id="asset-review-reference" name="review_reference" maxlength="255" placeholder="예: SEC-1234, 보안검토 회의록 2026-03" value="<?= vg_h((string) ($review['review_reference'] ?? '')) ?>">
              <span class="why">문서 내용이 아니라 식별자나 위치만 남깁니다.</span>
            </label>
            <label class="field" for="asset-next-review-date">다음 검토일
              <input id="asset-next-review-date" type="date" name="next_review_date" value="<?= vg_h((string) ($review['next_review_date'] ?? '')) ?>">
            </label>

            <div class="actions">
              <button type="submit" class="btn btn--sm btn--primary">등급 확정</button>
            </div>
          </form>
        <?php else: ?>
          <p class="why">등급 확정은 관리자만 할 수 있습니다.</p>
        <?php endif; ?>
      </div>
    </section>
    <?php
}

/**
 * 스캔 이력 탭의 리소스 추이 — 표와 같은 tb_scan_run 을 시간순으로만 다시 읽는다.
 *   최신 N건을 DESC 로 뽑은 뒤 뒤집는다 — 표는 최신이 위, 차트는 최신이 오른쪽이라 방향이 반대다.
 *   (표는 페이지네이션되므로 차트가 그 페이지에 종속되면 안 된다 → 별도 조회다.)
 */
function vg_host_load_resource_trend(PDO $pdo, int $hostId): array {
    $st = $pdo->prepare(
        'SELECT collected_at, peak_rss_mb, cpu_seconds, mem_total_mb, cpu_cores, elapsed_seconds
           FROM tb_scan_run WHERE host_id = ? ORDER BY scan_run_id DESC LIMIT ' . vg_ui_trend_limit()
    );
    $st->execute([$hostId]);
    $resourceScans = array_reverse($st->fetchAll());

    // 스캔(행) 단위로 먼저 %를 계산한다 — 절대치를 먼저 모아 나중에 나누면 스캔마다
    //   다른 스펙(mem_total_mb/cpu_cores)이 섞여 값이 왜곡된다. 필요값이 하나라도 없거나
    //   분모가 0이면 그 스캔은 이 지표에서 제외(NULL) — 0/100 대체 금지.
    foreach ($resourceScans as &$s) {
        $s['mem_pct'] = vg_agent_mem_pct($s['peak_rss_mb'], $s['mem_total_mb']);
        $s['cpu_pct'] = vg_agent_cpu_pct($s['cpu_seconds'], $s['elapsed_seconds'], $s['cpu_cores']);
    }
    unset($s);

    return $resourceScans;
}

function vg_host_load_packages_tab(PDO $pdo, int $scanId, int $perPage, int $offset, string $q): array {
    $where = "scan_id = ? AND container_id = 0 AND manager IN ('dpkg','rpm','apk')";
    $params = [$scanId];
    if ($q !== '') {
        $where .= ' AND (name LIKE ? OR source_pkg LIKE ? OR origin LIKE ? OR vendor LIKE ?)';
        $like = '%' . $q . '%';
        array_push($params, $like, $like, $like, $like);
    }
    $st = $pdo->prepare("SELECT COUNT(*) FROM tb_package WHERE $where");
    $st->execute($params);
    $total = (int) $st->fetchColumn();

    $st = $pdo->prepare(
        "SELECT manager,name,version,arch,source_pkg,source_version,origin,vendor
           FROM tb_package WHERE $where
          ORDER BY name,arch,version LIMIT $perPage OFFSET $offset"
    );
    $st->execute($params);
    return ['total' => $total, 'rows' => $st->fetchAll()];
}

/**
 * 컨테이너 탭 — 이 스캔이 찾아낸 컨테이너 대장.
 *   에이전트는 k8s 위치(namespace/pod/container)·워크로드 참조·이미지 다이제스트·SBOM 까지 보내지만
 *   **도커 단독 호스트에서는 이 값들이 전부 비어 있다.** 그래서 열로 세우지 않고, 값이 있는 행에서만
 *   셀 안에 한 줄로 덧붙인다(렌더 쪽) — 빈칸만 늘어선 표를 만들지 않기 위해서다.
 */
function vg_host_load_containers_tab(PDO $pdo, int $scanId, int $perPage, int $offset, string $q): array {
    $where  = 'scan_id = ? AND is_deleted = 0';
    $params = [$scanId];
    // 대장(표·카드)과 별개로 컨테이너별 심각도 분포를 **한 번의 GROUP BY** 로 가져온다.
    //   행마다 세면 N+1 이 되고, 페이지 행에만 맞춰 세면 쿼리를 페이지마다 다시 조립해야 한다.
    //   uq_find 좌측 접두가 (scan_id, container_id) 라 이 집계는 인덱스 그대로다.
    $sev = $pdo->prepare(
        'SELECT container_id, severity, COUNT(*) c
           FROM tb_finding WHERE scan_id = ? AND container_id > 0
          GROUP BY container_id, severity'
    );
    $sev->execute([$scanId]);
    $sevByContainer = [];
    foreach ($sev->fetchAll() as $r) {
        $sevByContainer[(int) $r['container_id']][(string) $r['severity']] = (int) $r['c'];
    }

    if ($q !== '') {
        $where .= ' AND (cid LIKE ? OR name LIKE ? OR image LIKE ?
                         OR k8s_namespace LIKE ? OR k8s_pod LIKE ? OR workload_ref LIKE ?)';
        $like = '%' . $q . '%';
        array_push($params, $like, $like, $like, $like, $like, $like);
    }

    $st = $pdo->prepare("SELECT COUNT(*) FROM tb_container WHERE $where");
    $st->execute($params);
    $total = (int) $st->fetchColumn();

    // ORDER BY cid — uq_container(scan_id, cid) 좌측 접두가 scan_id 라 정렬까지 인덱스가 받는다.
    $st = $pdo->prepare(
        "SELECT container_id, cid, name, image, image_digest, k8s_namespace, k8s_pod, k8s_container,
                workload_ref, runtime_state, sbom_format, sbom_hash,
                os_id, os_version, manager, pkg_count
           FROM tb_container WHERE $where
          ORDER BY cid LIMIT $perPage OFFSET $offset"
    );
    $st->execute($params);
    return ['total' => $total, 'rows' => $st->fetchAll(), 'sevByContainer' => $sevByContainer];
}

/**
 * 계정 탭 — 이 스캔의 계정 대장 + 파생 컴플라이언스 판정.
 *   판정은 목록 한 페이지가 아니라 **전 계정**을 봐야 한다(90일 미로그인 계정이 3페이지에 있어도
 *   판정은 나와야 한다) → 판정용으로 계정 전체를 따로 읽는다. 호스트당 계정은 수십 개 규모지만
 *   상한을 걸어 비정상 데이터가 화면을 못 죽이게 한다.
 */
const VG_HOST_ACCOUNT_JUDGE_MAX = 5000;

function vg_host_load_accounts_tab(PDO $pdo, int $scanId, int $perPage, int $offset, string $q, string $filter): array {
    $where  = 'scan_id = ? AND is_deleted = 0';
    $params = [$scanId];
    if ($q !== '') {
        $where .= ' AND (username LIKE ? OR shell LIKE ? OR home LIKE ?)';
        $like = '%' . $q . '%';
        array_push($params, $like, $like, $like);
    }
    if ($filter === 'sudo') {
        $where .= ' AND is_sudoer = 1';
    } elseif ($filter === 'locked') {
        $where .= ' AND is_locked = 1';
    } elseif ($filter === 'human') {
        $where .= ' AND is_system = 0';
    } elseif ($filter === 'stale') {
        // 미로그인 = 로그인 이력이 없거나 임계일을 넘긴 것. 시스템 계정은 애초에 로그인하지 않는다.
        $where .= ' AND is_system = 0 AND (never_logged_in = 1 OR last_login_at < DATE_SUB(NOW(), INTERVAL ? DAY))';
        $params[] = vg_account_stale_login_days();
    }

    $st = $pdo->prepare("SELECT COUNT(*) FROM tb_host_account WHERE $where");
    $st->execute($params);
    $total = (int) $st->fetchColumn();

    $cols = 'username, uid, gid, shell, home, is_locked, is_sudoer, is_system,
             pw_last_change, pw_max_days, expire_date, last_login_at, never_logged_in';
    $st = $pdo->prepare(
        "SELECT $cols FROM tb_host_account WHERE $where
          ORDER BY is_system, username LIMIT $perPage OFFSET $offset"
    );
    $st->execute($params);
    $rows = $st->fetchAll();

    $limit = VG_HOST_ACCOUNT_JUDGE_MAX;
    $st = $pdo->prepare(
        "SELECT $cols FROM tb_host_account WHERE scan_id = ? AND is_deleted = 0
          ORDER BY username LIMIT $limit"
    );
    $st->execute([$scanId]);
    $all = $st->fetchAll();

    return ['total' => $total, 'rows' => $rows, 'judgments' => vg_account_judgments($all), 'allCount' => count($all)];
}

function vg_host_load_scans_tab(PDO $pdo, int $hostId, int $scanTotal, int $perPage, int $offset): array {
    $total = $scanTotal;
    $st = $pdo->prepare(
        "SELECT scan_run_id, scan_id, collected_at, received_at, content_changed,
                package_count, exposure_count, agent_version, elapsed_seconds, peak_rss_mb, cpu_seconds
           FROM tb_scan_run WHERE host_id = ? ORDER BY scan_run_id DESC LIMIT $perPage OFFSET $offset"
    );
    $st->execute([$hostId]);
    $rows = $st->fetchAll();

    $ids = [];
    foreach ($rows as $s) { $ids[] = (int) $s['scan_id']; }
    $sevByScan = vg_sev_by_scan_ids($pdo, $ids);

    return [
        'total' => $total,
        'rows' => $rows,
        'sevByScan' => $sevByScan,
        'resourceScans' => vg_host_load_resource_trend($pdo, $hostId),
    ];
}

$counts =['CRITICAL'=>0,'HIGH'=>0,'MEDIUM'=>0,'LOW'=>0];
$exposureCount = 0; $processCount = 0; $runtimeTotal = 0; $cceFail = 0; $suppressedCount = 0; $vulnTotal = 0; $scanTotal = 0;
$critHighTotal = 0; $restartTotal = 0; $restartRows = []; $packageTotal = 0;
// 위험 요약(히어로 바로 아래) — 심각도 분포와 같은 한 번의 집계에서 함께 나온다.
$kevCount = 0; $externalFindings = 0;
// 같은 패키지에서 나온 취약점 묶음 — "이 하나를 올리면 N건". vuln 탭에서만 채운다.
$pkgRollup = ['rows' => [], 'truncated' => false];
// 상세 화면의 기본 페이지 크기는 목록 화면보다 크다(설정: UI_DETAIL_PER_PAGE_DEFAULT).
//   127건을 10개씩 13페이지로 넘기게 하면 "이 자산이 얼마나 위험한가"를 셀 수가 없다.
$tab = 'vuln'; $page = 1; $ePage = 1; $perPage = vg_perpage(vg_ui_detail_per_page_default()); $total = 0; $exposureTotal = 0;
/* 이 화면이 고른 크기를 요청 컨텍스트에도 반영한다. "N개씩 보기" 셀렉트(vg_perpage_select)와
 *   툴바는 공용 컴포넌트라 **쿼리스트링만 보고** 현재 크기를 판단한다 — 그대로 두면 40개를
 *   보여주면서 셀렉트는 "10개씩 보기" 가 선택된 채로 뜬다(사용자에겐 화면이 거짓말을 한다).
 *   사용자가 고른 값이 있으면 건드리지 않는다. */
if (!isset($_GET['per_page'])) { $_GET['per_page'] = (string) $perPage; }
$rows = []; $exposures = []; $sevByScan = []; $resourceScans = []; $restartRows = [];
$findingStatuses = [];   // 취약점 탭 행들의 조치 상태(자연키 → 행). 없으면 미조치로 읽는다.
$accountTotal = 0; $accountJudgments = []; $accountAllCount = 0; $depEdgeTotal = 0; $containerTotal = 0;
$sevByContainer = [];   // [container_id => [severity => n]] — 컨테이너 카드의 심각도 분포
// 전이 의존성 판정 + 손댈 대상(부모)별 묶음. 엣지가 없는 자산에선 이 기본값 그대로다.
$depOrigins = ['origins' => [], 'parents' => [], 'finding_total' => 0, 'finding_truncated' => false,
               'edge_truncated' => false, 'path_truncated' => false];
$gradeSuggestionHistory = [];
$q = trim((string) ($_GET['q'] ?? ''));
// 계정 탭 필터(?acc=). 화이트리스트 밖 값은 전체로 떨군다 — 값이 그대로 SQL 로 가지 않는다.
$accFilter = (string) ($_GET['acc'] ?? '');
if (!in_array($accFilter, ['sudo', 'locked', 'human', 'stale'], true)) { $accFilter = ''; }
$hasFilter = $q !== '' || $accFilter !== '';

try {
    $pdo = vg_pdo();
    $hostId = (int) ($_GET['id'] ?? 0);
    $st = $pdo->prepare('SELECT * FROM tb_host WHERE host_id = ? AND is_deleted = 0');
    $st->execute([$hostId]);
    $host = $st->fetch() ?: null;
    $pendingCommands = [];

    if ($host) {
        $gradeSuggestionHistory = vg_asset_grade_history_recent($pdo, $hostId);
        $gradeReview = vg_has_role('admin') ? vg_asset_grade_review_load($pdo, $hostId) : [];
        // 호스트 상세(설치 패키지·노출 포트·실행 프로세스 등 인프라 민감정보) 열람 감사로그.
        vg_log_activity($pdo, 'HOST', $hostId, 'view_host', (string) ($host['fqdn'] ?? null),
            subject: (string) ($host['fqdn'] ?? ''), action: 'READ');

        // 등급 확정자 이름(승인 이력) — 사용자가 지워졌으면 FK 가 NULL 이라 여기 안 들어온다.
        if (!empty($host['approved_by'])) {
            $st = $pdo->prepare('SELECT username FROM tb_user WHERE user_id = ?');
            $st->execute([(int) $host['approved_by']]);
            $u = $st->fetchColumn();
            $approver = $u === false ? null : (string) $u;
        }

        // 에이전트 연결 상태는 수집 실행 시각이 아니라 10초 poll의 마지막 통신으로 판단한다.
        $st = $pdo->prepare(
            'SELECT TIMESTAMPDIFF(MINUTE, MAX(last_seen_at), NOW())
               FROM tb_agent_token
              WHERE host_fqdn = ? AND is_revoked = 0 AND is_deleted = 0'
        );
        $st->execute([(string) $host['fqdn']]);
        $lastPollAge = $st->fetchColumn();
        $pollAge = $lastPollAge !== null && $lastPollAge !== false ? (int) $lastPollAge : null;

        if (vg_can('assets')) {
            $st = $pdo->prepare(
                "SELECT agent_command_id, status, progress_percent, progress_stage, progress_message,
                        run_at, created_at, started_at, heartbeat_at, cancel_requested_at
                   FROM tb_agent_command
                  WHERE host_id = ? AND status IN ('pending','running') AND is_deleted = 0
                  ORDER BY status = 'running' DESC, run_at IS NULL DESC, run_at, created_at"
            );
            $st->execute([$hostId]);
            $pendingCommands = $st->fetchAll();
        }

        // 컬럼을 못 박는 이유: tb_scan.raw_json 은 호스트당 MB 단위(실측 3.14MB)라
        // SELECT * 로 끌면 ORDER BY 의 정렬 버퍼(운영 sort_buffer_size=2M)를 한 행만으로도 넘겨 1038 이 난다.
        $st = $pdo->prepare('SELECT scan_id, collected_at, package_count,
                                    integrity_checked, integrity_partial, integrity_total,
                                    TIMESTAMPDIFF(MINUTE, collected_at, NOW()) AS age_min
                               FROM tb_scan WHERE host_id = ? ORDER BY scan_id DESC LIMIT 1');
        $st->execute([$hostId]);
        $scan = $st->fetch() ?: null;
    }

    if ($scan) {
        $sid = (int) $scan['scan_id'];
        $scanAge = $scan['age_min'];

        // 취약점 0건이 "판정 불가"인 컨테이너 — 피드 미지원 배포판 + **패키지 DB 없는 이미지**.
        //   후자는 rhel 처럼 피드가 지원하는 배포판이라 미지원 경고에 안 걸린다 → 따로 잡아야 한다.
        $st = $pdo->prepare(
            'SELECT c.cid, c.os_id, c.os_version, c.manager,
                    CASE WHEN EXISTS (
                        SELECT 1 FROM tb_package p
                         WHERE p.scan_id = c.scan_id AND p.container_id = c.container_id
                    ) THEN 1 ELSE c.pkg_count END AS pkg_count
               FROM tb_container c WHERE c.scan_id = ?'
        );
        $st->execute([$sid]);
        foreach ($st->fetchAll() as $c) {
            $reason = vg_container_unjudgeable(
                $c['os_id'] ?? null, $c['os_version'] ?? null,
                $c['manager'] ?? null, (int) ($c['pkg_count'] ?? 0)
            );
            if ($reason !== null) {
                $unsupContainers[] = ['cid' => (string) $c['cid'], 'reason' => $reason];
            }
        }

        // 수집 단계 누락 — 배포판도 알고 이미지도 멀쩡한데 **에이전트가 그 항목을 아예 못 걷은** 경우.
        //   MISSING 만 모은다. EMPTY 는 "정상적으로 없음"(컨테이너를 안 쓰는 호스트, 언어 패키지가
        //   없는 호스트)이라 같이 경고하면 정상 호스트마다 경고가 떠서 아무도 안 보게 된다.
        //   item_count 는 안 읽는다 — MISSING 은 정의상 0건이라(ingest.php 생산자) 볼 값이 없다.
        $st = $pdo->prepare("SELECT stage_code FROM tb_collection_stage
                              WHERE scan_id = ? AND status = 'MISSING' ORDER BY stage_code");
        $st->execute([$sid]);
        foreach ($st->fetchAll() as $r) {
            $code = (string) $r['stage_code'];
            $missingStageCodes[] = $code;
            $missingStages[] = VG_COLLECTION_STAGE_LABEL[$code] ?? $code;   // 모르는 코드는 원문 그대로
        }

        // --- 히어로/KPI 집계 (탭과 무관한 값싼 COUNT) ---
        //   KEV(알려진 악용)·외부노출 건수는 심각도 분포와 같은 성격의 "위험 요약" 이라
        //   쿼리를 늘리지 않고 같은 GROUP BY 에 집계를 얹어 가져온다.
        $st = $pdo->prepare("SELECT severity, COUNT(*) c,
                                    SUM(in_kev = 1) kev, SUM(runtime_status = 'EXTERNAL') ext
                               FROM tb_finding WHERE scan_id = ? GROUP BY severity");
        $st->execute([$sid]);
        foreach ($st->fetchAll() as $r) {
            if (isset($counts[$r['severity']])) { $counts[$r['severity']] = (int) $r['c']; }
            $kevCount += (int) $r['kev'];
            $externalFindings += (int) $r['ext'];
        }

        $st = $pdo->prepare('SELECT COUNT(*) FROM tb_exposure WHERE scan_id = ?');
        $st->execute([$sid]); $exposureCount = (int) $st->fetchColumn();

        $st = $pdo->prepare("SELECT COUNT(*) FROM tb_cce_finding WHERE scan_id = ? AND result = 'FAIL'");
        $st->execute([$sid]); $cceFail = (int) $st->fetchColumn();

        $st = $pdo->prepare('SELECT COUNT(*) FROM tb_suppressed_finding WHERE scan_id = ?');
        $st->execute([$sid]); $suppressedCount = (int) $st->fetchColumn();

        // 우선순위 취약점 = CRITICAL·HIGH + 재시작 필요(등급이 낮아도 숨기지 않는다).
        //   탭 배지는 둘의 합, 화면은 두 표로 나눠 보여준다(아래 vuln 탭 주석 참고).
        $st = $pdo->prepare("SELECT COUNT(*) FROM tb_finding
                              WHERE scan_id = ? AND (severity IN ('CRITICAL','HIGH') OR needs_restart = 1)");
        $st->execute([$sid]); $vulnTotal = (int) $st->fetchColumn();

        $st = $pdo->prepare("SELECT COUNT(*) FROM tb_finding
                              WHERE scan_id = ? AND severity IN ('CRITICAL','HIGH')");
        $st->execute([$sid]); $critHighTotal = (int) $st->fetchColumn();

        $st = $pdo->prepare('SELECT COUNT(*) FROM tb_finding WHERE scan_id = ? AND needs_restart = 1');
        $st->execute([$sid]); $restartTotal = (int) $st->fetchColumn();

        $st = $pdo->prepare('SELECT COUNT(*) FROM tb_scan_run WHERE host_id = ?');
        $st->execute([$hostId]); $scanTotal = (int) $st->fetchColumn();

        $st = $pdo->prepare('SELECT COUNT(*) FROM tb_process WHERE scan_id = ?');
        $st->execute([$sid]); $processCount = (int) $st->fetchColumn();
        $runtimeTotal = $exposureCount + $processCount;

        $st = $pdo->prepare("SELECT COUNT(*) FROM tb_package
                              WHERE scan_id = ? AND container_id = 0 AND manager IN ('dpkg','rpm','apk')");
        $st->execute([$sid]); $packageTotal = (int) $st->fetchColumn();

        // 의존성 그래프(depgraph.php) 진입 여부 — 엣지가 있는 자산에만 링크를 건다.
        //   uk_pkg_dep_edge 좌측 접두가 (scan_id, container_id)라 scan_id 만으로도 인덱스 레인지다.
        $st = $pdo->prepare('SELECT COUNT(*) FROM tb_package_dependency WHERE scan_id = ?');
        $st->execute([$sid]); $depEdgeTotal = (int) $st->fetchColumn();

        $st = $pdo->prepare('SELECT COUNT(*) FROM tb_host_account WHERE scan_id = ? AND is_deleted = 0');
        $st->execute([$sid]); $accountTotal = (int) $st->fetchColumn();

        $st = $pdo->prepare('SELECT COUNT(*) FROM tb_container WHERE scan_id = ? AND is_deleted = 0');
        $st->execute([$sid]); $containerTotal = (int) $st->fetchColumn();

        // --- 활성 탭 결정 (억제 탭은 건이 있을 때만 존재) ---
        $validTabs = ['vuln', 'packages', 'containers', 'runtime', 'cce', 'accounts'];
        if ($suppressedCount > 0) { $validTabs[] = 'suppressed'; }
        $validTabs[] = 'scans';
        // 설정 탭(수집 제어·자산 등급·자산 삭제) — 조회할 목록이 없어 아래 데이터 로딩에 분기가 없다.
        $validTabs[] = 'manage';
        $tab = (string) ($_GET['tab'] ?? 'vuln');
        if (!in_array($tab, $validTabs, true)) { $tab = 'vuln'; }

        $page   = vg_page();
        $offset = ($page - 1) * $perPage;
        $ePage  = vg_page('epage');

        // --- 활성 탭 데이터만 조회(+페이지네이션+검색) ---
        if ($tab === 'vuln') {
            ['total' => $total, 'rows' => $rows, 'restartRows' => $restartRows]
                = vg_host_load_vuln_tab($pdo, $sid, $critHighTotal, $perPage, $offset, $q);
            // 전이 의존성은 그 패키지만 갈아끼울 수 없다 — 손댈 대상(부모)을 찾아 조치 문구를 바꾸고,
            //   부모별로 묶어 "이 하나를 올리면 N건" 을 탭 상단에 보여준다.
            //   판정 대상은 **스캔 전체**다(페이지마다 답이 달라지면 우선순위가 아니다).
            //   $depEdgeTotal 은 위에서 이미 센 값이다. 0이면 여기서 끝나 쿼리가 늘지 않는다.
            if ($depEdgeTotal > 0) {
                $depOrigins = vg_pkgdep_scan_rollup($pdo, $sid);
            }
            // 위 묶음은 **의존성 엣지가 있는 자산에만** 나온다(언어 패키지). dpkg/rpm 만 있는
            //   자산에서도 "같은 패키지의 서로 다른 CVE" 는 행마다 같은 근거로 반복된다 —
            //   같은 질문("무엇부터 올리나")에 같은 형태로 답한다.
            $pkgRollup = vg_host_load_pkg_rollup($pdo, $sid, vg_ui_detail_preview_limit());
            // 이 화면에 보이는 행들의 조치 상태를 한 번에 읽는다(N+1 방지). 두 표(주 목록·재시작)를
            //   한 번에 물어본다 — 같은 자산의 같은 축이라 쿼리를 나눌 이유가 없다.
            $statusKeys = [];
            foreach (array_merge($rows, $restartRows) as $f) {
                $statusKeys[] = [$hostId, (string) ($f['container_cid'] ?? ''),
                                 (string) $f['cve_id'], (string) $f['package_name']];
            }
            $findingStatuses = vg_finding_statuses_map($pdo, $statusKeys);

        } elseif ($tab === 'packages') {
            ['total' => $total, 'rows' => $rows]
                = vg_host_load_packages_tab($pdo, $sid, $perPage, $offset, $q);
            // 패키지 무결성 — 상태 한 줄 + 상위 목록만(전체 표는 만들지 않는다). 이 탭에서만 조회한다.
            //   digest 불일치(5)를 먼저 보여준다 — 권한·소유자 차이보다 무거운 관측이다.
            $st = $pdo->prepare('SELECT package_name, flags, file_path FROM tb_package_integrity
                                  WHERE scan_id = ? ORDER BY INSTR(flags, \'5\') = 0, package_integrity_id
                                  LIMIT ' . VG_HOST_INTEGRITY_TOP);
            $st->execute([$sid]);
            $integrityRows = $st->fetchAll();
        } elseif ($tab === 'containers') {
            ['total' => $total, 'rows' => $rows, 'sevByContainer' => $sevByContainer]
                = vg_host_load_containers_tab($pdo, $sid, $perPage, $offset, $q);
        } elseif ($tab === 'runtime') {
            ['total' => $total, 'exposures' => $exposures, 'exposureTotal' => $exposureTotal,
             'rows' => $rows, 'ePage' => $ePage, 'stale' => $staleLibs]
                = vg_host_load_runtime_tab($pdo, $sid, $perPage, $offset, $ePage, $q);
        } elseif ($tab === 'cce') {
            ['total' => $total, 'rows' => $rows]
                = vg_host_load_cce_tab($pdo, $sid, $perPage, $offset, $q);
        } elseif ($tab === 'accounts') {
            ['total' => $total, 'rows' => $rows, 'judgments' => $accountJudgments, 'allCount' => $accountAllCount]
                = vg_host_load_accounts_tab($pdo, $sid, $perPage, $offset, $q, $accFilter);
            // 누가 이 호스트의 계정 목록을 열람했는지는 그 자체로 감사 대상이다(원칙 7).
            vg_log_activity($pdo, 'HOST', $hostId, 'view_host_accounts',
                '계정 인벤토리 열람: ' . (string) ($host['fqdn'] ?? ''), ['accounts' => $total]);
        } elseif ($tab === 'suppressed') {
            ['total' => $total, 'rows' => $rows, 'evidence' => $suppEvidence, 'layers' => $suppLayers]
                = vg_host_load_suppressed_tab($pdo, $sid, $suppressedCount, $perPage, $offset, $q);
        } elseif ($tab === 'scans') { // 회차 표 + 같은 회차들의 리소스 추이
            ['total' => $total, 'rows' => $rows, 'sevByScan' => $sevByScan, 'resourceScans' => $resourceScans]
                = vg_host_load_scans_tab($pdo, $hostId, $scanTotal, $perPage, $offset);
        } elseif ($tab === 'manage') {
            // 등급 제안 근거 칩 — 확정 화면(자산 설정)에서만 계산한다. 다른 탭의 쿼리를 늘리지 않는다.
            //   제안 자체와 **같은 함수**를 쓴다(assetgrade.php) — 화면이 근거를 따로 조립하면
            //   "제안은 S 인데 칩은 다른 얘기" 가 된다.
            $gradeSignals = vg_asset_grade_signals($pdo, $sid);
        }
    }
} catch (Throwable $e) {
    if (isset($pdo) && $pdo instanceof PDO && $pdo->inTransaction()) { $pdo->rollBack(); }
    error_log('[host] ' . $e->getMessage());
    $err = $e instanceof InvalidArgumentException || $e instanceof RuntimeException ? $e->getMessage() : '처리 중 오류가 발생했습니다.';
}

// 노출 범위 → 뱃지 톤(색은 CSS 가 결정).
//   FILTERED = 전체 인터페이스에 떠 있지만 방화벽이 막아 외부에서 못 닿는 포트.
// LAN = 링크로컬 멀티캐스트(mDNS 등) — 인터넷엔 안 닿고 같은 세그먼트만(외부노출보다 아래).
$scopeTone = ['EXTERNAL' => 'crit', 'LAN' => 'med', 'BOUND' => 'med', 'FILTERED' => 'muted', 'LOCAL' => 'muted'];

vg_header($host['fqdn'] ?? '호스트', 'assets');
// 예약 실행 입력용 datepicker(flatpickr, 의존성 0개) — CDN 없이 자체호스팅(vendor/).
//   defer 되는 페이지 전용 JS(assets/js/host.js)보다 먼저 실행돼야 하므로 body 시작 지점에서
//   바로 로드한다(defer 스크립트는 문서 순서대로 실행되므로 이 위치면 순서가 보장된다).
?>
<link rel="stylesheet" href="<?= vg_asset('/assets/vendor/flatpickr/flatpickr.min.css') ?>">
<script src="<?= vg_asset('/assets/vendor/flatpickr/flatpickr.min.js') ?>"></script>
<?php if ($err !== null): ?>
  <?php vg_page_title('호스트 상세', 'ASSET DETAIL', '호스트 정보를 불러오지 못했습니다.'); ?>
  <?php vg_alert('오류 · ' . $err); ?>
<?php elseif (!$host): ?>
  <?php vg_page_title('호스트를 찾을 수 없습니다', 'ASSET DETAIL', '삭제되었거나 존재하지 않는 자산입니다.'); ?>
  <div class="card"><?php vg_empty(['icon' => '🖥️', 'title' => '요청한 호스트 정보가 없습니다.', 'cta' => ['href' => '/', 'label' => '← 대시보드']]); ?></div>
<?php elseif (!$scan): ?>
  <?php
  $noScanMeta = [vg_h(trim($host['os_id'] . ' ' . $host['os_version']))];
  if (!empty($host['last_seen_ip'])) { $noScanMeta[] = 'IP ' . vg_h($host['last_seen_ip']); }
  $noScanMeta[] = '<a href="/">대시보드</a>';
  vg_hero(vg_h($host['fqdn']), $noScanMeta, null, 'ok', '수집 상태', '');
  ?>
  <?php if (vg_can('assets')): ?>
    <?php vg_host_render_agent_control($hostId, $host, $agentCsrf, $pendingCommands, $agentMsg, $agentErr); ?>
  <?php endif; ?>
  <?php vg_host_render_grade($hostId, $host, $gradeReview, $agentCsrf, $approver, vg_has_role('admin')); ?>
  <?php vg_asset_grade_history_render($gradeSuggestionHistory); ?>
  <div class="card"><?php vg_empty(['icon' => '📭', 'title' => '아직 수집된 스캔이 없습니다.', 'hint' => '에이전트를 --send 로 실행하면 여기에 나타납니다.']); ?></div>
<?php else:
    // 최고 위험도 → 히어로 톤. 하나도 없으면 '양호'(ok).
    $worst = null;
    foreach (['CRITICAL','HIGH','MEDIUM','LOW'] as $s) { if ($counts[$s] > 0) { $worst = $s; break; } }
    $heroTone = $worst ? vg_sev_tone($worst) : 'ok';

    // 탭 정의(배열 순서 = 표시 순서). n 은 라벨 옆 숫자(null 이면 숨김).
    $tabDefs = [
        'vuln'    => ['label' => '취약점',    'n' => $vulnTotal],
        'packages'=> ['label' => '설치 패키지', 'n' => $packageTotal],
        // 컨테이너 대장 — 호스트와 OS 가 다를 수 있는 별도 자산이라 목록을 따로 준다.
        'containers'=> ['label' => '컨테이너', 'n' => $containerTotal],
        // 이 탭은 노출 소켓과 실행 프로세스 두 목록을 함께 제공하므로 둘의 합계를 표시한다.
        'runtime' => ['label' => '런타임',    'n' => $runtimeTotal],
        'cce'     => ['label' => '보안 설정', 'n' => $cceFail],
        // 계정 대장 — "설정 정책"이 아니라 실제로 존재하는 계정(ISMS-P 2.5.x · N2SF AC).
        'accounts'=> ['label' => '계정',      'n' => $accountTotal],
    ];
    if ($suppressedCount > 0) { $tabDefs['suppressed'] = ['label' => '억제', 'n' => $suppressedCount]; }
    // 스캔 이력 = 회차 표 + 그 회차들의 에이전트 리소스 추이(예전 '리소스' 탭을 흡수).
    $tabDefs['scans'] = ['label' => '스캔 이력', 'n' => $scanTotal];
    /* 자산 설정 = 수집 제어 + 자산 등급 + 자산 삭제. 위험을 읽는 탭들 뒤에 둔다.
     *   등급 카드·삭제 카드는 예전엔 **모든 탭 아래**에 매번 붙어 있었다 — 취약점을 보러 온
     *   사람이 탭을 옮길 때마다 열 칸짜리 등급 확정 폼을 지나쳐야 했다. 한 곳으로 모은다. */
    $tabDefs['manage'] = ['label' => '자산 설정', 'n' => null];
?>
  <?php
  $meta = [
      vg_h(trim($host['os_id'] . ' ' . $host['os_version'])) ?: 'OS 미상',
      vg_asset_state(
          $scan !== null,
          $pollAge,
          $scanAge,
          (int) ($host['poll_schedule_seconds'] ?? 3600)
      ),
      '최신 수집 ' . vg_h($scan['collected_at']),
      '<a href="' . vg_h(vg_qs(['tab' => 'packages', 'page' => null, 'q' => null])) . '">패키지 '
          . number_format($packageTotal) . '개</a>',
  ];
  /* 의존성 그래프 링크는 식별부에서 내렸다 — 자산 계열 화면(전체 설치 패키지·의존성 그래프)의
   *   진입점은 '구성 > 설치 패키지' 탭 한 곳으로 모은다. 링크 자체는 그 탭에 그대로 있다
   *   (엣지가 있는 자산에만 — 없는 자산에 걸면 빈 화면으로 보내게 된다). */
  if (!empty($host['last_seen_ip'])) { $meta[] = 'IP ' . vg_h($host['last_seen_ip']); }
  /* 자산 등급은 설정 탭으로 내려갔지만 "이 자산이 무엇인가"의 일부라 식별부에 남긴다 —
   *   옮기는 것이지 지우는 것이 아니다. 미확정이면 확정하러 갈 자리를 링크로 준다. */
  $meta[] = ($host['grade'] ?? '') !== ''
      ? '등급 ' . vg_asset_grade_badge((string) $host['grade'], false, (string) ($host['grade_reason'] ?? ''))
      : '<a href="' . vg_h(vg_qs(['tab' => 'manage', 'page' => null, 'q' => null])) . '">등급 미확정</a>';
  /* 자산 설정(수집 제어·등급·삭제)은 '이력' 그룹의 두 번째 하위 탭이라 상위 탭 한 번으로는
   *   닿지 않는다 — 첫 화면에서 한 번에 갈 자리를 식별부에 남긴다. 탭 줄에서 내린 것이지
   *   기능을 숨긴 것이 아니다(폼은 그 탭에 그대로 있다). */
  if (vg_can('assets')) {
      $meta[] = '<a href="' . vg_h(vg_qs(['tab' => 'manage', 'page' => null, 'q' => null])) . '">자산 설정</a>';
  }
  $meta[] = '<a href="/">대시보드</a>';
  if (vg_can('assets')) { $meta[] = '<a href="/assets.php">자산관리</a>'; }
  vg_hero(vg_h($host['fqdn']), $meta, $worst ?? '양호', $heroTone, '최고 위험도', '');
  /* 수집 제어(즉시 실행·예약·주기·속도 티어)는 '자산 설정' 탭으로 내려갔다.
   *   자산 상세를 여는 이유는 "이 서버가 얼마나 위험한가"이지 "수집 주기가 몇 분인가"가 아니다 —
   *   첫 화면을 설정 폼이 통째로 차지하면 위험 요약과 취약점 목록이 스크롤 아래로 밀린다.
   *   기능은 그대로 살아 있다(같은 폼·같은 action·같은 엔드포인트). */

  /* SBOM 다운로드. 지금까지 sbom.php 는 만들어 두고 **화면 어디에서도 링크하지 않아**,
   *   URL 을 아는 사람만 쓸 수 있었다(grep 결과 링크 0건). 부품표는 자산의 속성이라
   *   자산 상세 첫 화면이 제자리다. 컨테이너별 SBOM 은 컨테이너 상세에 같은 줄로 있다. */
  vg_sbom_links((string) $host['fqdn']);

  // CVE 피드가 지원하지 않는 배포판이면 매칭 후보가 아예 없어 **취약점이 0건으로 뜬다.**
  //   운영자는 "안전하다"고 읽는다 — 침묵하는 미탐이라 반드시 화면에 알린다.
  $unsup = [];
  $u = vg_distro_unsupported($host['os_id'] ?? null, $host['os_version'] ?? null);
  if ($u !== null) { $unsup[] = '이 호스트 — ' . $u; }
  foreach ($unsupContainers as $c) {
      $unsup[] = '컨테이너 ' . $c['cid'] . ' — ' . $c['reason'];
  }
  if ($unsup) {
      vg_alert([
          'type'  => 'warn',
          'title' => '취약점 매칭이 수행되지 않습니다',
          'hints' => array_merge(
              [
                  '아래 대상은 피드가 모르는 배포판이거나, 패키지 DB 가 없어 무엇이 깔렸는지 알 수 없습니다.',
                  '취약점 0건은 "안전함"이 아니라 "판정 불가"입니다.',
              ],
              $unsup
          ),
      ]);
  }

  // 위 경고와 같은 주제("0건 = 안전"이 아닐 수 있다)의 세 번째 축.
  //   배포판·이미지 문제가 아니라 **에이전트가 그 항목을 못 걷은** 경우다 — 지금까진 침묵했다.
  if ($missingStages) {
      $stageHints = [
          '해당 항목의 0건은 "없음"이 아니라 "수집 실패"입니다.',
          '에이전트 실행 권한·환경을 확인한 뒤 다시 수집하세요.',
      ];
      foreach ($missingStages as $s) { $stageHints[] = '수집 실패 — ' . $s; }
      vg_alert([
          'type'  => 'warn',
          'title' => '이 스캔은 일부 항목을 수집하지 못했습니다',
          'hints' => $stageHints,
      ]);
  }
  ?>

  <div class="cards">
    <?php foreach (['CRITICAL','HIGH','MEDIUM','LOW'] as $s): ?>
      <div class="kpi kpi--sm tone-<?= vg_sev_tone($s) ?>"><b><?= (int) $counts[$s] ?></b><span><?= $s ?></span></div>
    <?php endforeach; ?>
    <?php /* 심각도 분포만으로는 "지금 당장 무엇이 무서운가"를 못 읽는다 — 실제로 악용되고 있고
             (KEV) 밖에서 닿는(EXTERNAL) 건수를 같은 줄에 세운다. 둘 다 위 GROUP BY 한 번에서 나온다. */ ?>
    <div class="kpi kpi--sm tone-<?= $kevCount > 0 ? 'crit' : 'muted' ?>"
         title="KEV — 실제 악용이 확인된 취약점(CISA Known Exploited Vulnerabilities)">
      <b><?= number_format($kevCount) ?></b><span>KEV 악용확인</span>
    </div>
    <a class="kpi kpi--sm tone-<?= $externalFindings > 0 ? 'crit' : 'ok' ?>"
       href="/findings.php?scan_id=<?= (int) $scan['scan_id'] ?>&amp;st=EXTERNAL">
      <b><?= number_format($externalFindings) ?></b><span>외부노출 취약점</span>
    </a>
    <a class="kpi kpi--sm" href="<?= vg_h(vg_qs(['tab' => 'runtime', 'page' => null, 'q' => null])) ?>">
      <b><?= number_format($exposureCount) ?></b><span>노출 소켓</span>
    </a>
    <a class="kpi kpi--sm tone-<?= $cceFail > 0 ? 'high' : 'ok' ?>" href="<?= vg_h(vg_qs(['tab' => 'cce', 'page' => null])) ?>">
      <b><?= (int) $cceFail ?></b><span>설정 취약</span>
    </a>
  </div>

  <?php /* 2단 탭 — 상위 4개(위험·구성·준거·이력) + 그 그룹의 하위 탭. 매핑은 nav.php 소유.
           $tab 키와 각 탭의 조회 분기는 그대로다(URL 하위호환 · 쿼리는 여전히 활성 탭 하나만 돈다). */ ?>
  <?php vg_asset_tabs($tabDefs, $tab); ?>

  <?php if ($tab === 'vuln'):
    // 두 표(CRITICAL·HIGH / 재시작·재부팅)는 열 구성이 같다 — 스펙을 한 번만 만들어 나눠 쓴다.
    /* 열 구성의 기준: 식별자는 절대 접지 않고(CVE-2023-6780 이 세 줄로 쪼개지던 자리),
     *   문장은 접되 뜻이 끊기지 않게 한다.
     *   - '등급'·'상태' 를 한 칸에 겹쳤다 — 둘 다 뱃지 하나짜리라 열을 따로 세울 값이 아니었고,
     *     열이 하나 줄어야 '근거' 가 문장으로 읽히는 폭을 갖는다. KEV 도 여기 붙는다.
     *   - 'width' 는 %로 준다. rem 으로 주면 나머지 한 칸(근거)이 "남은 자리"만 받아
     *     실측 1568px 에서 90px 까지 눌렸다 — 문장이 두 글자에서 끊긴다. 비율로 나누면
     *     화면이 좁아져도 근거가 문장 폭을 유지한다.
     *   - 근거는 **자르지 않고 접는다**(줄바꿈). vg_trunc(.trunc = 한 줄 nowrap · 최대 46vw)를
     *     쓰면 그 칸이 46vw 를 요구해 표가 가로로 넘치고, 밀려난 CVE 열이 하이픈마다 접혔다.
     *     .clamp-2 도 안 쓴다 — overflow:hidden 이라 이 칸의 최소폭이 0 이 되어(auto 레이아웃에서
     *     항상 지는 칸이 된다) 실측 90px 까지 눌려 두 글자에서 끊겼다. 그냥 접히게 두면
     *     max-content 가 가장 커서 남는 폭을 이 칸이 가장 많이 받는다 — 행은 높아지고 문장은 산다.
     *     (전체 문장은 행을 눌러 여는 상세 모달에도 그대로 있다.) */
    $vulnHeaders = [
        ['label' => '등급·상태', 'key' => 'severity', 'width' => '11%'],
        ['label' => 'CVE', 'nowrap' => true, 'width' => '12%'],
        ['label' => 'EPSS', 'align' => 'right', 'nowrap' => true, 'width' => '9%'],   // 확률(%) — advisory·package·cves 화면과 같은 정렬
        ['label' => '패키지', 'width' => '14%'],
        ['label' => '근거', 'width' => '34%'],
        ['label' => '조치', 'width' => '20%'],
    ];
    $vulnCells = [
        // 등급·노출상태·KEV — 이 행이 얼마나 급한지를 한 칸에서 읽는다.
        'severity' => fn($f) => vg_sev_badge((string) $f['severity'])
                       . ' ' . vg_status_badge($f['runtime_status'])
                       . (!empty($f['in_kev']) ? ' ' . vg_badge('KEV', 'crit', '실제 악용이 확인된 취약점') : ''),
        // 이력은 열을 따로 세우지 않는다 — 뱃지 하나짜리 열이 근거 문장에서 폭을 가져갔다.
        //   같은 CVE 를 가리키는 링크라 식별자 아래가 제자리다.
        1 => fn($f) => '<strong><a href="/cve.php?cve=' . urlencode($f['cve_id']) . '">' . vg_h($f['cve_id']) . '</a></strong>'
                       . '<div><a class="pill" href="'
                       . vg_h(vg_finding_history_url($hostId, (int) $f['container_id'], (string) $f['cve_id'], (string) $f['package_name']))
                       . '" title="스캔별 이력 보기">🕘 이력</a></div>',
        2 => fn($f) => vg_epss_cell($f['epss'], $f['epss_percentile']),
        // 패키지명과 버전은 한 줄로 눕힌다(예전엔 'libc6 2.39-' / '0ubuntu8.8' 로 접혔다).
        //   커널은 재부팅해야 새 코드가 올라온다 — 프로세스 재시작으로는 안 고쳐진다.
        3 => fn($f) => '<strong>' . vg_h($f['package_name']) . '</strong> <code>' . vg_h($f['installed_version']) . '</code>'
                       . (!empty($f['needs_restart'])
                          ? ' ' . vg_badge(vg_is_kernel_code_pkg((string) ($f['package_name'] ?? '')) ? '재부팅 필요' : '재시작 필요', 'high')
                          : ''),
        4 => fn($f) => '<span class="why">' . vg_h((string) ($f['rationale'] ?? '')) . '</span>',
        // 재시작/재부팅이 필요하면 조치는 "업그레이드"가 아니다(이미 패치돼 있다).
        //   전이 의존성이면 "이 버전으로 올려라"도 틀린다 — 부모가 끌어오는 것이라 혼자 못 바꾼다.
        5 => function ($f) use ($depOrigins, $hostId) {
            if (!empty($f['needs_restart'])) {
                return '<span class="pill">' . (vg_is_kernel_code_pkg((string) ($f['package_name'] ?? '')) ? '재부팅' : '프로세스 재시작') . '</span>';
            }
            $o = $depOrigins['origins'][vg_host_dep_key($f)] ?? null;
            if ($o !== null) { return vg_host_dep_origin_cell($o, $hostId); }
            /* 버전 조치는 이 화면에서만 평문으로 눕힌다. vg_fix_cell 의 .pill 은 nowrap 이고
             *   (app.css 소유 — 목록 화면들은 거기서 white-space:normal 로 풀어 준다)
             *   이 표는 table-layout:auto 라, 접히지 않는 한 칸이 "0:2.34-60.el9_2.3 →
             *   0:2.28-225.0.4.el8_8.6 이상" 만으로 표 폭의 38%(실측 466px)를 가져가
             *   근거 문장이 100px 로 눌렸다. 조치 문구가 접히면 그 폭이 근거로 돌아온다.
             *   조치버전이 없는 경우(참조 링크·평문)는 짧으므로 공용 헬퍼를 그대로 쓴다. */
            $fixed = (string) ($f['fixed_version'] ?? '');
            if ($fixed !== '') {
                // 목표 버전이 먼저다(그게 조치다). 현재 버전은 아랫줄 — 두 버전을 한 줄에 이으면
                //   그 줄 하나가 이 열의 폭을 결정한다(같은 이유로 위 근거가 눌렸다).
                $installed = (string) ($f['installed_version'] ?? '');
                return '<strong>→ ' . vg_h($fixed) . ' 이상</strong>'
                    . ($installed !== '' ? '<div class="why">현재 ' . vg_h($installed) . '</div>' : '');
            }
            return vg_fix_cell(null, $f['ref_urls_json'] ?? null, $f['installed_version'] ?? null);
        },
    ];
    $findingRowAttrs = function (array $f) use ($hostId, $depOrigins, $findingStatuses): array {
        $epss = ($f['epss'] ?? null) === null ? '–' : number_format((float) $f['epss'] * 100, 1) . '%';
        if (($f['epss_percentile'] ?? null) !== null) {
            $top = max(0.01, (1.0 - (float) $f['epss_percentile']) * 100);
            $epss .= ' · 상위 ' . number_format($top, $top < 1 ? 2 : ($top < 10 ? 1 : 0)) . '%';
        }
        $isKernel = vg_is_kernel_code_pkg((string) ($f['package_name'] ?? ''));
        $depOrigin = $depOrigins['origins'][vg_host_dep_key($f)] ?? null;
        if (!empty($f['needs_restart'])) {
            $action = $isKernel ? '패치된 커널을 적용하려면 호스트를 재부팅하세요.' : '패치된 라이브러리를 적용하려면 관련 프로세스를 재시작하세요.';
        } elseif ($depOrigin !== null) {
            // 전이 의존성 — 이 패키지만 갈아끼우면 부모가 깨진다. 부모를 올리는 것이 조치다.
            $action = '직접 조치 불가 — ' . vg_host_dep_parent_label($depOrigin)
                    . '. 이 패키지만 바꾸면 부모가 깨집니다. 부모를 올려 안전한 자식을 끌어오게 하세요.';
        } elseif (!empty($f['fixed_version'])) {
            $action = (string) ($f['installed_version'] ?? '') . ' → ' . (string) $f['fixed_version'] . ' 이상으로 업데이트';
        } else {
            $action = '공식 패치 또는 벤더 권고를 확인하세요.';
        }
        $historyUrl = vg_finding_history_url($hostId, (int) $f['container_id'], (string) $f['cve_id'], (string) $f['package_name']);
        /* 조치 상태 — 모달의 상태 폼이 이 값으로 셀렉트를 맞추고, 저장 대상을 식별할 자연키
         *   (컨테이너 이름·CVE·패키지)를 hidden 으로 채운다. 기록이 없으면 미조치(OPEN)다. */
        $cref = (string) ($f['container_cid'] ?? '');
        $fs = $findingStatuses[vg_finding_status_key($hostId, $cref, (string) $f['cve_id'], (string) $f['package_name'])] ?? null;
        $detail = [
            'severity' => (string) $f['severity'],
            'status' => vg_status_label($f['runtime_status'] ?? null),
            'fix_status' => (string) ($fs['status'] ?? 'OPEN'),
            'fix_status_label' => vg_finding_status_label($fs['status'] ?? null),
            'fix_note' => (string) ($fs['note'] ?? ''),
            'container_ref' => $cref,
            'cve' => (string) $f['cve_id'],
            'epss' => $epss,
            'package' => (string) $f['package_name'],
            'installed' => (string) ($f['installed_version'] ?? '–'),
            'fixed' => (string) ($f['fixed_version'] ?? '–'),
            'rationale' => (string) ($f['rationale'] ?? '근거 정보가 없습니다.'),
            'action' => $action,
            'cve_url' => '/cve.php?cve=' . urlencode((string) $f['cve_id']),
            'history_url' => $historyUrl,
        ];
        return [
            'data-finding-detail' => json_encode($detail, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
            'tabindex' => '0',
            'role' => 'button',
            'aria-label' => (string) $f['cve_id'] . ' 상세 보기',
        ];
    };
    $vulnOpts = [
        'card'      => false,
        'row_class' => fn($f) => vg_sev_row((string) $f['severity']),
        'row_attrs' => $findingRowAttrs,
        'cell'      => $vulnCells,
    ];
    // 그래프가 상한에서 잘렸으면 밝힌다 — 조용히 자르면 "전이 아님"이 사실처럼 보인다.
    if ($depOrigins['edge_truncated'] || $depOrigins['path_truncated'] || $depOrigins['finding_truncated']) {
        $depHints = [];
        if ($depOrigins['finding_truncated']) {
            $depHints[] = '집계에 쓴 취약점이 상한(' . number_format(VG_PKGDEP_ROLLUP_FINDING_MAX)
                . '건)에서 잘렸습니다 — 아래 "먼저 올릴 대상"의 건수는 전수가 아닙니다.';
        }
        if ($depOrigins['edge_truncated']) {
            $depHints[] = '엣지가 상한(' . number_format(VG_PKGDEP_EDGE_MAX) . '개)에서 잘렸습니다 — 그 뒤의 의존성은 보지 않았습니다.';
        }
        if ($depOrigins['path_truncated']) {
            $depHints[] = '경로가 상한(깊이 ' . VG_PKGDEP_DEPTH_MAX . ' · ' . VG_PKGDEP_PATH_MAX . '개)에서 끊겼습니다 — 손댈 대상이 더 있을 수 있습니다.';
        }
        $depHints[] = '전체 구조는 의존성 그래프 화면에서 확인하세요.';
        vg_alert(['type' => 'warn', 'title' => '의존성 판정이 일부만 반영됐습니다', 'hints' => $depHints]);
    }
  ?>
    <?php
    /* ── 손댈 대상(부모)별 묶음 — "이 하나를 올리면 N건" ────────────────────────
     *   행 단위로만 보면 "그래서 뭐부터 올리지?" 에 답이 안 나온다. 같은 부모가 여러
     *   취약점을 끌어오는 건 흔해서, 그 묶음을 먼저 보여주는 것이 조치 순서를 바꾼다.
     *   집계는 **스캔 전체** 기준이라 페이지를 넘겨도 값이 변하지 않는다.
     *   전이 취약점이 없으면 이 요약 자체를 그리지 않는다 — 빈 카드는 잡음이다. */
    if ($depOrigins['parents']):
        $rollupAll = $depOrigins['parents'];
        $rollupTop = array_slice($rollupAll, 0, VG_PKGDEP_ROLLUP_TOP);
        $rollupHeaders = [
            ['label' => '먼저 올릴 대상'],
            ['label' => '최고 등급', 'key' => 'severity'],
            ['label' => '해결 건수', 'align' => 'right', 'nowrap' => true],
            ['label' => '끌어오는 취약 패키지'],
        ];
        $rollupOpts = [
            'card'      => false,
            'row_class' => fn($p) => vg_sev_row((string) $p['severity']),
            'cell'      => [
                0 => fn($p) => vg_host_dep_rollup_target($p, $hostId),
                'severity' => fn($p) => vg_sev_badge((string) $p['severity']),
                2 => fn($p) => '<strong>' . number_format((int) $p['count']) . '</strong>건',
                3 => function ($p) {
                    $shown = array_slice($p['packages'], 0, VG_PKGDEP_ROLLUP_PKG_TOP);
                    $more  = count($p['packages']) - count($shown);
                    return '<span class="why">' . vg_h(implode(', ', $shown))
                        . ($more > 0 ? ' 외 ' . $more . '개' : '') . '</span>';
                },
            ],
        ];
    ?>
    <div class="card">
      <strong>먼저 올릴 대상 <span class="hint">(<?= number_format(count($rollupAll)) ?>개)</span></strong>
      <span class="why">— 이 부모를 올리면 그 아래 취약점이 함께 해결됩니다. 스캔 전체 기준이라 페이지를 넘겨도 값이 변하지 않습니다.
        <?php if (count($rollupAll) > count($rollupTop)): ?>
          · <?= number_format(count($rollupAll)) ?>개 중 상위 <?= count($rollupTop) ?>개
        <?php endif; ?>
        · 올릴 버전은 제시하지 않습니다 — 부모의 다른 버전이 무엇을 끌어오는지는 수집된 정보로 알 수 없습니다.
      </span>
      <div class="card__body">
      <?php vg_table($rollupHeaders, $rollupTop, $rollupOpts); ?>
      </div>
    </div>
    <?php endif; ?>
    <?php
    /* ── 같은 패키지에서 나온 묶음 ────────────────────────────────────────────
     *   위 "먼저 올릴 대상" 은 전이 의존성이 있는 자산에만 나온다. dpkg/rpm 만 있는 자산에서는
     *   libc6 하나가 만든 CVE 다섯 건이 근거까지 사실상 같은 다섯 행으로 화면을 채운다 —
     *   같은 질문("무엇부터 올리나")에 같은 형태로 답한다.
     *   묶임이 없으면(전부 1건씩) 이 카드는 아예 그리지 않는다 — 빈 요약은 잡음이다. */
    if ($pkgRollup['rows']):
        $pkgRollupHeaders = [
            ['label' => '먼저 올릴 패키지'],
            ['label' => '최고 등급', 'key' => 'severity', 'nowrap' => true, 'width' => '8rem'],
            ['label' => '해결 건수', 'align' => 'right', 'nowrap' => true, 'width' => '7rem'],
            ['label' => '비고'],
        ];
        $pkgRollupOpts = [
            'card'      => false,
            'row_class' => fn($p) => vg_sev_row((string) $p['severity']),
            'cell'      => [
                0 => fn($p) => '<strong>' . vg_h((string) $p['package_name']) . '</strong> '
                    . '<code>' . vg_h((string) $p['installed_version']) . '</code> '
                    . '<a class="pill" href="' . vg_h(vg_qs(['q' => (string) $p['package_name'], 'page' => null]))
                    . '">이 패키지만 보기</a>',
                'severity' => fn($p) => vg_sev_badge((string) $p['severity']),
                2 => fn($p) => '<strong>' . number_format((int) $p['cnt']) . '</strong>건',
                3 => function ($p) {
                    $b = [];
                    if (!empty($p['kev'])) { $b[] = vg_badge('KEV 포함', 'crit', '실제 악용이 확인된 취약점이 섞여 있습니다.'); }
                    if (!empty($p['needs_restart'])) {
                        $b[] = vg_badge(vg_is_kernel_code_pkg((string) $p['package_name']) ? '재부팅 필요 포함' : '재시작 필요 포함', 'high');
                    }
                    return $b ? implode(' ', $b) : '<span class="why">–</span>';
                },
            ],
        ];
    ?>
    <div class="card">
      <strong>같은 패키지에서 나온 취약점 <span class="hint">(<?= count($pkgRollup['rows']) ?>개 패키지)</span></strong>
      <span class="why">— 이 패키지 하나를 올리면 그 아래 CRITICAL·HIGH 가 함께 해결됩니다.
        스캔 전체 기준이라 페이지를 넘겨도 값이 변하지 않습니다. 2건 이상 묶인 것만 셉니다.
        <?php if ($pkgRollup['truncated']): ?>
          · 묶음이 더 있습니다 — 많이 묶인 순으로 <?= count($pkgRollup['rows']) ?>개만 보여줍니다.
        <?php endif; ?>
      </span>
      <div class="card__body">
      <?php vg_table($pkgRollupHeaders, $pkgRollup['rows'], $pkgRollupOpts); ?>
      </div>
    </div>
    <?php endif; ?>
    <?php vg_toolbar([
        ['type' => 'search', 'name' => 'q', 'placeholder' => 'CVE 또는 패키지명 검색', 'value' => $q],
        ['type' => 'hidden', 'name' => 'tab', 'value' => $tab],
        ['type' => 'hidden', 'name' => 'id', 'value' => (string) $hostId],
    ]); ?>
    <div class="card">
      <strong>우선순위 취약점 (CRITICAL·HIGH)</strong>
      <span class="why">— <a href="/findings.php?scan_id=<?= (int) $scan['scan_id'] ?>">전체 취약점 보기 →</a></span>
      <div class="card__body">
      <?php
      vg_table($vulnHeaders, $rows, $vulnOpts + [
          'empty' => $hasFilter
              ? [
                  'icon'  => '🔍',
                  'title' => '검색 결과가 없습니다.',
                  'hint'  => '검색어를 확인하거나 초기화해 보세요.',
                  'cta'   => ['href' => vg_qs(['q' => null, 'page' => null]), 'label' => '검색 초기화'],
              ]
              : [
                  'icon'  => '✅',
                  'title' => 'CRITICAL·HIGH 가 없습니다.',
                  'hint'  => '아래의 재시작·재부팅 필요 항목은 등급이 낮아도 확인하세요.',
              ],
      ]);
      ?>
      </div>
    </div>
    <?php vg_page_nav($total, $perPage, $page); ?>

    <div class="card mt-lg">
      <strong>재시작·재부팅 필요 <span class="hint">(<?= number_format($restartTotal) ?>건)</span></strong>
      <span class="why">— 패치 완료, 재시작 전까지 옛 코드 실행 중
        <?php if ($restartTotal > count($restartRows)): ?>
          · 상위 <?= count($restartRows) ?>건 ·
          <a href="/findings.php?scan_id=<?= (int) $scan['scan_id'] ?>&amp;fx=restart">전체 보기 →</a>
        <?php endif; ?>
      </span>
      <div class="card__body">
      <?php
      vg_table($vulnHeaders, $restartRows, $vulnOpts + [
          'empty' => [
              'icon'  => '✅',
              'title' => '재시작·재부팅이 필요한 항목이 없습니다.',
              'hint'  => '패치된 라이브러리를 옛 프로세스가 물고 있는 경우가 없습니다.',
          ],
      ]);
      ?>
      </div>
    </div>

    <?php
    /* 조치 상태 변경은 **쓰기 작업**이다 — 조회(findings 메뉴)만으로는 못 한다. 자산 등급 확정이
     *   관리자 전용인 것과 같은 기준으로, 상태는 실제 조치를 굴리는 운영자까지 허용한다
     *   (자산 삭제·속도 티어와 동일). 인가는 아래 POST 분기에서 서버측으로 다시 확정한다 —
     *   여기서 폼을 숨기는 것은 화면 정리일 뿐 통제가 아니다. */
    $canFixStatus = vg_has_role('admin', 'operator');
    vg_modal_open('findingDetailModal', '취약점 상세', 'modal--wide finding-detail-modal');
    if ($canFixStatus) {
        // 폼이 모달 본문 전체를 감싼다 — 저장 버튼이 모달 푸터(오른쪽 아래)에 서야 하기 때문
        //   (vg_modal_foot 은 본문 안에서 그려진다). 대상 식별자는 JS 가 행에서 받아 채운다.
        echo '<form method="post">'
           . '<input type="hidden" name="csrf" value="' . vg_h($agentCsrf) . '">'
           . '<input type="hidden" name="action" value="finding_set_status">'
           . '<input type="hidden" name="id" value="' . (int) $hostId . '">'
           . '<input type="hidden" name="container_ref" data-finding-fix-ref value="">'
           . '<input type="hidden" name="cve_id" data-finding-fix-cve value="">'
           . '<input type="hidden" name="package_name" data-finding-fix-package value="">';
    }
    ?>
      <div class="finding-detail__summary">
        <span class="badge" data-finding-severity></span>
        <span class="badge tone-muted" data-finding-status></span>
        <strong data-finding-cve></strong>
      </div>
      <dl class="finding-detail__grid">
        <div><dt>패키지</dt><dd data-finding-package></dd></div>
        <div><dt>설치 버전</dt><dd data-finding-installed></dd></div>
        <div><dt>조치 버전</dt><dd data-finding-fixed></dd></div>
        <div><dt>EPSS</dt><dd data-finding-epss></dd></div>
      </dl>
      <section class="finding-detail__section">
        <strong>판정 근거</strong>
        <p data-finding-rationale></p>
      </section>
      <section class="finding-detail__section">
        <strong>권장 조치</strong>
        <p data-finding-action></p>
      </section>
      <section class="finding-detail__section">
        <strong>조치 상태</strong>
        <?php if ($canFixStatus): ?>
          <div class="form-grid">
            <label class="field" for="findingFixStatus">상태
              <select id="findingFixStatus" name="status" data-finding-fix-status>
                <?php foreach (vg_finding_status_labels() as $code => $label): ?>
                  <option value="<?= vg_h($code) ?>"><?= vg_h($label) ?></option>
                <?php endforeach; ?>
              </select>
            </label>
            <label class="field" for="findingFixNote">메모 (선택)
              <input type="text" id="findingFixNote" name="note" data-finding-fix-note
                     maxlength="<?= VG_FINDING_STATUS_NOTE_MAX ?>" autocomplete="off"
                     placeholder="예: 다음 정기 점검 때 반영">
            </label>
          </div>
          <span class="why">담당자 배정·결재선은 없습니다 — 상태와 메모 한 줄만 남습니다. 저장하면 접속기록에 남습니다.</span>
        <?php else: ?>
          <p data-finding-fix-status-label></p>
          <span class="why">상태 변경은 관리자·운영자만 할 수 있습니다.</span>
        <?php endif; ?>
      </section>
    <?php
    vg_modal_foot($canFixStatus ? '상태 저장' : null, [
        'extra' => '<a class="btn btn--ghost" data-finding-history href="#">이력 보기</a>'
                 . '<a class="btn btn--primary" data-finding-cve-link href="#">CVE 상세</a>',
        'cancel' => '닫기',
        'loading' => '저장 중…',
    ]);
    if ($canFixStatus) { echo '</form>'; }
    vg_modal_close();
    ?>

  <?php elseif ($tab === 'packages'): ?>
    <?php vg_toolbar([
        ['type' => 'search', 'name' => 'q', 'placeholder' => '패키지명·소스·출처 검색', 'value' => $q],
        ['type' => 'hidden', 'name' => 'tab', 'value' => $tab],
        ['type' => 'hidden', 'name' => 'id', 'value' => (string) $hostId],
    ]); ?>
    <?php
    // ── 패키지 무결성(관측) ─────────────────────────────────────────────
    //   "미수행"과 "0건"을 절대 합치지 않는다 — 합치면 검사도 안 한 자산이 "정상"으로 보인다.
    //   어휘도 단정하지 않는다: 운영자가 직접 고친 파일일 수 있으므로 "변조됨"이 아니라
    //   "패키지 원본과 다름(관측)" 이다(nofix.php 의 EOL 표현과 같은 원칙).
    $integChecked = !empty($scan['integrity_checked']);
    $integTotal   = (int) ($scan['integrity_total'] ?? 0);
    $integPartial = !empty($scan['integrity_partial']);
    if (!$integChecked) {
        $integTone = 'muted';
        $integText = '미수행 — 에이전트를 <code>--verify-files</code> 로 실행해야 검사합니다(비용 때문에 기본 꺼짐).';
    } elseif ($integTotal === 0) {
        $integTone = 'ok';
        $integText = '패키지 원본과 다른 파일이 관측되지 않았습니다.';
    } else {
        $integTone = 'high';
        $integText = '패키지 원본과 다른 파일 ' . number_format($integTotal) . '건이 관측되었습니다. '
            . '운영자가 직접 바꾼 파일일 수도 있어 변조로 단정하지 않습니다.';
    }
    ?>
    <div class="card">
      <strong>패키지 무결성</strong>
      <?= vg_badge($integChecked ? ($integTotal === 0 ? '정상' : '원본과 다름 ' . number_format($integTotal) . '건') : '미수행', $integTone) ?>
      <?php if ($integPartial): ?><?= vg_badge('부분 결과', 'med', '제한시간·줄수 상한으로 잘렸습니다. 0건이 "깨끗함"을 뜻하지 않습니다.') ?><?php endif; ?>
      <span class="why"> · <?= $integText ?></span>
      <?php if ($integPartial): ?>
        <span class="why"> · 검사가 도중에 잘렸습니다 — 아래 목록과 건수는 전수가 아닙니다.</span>
      <?php endif; ?>
      <?php if ($integrityRows): ?>
        <div class="card__body">
        <?php
        vg_table(
            [
                ['label' => '파일', 'key' => 'file_path', 'class' => 'col-id'],
                ['label' => '관측된 차이', 'key' => 'flags'],
                ['label' => '패키지', 'key' => 'package_name'],
            ],
            $integrityRows,
            [
                'card' => false,
                'cell' => [
                    'file_path' => fn($r) => '<code>' . vg_h((string) $r['file_path']) . '</code>',
                    'flags' => fn($r) => vg_h(vg_integrity_flag_label((string) $r['flags']))
                        . ' <span class="why">' . vg_h((string) $r['flags']) . '</span>',
                    'package_name' => fn($r) => ($r['package_name'] ?? '') !== ''
                        ? vg_h((string) $r['package_name'])
                        : '<span class="why">미상</span>',
                ],
            ]
        );
        ?>
        </div>
        <?php if ($integTotal > count($integrityRows)): ?>
          <span class="why">상위 <?= count($integrityRows) ?>건만 표시합니다(전체 <?= number_format($integTotal) ?>건).</span>
        <?php endif; ?>
      <?php endif; ?>
    </div>

    <div class="card">
      <strong>설치 패키지</strong>
      <span class="why"> · 최신 수집 기준 호스트 운영체제 패키지 <?= number_format($packageTotal) ?>개</span>
      <?php if ($depEdgeTotal > 0): ?>
        <span class="why"> · <a href="/depgraph.php?id=<?= (int) $hostId ?>">무엇이 이 패키지를 끌어왔나(의존성 그래프)</a></span>
      <?php endif; ?>
      <?php /* 전체 설치 패키지(asset-packages.php)는 자산을 고르지 않으면 함대 전체가 한 표에 쏟아진다 —
               이 자산으로 필터한 링크를 주 진입점으로 둔다(화면 자체는 전역 검색용으로 남는다). */ ?>
      <span class="why"> · <a href="/asset-packages.php?host=<?= (int) $hostId ?>">다른 자산과 나란히 보기(전체 설치 패키지)</a></span>
      <div class="card__body">
      <?php
      vg_table(
          [
              ['label' => '패키지', 'key' => 'name', 'class' => 'col-id'],
              ['label' => '설치 버전', 'key' => 'version'],
              ['label' => '아키텍처', 'key' => 'arch'],
              ['label' => '관리자', 'key' => 'manager'],
              ['label' => '소스 패키지', 'key' => 'source_pkg'],
              ['label' => '출처', 'key' => 'origin'],
          ],
          $rows,
          [
              'card' => false,
              'empty' => $hasFilter
                  ? [
                      'icon' => '⌕',
                      'title' => '검색 조건에 맞는 설치 패키지가 없습니다.',
                      'cta' => ['href' => vg_qs(['q' => null, 'page' => null]), 'label' => '검색 초기화'],
                  ]
                  : [
                      'icon' => '□',
                      'title' => '수집된 운영체제 패키지가 없습니다.',
                  ],
              'cell' => [
                  'name' => fn($p) => '<strong>' . vg_h((string)$p['name']) . '</strong>',
                  'version' => fn($p) => '<code>' . vg_h((string)($p['version'] ?? '')) . '</code>',
                  'arch' => fn($p) => $p['arch'] ? vg_h((string)$p['arch']) : '<span class="why">–</span>',
                  'manager' => fn($p) => '<code>' . vg_h((string)$p['manager']) . '</code>',
                  'source_pkg' => function ($p) {
                      if (empty($p['source_pkg'])) { return '<span class="why">–</span>'; }
                      return vg_h((string)$p['source_pkg'])
                          . (!empty($p['source_version']) ? ' <span class="why">' . vg_h((string)$p['source_version']) . '</span>' : '');
                  },
                  'origin' => fn($p) => $p['origin']
                      ? vg_h((string)$p['origin'])
                      : (!empty($p['vendor']) ? vg_h((string)$p['vendor']) : '<span class="why">–</span>'),
              ],
          ]
      );
      ?>
      </div>
    </div>
    <?php vg_page_nav($total, $perPage, $page); ?>

  <?php elseif ($tab === 'containers'): ?>
    <?php vg_toolbar([
        ['type' => 'search', 'name' => 'q', 'placeholder' => '컨테이너·이미지·네임스페이스 검색', 'value' => $q],
        ['type' => 'hidden', 'name' => 'tab', 'value' => $tab],
        ['type' => 'hidden', 'name' => 'id', 'value' => (string) $hostId],
    ]); ?>
    <?php
    /* 표가 아니라 **계층**으로 그린다.
     *   컨테이너는 "호스트에 딸린 행 6개"가 아니라 그 안에 자기 OS·패키지·프로세스·취약점을
     *   가진 별개 자산이다. 표 6열로는 그게 안 보여서, 운영자가 컨테이너 안을 볼 수 있다는
     *   사실 자체를 몰랐다(드릴다운 링크가 아예 없었다).
     *   루트(호스트) 한 줄 아래에 컨테이너 카드를 늘어놓고, 카드마다 이미지·OS·패키지 수와
     *   **심각도 분포 미니 게이지**를 얹어 "어느 컨테이너부터 열어야 하나"를 한눈에 준다.
     *   표에 있던 값(k8s 위치·다이제스트·SBOM 해시·상태)은 하나도 버리지 않고 카드로 옮겼다 —
     *   같은 행을 표와 카드로 두 번 그리지 않기 위해 표를 대체한다.
     *   JS·차트 라이브러리는 쓰지 않는다(CSP·오프라인 배포). 전부 CSS 와 게이지 폭 계산뿐이다. */
    // 런타임 상태 톤 — dead 만 위험으로 올린다(멈춘 컨테이너는 위험이 아니라 사실).
    $stateTone = ['running' => 'ok', 'restarting' => 'med', 'dead' => 'high'];
    ?>
    <div class="card">
      <strong>컨테이너</strong>
      <span class="why"> · 최신 수집 기준 <?= number_format($containerTotal) ?>개 · 컨테이너는 호스트와 OS 가 다를 수 있습니다</span>
      <div class="card__body">
        <?php if (!$rows): ?>
          <?php vg_empty($hasFilter
              ? [
                  'icon' => '⌕',
                  'title' => '검색 조건에 맞는 컨테이너가 없습니다.',
                  'cta' => ['href' => vg_qs(['q' => null, 'page' => null]), 'label' => '검색 초기화'],
              ]
              : [
                  'icon' => '□',
                  'title' => '수집된 컨테이너가 없습니다.',
                  'hint' => '이 호스트에서 실행 중인 컨테이너를 찾지 못했습니다.',
              ]); ?>
        <?php else: ?>
        <div class="ctree">
          <?php /* 루트 = 호스트 자신. 컨테이너가 "무엇 위에 떠 있는지"를 화면에서 잃지 않게 한다. */ ?>
          <div class="ctree__root">
            <span class="ctree__icon" aria-hidden="true">🖥️</span>
            <div class="ctree__rootid">
              <strong><?= vg_h((string) $host['fqdn']) ?></strong>
              <span class="why"><?= vg_h(trim($host['os_id'] . ' ' . $host['os_version'])) ?: 'OS 미상' ?>
                · 호스트 패키지 <?= number_format($packageTotal) ?>개</span>
            </div>
            <span class="badge tone-muted">컨테이너 <?= number_format($containerTotal) ?></span>
          </div>
          <ul class="ctree__list">
          <?php foreach ($rows as $c):
              $ctrId  = (int) $c['container_id'];
              $sev    = $sevByContainer[$ctrId] ?? [];
              $sevSum = array_sum($sev);
              // 카드 톤은 그 컨테이너의 최고 등급이다 — 취약점이 없으면 색을 가져가지 않는다.
              $ctrWorst = null;
              foreach (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as $s) {
                  if (($sev[$s] ?? 0) > 0) { $ctrWorst = $s; break; }
              }
              $href = '/container.php?id=' . (int) $hostId . '&cid=' . urlencode((string) $c['cid']);
              $os   = trim((string) ($c['os_id'] ?? '') . ' ' . (string) ($c['os_version'] ?? ''));
              $rState = (string) ($c['runtime_state'] ?? '');
              $k8s  = array_filter(
                  [$c['k8s_namespace'] ?? null, $c['k8s_pod'] ?? null, $c['k8s_container'] ?? null],
                  fn($v) => (string) $v !== ''
              );
          ?>
            <li class="ctrcard tone-<?= $ctrWorst !== null ? vg_h(vg_sev_tone($ctrWorst)) : 'muted' ?>">
              <div class="ctrcard__head">
                <a class="ctrcard__name" href="<?= vg_h($href) ?>"><?= vg_h((string) $c['cid']) ?></a>
                <?php if (!empty($c['name']) && (string) $c['name'] !== (string) $c['cid']): ?>
                  <span class="why"><?= vg_h((string) $c['name']) ?></span>
                <?php endif; ?>
                <?php if ($rState !== ''): ?><?= vg_badge($rState, $stateTone[$rState] ?? 'muted') ?><?php endif; ?>
              </div>

              <?php /* 이미지는 이 컨테이너가 무엇인지 그 자체다 — 길어도 접어서 다 보여준다. */ ?>
              <div class="ctrcard__image">
                <?= ((string) ($c['image'] ?? '')) !== ''
                      ? '<code>' . vg_h((string) $c['image']) . '</code>'
                      : '<span class="why">이미지 미상</span>' ?>
              </div>

              <div class="ctrcard__facts">
                <span><?= $os !== '' ? vg_h($os) : '<span class="why">OS 미상</span>' ?></span>
                <span><?= !empty($c['manager'])
                        ? '<code>' . vg_h((string) $c['manager']) . '</code>'
                        : '<span class="why">패키지 DB 없음</span>' ?></span>
                <span>패키지 <b><?= number_format((int) $c['pkg_count']) ?></b></span>
              </div>

              <?php /* 심각도 분포 — 게이지 폭(width:N%)은 vg_sev_bar() 가 계산한다(인라인 style 예외). */ ?>
              <div class="ctrcard__risk">
                <?php if ($sevSum > 0): ?>
                  <?= vg_sev_bar($sev) ?>
                  <div class="legend--inline">
                    <?php foreach (['CRITICAL' => 'crit', 'HIGH' => 'high', 'MEDIUM' => 'med', 'LOW' => 'low'] as $s => $tone): ?>
                      <?php if (($sev[$s] ?? 0) > 0): ?>
                        <span class="why"><?= vg_h($s) ?><span class="n"><?= number_format($sev[$s]) ?></span></span>
                      <?php endif; ?>
                    <?php endforeach; ?>
                  </div>
                <?php else: ?>
                  <span class="why">판정된 취약점 없음</span>
                <?php endif; ?>
              </div>

              <?php if ($k8s || !empty($c['workload_ref']) || !empty($c['image_digest']) || !empty($c['sbom_hash'])): ?>
                <div class="ctrcard__more">
                  <?php if ($k8s): ?><span class="why">k8s <?= vg_h(implode(' / ', $k8s)) ?></span><?php endif; ?>
                  <?php if (!empty($c['workload_ref'])): ?><span class="why">워크로드 <?= vg_h((string) $c['workload_ref']) ?></span><?php endif; ?>
                  <?php if (!empty($c['image_digest'])): ?><span class="why"><?= vg_trunc((string) $c['image_digest'], 24) ?></span><?php endif; ?>
                  <?php if (!empty($c['sbom_format']) || !empty($c['sbom_hash'])): ?>
                    <span class="why">SBOM <?= vg_h((string) ($c['sbom_format'] ?? '')) ?> <?= vg_trunc((string) ($c['sbom_hash'] ?? ''), 20) ?></span>
                  <?php endif; ?>
                </div>
              <?php endif; ?>

              <div class="links">
                <a href="<?= vg_h($href) ?>">상세 열기 →</a>
                <a href="<?= vg_h($href . '&tab=packages') ?>">패키지</a>
                <a href="<?= vg_h($href . '&tab=runtime') ?>">런타임</a>
              </div>
            </li>
          <?php endforeach; ?>
          </ul>
        </div>
        <?php endif; ?>
      </div>
    </div>
    <?php vg_page_nav($total, $perPage, $page); ?>

  <?php elseif ($tab === 'runtime'): ?>
    <?php vg_toolbar([
        ['type' => 'search', 'name' => 'q', 'placeholder' => '프로세스명·사용자·실행패키지 검색', 'value' => $q],
        ['type' => 'hidden', 'name' => 'tab', 'value' => $tab],
        ['type' => 'hidden', 'name' => 'id', 'value' => (string) $hostId],
    ]); ?>
    <?php
    // ── 재시작 필요(억제 취소 신호) ────────────────────────────────────────
    //   패치는 끝났는데 프로세스가 옛 .so 를 메모리에 물고 있으면 **여전히 취약**하다.
    //   오탐이 아니라 미탐 쪽이라(대시보드엔 "패치됨"으로 보인다) 억제 근거보다 세게 말한다.
    //   0건을 '깨끗함'으로 쓰지 않는다 — 이 목록은 실행 프로세스 수집에서 나오므로,
    //   그 단계가 없으면 "재시작 필요 없음"이 아니라 "알 수 없음"이다(NA ≠ PASS).
    $staleCollected = !in_array('runtime_processes', $missingStageCodes, true);
    $staleTotal = (int) ($staleLibs['total'] ?? 0);
    if (!$staleCollected) {
        $staleTone = 'muted';
        $staleText = '실행 프로세스를 수집하지 못해 재시작 필요 여부를 판정할 수 없습니다(0건이 "없음"이 아닙니다).';
        $staleLabel = '판정 불가';
    } elseif ($staleTotal === 0) {
        $staleTone = 'ok';
        $staleText = '옛 라이브러리를 물고 있는 프로세스가 관측되지 않았습니다.';
        $staleLabel = '해당 없음';
    } else {
        $staleTone = 'high';
        $staleText = '패치는 적용됐지만 아래 프로세스가 교체 전 라이브러리를 아직 메모리에 물고 있습니다. '
            . '조치는 업데이트가 아니라 재시작이며, 그동안 이 취약점은 억제되지 않습니다.';
        $staleLabel = '재시작 필요 ' . number_format($staleTotal) . '건';
    }
    ?>
    <div class="card">
      <strong>재시작 필요 (억제 취소 신호)</strong>
      <?= vg_badge($staleLabel, $staleTone) ?>
      <span class="why"> · <?= vg_h($staleText) ?></span>
      <?php if ($staleLibs['rows']): ?>
        <div class="card__body">
        <?php
        vg_table(
            [
                ['label' => '프로세스', 'key' => 'comm', 'class' => 'col-id'],
                ['label' => '패키지', 'key' => 'package_name'],
                ['label' => '옛 라이브러리'],
                ['label' => '조치'],
            ],
            $staleLibs['rows'],
            [
                'card' => false,
                'cell' => [
                    'comm' => fn($s) => '<strong>' . vg_h((string) ($s['comm'] ?? '?')) . '</strong>'
                        . ' <span class="why">PID ' . (int) $s['sample_pid']
                        . ((int) $s['procs'] > 1 ? ' 외 ' . ((int) $s['procs'] - 1) . '개' : '') . '</span>',
                    2 => fn($s) => '<code>' . vg_trunc((string) ($s['sample_lib'] ?? ''), 60) . '</code>'
                        . ((int) $s['libs'] > 1 ? ' <span class="why">외 ' . ((int) $s['libs'] - 1) . '개</span>' : ''),
                    3 => fn($s) => '<span class="why">해당 서비스 재시작(또는 재부팅)</span>',
                ],
            ]
        );
        ?>
        </div>
        <?php if ($staleTotal > count($staleLibs['rows'])): ?>
          <span class="why">상위 <?= count($staleLibs['rows']) ?>건만 표시합니다(전체 <?= number_format($staleTotal) ?>건).</span>
        <?php endif; ?>
        <span class="why"> · 해당 취약점은 <a href="<?= vg_h(vg_qs(['tab' => 'vuln', 'page' => null, 'q' => null])) ?>">취약점 탭의 "재시작·재부팅" 표</a>에 그대로 남아 있습니다.</span>
      <?php endif; ?>
    </div>

    <div class="card mt-lg">
      <strong>런타임 노출</strong> <span class="why">— 프로세스별 열린 포트와 로드한 라이브러리</span>
      <div class="card__body">
      <?php
      vg_table(
          [
              ['label' => '범위'],
              ['label' => '위치'],
              ['label' => '프로세스', 'key' => 'proc'],
              ['label' => '포트'],
              ['label' => '실행패키지', 'key' => 'exe_pkg'],
              ['label' => '로드한 패키지'],
          ],
          $exposures,
          [
              'card' => false,
              'empty' => $hasFilter
                  ? [
                      'icon'  => '🔍',
                      'title' => '검색 결과가 없습니다.',
                      'hint'  => '검색어를 확인하거나 초기화해 보세요.',
                      'cta'   => ['href' => vg_qs(['q' => null, 'page' => null, 'epage' => null]), 'label' => '검색 초기화'],
                  ]
                  : [
                      'icon'  => '✅',
                      'title' => '리스닝 소켓이 없습니다.',
                      'hint'  => '외부·내부 포함 열린 포트가 없습니다.',
                  ],
              'cell' => [
                  0 => fn($e) => vg_badge(vg_scope_label((string) $e['scope']), $scopeTone[$e['scope']] ?? 'muted'),
                  1 => fn($e) => $e['ctr'] !== ''
                        ? '<span class="why">컨테이너 ' . vg_h($e['ctr']) . '</span>'
                        : '<span class="why">호스트</span>',
                  3 => fn($e) => vg_h($e['proto']) . '/' . (int) $e['port'],
                  5 => fn($e) => '<span class="why">' . vg_trunc($e['loaded_pkgs'], 60) . '</span>',
              ],
          ]
      );
      ?>
      </div>
    </div>
    <?php vg_page_nav($exposureTotal, $perPage, $ePage, 'epage'); ?>

    <div class="card mt-lg">
      <strong>실행 프로세스</strong> <span class="why">— 실행 중 프로그램의 소속 패키지·로드한 라이브러리</span>
      <div class="card__body">
      <?php
      vg_table(
          [
              ['label' => 'PID'],
              ['label' => '위치'],
              ['label' => '프로세스', 'key' => 'comm'],
              ['label' => '사용자'],
              ['label' => '실행 패키지', 'key' => 'exe_pkg'],
              ['label' => '로드한 패키지'],
          ],
          $rows,
          [
              'card' => false,
              'empty' => $hasFilter
                  ? [
                      'icon'  => '🔍',
                      'title' => '검색 결과가 없습니다.',
                      'hint'  => '검색어를 확인하거나 초기화해 보세요.',
                      'cta'   => ['href' => vg_qs(['q' => null, 'page' => null, 'epage' => null]), 'label' => '검색 초기화'],
                  ]
                  : [
                      'icon'  => '🗂️',
                      'title' => '실행 프로세스 데이터가 없습니다.',
                      'hint'  => '구버전 에이전트로 수집된 스캔입니다.',
                  ],
              'cell' => [
                  0 => fn($pr) => '<span class="why">' . (int) $pr['pid'] . '</span>',
                  1 => fn($pr) => $pr['ctr'] !== ''
                        ? '<span class="why">컨테이너 ' . vg_h($pr['ctr']) . '</span>'
                        : '<span class="why">호스트</span>',
                  3 => fn($pr) => '<span class="why">' . vg_h($pr['username']) . '</span>',
                  5 => fn($pr) => '<span class="why">' . vg_trunc($pr['loaded_pkgs'], 60) . '</span>',
              ],
          ]
      );
      ?>
      </div>
    </div>
    <?php vg_page_nav($total, $perPage, $page); ?>

  <?php elseif ($tab === 'cce'): ?>
    <?php vg_toolbar([
        ['type' => 'search', 'name' => 'q', 'placeholder' => '코드·점검항목·SSG 룰 검색', 'value' => $q],
        ['type' => 'hidden', 'name' => 'tab', 'value' => $tab],
        ['type' => 'hidden', 'name' => 'id', 'value' => (string) $hostId],
    ]); ?>
    <div class="card">
      <strong>보안 설정 점검 (CCE)</strong>
      <span class="why">— 버전이 아닌 설정 점검 · NA=미수집</span>
      <div class="card__body">
      <?php
      // 결과 → 톤: FAIL 은 위험도색, PASS 는 low(초록), NA 는 muted.
      $cceBadge = function (array $r): string {
          $tone = $r['result'] === 'FAIL' ? vg_sev_tone($r['severity'])
                : ($r['result'] === 'PASS' ? 'low' : 'muted');
          return vg_badge($r['result'], $tone);
      };
      // 기준 배지 — 이 점검이 **어느 룰셋의 어느 항목**에 근거하는지 보여준다.
      //   예전엔 우리가 정한 코드(CCE-SSH-ROOT)만 있어서 "왜 이게 기준인가" 를 답할 수 없었다.
      //   이제 SSG 룰에 묶여 있고, 그 룰이 CIS·NIST·STIG 참조를 들고 있다.
      $refBadges = static function (array $r): string {
          if (empty($r['ssg_rule_id'])) {
              return '<span class="why">자체 기준(대응 SSG 룰 없음)</span>';
          }
          $refs = vg_json_col($r['refs_json'] ?? '');
          $html = '';
          foreach ($refs as $k => $v) {
              // 기관 기준만 보여준다 — cis-csc 같은 상위 카테고리는 항목 번호가 아니라 생략.
              if (strncmp((string) $k, 'cis@', 4) === 0) {
                  $html .= ' ' . vg_badge('CIS ' . $v, 'info', 'CIS 벤치마크 ' . $k . ' 항목 ' . $v);
              } elseif ($k === 'nist') {
                  $html .= ' ' . vg_badge('NIST ' . vg_trunc((string) $v, 14), 'muted', 'NIST 800-53: ' . $v);
              } elseif ($k === 'stigid') {
                  $html .= ' ' . vg_badge('STIG', 'muted', 'DISA STIG: ' . $v);
              }
          }
          $ruleId = (string) $r['ssg_rule_id'];
          $rule = '<a href="/compliance_rule.php?rule=' . urlencode($ruleId) . '">'
              . '<code class="why">' . vg_h($ruleId) . '</code></a>';
          return $rule . ($html !== '' ? '<br>' . $html : '');
      };

      vg_table(
          [
              ['label' => '결과', 'key' => 'result'],
              ['label' => '점검 항목', 'key' => 'title'],
              ['label' => '코드', 'key' => 'code'],
              ['label' => '기준(SSG 룰 · CIS/NIST)'],
              ['label' => '근거'],
              ['label' => '사유'],
          ],
          $rows,
          [
              'card' => false,
              'empty' => $hasFilter
                  ? [
                      'icon'  => '🔍',
                      'title' => '검색 결과가 없습니다.',
                      'hint'  => '검색어를 확인하거나 초기화해 보세요.',
                      'cta'   => ['href' => vg_qs(['q' => null, 'page' => null]), 'label' => '검색 초기화'],
                  ]
                  : [
                      'icon'  => '🗂️',
                      'title' => 'CCE 점검 데이터가 없습니다.',
                      'hint'  => '구버전 에이전트 또는 security/users 미수집입니다.',
                  ],
              'cell' => [
                  'result' => $cceBadge,
                  'code'   => fn($r) => '<code>' . vg_h($r['code']) . '</code>',
                  3 => $refBadges,
                  4 => fn($r) => '<span class="why">' . vg_trunc($r['evidence'], 40) . '</span>',
                  5 => fn($r) => '<span class="why">' . vg_trunc($r['rationale']) . '</span>',
              ],
          ]
      );
      ?>
      </div>
    </div>
    <?php vg_page_nav($total, $perPage, $page); ?>

  <?php elseif ($tab === 'accounts'):
    // 판정 결과 → 톤. NA 는 회색이다 — 정상(초록)과 절대 같은 색을 쓰지 않는다.
    $accTone = ['FAIL' => 'high', 'REVIEW' => 'warn', 'PASS' => 'ok', 'NA' => 'muted'];
    $accLabel = ['FAIL' => '위반', 'REVIEW' => '검토 필요', 'PASS' => '양호', 'NA' => '판정 불가'];
    // 값이 없다(NULL)는 것과 "아니다"(0)는 다르다 — 화면에서도 구분한다.
    $accNa = '<span class="why">판정 불가</span>';
    ?>
    <div class="card">
      <strong>계정 컴플라이언스 판정</strong>
      <span class="why">— 실제 계정 목록에서 파생 · 추정 항목은 "검토 필요" · 원자료 미수집은 "판정 불가"</span>
      <div class="card__body">
      <?php
      vg_table(
          [
              ['label' => '결과', 'width' => '92px'],
              ['label' => '판정 항목', 'key' => 'title'],
              ['label' => '설명'],
              ['label' => '해당 계정'],
              ['label' => '기준', 'nowrap' => true],
          ],
          $accountJudgments,
          [
              'card'  => false,
              'empty' => ['icon' => '🗂️', 'title' => '계정 인벤토리가 없습니다.',
                          'hint' => '구버전 에이전트로 수집된 스캔입니다. 다시 수집하면 채워집니다.'],
              'cell'  => [
                  0 => fn($j) => vg_badge($accLabel[$j['result']] ?? $j['result'], $accTone[$j['result']] ?? 'muted'),
                  2 => fn($j) => '<span class="why">' . vg_h((string) $j['detail']) . '</span>',
                  3 => fn($j) => $j['names']
                        ? vg_h(vg_trunc(implode(', ', $j['names']), 90))
                        : '<span class="why">–</span>',
                  4 => fn($j) => '<span class="why">ISMS-P ' . vg_h((string) $j['isms'])
                        . '<br>N2SF ' . vg_h((string) $j['n2sf']) . '</span>',
              ],
          ]
      );
      ?>
      </div>
    </div>

    <?php vg_toolbar([
        ['type' => 'search', 'name' => 'q', 'placeholder' => '계정명·셸·홈 디렉토리 검색', 'value' => $q],
        ['type' => 'select', 'name' => 'acc', 'selected' => $accFilter, 'empty_label' => '전체 계정',
         'options' => [
             'human'  => '사람 계정(시스템 제외)',
             'sudo'   => 'sudo 권한 보유',
             'locked' => '잠긴 계정',
             'stale'  => vg_account_stale_login_days() . '일 이상 미로그인',
         ]],
        ['type' => 'hidden', 'name' => 'tab', 'value' => $tab],
        ['type' => 'hidden', 'name' => 'id', 'value' => (string) $hostId],
    ]); ?>
    <div class="card mt-lg">
      <strong>계정 목록</strong>
      <span class="why">— 최신 수집 기준 <?= number_format($accountTotal) ?>개 · 패스워드 해시는 수집하지 않습니다</span>
      <div class="card__body">
      <?php
      vg_table(
          [
              ['label' => '계정', 'key' => 'username', 'class' => 'col-id'],
              ['label' => 'UID / GID', 'nowrap' => true],
              ['label' => '구분'],
              ['label' => '셸', 'key' => 'shell'],
              ['label' => '홈', 'key' => 'home'],
              ['label' => '마지막 로그인', 'nowrap' => true],
              ['label' => '패스워드 변경', 'nowrap' => true],
              ['label' => '만료일', 'nowrap' => true],
          ],
          $rows,
          [
              'card'  => false,
              'empty' => $hasFilter
                  ? ['icon' => '🔍', 'title' => '조건에 맞는 계정이 없습니다.',
                     'cta' => ['href' => vg_qs(['q' => null, 'acc' => null, 'page' => null]), 'label' => '검색 초기화']]
                  : ['icon' => '🗂️', 'title' => '수집된 계정이 없습니다.',
                     'hint' => '/etc/passwd 를 수집하지 못했습니다 — 0건은 "계정 없음"이 아니라 "판정 불가"입니다.'],
              'cell' => [
                  'username' => fn($a) => '<strong>' . vg_h((string) $a['username']) . '</strong>',
                  1 => fn($a) => '<span class="why">' . vg_h((string) ($a['uid'] ?? '–'))
                        . ' / ' . vg_h((string) ($a['gid'] ?? '–')) . '</span>',
                  2 => function ($a) {
                      $b = [];
                      $b[] = (int) $a['is_system'] === 1 ? vg_badge('시스템', 'muted') : vg_badge('사용자', 'info');
                      if ($a['is_sudoer'] === null) { $b[] = vg_badge('sudo?', 'muted', 'sudoers 미수집 — 판정 불가'); }
                      elseif ((int) $a['is_sudoer'] === 1) { $b[] = vg_badge('sudo', 'warn', 'sudo 관리자 권한 보유'); }
                      if ($a['is_locked'] === null) { $b[] = vg_badge('잠금?', 'muted', '/etc/shadow 미수집 — 판정 불가'); }
                      elseif ((int) $a['is_locked'] === 1) { $b[] = vg_badge('잠김', 'low', '패스워드 로그인 불가'); }
                      return implode(' ', $b);
                  },
                  'shell' => fn($a) => '<code class="why">' . vg_h((string) ($a['shell'] ?? '')) . '</code>',
                  'home'  => fn($a) => '<span class="why">' . vg_h(vg_trunc((string) ($a['home'] ?? ''), 28)) . '</span>',
                  5 => function ($a) use ($accNa) {
                      if ($a['never_logged_in'] === null) { return $accNa; }
                      if ((int) $a['never_logged_in'] === 1) { return '<span class="why">이력 없음</span>'; }
                      $ts = strtotime((string) $a['last_login_at']);
                      $age = $ts ? (int) floor((time() - $ts) / 86400) : null;
                      $txt = vg_h(substr((string) $a['last_login_at'], 0, 16));
                      return $age !== null && $age >= vg_account_stale_login_days()
                          ? $txt . ' ' . vg_badge($age . '일', 'warn', vg_account_stale_login_days() . '일 이상 미로그인')
                          : $txt;
                  },
                  // shadow 를 못 읽었으면(is_locked 가 NULL) 정책 필드 전체가 NA 다.
                  //   읽었는데 값이 없는 것(–)과 못 읽은 것(판정 불가)은 다르다.
                  6 => function ($a) use ($accNa) {
                      if ($a['is_locked'] === null) { return $accNa; }
                      if (empty($a['pw_last_change'])) { return '<span class="why">–</span>'; }
                      return vg_h((string) $a['pw_last_change'])
                          . ($a['pw_max_days'] ? ' <span class="why">/ 최대 ' . (int) $a['pw_max_days'] . '일</span>' : '');
                  },
                  7 => function ($a) use ($accNa) {
                      if ($a['is_locked'] === null) { return $accNa; }
                      return $a['expire_date'] ? vg_h((string) $a['expire_date']) : '<span class="why">없음</span>';
                  },
              ],
          ]
      );
      ?>
      </div>
    </div>
    <?php vg_page_nav($total, $perPage, $page); ?>

  <?php elseif ($tab === 'suppressed'): ?>
    <?php vg_toolbar([
        ['type' => 'search', 'name' => 'q', 'placeholder' => 'CVE 또는 패키지명 검색', 'value' => $q],
        ['type' => 'hidden', 'name' => 'tab', 'value' => $tab],
        ['type' => 'hidden', 'name' => 'id', 'value' => (string) $hostId],
    ]); ?>
    <div class="card">
      <strong>백포트로 억제된 취약점</strong>
      <span class="why">— 위험 집계에서 빠진 건들 · 근거는 숨기지 않고 그대로 보여줍니다</span>
      <?php if ($suppLayers): ?>
        <div class="card__body">
          <?php /* 어느 겹이 얼마나 걷어냈나 — 표를 읽기 전에 "왜 이만큼이 빠졌는지"가 먼저 보여야 한다. */ ?>
          <div class="badge-set">
            <?php foreach ($suppLayers as $lk => $lc):
                $meta = vg_suppress_layer_meta($lk); ?>
              <?= vg_badge($meta['label'] . ' ' . number_format($lc) . '건', $meta['tone'], $meta['desc']) ?>
            <?php endforeach; ?>
          </div>
          <p class="why">억제는 "안 봐도 된다"가 아니라 "이 근거로 지금은 해당 없음"입니다. 근거가 사라지면 다음 수집에서 다시 위험으로 올라옵니다.</p>
        </div>
      <?php endif; ?>
      <div class="card__body">
      <?php
      vg_table(
          [
              ['label' => '원래등급', 'key' => 'base_severity'],
              ['label' => 'CVE'],
              ['label' => '대상', 'key' => 'target'],
              ['label' => '패키지'],
              ['label' => '억제 근거'],
          ],
          $rows,
          [
              'card' => false,
              'empty' => $hasFilter
                  ? [
                      'icon'  => '🔍',
                      'title' => '검색 결과가 없습니다.',
                      'hint'  => '검색어를 확인하거나 초기화해 보세요.',
                      'cta'   => ['href' => vg_qs(['q' => null, 'page' => null]), 'label' => '검색 초기화'],
                  ]
                  : [
                      'icon'  => '✅',
                      'title' => '억제된 취약점이 없습니다.',
                      'hint'  => '백포트로 억제 처리된 항목이 없습니다.',
                  ],
              'row_class' => fn($r) => vg_sev_row((string) $r['base_severity']),
              'cell' => [
                  'base_severity' => fn($r) => vg_sev_badge((string) $r['base_severity'])
                      . ((int) $r['in_kev'] === 1 ? ' ' . vg_badge('KEV', 'crit') : ''),
                  1 => fn($r) => '<strong><a href="/cve.php?cve=' . urlencode($r['cve_id']) . '">' . vg_h($r['cve_id']) . '</a></strong>',
                  3 => fn($r) => vg_h($r['package_name']) . ' <span class="why">' . vg_h($r['installed_version']) . '</span>',
                  /* 근거 칸은 세 층이다: 어느 겹인가(뱃지) → 그 겹이 왜 억제하나(한 줄) →
                   *   접으면 그 겹의 **원 데이터**(errata·changelog 행, 트래커에 남은 CVE 수).
                   *   원 데이터가 있어야 "이 판정을 믿을지" 를 사람이 스스로 확인할 수 있다. */
                  4 => function ($r) use ($suppEvidence) {
                      $meta = vg_suppress_layer_meta((string) $r['layer']);
                      $key = (string) $r['package_name'] . '|' . (string) $r['cve_id'];
                      $raw = [];
                      if (isset($suppEvidence['errata'][$key])) {
                          $raw[] = 'tb_applied_errata · ' . ($suppEvidence['errata'][$key] !== ''
                              ? (string) $suppEvidence['errata'][$key] : '권고가 이 빌드를 지목함');
                      }
                      if (isset($suppEvidence['changelog'][$key])) {
                          $raw[] = 'tb_pkg_changelog_cve · ' . ($suppEvidence['changelog'][$key] !== ''
                              ? (string) $suppEvidence['changelog'][$key] : 'changelog 에 CVE 기록');
                      }
                      if (($r['layer'] ?? '') === 'tracker' && !empty($suppEvidence['debsecan'][$r['package_name']])) {
                          $raw[] = 'tb_debsecan · 같은 패키지에 아직 취약으로 남은 CVE '
                              . (int) $suppEvidence['debsecan'][$r['package_name']] . '건'
                              . ' — 판정이 실제로 수집됐다는 뜻입니다(이 CVE 만 해당 없음).';
                      }
                      $out = vg_badge($meta['label'], $meta['tone'], $meta['desc'])
                          . ' <span class="why">' . vg_trunc($r['suppress_reason'], 90) . '</span>';
                      $out .= '<details><summary>근거 상세</summary><div class="why">'
                          . vg_h($meta['desc']) . '<br>' . vg_h((string) $r['suppress_reason']);
                      foreach ($raw as $line) { $out .= '<br>' . vg_h($line); }
                      if (!$raw) {
                          $out .= '<br>' . vg_h('원 근거 행 없음 — 이 겹은 벤더 판정(' . $meta['source'] . ')으로만 성립합니다.');
                      }
                      return $out . '</div></details>';
                  },
              ],
          ]
      );
      ?>
      </div>
    </div>
    <?php vg_page_nav($total, $perPage, $page); ?>

  <?php elseif ($tab === 'scans'): /* 회차 표 + 같은 회차들의 에이전트 리소스 추이 */ ?>
    <div class="card">
      <strong>스캔 이력</strong> <span class="why">— 회차를 눌러 그 시점의 취약점을 본다</span>
      <div class="card__body">
      <?php
      vg_table(
          [
              ['label' => '실행', 'key' => 'scan_id'],
              ['label' => '수집시각', 'key' => 'collected_at'],
              ['label' => '수신시각', 'key' => 'received_at'],
              ['label' => '패키지', 'key' => 'package_count', 'align' => 'right'],
              ['label' => '노출', 'key' => 'exposure_count', 'align' => 'right'],
              ['label' => '메모리', 'key' => 'peak_rss_mb', 'align' => 'right'],
              ['label' => 'CPU', 'key' => 'cpu_seconds', 'align' => 'right'],
              ['label' => '에이전트', 'key' => 'agent_version'],
              ['label' => '심각도', 'key' => 'sev'],
          ],
          $rows,
          [
              'card' => false,
              'empty' => [
                  'icon'  => '🕘',
                  'title' => '스캔 이력이 없습니다.',
              ],
              'cell' => [
                  'scan_id'        => fn($s) => '<a href="/findings.php?scan_id=' . (int) $s['scan_id'] . '">#' . (int) $s['scan_run_id'] . '</a>'
                      . ((int) $s['content_changed'] === 1
                          ? ' <span class="badge">변경</span>'
                          : ' <span class="why">동일</span>'),
                  'collected_at'   => fn($s) => vg_h($s['collected_at']),
                  'received_at'    => fn($s) => '<span class="why">' . vg_h($s['received_at']) . '</span>',
                  'package_count'  => fn($s) => number_format((int) $s['package_count']),
                  'exposure_count' => fn($s) => number_format((int) $s['exposure_count']),
                  'peak_rss_mb'    => fn($s) => vg_resource_mem($s['peak_rss_mb']),
                  'cpu_seconds'    => fn($s) => vg_resource_cpu($s['cpu_seconds']),
                  'agent_version'  => fn($s) => $s['agent_version'] ? '<code>' . vg_h($s['agent_version']) . '</code>' : '<span class="why">–</span>',
                  'sev' => fn($s) => vg_sev_counts($sevByScan[(int) $s['scan_id']] ?? []),
              ],
          ]
      );
      ?>
      </div>
    </div>
    <?php vg_page_nav($total, $perPage, $page); ?>

    <?php
    /* 위 표와 같은 회차들을 추이로 — 표는 회차별 절대치(MB·초), 차트는 호스트 스펙 대비 비율이다.
     *   비율이 필요한 이유: 512MB 짜리 노드의 40MB 와 64GB 노드의 40MB 는 같은 숫자지만 다른 부담이다.
     *   표가 페이지네이션돼도 차트는 최근 구간 전체를 본다(별도 조회). */
    $latestResourceScan = $resourceScans ? end($resourceScans) : null;
    ?>
    <div class="card mt-lg">
      <strong>에이전트 메모리 사용률</strong>
      <span class="why">— 회차별 피크 RSS의 호스트 총 메모리 대비 %
        <?php if ($latestResourceScan && $latestResourceScan['mem_pct'] !== null): ?>
          · 현재 <?= vg_resource_pct($latestResourceScan['mem_pct']) ?>
        <?php endif; ?>
      </span>
      <div class="card__body">
      <?php vg_resource_trend($resourceScans, 'mem_pct', '%', 1, 'mem'); ?>
      </div>
    </div>

    <div class="card mt-lg">
      <strong>에이전트 CPU 사용률</strong>
      <span class="why">— 회차별 CPU 시간의 호스트 코어 용량 대비 %
        <?php if ($latestResourceScan && $latestResourceScan['cpu_pct'] !== null): ?>
          · 현재 <?= vg_resource_pct($latestResourceScan['cpu_pct']) ?>
        <?php endif; ?>
      </span>
      <div class="card__body">
      <?php vg_resource_trend($resourceScans, 'cpu_pct', '%', 1, 'cpu'); ?>
      </div>
    </div>

  <?php else: /* manage — 이 자산의 설정: 수집 제어 · 등급 · 삭제 */ ?>
    <?php if (vg_can('assets')): ?>
      <?php /* 처리 결과(등급 확정 포함)는 이 카드 안에서 한 번만 알린다 — 두 군데서 그리면 중복된다. */ ?>
      <?php vg_host_render_agent_control($hostId, $host, $agentCsrf, $pendingCommands, $agentMsg, $agentErr); ?>
    <?php else: ?>
      <?php /* 수집 제어 카드가 없는 역할(등급만 확정하는 관리자)도 처리 결과는 봐야 한다. */ ?>
      <?php vg_alert($agentMsg, 'ok'); vg_alert($agentErr); ?>
    <?php endif; ?>
    <?php vg_host_render_grade($hostId, $host, $gradeReview, $agentCsrf, $approver, vg_has_role('admin'), $gradeSignals); ?>
    <?php vg_asset_grade_history_render($gradeSuggestionHistory); ?>

    <?php if (vg_has_role('admin', 'operator')): ?>
      <div class="card mt-lg">
        <strong>자산 관리</strong>
        <span class="why"> · 목록·집계에서만 제외합니다(수집 이력 보존)</span>
        <div class="card__body">
          <form method="post" class="actions" data-confirm="<?= vg_h((string)$host['fqdn']) ?> 자산을 삭제할까요? 수집 이력은 남고 목록·집계에서만 제외됩니다.">
            <input type="hidden" name="csrf" value="<?= vg_h($agentCsrf) ?>">
            <input type="hidden" name="action" value="host_delete">
            <input type="hidden" name="id" value="<?= (int)$host['host_id'] ?>">
            <button type="submit" class="btn btn--sm btn--danger">자산 삭제</button>
          </form>
        </div>
      </div>
    <?php endif; ?>
  <?php endif; ?>
<?php endif; ?>
<?php vg_footer();
