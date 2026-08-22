<?php
declare(strict_types=1);

/**
 * report-job-create.php — AI 보고서 생성 요청(프록시). host.php 의 [AI 보고서 생성] 버튼이 부른다.
 *
 *   외부 보고서 API 에 job 을 만들고(POST /jobs/) 그 job 을 tb_report_job 에 남긴 뒤 JSON 을 준다.
 *   **외부 API 에는 인증이 없으므로 인가는 여기서 확정한다**(vg_require_menu + CSRF) —
 *   화면에서 버튼을 감추는 것은 통제가 아니다.
 *   실패는 일반화된 메시지만 내보내고 원인은 error_log() 로만 남긴다(내부 주소 유출 방지).
 */

header('Content-Type: application/json; charset=utf-8');
require __DIR__ . '/../src/auth.php';
require_once __DIR__ . '/../src/audit.php';       // vg_log_activity
require_once __DIR__ . '/../src/report_job.php';  // 외부 API 호출 + tb_report_job
vg_require_menu('assets');   // 보고서 생성은 자산에 대한 조작 — 수집 제어와 같은 인가 범위

function report_create_fail(int $code, string $message): void {
    http_response_code($code);
    echo json_encode(['ok' => false, 'error' => $message], JSON_UNESCAPED_UNICODE);
    exit;
}

// 연동이 꺼진 설치(설정에 API 주소가 없다)에서는 화면에 버튼도 없다. 그래도 직접 호출될 수
//   있으므로 여기서 끊는다 — 인가 검증(vg_require_menu) 뒤에서, 일반화된 메시지로만.
if (!vg_report_enabled()) { report_create_fail(404, 'AI 보고서 연동을 사용하지 않는 설치입니다.'); }

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') { report_create_fail(405, '허용되지 않은 요청입니다.'); }
if (!vg_csrf_check($_POST['csrf'] ?? null))        { report_create_fail(403, '세션이 만료되었습니다. 새로고침 후 다시 시도하세요.'); }

$hostId = filter_input(INPUT_POST, 'id', FILTER_VALIDATE_INT);
if (!$hostId || $hostId < 1) { report_create_fail(422, '대상 자산을 확인할 수 없습니다.'); }

/* 대상 조회부터 try 안이다 — 이 SELECT 는 **이 변경이 신설한 컬럼**(host_uuid)을 읽는다.
 *   dev 는 코드가 먼저 배포되고 마이그레이션이 뒤이어 적용되는 구조라, 그 사이 창에서는
 *   'Unknown column' PDOException 이 뜨는데, try 밖이면 그게 미포착으로 던져져 JSON 대신
 *   PHP 오류가 나가고 이 응답을 기다리는 화면 JS 까지 함께 깨진다. 아래 catch 가 이미
 *   일반화된 메시지로 끊고 상세는 error_log 로만 남긴다. */
try {
    $pdo = vg_pdo();
    // 외부로 나가는 식별자는 host_uuid 다(순번 PK 는 안 보낸다 — vg_report_api_create 주석 참고).
    //   이미 치던 조회에 컬럼 하나를 얹어 가져온다 — 쿼리를 늘리지 않는다.
    $st = $pdo->prepare('SELECT fqdn, host_uuid FROM tb_host WHERE host_id = ? AND is_deleted = 0');
    $st->execute([$hostId]);
    $hostRow = $st->fetch();
    if ($hostRow === false) { report_create_fail(404, '자산을 찾을 수 없습니다.'); }
    $fqdn     = (string) $hostRow['fqdn'];
    $hostUuid = (string) ($hostRow['host_uuid'] ?? '');
    // uuid 는 마이그레이션이 전 행을 채웠고 새 행은 DB 기본값이 채운다. 그래도 비어 있다면
    //   외부에 대상을 특정할 수 없는 요청을 보내는 셈이라 여기서 끊는다(조용한 오배정 방지).
    if ($hostUuid === '') {
        error_log('[report_job] host_uuid 가 비어 있다: host_id=' . $hostId);
        report_create_fail(500, '보고서 작업을 시작하지 못했습니다.');
    }

    $resp = vg_report_api_create($hostUuid);
    $externalId = (int) ($resp['id'] ?? 0);
    if ($externalId < 1) {
        error_log('[report_job] 생성 응답에 id 가 없다: ' . json_encode($resp, JSON_UNESCAPED_UNICODE));
        report_create_fail(502, '보고서 작업을 시작하지 못했습니다.');
    }
    $reportJobId = vg_report_job_insert($pdo, (int) $hostId, $resp, vg_current_user()['id'] ?? null);
} catch (PDOException $e) {
    // PDOException 도 RuntimeException 을 상속하므로 먼저 잡는다 — 아래 분기로 흘러가면
    //   DB 오류 원문(계정명·컬럼명)이 그대로 응답에 실린다.
    error_log('[report_job] create db: ' . $e->getMessage());
    report_create_fail(500, '보고서 작업을 기록하지 못했습니다.');
} catch (RuntimeException $e) {
    // report_job.php 가 던지는 메시지는 이미 일반화돼 있다(상세는 그쪽에서 error_log 로 남긴다).
    report_create_fail(502, $e->getMessage());
} catch (Throwable $e) {
    error_log('[report_job] create: ' . $e->getMessage());
    report_create_fail(500, '보고서 작업을 시작하지 못했습니다.');
}

vg_log_activity($pdo, 'HOST', (int) $hostId, 'report_job_create',
    'AI 보고서 생성 요청: ' . (string) $fqdn,
    ['report_job_id' => $reportJobId, 'external_job_id' => $externalId],
    subject: (string) $fqdn, action: 'CREATE');

$row = vg_report_job_find($pdo, $reportJobId);
echo json_encode(['ok' => true, 'job' => $row !== null ? vg_report_job_public($row) : null], JSON_UNESCAPED_UNICODE);
