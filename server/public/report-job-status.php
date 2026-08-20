<?php
declare(strict_types=1);

/**
 * report-job-status.php — AI 보고서 작업 상태 조회(프록시). host.php 의 폴링과 이력의
 *   "결과 보기" 가 부른다.
 *
 *   우리 job 행(tb_report_job)을 기준으로 외부 GET /jobs/{외부 id} 를 호출해 행을 갱신하고
 *   JSON 으로 돌려준다. 이미 끝난 job 은 외부를 다시 부르지 않는다(report_job.php).
 *   인가는 여기서 확정하고(vg_require_menu), 완성된 보고서를 실제로 내보낼 때는 열람으로
 *   감사로그를 남긴다(CLAUDE.md 원칙 7 — 누가 무엇을 봤는지가 중요한 행위).
 */

header('Content-Type: application/json; charset=utf-8');
require __DIR__ . '/../src/auth.php';
require_once __DIR__ . '/../src/audit.php';       // vg_log_activity
require_once __DIR__ . '/../src/report_job.php';
vg_require_menu('assets');   // 생성과 같은 인가 범위(자산에 딸린 산출물이다)

function report_status_fail(int $code, string $message): void {
    http_response_code($code);
    echo json_encode(['ok' => false, 'error' => $message], JSON_UNESCAPED_UNICODE);
    exit;
}

$jobId = filter_input(INPUT_GET, 'job', FILTER_VALIDATE_INT);
if (!$jobId || $jobId < 1) { report_status_fail(422, '대상 작업을 확인할 수 없습니다.'); }

$pdo = vg_pdo();
try {
    $row = vg_report_job_find($pdo, (int) $jobId);
} catch (Throwable $e) {
    error_log('[report_job] status db: ' . $e->getMessage());
    report_status_fail(500, '작업 상태를 읽지 못했습니다.');
}
if ($row === null) { report_status_fail(404, '작업을 찾을 수 없습니다.'); }

try {
    $row = vg_report_job_sync($pdo, $row);
} catch (PDOException $e) {
    error_log('[report_job] status db: ' . $e->getMessage());
    report_status_fail(500, '작업 상태를 저장하지 못했습니다.');
} catch (RuntimeException $e) {
    // 외부 API 에 못 닿는 상황은 **정상적으로 일어난다**(망이 갈려 있다). 화면이 500 으로
    //   깨지지 않고 에러 배지로 떨어지도록, 여기서 일반화된 메시지만 JSON 으로 준다.
    report_status_fail(502, $e->getMessage());
} catch (Throwable $e) {
    error_log('[report_job] status: ' . $e->getMessage());
    report_status_fail(500, '작업 상태를 읽지 못했습니다.');
}

$job = vg_report_job_public($row);

// 완성된 보고서 본문을 실제로 내보내는 순간만 열람으로 남긴다 — 진행 중 폴링은 본문이
//   없으므로 로그가 부풀지 않고, 클라이언트가 무엇을 보내든(파라미터를 빼든) 판단은 서버가 한다.
if ($job['result'] !== null && $job['result'] !== '') {
    vg_log_activity($pdo, 'HOST', (int) $row['host_id'], 'view_report_job',
        'AI 보고서 열람: 작업 #' . (int) $row['report_job_id'],
        ['report_job_id' => (int) $row['report_job_id']], action: 'READ');
}

echo json_encode(['ok' => true, 'job' => $job], JSON_UNESCAPED_UNICODE);
