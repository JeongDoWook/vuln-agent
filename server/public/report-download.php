<?php
declare(strict_types=1);

/**
 * report-download.php — AI 보고서 PDF 내려받기(프록시). 호스트 상세의 [PDF 다운로드] 가 가리킨다.
 *
 *   외부 보고서 API 는 result 에 **PDF 를 받을 수 있는 링크**를 넣어 준다(담당자 확인 2026-08-20).
 *   그 링크는 도커 브리지 게이트웨이 뒤 사내 주소라 **사용자 브라우저에서는 안 닿는다** —
 *   그래서 우리 서버가 대신 받아 그대로 흘려보낸다. 저장하지 않는다(보존기간·저장경로를 정할
 *   근거가 아직 없다 — 필요해지면 그때 붙인다).
 *
 *   보안이 이 파일의 전부다:
 *     · 클라이언트는 **URL 을 보내지 않는다. job id 만** 받는다 — URL 을 파라미터로 받는 순간
 *       그 자체가 SSRF 구멍이다. 목적지는 서버가 tb_report_job.result 에서 만든다.
 *     · 저장된 result 도 믿지 않는다 — 절대화한 URL 의 scheme+host+port 가 **설정된 API base
 *       와 같을 때만** 나간다(vg_report_download_url). 외부 응답이 조작되면 우리 서버가 내부
 *       임의 주소를 치게 되므로 목적지를 설정된 한 곳으로 고정한다.
 *     · 외부 호출은 feeds/http.php 의 $allowInternal 경로 — **그 모드는 리다이렉트를 따라가지
 *       않는다**(302 로 딴 데 끌려갈 여지 차단). 이 성질에 기대고 있다.
 *     · 응답 헤더는 우리가 정한다. 외부 헤더(Content-Type·파일명)를 흘리지 않는다.
 *     · 크기 상한은 VG_REPORT_DOWNLOAD_MAX_BYTES(report_job.php).
 *   인가는 생성·상태와 같은 범위(vg_require_menu('assets'))고, 열람 행위라 감사로그를 남긴다.
 */

require __DIR__ . '/../src/auth.php';
require_once __DIR__ . '/../src/audit.php';           // vg_log_activity
require_once __DIR__ . '/../src/format/text.php';     // vg_h — 오류 페이지 이스케이프(레이아웃은 안 쓴다)
require_once __DIR__ . '/../src/report_job.php';
vg_require_menu('assets');

/**
 * 실패는 **일반화된 메시지**만 — 내부 URL·예외 원문은 error_log 로만 남긴다.
 *   이 자리는 JSON API 가 아니라 사람이 링크를 눌러 도착하는 곳이라 짧은 HTML 로 떨어뜨린다.
 */
function report_download_fail(int $code, string $message): void {
    http_response_code($code);
    header('Content-Type: text/html; charset=utf-8');
    echo '<!doctype html><meta charset="utf-8"><title>보고서 다운로드</title>'
       . '<p>' . vg_h($message) . '</p>';
    exit;
}

// 연동이 꺼진 설치에서는 받아올 곳이 없다(인가 검증 뒤, 일반화된 메시지로만 거절한다).
if (!vg_report_enabled()) { report_download_fail(404, 'AI 보고서 연동을 사용하지 않는 설치입니다.'); }

$jobId = filter_input(INPUT_GET, 'job', FILTER_VALIDATE_INT);
if (!$jobId || $jobId < 1) { report_download_fail(422, '대상 작업을 확인할 수 없습니다.'); }

$pdo = vg_pdo();
try {
    $row = vg_report_job_find($pdo, (int) $jobId);
} catch (Throwable $e) {
    error_log('[report_job] download db: ' . $e->getMessage());
    report_download_fail(500, '작업을 읽지 못했습니다.');
}
if ($row === null) { report_download_fail(404, '작업을 찾을 수 없습니다.'); }

// 아직 안 끝난 job 에는 내려줄 파일이 없다(여기서 외부 상태를 새로 묻지 않는다 —
//   그건 report-job-status.php 의 일이고, 이 자리는 파일만 내린다).
if (vg_report_state((string) $row['status']) !== 'done') {
    report_download_fail(409, '보고서가 아직 준비되지 않았습니다.');
}

// 목적지는 **서버가** 만든다. 링크가 아니거나 설정된 API 서버가 아니면 여기서 끝난다.
$url = vg_report_download_url($row['result'] ?? null);
if ($url === null) {
    error_log(sprintf('[report_job] download 거부: job=%d — result 가 허용된 API 주소의 링크가 아니다',
                      (int) $row['report_job_id']));
    report_download_fail(404, '내려받을 보고서 파일이 없습니다.');
}

$st = $pdo->prepare('SELECT fqdn FROM tb_host WHERE host_id = ? AND is_deleted = 0');
$st->execute([(int) $row['host_id']]);
$fqdn = $st->fetchColumn();
if ($fqdn === false) { report_download_fail(404, '자산을 찾을 수 없습니다.'); }

try {
    $pdf = vg_report_download_fetch($url);
} catch (RuntimeException $e) {
    // 외부에 못 닿는 상황은 정상적으로 일어난다(망이 갈려 있다) — 500 이 아니라 곱게 떨어뜨린다.
    report_download_fail(502, $e->getMessage());
} catch (Throwable $e) {
    error_log('[report_job] download: ' . $e->getMessage());
    report_download_fail(500, '보고서 파일을 받지 못했습니다.');
}

$filename = vg_report_download_filename((string) $fqdn, (int) $row['report_job_id'],
                                        (string) ($row['external_finished_at'] ?? $row['created_at'] ?? ''));

// 누가 어느 자산의 보고서 파일을 내려받았는지가 남아야 한다(CLAUDE.md 원칙 7).
vg_log_activity($pdo, 'HOST', (int) $row['host_id'], 'download_report_job',
    'AI 보고서 파일 다운로드: 작업 #' . (int) $row['report_job_id'] . ' (' . (string) $fqdn . ')',
    ['report_job_id' => (int) $row['report_job_id'], 'filename' => $filename, 'bytes' => strlen($pdf)],
    subject: (string) $fqdn, action: 'EXPORT');

// 헤더는 전부 우리가 정한다(파일명 포함) — 외부가 준 값을 헤더에 실으면 인젝션·경로 조작이 된다.
header('Content-Type: application/pdf');
header('Content-Disposition: attachment; filename="' . $filename . '"');
header('Content-Length: ' . (string) strlen($pdf));
header('X-Content-Type-Options: nosniff');
echo $pdf;
