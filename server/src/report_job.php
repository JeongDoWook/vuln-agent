<?php
declare(strict_types=1);

/**
 * report_job.php — AI 보고서 작업(job) 도메인. 외부 보고서 API 호출 + tb_report_job 읽기/쓰기.
 *
 *   보고서 본문은 외부 작업큐(FastAPI + 워커)가 만든다. 우리는 job 을 만들고(POST /jobs/)
 *   상태를 물어(GET /jobs/{id}) 화면에 옮길 뿐이다. 프록시 엔드포인트
 *   (public/report-job-create.php · report-job-status.php)와 화면(host/report.php)이
 *   여기만 통해 외부로 나가고 표를 만진다 — HTTP·SQL 을 화면에 흩지 않는다(SRP).
 *
 *   ⚠ 외부 API 에는 인증이 없다. 그래서 인가는 **우리 엔드포인트가** 확정한다
 *     (vg_require_menu). 이 파일은 인가를 판단하지 않는다.
 */

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/setting.php';
require_once __DIR__ . '/feeds/http.php';   // vg_http_json — 타임아웃·프로토콜 제한을 갖춘 공용 래퍼

/**
 * 기본값 상수 — 설정(tb_setting)에 행이 없을 때 실제로 쓰이는 값이자, 설정 화면이
 *   "기본값 N" 으로 보여주는 값이다. **숫자를 setting.php 에 다시 적지 않는다**
 *   (두 곳에 두면 폴백과 화면이 갈라진다 — c09a6a33 / PR #593).
 *
 *   기본 주소가 도커 브리지 게이트웨이인 이유: 외부 API 컨테이너는 `bridge` 네트워크에,
 *   우리 web 은 `vulnagent_vulnagent` 에 있어 서비스명(vulnagent-api)으로는 못 닿는다.
 *   운영 서버 실측(2026-08-20)에서 http://172.17.0.1:8000/health 만 200 이었다.
 */
const VG_REPORT_API_BASE_URL = 'http://172.17.0.1:8000';
/* 폴링 창(간격 × 최대 횟수)은 **보고서가 실제로 만들어지는 시간**에 맞춘다. AI 본문이 붙으면
   생성에 몇 분씩 걸리므로 5초 × 720회 = 60분을 기본으로 잡는다(처음엔 3초 × 60회 = 3분이었는데,
   그 시점엔 외부가 더미 응답을 5초에 돌려주고 있어서 실제 소요시간을 몰랐다).
   간격을 3초가 아니라 5초로 둔 이유: 폴링 한 번이 우리 프록시를 거쳐 외부 API 를 친다.
   같은 60분을 3초로 버티면 1200회를 치는데 5초면 720회로 줄고, 체감 지연은 2초만 늘어난다.
   상한에 걸려도 job 은 서버에 남아 나중에 그 화면에서 이어 볼 수 있다(유실 아님). */
const VG_REPORT_POLL_INTERVAL_SECONDS = 5;
const VG_REPORT_POLL_MAX_ATTEMPTS = 720;

/** 외부 API 한 번 호출의 응답 대기 상한(초). 화면이 프록시 응답을 기다리는 시간이라 짧게 잡는다. */
const VG_REPORT_HTTP_TIMEOUT = 10;

/**
 * 보고서 파일(PDF) 받아오기 — 상한과 대기시간.
 *   본문 JSON 왕복(VG_REPORT_HTTP_TIMEOUT)보다 길게 잡는다(파일 전송이라 느릴 수 있다).
 *   크기 상한은 vg_http_raw 의 $maxBytes 로 넘어가 **넘는 순간 전송을 끊는다** — 외부가
 *   보내는 만큼 우리 메모리에 담기므로 상한이 없으면 이 요청 하나로 web 이 죽는다.
 */
const VG_REPORT_DOWNLOAD_TIMEOUT   = 60;
const VG_REPORT_DOWNLOAD_MAX_BYTES = 20971520;   // 20MB

/** 우리 다운로드 프록시의 경로. 화면(카드·이력표)과 JSON 응답이 같은 값을 쓴다. */
const VG_REPORT_DOWNLOAD_PATH = '/report-download.php';

/**
 * 이력 목록이 함께 읽는 결과 본문의 앞부분 길이(자). 목록에서 "이 결과가 파일 링크인가" 를
 *   판단할 만큼만 읽는다 — MEDIUMTEXT 전체를 목록에 싣지 않으려는 것이고, 실제 다운로드는
 *   프록시가 **저장된 원문 전체**를 다시 읽어 판단하므로 여기서 잘려도 링크가 틀어지지 않는다.
 */
const VG_REPORT_RESULT_HEAD_CHARS = 1024;

/**
 * 상태 어휘 — 외부가 주는 status 문자열 중 **완료로 볼 값 / 실패로 볼 값**.
 *   외부 API 담당자에게 확정받은 값은 네 가지다(2026-08-20): PENDING · PROCESSING ·
 *   SUCCESS · FAILED. 아래 목록은 그 넷을 이미 정확히 가른다(SUCCESS=완료, FAILED=실패,
 *   나머지 둘은 어느 목록에도 없으므로 진행 중). 함께 담아 둔 Celery 계열 어휘는 확정 전에
 *   넣어 둔 여분이라 무해해서 그대로 둔다. 그래서 특정 문자열에 하드 매칭하는
 *   대신 여기 두 목록만 두고, **어느 쪽에도 없는 값은 진행 중으로 읽는다**(모르는 값을 완료로
 *   읽으면 아직 안 끝난 job 의 빈 결과를 보여주게 된다). Celery 계열 워커가 쓰는 흔한 어휘를
 *   함께 담아 두지만, 늘리려면 이 두 줄만 고친다.
 */
const VG_REPORT_STATUS_DONE   = ['SUCCESS', 'SUCCEEDED', 'COMPLETED', 'COMPLETE', 'DONE', 'FINISHED'];
const VG_REPORT_STATUS_FAILED = ['FAILURE', 'FAILED', 'ERROR', 'REVOKED', 'CANCELLED', 'CANCELED', 'TIMEOUT'];

// ─────────────────────────────────────────────────────────────────────────
// 설정값
// ─────────────────────────────────────────────────────────────────────────
/** 외부 보고서 API 의 base URL(끝 슬래시 없음). 값이 없거나 비면 상수 폴백. */
function vg_report_api_base(): string {
    $url = trim(vg_setting_str('report.api_base_url', VG_REPORT_API_BASE_URL));
    return rtrim($url !== '' ? $url : VG_REPORT_API_BASE_URL, '/');
}

/** 화면이 상태를 다시 물어보는 간격(초). */
function vg_report_poll_interval(): int {
    return vg_setting_int('report.poll_interval_seconds', VG_REPORT_POLL_INTERVAL_SECONDS);
}

/** 화면이 상태를 물어보는 최대 횟수. 넘으면 폴링을 멈추고 "나중에 다시 확인" 으로 떨어뜨린다. */
function vg_report_poll_max_attempts(): int {
    return vg_setting_int('report.poll_max_attempts', VG_REPORT_POLL_MAX_ATTEMPTS);
}

// ─────────────────────────────────────────────────────────────────────────
// 상태 해석
// ─────────────────────────────────────────────────────────────────────────
/** 외부 status 문자열 → 화면이 아는 세 가지 상태('done' | 'failed' | 'running'). */
function vg_report_state(?string $status): string {
    $s = strtoupper(trim((string) $status));
    if (in_array($s, VG_REPORT_STATUS_DONE, true))   { return 'done'; }
    if (in_array($s, VG_REPORT_STATUS_FAILED, true)) { return 'failed'; }
    return 'running';
}

/** 더 물어볼 필요가 없는 상태인가. */
function vg_report_state_final(?string $status): bool {
    return vg_report_state($status) !== 'running';
}

/** 상태 → 사람이 읽는 라벨. 화면 세 곳(카드·이력표·JSON 응답)이 같은 말을 쓰게 한다. */
function vg_report_state_label(string $state): string {
    return ['done' => '완료', 'failed' => '실패', 'running' => '생성 중'][$state] ?? '생성 중';
}

/** 상태 → 뱃지 톤(색은 app.css 가 정한다). */
function vg_report_state_tone(string $state): string {
    return ['done' => 'ok', 'failed' => 'crit', 'running' => 'info'][$state] ?? 'muted';
}

// ─────────────────────────────────────────────────────────────────────────
// 외부 API
// ─────────────────────────────────────────────────────────────────────────
/**
 * 외부 API 호출 공통부. 실패는 **일반화된 메시지**의 RuntimeException 으로만 알린다 —
 *   URL·예외 원문·응답 본문은 error_log() 로만 남긴다(응답에 실으면 내부 주소가 샌다.
 *   codelore constraint 0.92 / 0a4ab316 과 같은 이유).
 *
 * @param string $method 'POST' | 'GET'
 * @param string $path   '/jobs/' 처럼 base 뒤에 붙는 경로
 * @return array 응답 JSON(JobResponse)
 */
function vg_report_api_call(string $method, string $path, ?array $body = null): array {
    $url = vg_report_api_base() . $path;
    try {
        /* 목적지는 **관리자가 설정에 넣은 내부 인프라 주소**다(기본값이 도커 브리지
           게이트웨이). 피드 커넥터용 SSRF 차단대역에 정확히 걸리는 자리라, 이 호출만
           $allowInternal 로 예외를 둔다 — 대신 그 모드는 리다이렉트를 따라가지 않으므로
           요청은 설정된 그 호스트 하나로 끝난다. */
        $r = vg_http_json($method, $url, $body, [], VG_REPORT_HTTP_TIMEOUT, 0, true);
    } catch (Throwable $e) {
        error_log('[report_job] ' . $method . ' ' . $url . ' : ' . $e->getMessage());
        throw new RuntimeException('보고서 서비스에 연결하지 못했습니다.');
    }
    if ($r['code'] < 200 || $r['code'] >= 300 || !is_array($r['json'])) {
        error_log(sprintf('[report_job] %s %s → HTTP %d %s', $method, $url, (int) $r['code'], (string) $r['error']));
        throw new RuntimeException('보고서 서비스가 응답하지 않습니다.');
    }
    return $r['json'];
}

/** 외부에 job 을 만든다. 성공하면 JobResponse. */
function vg_report_api_create(int $hostId): array {
    return vg_report_api_call('POST', '/jobs/', ['host_id' => $hostId]);
}

/** 외부 job 하나의 현재 상태. */
function vg_report_api_fetch(int $externalJobId): array {
    return vg_report_api_call('GET', '/jobs/' . $externalJobId);
}

// ─────────────────────────────────────────────────────────────────────────
// 결과(result) 해석 — 링크인가 텍스트인가
// ─────────────────────────────────────────────────────────────────────────
/**
 * result 안에서 **다운로드 링크로 보이는 값**을 찾아 절대 URL 로 만든다. 아니면 null.
 *
 *   외부가 result 에 무엇을 넣을지는 아직 고정되지 않았다(담당자 확인 2026-08-20:
 *   "result 에 보고서 다운받을 수 있는 api 링크 넣어두면"). 지금은 "Job 5 completed" 같은
 *   더미 텍스트가 오므로 **두 경우가 모두 살아 있어야 한다** — 그래서 링크로 안 보이면
 *   조용히 null 을 주고 화면은 예전처럼 본문을 그린다.
 *
 *   받아들이는 모양:
 *     · 값 전체가 링크 하나       → 절대 URL(http/https) 또는 상대 경로(/files/5.pdf)
 *     · 텍스트에 링크가 섞임      → **절대 URL 만** 줍는다. 산문 속의 '/…' 토큰까지 경로로
 *       읽으면 "완료 12/30" 같은 평범한 문장이 링크로 뒤집힌다.
 *   상대 경로는 설정된 API base 를 앞에 붙여 절대화한다. `//host/x`(프로토콜 상대)는
 *   경로가 아니라 다른 호스트를 가리키므로 받지 않는다.
 */
function vg_report_result_url(?string $result): ?string {
    $s = trim((string) $result);
    if ($s === '') { return null; }
    $tokens = preg_split('/\s+/', $s) ?: [];
    $single = count($tokens) === 1;
    foreach ($tokens as $tok) {
        // 문장에 섞여 오면 따라붙는 문장부호를 턴다(<url>, "url", (url) 등).
        $tok = trim($tok, "\"'<>()[]{},;");
        if ($tok === '') { continue; }
        if (preg_match('~^https?://~i', $tok)) {
            $host = (string) (parse_url($tok, PHP_URL_HOST) ?? '');
            if ($host !== '') { return $tok; }
            continue;
        }
        if ($single && strlen($tok) > 1 && $tok[0] === '/' && $tok[1] !== '/') {
            return vg_report_api_base() . $tok;
        }
    }
    return null;
}

/**
 * 이 URL 의 목적지가 **설정에 적힌 그 API 서버**인가(scheme+host+port 대조).
 *   외부 응답이 조작되면 우리 서버가 내부 임의 주소를 대신 치게 된다(SSRF) — result 는
 *   우리가 만든 값이 아니므로 저장돼 있다고 믿지 않는다. 목적지는 설정된 한 곳으로 고정한다.
 */
function vg_report_url_same_origin(string $url): bool {
    $origin = static function (string $u): ?string {
        $p = parse_url($u);
        if (!is_array($p)) { return null; }
        $scheme = strtolower((string) ($p['scheme'] ?? ''));
        $host   = strtolower(trim((string) ($p['host'] ?? ''), '[]'));
        if (!in_array($scheme, ['http', 'https'], true) || $host === '') { return null; }
        $port = (int) ($p['port'] ?? ($scheme === 'https' ? 443 : 80));
        return $scheme . '://' . $host . ':' . $port;
    };
    $a = $origin($url);
    $b = $origin(vg_report_api_base());
    return $a !== null && $b !== null && $a === $b;
}

/**
 * 화면·프록시가 함께 쓰는 판정 한 곳 — result 가 **우리가 받아올 수 있는 파일 링크**면
 *   절대 URL, 아니면 null. 둘이 서로 다른 판단을 하면 버튼은 떠 있는데 눌러도 거부되거나
 *   그 반대가 된다.
 */
function vg_report_download_url(?string $result): ?string {
    $url = vg_report_result_url($result);
    return ($url !== null && vg_report_url_same_origin($url)) ? $url : null;
}

/**
 * 내려줄 파일명. **우리가 조립한다** — 외부가 준 이름을 쓰면 헤더 인젝션·경로 조작이 된다.
 *   ASCII 안전문자만 남긴다(자산명은 한글 fqdn 이 없지만 방어).
 */
function vg_report_download_filename(string $fqdn, int $reportJobId, ?string $when): string {
    $safe = preg_replace('/[^A-Za-z0-9._-]/', '_', $fqdn);
    if ($safe === null || $safe === '') { $safe = 'host'; }
    $ts = $when !== null && $when !== '' ? strtotime($when) : false;
    return sprintf('report-%s-%d-%s.pdf', substr($safe, 0, 100), $reportJobId,
                   date('Ymd', $ts !== false ? $ts : time()));
}

/**
 * 보고서 파일을 외부에서 받아 **바이트 그대로** 돌려준다(저장하지 않는다 — 보존기간·저장경로를
 *   정할 근거가 아직 없다).
 *   호출자는 URL 을 만들지 않는다. 반드시 vg_report_download_url() 이 통과시킨 URL 만 넘긴다.
 *   실패는 일반화된 메시지로만 알리고 URL·오류 원문은 error_log 로만 남긴다.
 */
function vg_report_download_fetch(string $url): string {
    $r = vg_http_raw('GET', $url, ['Accept: application/pdf'],
                     VG_REPORT_DOWNLOAD_TIMEOUT, VG_REPORT_DOWNLOAD_MAX_BYTES, true);
    if ($r['code'] < 200 || $r['code'] >= 300 || $r['body'] === '') {
        error_log(sprintf('[report_job] GET %s → HTTP %d %s (%dB)',
                          $url, (int) $r['code'], (string) $r['error'], strlen((string) $r['body'])));
        throw new RuntimeException('보고서 파일을 받지 못했습니다.');
    }
    return $r['body'];
}

// ─────────────────────────────────────────────────────────────────────────
// 우리 표(tb_report_job)
// ─────────────────────────────────────────────────────────────────────────
/**
 * 외부 응답에서 우리 컬럼으로 옮길 값만 추린다. 외부 스키마가 늘어도 여기만 본다.
 * @return array{status:string, result:?string, error_message:?string, created_at:?string, finished_at:?string}
 */
function vg_report_job_map(array $resp): array {
    $dt = static function ($v): ?string {
        $s = trim((string) ($v ?? ''));
        if ($s === '') { return null; }
        $ts = strtotime($s);
        return $ts === false ? null : date('Y-m-d H:i:s', $ts);
    };
    $text = static function ($v): ?string {
        $s = trim((string) ($v ?? ''));
        return $s === '' ? null : $s;
    };
    $err = $text($resp['error_message'] ?? null);
    return [
        'status'        => mb_substr(trim((string) ($resp['status'] ?? 'PENDING')), 0, 32),
        'result'        => $text($resp['result'] ?? null),
        'error_message' => $err !== null ? mb_substr($err, 0, 1000) : null,
        'created_at'    => $dt($resp['created_at'] ?? null),
        'finished_at'   => $dt($resp['finished_at'] ?? null),
    ];
}

/** 새 job 행을 남긴다. 반환은 우리 PK(report_job_id). */
function vg_report_job_insert(PDO $pdo, int $hostId, array $resp, ?int $userId): int {
    $m = vg_report_job_map($resp);
    $st = $pdo->prepare(
        'INSERT INTO tb_report_job
            (host_id, external_job_id, status, result, error_message, requested_user_id,
             external_created_at, external_finished_at)
         VALUES (?,?,?,?,?,?,?,?)'
    );
    $st->execute([
        $hostId, (int) ($resp['id'] ?? 0), $m['status'], $m['result'], $m['error_message'],
        $userId, $m['created_at'], $m['finished_at'],
    ]);
    return (int) $pdo->lastInsertId();
}

/** 우리 job 행 하나. 없으면 null. */
function vg_report_job_find(PDO $pdo, int $reportJobId): ?array {
    $st = $pdo->prepare(
        'SELECT report_job_id, host_id, external_job_id, status, result, error_message,
                created_at, updated_at, external_finished_at
           FROM tb_report_job WHERE report_job_id = ?'
    );
    $st->execute([$reportJobId]);
    return $st->fetch() ?: null;
}

/** 이 호스트에서 아직 안 끝난 가장 최근 job(새로고침 뒤에도 폴링을 이어가려고 화면이 읽는다). */
function vg_report_job_active(PDO $pdo, int $hostId): ?array {
    $st = $pdo->prepare(
        'SELECT report_job_id, status, result, error_message, created_at
           FROM tb_report_job WHERE host_id = ? ORDER BY report_job_id DESC LIMIT 1'
    );
    $st->execute([$hostId]);
    $row = $st->fetch() ?: null;
    return ($row && !vg_report_state_final((string) $row['status'])) ? $row : null;
}

/**
 * 호스트별 보고서 이력(최신순, 상한 있음). 상한을 넘겨 잘린 건 총건수로 알린다 —
 *   목록이 조용히 잘리면 사용자는 더 있다는 걸 알 수 없다.
 *   결과 본문(MEDIUMTEXT)은 목록에 싣지 않는다. 길이만 세어 "결과 보기" 버튼 유무를 정하고,
 *   "이 결과가 파일 링크인가" 를 가릴 앞부분만 VG_REPORT_RESULT_HEAD_CHARS 만큼 함께 읽는다.
 * @return array{rows: array<int,array>, total: int}
 */
function vg_report_jobs_recent(PDO $pdo, int $hostId, int $limit): array {
    // LIMIT 은 정수 리터럴로 넣는다(자리표시자를 쓰면 MySQL 이 문자열로 바인딩해 문법오류).
    //   값은 여기서 int 로 좁히므로 사용자 입력이 그대로 SQL 로 가지 않는다.
    $limit = max(1, min(200, $limit));
    $st = $pdo->prepare(
        'SELECT r.report_job_id, r.status, r.error_message, r.created_at, r.external_finished_at,
                CHAR_LENGTH(COALESCE(r.result, "")) AS result_len,
                LEFT(r.result, ' . VG_REPORT_RESULT_HEAD_CHARS . ') AS result_head, u.username
           FROM tb_report_job r
           LEFT JOIN tb_user u ON u.user_id = r.requested_user_id
          WHERE r.host_id = ?
          ORDER BY r.report_job_id DESC
          LIMIT ' . $limit
    );
    $st->execute([$hostId]);
    $rows = $st->fetchAll();
    $cnt = $pdo->prepare('SELECT COUNT(*) FROM tb_report_job WHERE host_id = ?');
    $cnt->execute([$hostId]);
    return ['rows' => $rows, 'total' => (int) $cnt->fetchColumn()];
}

/**
 * 우리 행 하나를 외부 상태로 갱신한다. 이미 끝난 job 은 외부를 다시 부르지 않는다
 *   (결과는 안 바뀌는데 왕복만 는다 — 이력에서 과거 보고서를 열 때마다 외부를 치게 된다).
 * @return array 갱신된 우리 행
 */
function vg_report_job_sync(PDO $pdo, array $row): array {
    if (vg_report_state_final((string) $row['status'])) {
        return $row;
    }
    $m = vg_report_job_map(vg_report_api_fetch((int) $row['external_job_id']));
    $st = $pdo->prepare(
        'UPDATE tb_report_job
            SET status = ?, result = ?, error_message = ?, external_finished_at = ?
          WHERE report_job_id = ?'
    );
    $st->execute([$m['status'], $m['result'], $m['error_message'], $m['finished_at'], (int) $row['report_job_id']]);
    return array_merge($row, [
        'status'               => $m['status'],
        'result'               => $m['result'],
        'error_message'        => $m['error_message'],
        'external_finished_at' => $m['finished_at'],
    ]);
}

/**
 * 화면·JSON 응답이 함께 쓰는 job 표현. 상태 라벨/톤을 한 곳에서 붙여 카드와 이력표가
 *   서로 다른 말을 하지 않게 한다. 결과 본문은 **형식이 정해지지 않은 plain text** 라
 *   그대로 담고, 이스케이프는 그리는 쪽(vg_h)·JSON 인코딩이 맡는다.
 */
function vg_report_job_public(array $row): array {
    $state = vg_report_state((string) ($row['status'] ?? ''));
    return [
        'report_job_id' => (int) $row['report_job_id'],
        'state'         => $state,
        'state_label'   => vg_report_state_label($state),
        'state_tone'    => vg_report_state_tone($state),
        'result'        => isset($row['result']) && $row['result'] !== null ? (string) $row['result'] : null,
        // 결과가 파일 링크면 **우리 프록시 경로**만 내보낸다 — 외부 내부주소는 화면에 내리지 않는다.
        'download_url'  => vg_report_download_url($row['result'] ?? null) !== null
            ? VG_REPORT_DOWNLOAD_PATH . '?job=' . (int) $row['report_job_id'] : null,
        'error_message' => isset($row['error_message']) && $row['error_message'] !== null
            ? (string) $row['error_message'] : null,
    ];
}
