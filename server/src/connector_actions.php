<?php
declare(strict_types=1);

/**
 * connector_actions.php — CVE 피드 커넥터 관리 페이지의 POST 액션 처리 —
 *   save/run/delete. HTML 출력 없음, DB 조작만.
 *   활성 여부(enabled)는 save 가 폼의 체크박스로 함께 저장한다 — 목록의 토글 버튼은 걷어냈다.
 */

require_once __DIR__ . '/db.php';      // vg_json_col — feeds.php 가 이미 물고 오지만 직접 쓰므로 명시
require_once __DIR__ . '/feeds.php';
require_once __DIR__ . '/matcher.php';
require_once __DIR__ . '/audit.php';

/**
 * 전제: **호출 전에 vg_csrf_check() 로 CSRF 검증이 끝나 있어야 한다.**
 *   이 함수는 검증을 다시 하지 않는다 — 호출부(connectors.php)가 소유.
 *
 * 주의: action='run' 은 내부에서 session_write_close() 를 호출한다(장시간 수집 중
 *   세션 파일 락으로 다른 탭이 얼어붙는 것을 막기 위함). 호출 이후 세션에 쓰는
 *   코드(예: CSRF 토큰 신규 발급)를 두면 그 쓰기가 유실된다.
 * @param array<string,mixed> $post
 * @return array{msg: ?string, err: ?string}
 */
function vg_connector_handle_post(PDO $pdo, array $post): array {
    $msg = null; $err = null;
    $action = $post['action'] ?? '';
    try {
        if ($action === 'save') {
            $id    = (int) ($post['id'] ?? 0);
            $name  = trim((string) ($post['name'] ?? ''));
            $type  = (string) ($post['connector_type'] ?? '');
            // 타입 목록의 근거는 src/feeds.php 의 카탈로그 하나다(폼 <select>·vg_feed_make 와 같은 표).
            if ($name === '' || !isset(VG_CONNECTOR_TYPES[$type])) {
                throw new RuntimeException('이름과 커넥터 타입을 확인하세요.');
            }
            // 기존 레코드(편집일 때). connection_json 병합과 next_run_at 계산이 함께 쓴다.
            $prev = null;
            if ($id > 0) {
                $q = $pdo->prepare('SELECT connection_json, last_run_at FROM tb_feed_connector WHERE feed_connector_id=?');
                $q->execute([$id]);
                $prev = $q->fetch() ?: null;
            }
            if ($type === 'generic_api') {
                // 범용 API 커넥터는 폼 전체(role/url_template/headers/pagination/response)를
                // JS 가 하나의 JSON(g_config_json)으로 직렬화해 보낸다 — 필드마다 흩어진
                // g_xxx[] 배열을 여기서 다시 조립하지 않고, generic_api.php 의 파서를 그대로
                // 재사용해 저장 시점 검증까지 한 번에 맞춘다(run() 과 같은 규칙 — DRY).
                $conn = json_decode((string) ($post['g_config_json'] ?? ''), true);
                if (!is_array($conn)) {
                    throw new RuntimeException('범용 API 커넥터 설정이 비어있습니다.');
                }
                vg_generic_parse_config($conn); // role/url_template/field_mapping 검증(설계문서 5장)
            } else {
                // **기존 설정 위에 덮는다.** 전엔 $conn 을 새로 만들어 버려서, 폼에 없는 키가
                // 편집·저장 한 번에 조용히 날아갔다 — debtracker/rhoval/ubuntuoval 의
                // releases(수집 대상 릴리스)와 rhunfixed 의 max_detail 이 그렇다.
                $conn = $prev ? vg_json_col($prev['connection_json']) : [];
                // 폼이 소유한 키만 갈아끼운다. 일단 전부 지우고 이 타입이 실제로 읽는 것만
                // 다시 채워, 타입을 바꿔 무관해진 값(kev 로 바꿨는데 남은 ecosystem)이 안 남게 한다.
                foreach (vg_connector_form_fields() as $f) { unset($conn[$f]); }
                foreach (vg_connector_fields($type) as $f) {
                    $v = trim((string) ($post[$f] ?? ''));
                    if ($v === '') { continue; }   // 빈 값은 키를 아예 안 만든다 → 커넥터의 기본 URL 이 산다
                    $conn[$f] = $f === 'days' ? (int) $v : $v;
                }
            }
            $mode = (string) ($post['schedule_mode'] ?? 'manual');
            if (!in_array($mode, ['interval', 'daily', 'cron', 'manual'], true)) { $mode = 'manual'; }
            $sched = ['mode' => $mode];
            if ($mode === 'interval') {
                $sched['interval_minutes'] = max(1, (int) ($post['interval_minutes'] ?? 1440));
            } elseif ($mode === 'daily') {
                $t = (string) ($post['schedule_time'] ?? '');
                $sched['time'] = preg_match('/^\d{1,2}:\d{2}$/', $t) ? $t : '03:00';
            } elseif ($mode === 'cron') {
                $expr = trim((string) ($post['schedule_cron'] ?? ''));
                if ($expr === '' || count(preg_split('/\s+/', $expr) ?: []) !== 5) {
                    throw new RuntimeException('cron 은 5필드(분 시 일 월 요일)로 입력하세요. 예: 0 3 * * *');
                }
                $sched['expr'] = $expr;
            }
            $enabled = isset($post['enabled']) ? 1 : 0;

            // 저장 즉시 next_run_at 을 새 스케줄로 다시 계산한다.
            //   이 컬럼은 표시 전용 캐시인데 vg_feed_run() 안에서만 갱신됐다. 그래서 스케줄을
            //   바꿔도 다음 실행이 한 번 돌기 전까지 화면에 옛 시각이 남았다(05:00 → 12:11 로
            //   고쳐도 "다음 실행 05:00"). 실제 due 판정은 vg_feed_due() 가 schedule_json 과
            //   last_run_at 로 매번 새로 하므로 실행 시각 자체는 원래 정상이었다.
            //   interval 은 "마지막 실행 + N분" 이라야 due 판정과 같은 값이 나온다.
            $lastRun = ($prev['last_run_at'] ?? null) ?: null;
            $from = ($mode === 'interval' && $lastRun !== null) ? strtotime((string) $lastRun) : time();
            $next = ($enabled && $mode !== 'manual') ? vg_schedule_next($sched, $from) : null;

            if ($id > 0) {
                $st = $pdo->prepare('UPDATE tb_feed_connector SET name=?, connector_type=?, connection_json=?, schedule_json=?, enabled=?, next_run_at=? WHERE feed_connector_id=?');
                $st->execute([$name, $type, json_encode($conn), json_encode($sched), $enabled, $next, $id]);
                $msg = "커넥터 '$name' 수정됨.";
            } else {
                $st = $pdo->prepare('INSERT INTO tb_feed_connector (name, connector_type, connection_json, schedule_json, enabled, last_status, next_run_at) VALUES (?,?,?,?,?,?,?)');
                $st->execute([$name, $type, json_encode($conn), json_encode($sched), $enabled, 'never', $next]);
                $id = (int) $pdo->lastInsertId();
                $msg = "커넥터 '$name' 추가됨.";
            }
            vg_log_activity($pdo, 'CONNECTOR', $id, 'connector_save', "커넥터 '$name' 저장", ['type' => $type, 'enabled' => $enabled],
                subject: $name, action: 'UPDATE');
        } elseif ($action === 'run') {
            $id = (int) ($post['id'] ?? 0);
            // 수동 실행은 apache 요청 안에서 동기로 돈다. NVD lastMod 수집은 실측 432초가
            // 걸린다(4,632건). max_execution_time=30 을 넘겨도 리눅스에서는 CPU 시간만
            // 세기에 네트워크 대기가 빠져 우연히 통과할 뿐이다. 파싱·upsert 가 무거워져
            // CPU 30초를 넘기면 그 순간 죽고, catch 가 안 돌아 로그가 'running' 으로 굳는다.
            set_time_limit(0);
            ignore_user_abort(true);   // 브라우저를 닫아도 수집은 끝까지 마친다
            // CLI 경로(bin/sync.php · scheduler.php)는 512M 을 쓰는데 웹만
            // 기본 256M 이었다. 같은 수집을 부르는 경로이니 한도도 같아야 한다.
            //
            // 실측(2026-07-10): 가장 무거운 EPSS 도 운영 규모(CVE 40만)에서 피크 74MB 다
            // — 보유 CVE 해시 34MB + CSV 평문 10MB + explode 배열 28MB. 지금은 256M 으로도
            // 넉넉하다. 터진 적은 없고, 호스트가 늘어 USN 캐시가 커질 때 UI 경로만 먼저
            // 죽는 함정을 막아두는 것이다(죽으면 로그가 'running' 으로 굳는다).
            ini_set('memory_limit', '512M');
            // 세션 파일 락을 먼저 놓는다. PHP 는 session_start 부터 스크립트 끝까지 세션
            // 파일을 배타 잠그는데, 이 실행은 위 주석대로 수 분(NVD 432초)이 걸린다. 락을
            // 쥔 채 돌면 같은 세션(같은 브라우저)의 다른 탭·페이지가 그 시간 내내
            // session_start 에서 막혀 UI 전체가 얼어붙는다. 아래는 세션에 쓰지 않고
            // ($msg/$err 로 인라인 렌더, csrf 는 이미 검증됨) 읽기만 하므로 지금 닫아도 안전하다.
            // ※ 이 시점 이후로는 이 요청 전체에서 세션 쓰기가 유실된다 — 호출부
            //   (connectors.php)가 이 뒤에 세션에 쓰는 코드를 추가하면 안 된다.
            session_write_close();
            $r = vg_feed_run($pdo, $id, 'manual');
            // 성공 여부가 아니라 **실제 수집분**이 기준이다 — 0건 수집이면 재계산할 근거가 없다.
            if (!empty($r['ok']) && (int) $r['upserted'] > 0) {
                $scans = vg_rematch_scan_ids($pdo);
                foreach ($scans as $sid) { vg_match_scan($pdo, $sid); }
                $msg = "실행 완료: {$r['upserted']} 건 수집 · 재매칭 " . count($scans) . ' 스캔.';
                // OSV 면 조치안(fixed_version)까지 이어서 보강한다(findings 를 읽으므로 재매칭 뒤에).
                if (vg_feed_has_type($pdo, [$id], 'osv')) {
                    $s = vg_osv_enrich_fixed($pdo);
                    $msg .= " 조치안 {$s['filled']}건 보강.";
                    // OSV 로 affected_packages 가 바뀌었으니 packages.php 요약을 다시 만든다.
                    if ($s['filled'] > 0) {
                        vg_load_cve_catalog($pdo, [], true);
                        foreach ($scans as $sid) { vg_match_scan($pdo, $sid); }
                    }
                    vg_rebuild_package_summary($pdo);
                    // 라이선스 요약은 여기서 돌리지 않는다 — DELETE→INSERT...SELECT 벌크라도
                    // 웹 요청(동기 실행) 안에서 매번 도는 건 불필요하다. scheduler.php 가 1분마다
                    // 무조건 재빌드하므로 최대 1분 지연으로 최신화된다(OSV 게이트 밖, license_summary.php 참고).
                }
            } elseif (!empty($r['ok'])) {
                // 조용히 건너뛰지 않는다 — 왜 재매칭이 안 돌았는지 화면에 드러나야 한다.
                $msg = '실행 완료: 수집 0건 — 재매칭 생략.';
            } else {
                $err = "실행 실패: {$r['error']}";
            }
        } elseif ($action === 'delete') {
            $id = (int) ($post['id'] ?? 0);
            vg_soft_delete($pdo, 'tb_feed_connector', $id);
            vg_log_activity($pdo, 'CONNECTOR', $id, 'connector_delete', '커넥터 삭제');
            $msg = '커넥터 삭제됨.';
        }
    } catch (Throwable $e) {
        error_log('[connector_actions] action=' . (string) $action . ': ' . $e->getMessage());
        $err = $e->getMessage();
    }
    return ['msg' => $msg, 'err' => $err];
}
