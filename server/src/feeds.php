<?php
declare(strict_types=1);

/**
 * feeds.php — CVE 피드 커넥터 레지스트리 + 실행/스케줄/미리보기.
 *   커넥터 계약(VgFeedConnector)과 등록(vg_feed_make)만 여기 두고, 커넥터 구현과 공용
 *   헬퍼는 feeds/ 아래로 분할했다. 호출부(connectors.php·feed_preview.php·bin/*)는
 *   예전처럼 이 파일 하나만 require 하면 전체가 로드된다.
 *
 *   분할:
 *     feeds/http.php   — SSRF 가드 + curl(vg_http_*) + vg_conn_url
 *     feeds/upsert.php — tb_cves/kev/affected 공용 write + CVE-ID 형식검증 + VG_TEXT_MAX
 *     feeds/kev.php    — VgKevConnector
 *     feeds/osv.php    — VgOsvConnector + vg_osv_* + vg_osv_enrich_fixed
 *     feeds/nvd.php    — VgNvdConnector + vg_nvd_sync(백필 공용)
 *     feeds/kisa.php   — VgKisaConnector + KISA RSS/URL/HTML 파싱(공지 저장/본문 로직은 advisory.php)
 *     feeds/epss.php   — VgEpssConnector + vg_epss_fetch
 *     feeds/debtracker.php — VgDebtrackerConnector + 데비안 보안 트래커(백포트 오탐 억제 근거)
 *
 *   새 피드 추가: feeds/<type>.php 에 VgFeedConnector 구현 + 여기 require 한 줄 +
 *   vg_feed_make() 한 줄. run/preview 는 같은 클래스가 갖는다(미리보기가 실제 수집과
 *   다른 소스·기준을 보는 사고를 구조적으로 막는다 — 예전 NVD 발행일/수정일 불일치).
 */

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/audit.php';   // vg_log_activity
require_once __DIR__ . '/distro.php';  // vg_osv_ecosystem (매처와 공유)
require_once __DIR__ . '/schedule.php'; // vg_cron_*/vg_schedule_* — 스케줄 계산(순수 함수)

// 공용 계층(커넥터들이 의존) — 커넥터 클래스보다 먼저 로드한다.
require_once __DIR__ . '/feeds/http.php';
require_once __DIR__ . '/feeds/upsert.php';

// ─────────────────────────────────────────────────────────────────────────
// 커넥터 계약: 각 타입은 run(PDO,$conn) → ['fetched'=>N,'upserted'=>N] 을 반환하고,
//   preview(PDO,$conn) 로 저장 없이 최대 10건 미리보기를 돌려준다(run 과 같은 소스·기준).
// ─────────────────────────────────────────────────────────────────────────
interface VgFeedConnector {
    public function run(PDO $pdo, array $conn): array;
    public function preview(PDO $pdo, array $conn): array;
}

// 커넥터 구현(계약 정의 뒤에 로드).
require_once __DIR__ . '/feeds/kev.php';
require_once __DIR__ . '/feeds/osv.php';
require_once __DIR__ . '/feeds/nvd.php';
require_once __DIR__ . '/feeds/kisa.php';
require_once __DIR__ . '/feeds/epss.php';
require_once __DIR__ . '/feeds/debtracker.php';
require_once __DIR__ . '/feeds/rhoval.php';
require_once __DIR__ . '/feeds/rhunfixed.php';
require_once __DIR__ . '/feeds/ssg.php';

function vg_feed_make(string $type): VgFeedConnector {
    switch ($type) {
        case 'kev':  return new VgKevConnector();
        case 'osv':  return new VgOsvConnector();
        case 'nvd':  return new VgNvdConnector();
        case 'kisa': return new VgKisaConnector();
        case 'epss': return new VgEpssConnector();
        case 'debtracker': return new VgDebtrackerConnector();
        case 'rhoval': return new VgRhovalConnector();
        case 'rhunfixed': return new VgRhunfixedConnector();
        case 'ssg': return new VgSsgConnector();
        default: throw new InvalidArgumentException("알 수 없는 커넥터 타입: $type");
    }
}

// ─────────────────────────────────────────────────────────────────────────
// 실행 (cron/스케줄 계산은 schedule.php 로 분리 — vg_cron_*/vg_schedule_*)
// ─────────────────────────────────────────────────────────────────────────

/** 주어진 커넥터 id 중에 해당 타입이 있는가. 수집 후 후처리를 걸지 결정할 때 쓴다. */
function vg_feed_has_type(PDO $pdo, array $ids, string $type): bool {
    if (!$ids) { return false; }
    $in = implode(',', array_fill(0, count($ids), '?'));
    $st = $pdo->prepare("SELECT 1 FROM tb_feed_connectors WHERE connector_type = ? AND id IN ($in) LIMIT 1");
    $st->execute(array_merge([$type], array_map('intval', $ids)));
    return (bool) $st->fetchColumn();
}

/** 커넥터 1건 실행: 로그(running→success/error) + 커넥터 상태/다음실행 갱신. */
function vg_feed_run(PDO $pdo, int $connectorId, string $triggerBy = 'schedule'): array {
    $st = $pdo->prepare('SELECT * FROM tb_feed_connectors WHERE id = ? AND is_deleted = 0');
    $st->execute([$connectorId]);
    $c = $st->fetch();
    if (!$c) {
        throw new RuntimeException("커넥터 없음: $connectorId");
    }
    // 스케줄러가 돌리면 SYSTEM, 사람이 누르면 USER 로 감사 기록.
    $actor = $triggerBy === 'schedule' ? 'SYSTEM' : 'USER';
    $conn     = json_decode((string) $c['connection_json'], true) ?: [];
    $schedule = json_decode((string) $c['schedule_json'], true) ?: [];

    $lg = $pdo->prepare('INSERT INTO tb_feed_collection_logs (connector_id, trigger_by, status) VALUES (?,?,?)');
    $lg->execute([$connectorId, $triggerBy, 'running']);
    $logId = (int) $pdo->lastInsertId();
    $pdo->prepare('UPDATE tb_feed_connectors SET last_status=?, last_run_at=NOW() WHERE id=?')->execute(['running', $connectorId]);

    try {
        $res = vg_feed_make((string) $c['connector_type'])->run($pdo, $conn);
        $msg = "fetched={$res['fetched']} upserted={$res['upserted']}";
        $pdo->prepare('UPDATE tb_feed_collection_logs SET status=?, finished_at=NOW(), items_fetched=?, items_upserted=?, message=? WHERE id=?')
            ->execute(['success', $res['fetched'], $res['upserted'], $msg, $logId]);
        $pdo->prepare('UPDATE tb_feed_connectors SET last_status=?, last_message=?, next_run_at=? WHERE id=?')
            ->execute(['success', $msg, vg_schedule_next($schedule), $connectorId]);
        vg_log_activity($pdo, 'CONNECTOR', $connectorId, 'feed_run', "수집 {$res['upserted']}건",
            ['fetched' => $res['fetched'], 'upserted' => $res['upserted'], 'status' => 'success'], null, $actor);
        return ['ok' => true] + $res;
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) { $pdo->rollBack(); }
        $msg = mb_substr($e->getMessage(), 0, 480);
        $pdo->prepare('UPDATE tb_feed_collection_logs SET status=?, finished_at=NOW(), message=? WHERE id=?')
            ->execute(['error', $msg, $logId]);
        $pdo->prepare('UPDATE tb_feed_connectors SET last_status=?, last_message=?, next_run_at=? WHERE id=?')
            ->execute(['error', $msg, vg_schedule_next($schedule), $connectorId]);
        vg_log_activity($pdo, 'CONNECTOR', $connectorId, 'feed_run', "수집 실패: $msg",
            ['status' => 'error'], null, $actor);
        return ['ok' => false, 'error' => $msg];
    }
}

/**
 * 미리보기: 소스에서 최대 10건을 가져와 그대로 보여준다(저장 안 함).
 *   커넥터 설정 전에 URL/응답 형태를 눈으로 확인하는 용도. 각 커넥터의 preview() 로 위임한다
 *   — run 과 같은 클래스라 같은 소스·기준을 본다. 알 수 없는 타입은 미지원으로 응답한다.
 */
function vg_feed_preview(string $type, array $conn, PDO $pdo): array {
    try {
        $connector = vg_feed_make($type);
    } catch (InvalidArgumentException $e) {
        return ['ok' => false, 'error' => "미리보기 미지원 타입: $type"];
    }
    return $connector->preview($pdo, $conn);
}

/**
 * 중단된 실행 정리. vg_feed_run 은 try/catch 로 성공·실패 모두 로그를 닫지만,
 * PHP 가 통째로 죽으면(치명적 오류·CPU 시간 초과·컨테이너 재기동) catch 가 돌지 않아
 * 로그가 'running' 으로 영구히 굳는다. 실측: OSV 로그 1건이 27시간째 running 이었다.
 *
 * 시작 후 $hours 시간이 지난 running 을 실패로 마감한다. 정상 수집은 길어야 10분대라
 * 기본 6시간이면 진행 중인 실행을 잘못 죽일 위험이 없다.
 *
 * @return int 정리한 로그 수
 */
function vg_feed_reap_stale(PDO $pdo, int $hours = 6): int {
    $hours = max(1, $hours);   // SQL 에 직접 넣으므로 정수로 못박는다
    $msg   = "중단된 실행으로 판단해 정리(시작 후 {$hours}시간 초과)";

    $st = $pdo->prepare(
        "UPDATE tb_feed_collection_logs
            SET status = 'error', finished_at = NOW(), message = ?
          WHERE status = 'running' AND started_at < NOW() - INTERVAL $hours HOUR"
    );
    $st->execute([$msg]);
    $n = $st->rowCount();

    if ($n > 0) {
        $pdo->prepare(
            "UPDATE tb_feed_connectors
                SET last_status = 'error', last_message = ?
              WHERE last_status = 'running' AND last_run_at < NOW() - INTERVAL $hours HOUR"
        )->execute([$msg]);
    }
    return $n;
}

/** 스케줄러가 돌릴 대상: enabled=1 이고 스케줄(interval/daily/cron) 상 지금이 due. */
function vg_feed_due(PDO $pdo): array {
    $rows = $pdo->query('SELECT id, schedule_json, last_run_at FROM tb_feed_connectors WHERE enabled = 1 AND is_deleted = 0')->fetchAll();
    $due = [];
    foreach ($rows as $r) {
        $sch = json_decode((string) $r['schedule_json'], true) ?: [];
        if (vg_schedule_due($sch, $r['last_run_at'])) {
            $due[] = (int) $r['id'];
        }
    }
    return $due;
}
