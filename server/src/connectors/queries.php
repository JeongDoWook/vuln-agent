<?php
declare(strict_types=1);

/**
 * connectors/queries.php — 데이터 수집 화면의 **조회층**. 커넥터 목록·수집 이력·편집 대상만
 *   읽는다. POST 처리(save/run/delete)는 여기 없다 — src/connector_actions.php 가 갖고,
 *   커넥터 화면이 헤더 출력 전에 직접 부른다(action='run' 은 그 안에서 세션 락을 놓는다).
 */

/** 살아 있는 커넥터 전부(표시 순서는 등록 순). */
function vg_connectors_all(PDO $pdo): array
{
    return $pdo->query('SELECT * FROM tb_feed_connector WHERE is_deleted = 0 ORDER BY feed_connector_id')->fetchAll();
}

/** 커넥터별 수집 이력 건수([[상세 N]] 버튼과 상세 카드가 같은 값을 쓴다). */
function vg_connectors_log_counts(PDO $pdo): array
{
    $logCountByConn = [];
    foreach ($pdo->query(
        'SELECT feed_connector_id, COUNT(*) AS total
           FROM tb_feed_collection_log GROUP BY feed_connector_id'
    )->fetchAll() as $r) {
        $logCountByConn[(int) $r['feed_connector_id']] = (int) $r['total'];
    }
    return $logCountByConn;
}

/**
 * ?conn=N — 그 커넥터의 전체 이력(페이지네이션).
 * @param array $out {logs, logTotal, connName, connDetail}
 */
function vg_connectors_load_logs(
    PDO $pdo,
    array $connectors,
    int $connFilter,
    array $logCountByConn,
    int $page,
    int $perPage,
    array &$out
): void {
    $logs = []; $logTotal = 0; $connName = ''; $connDetail = null;
    if ($connFilter > 0) {
        foreach ($connectors as $c) {
            if ((int) $c['feed_connector_id'] === $connFilter) {
                $connName = (string) $c['name'];
                $connDetail = $c;
                break;
            }
        }
        $logTotal = $logCountByConn[$connFilter] ?? 0;
        $offset   = ($page - 1) * $perPage;
        $st = $pdo->prepare(
            "SELECT status, trigger_by, items_fetched, items_upserted, message, started_at
               FROM tb_feed_collection_log WHERE feed_connector_id = ?
              ORDER BY started_at DESC
              LIMIT $perPage OFFSET $offset"
        );
        $st->execute([$connFilter]);
        $logs = $st->fetchAll();
    }
    $out = compact('logs', 'logTotal', 'connName', 'connDetail');
}

/**
 * 추가/편집 모달을 채울 값. ?edit=N 이면 그 커넥터로, 저장에 실패했으면 **방금 입력한 값**으로
 *   되돌려 준다(실패했다고 사용자가 친 것을 버리지 않는다).
 *
 * @param int|null    $editId ?edit= 값(파라미터가 없으면 null). 쿼리스트링을 읽는 것은 라우트의 몫이다.
 * @param string|null $err    저장 실패 메시지(있으면 $post 로 폼을 복원한다)
 */
function vg_connectors_edit_target(array $connectors, ?int $editId, array $post, ?string $err): ?array
{
    // 편집 대상 — ?edit=N 이면 추가/편집 모달을 그 값으로 채워 자동으로 연다.
    $edit = null;
    if ($editId !== null) {
        foreach ($connectors as $c) { if ((int) $c['feed_connector_id'] === $editId) { $edit = $c; } }
    }
    $saveFailed = $err !== null && ($post['action'] ?? '') === 'save';
    if ($saveFailed) {
        $submittedId = (int) ($post['id'] ?? 0);
        $submitted = null;
        foreach ($connectors as $c) {
            if ((int) $c['feed_connector_id'] === $submittedId) { $submitted = $c; break; }
        }
        $edit = $submitted ?? ['feed_connector_id' => $submittedId];
        $edit['name'] = (string) ($post['name'] ?? '');
        $edit['connector_type'] = (string) ($post['connector_type'] ?? 'kev');
        $edit['enabled'] = isset($post['enabled']) ? 1 : 0;
        $edit['connection_json'] = $edit['connector_type'] === 'generic_api'
            ? (string) ($post['g_config_json'] ?? '{}')
            : json_encode([
                'url' => (string) ($post['url'] ?? ''),
                'api_key' => (string) ($post['api_key'] ?? ''),
                'ecosystem' => (string) ($post['ecosystem'] ?? ''),
                'days' => (string) ($post['days'] ?? ''),
            ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        $edit['schedule_json'] = json_encode([
            'mode' => (string) ($post['schedule_mode'] ?? 'manual'),
            'interval_minutes' => (string) ($post['interval_minutes'] ?? ''),
            'time' => (string) ($post['schedule_time'] ?? ''),
            'expr' => (string) ($post['schedule_cron'] ?? ''),
        ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    }
    return $edit;
}
