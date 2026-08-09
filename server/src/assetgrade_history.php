<?php
declare(strict_types=1);

require_once __DIR__ . '/assetgrade.php';

/**
 * 시스템 자산등급 제안을 현재 호환 컬럼과 append-only 관찰 이력에 함께 반영한다.
 * 호출자의 ingest 트랜잭션 안에서만 실행해 둘 중 하나만 남는 부분 반영을 막는다.
 *
 * @param list<array{0:string,1:string,2:int}> $collectionStages
 */
function vg_asset_grade_observe(
    PDO $pdo,
    int $hostId,
    int $scanId,
    ?string $observedAt,
    array $collectionStages
): void {
    if (!$pdo->inTransaction()) {
        throw new LogicException('자산등급 제안 관찰은 ingest 트랜잭션 안에서 기록해야 합니다.');
    }

    $suggestion = vg_asset_grade_suggest($pdo, $scanId);
    $grade = $suggestion['grade'] ?? null;
    $reason = $suggestion === null ? null : mb_strimwidth((string) $suggestion['reason'], 0, 255, '');

    $stages = [];
    foreach ($collectionStages as $stage) {
        $stages[(string) $stage[0]] = ['status' => (string) $stage[1], 'item_count' => (int) $stage[2]];
    }
    $source = (string) ($suggestion['source'] ?? 'none');
    $required = match ($source) {
        'log_listener' => ['network_exposure'],
        'process' => ['runtime_processes'],
        default => ['runtime_processes', 'network_exposure'],
    };
    $missing = array_values(array_filter($required, static function (string $code) use ($stages): bool {
        return !isset($stages[$code]) || $stages[$code]['status'] === 'MISSING';
    }));
    $status = $missing ? 'NOT_EVALUATED' : ($suggestion === null ? 'NO_MATCH' : 'SUGGESTED');
    if ($status === 'NOT_EVALUATED') {
        $grade = null;
        $reason = null;
    }

    $requiredStages = [];
    foreach ($required as $code) {
        $requiredStages[$code] = $stages[$code] ?? ['status' => 'MISSING', 'item_count' => 0];
    }
    $evidence = json_encode(
        ['source' => $source, 'required_stages' => $requiredStages, 'missing_stages' => $missing],
        JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR
    );
    $fingerprint = hash('sha256', json_encode(
        [$grade, $reason, $status, $evidence],
        JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR
    ), true);

    $sourceCollectedAt = trim((string) $observedAt);
    $sourceCollectedAt = $sourceCollectedAt !== '' ? $sourceCollectedAt : null;
    $st = $pdo->prepare(
        'INSERT INTO tb_asset_grade_suggestion_history
            (host_id, scan_id, suggested_grade, suggested_reason, evaluation_status,
             evidence_snapshot, result_fingerprint, source_collected_at, observed_at,
             last_source_collected_at, last_observed_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW(), ?, NOW())
         ON DUPLICATE KEY UPDATE
           last_source_collected_at = CASE
             WHEN VALUES(last_source_collected_at) IS NULL THEN last_source_collected_at
             WHEN last_source_collected_at IS NULL
               OR VALUES(last_source_collected_at) > last_source_collected_at
             THEN VALUES(last_source_collected_at) ELSE last_source_collected_at END,
           last_observed_at = GREATEST(last_observed_at, VALUES(last_observed_at))'
    );
    $st->execute([$hostId, $scanId, $grade, $reason, $status, $evidence, $fingerprint,
        $sourceCollectedAt, $sourceCollectedAt]);

    // 수집 불완전은 관찰만 남기고 현재 제안을 지우지 않는다. 지연 도착한 과거 스캔도
    // 이력에는 남기되 현재 호환 컬럼을 과거 상태로 되돌리지 않는다.
    if ($status === 'NOT_EVALUATED') { return; }
    $st = $pdo->prepare(
        'UPDATE tb_host SET grade_suggested = ?, grade_suggested_reason = ?
          WHERE host_id = ?
            AND NOT (grade_suggested <=> ? AND grade_suggested_reason <=> ?)
            AND NOT EXISTS (
                SELECT 1 FROM tb_asset_grade_suggestion_history newer
                 WHERE newer.host_id = ?
                   AND newer.evaluation_status <> \'NOT_EVALUATED\'
                   AND (newer.effective_at > LEAST(GREATEST(COALESCE(?,NOW()),DATE_SUB(NOW(),INTERVAL 7 DAY)),NOW())
                        OR (newer.effective_at = LEAST(GREATEST(COALESCE(?,NOW()),DATE_SUB(NOW(),INTERVAL 7 DAY)),NOW())
                            AND (newer.last_observed_at > NOW() OR newer.scan_id > ?)))
            )'
    );
    $st->execute([$grade, $reason, $hostId, $grade, $reason, $hostId, $sourceCollectedAt, $sourceCollectedAt, $scanId]);
}

/** @return list<array<string,mixed>> */
function vg_asset_grade_history_recent(PDO $pdo, int $hostId, int $limit = 8): array
{
    $limit = max(1, min(25, $limit));
    $st = $pdo->prepare(
        'SELECT h.scan_id, h.suggested_grade, h.suggested_reason, h.evaluation_status,
                h.evidence_snapshot, h.effective_at, h.observed_at, h.last_observed_at
           FROM tb_asset_grade_suggestion_history h
           JOIN tb_scan s ON s.scan_id = h.scan_id AND s.is_deleted = 0
          WHERE h.host_id = ?
          ORDER BY h.effective_at DESC, h.last_observed_at DESC, h.suggestion_history_id DESC
          LIMIT ' . $limit
    );
    $st->execute([$hostId]);
    return $st->fetchAll();
}

/** 최근 시스템 관찰을 확정/승인과 분리된 카드로 렌더한다. */
function vg_asset_grade_history_render(array $rows): void
{
    if (!$rows) { return; }
    ?>
    <section class="card mt-lg" aria-labelledby="asset-grade-history-title">
      <strong id="asset-grade-history-title">최근 시스템 제안 관찰</strong>
      <p class="why">스캔 데이터로 계산한 초안 관찰이며, 사람의 등급 승인·확정 이력이 아닙니다.</p>
      <div class="table-wrap"><table>
        <thead><tr><th>관찰 시각</th><th>스캔</th><th>시스템 제안</th><th>판정 상태</th><th>제안 근거</th></tr></thead>
        <tbody>
        <?php foreach ($rows as $row):
            $grade = $row['suggested_grade'] ?? null;
            $reason = (string) ($row['suggested_reason'] ?? '');
            $status = (string) ($row['evaluation_status'] ?? '');
            $statusLabel = ['SUGGESTED' => '제안', 'NO_MATCH' => '근거 없음', 'NOT_EVALUATED' => '판정 불가'][$status] ?? $status;
            $evidence = json_decode((string) ($row['evidence_snapshot'] ?? ''), true);
            $missingLabels = ['runtime_processes' => '실행 프로세스', 'network_exposure' => '네트워크 노출'];
            $missingText = [];
            foreach (($evidence['missing_stages'] ?? []) as $code) {
                $missingText[] = $missingLabels[(string) $code] ?? (string) $code;
            }
        ?>
          <tr>
            <td><?= vg_h((string) ($row['effective_at'] ?? '')) ?>
              <span class="why">(서버 마지막 관찰 <?= vg_h((string) ($row['last_observed_at'] ?? $row['observed_at'] ?? '')) ?>)</span></td>
            <td>#<?= (int) ($row['scan_id'] ?? 0) ?></td>
            <td><?= $grade !== null
                ? vg_asset_grade_badge((string) $grade, true, $reason)
                : '<span class="why">제안 없음</span>' ?></td>
            <td><?= vg_badge($statusLabel, $status === 'SUGGESTED' ? 'med' : 'muted') ?></td>
            <td><?= $reason !== '' ? vg_h($reason)
                : ($missingText ? vg_h('수집 누락: ' . implode(', ', $missingText)) : '<span class="why">–</span>') ?></td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table></div>
    </section>
    <?php
}
