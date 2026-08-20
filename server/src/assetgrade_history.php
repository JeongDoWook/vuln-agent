<?php
declare(strict_types=1);

require_once __DIR__ . '/assetgrade.php';
require_once __DIR__ . '/format.php';   // vg_h·vg_badge·VG_COLLECTION_STAGE_LABEL (렌더에서 쓴다)

/**
 * 에이전트가 보고한 수집 시각(source_collected_at)을 신뢰할 하한. 서버 관찰 시각에서 이 일수
 * 이상 과거인 값은 시계 오류·리플레이로 보고 서버 관찰 시각 쪽으로 끌어올린다.
 *
 * 왜 필요한가: source_collected_at 은 신뢰 경계 밖 값이다. 노드 시계가 과거로 크게 밀린 채
 *   들어오면 effective_at 정렬이 뒤집혀 오래된 관찰이 최신 제안을 덮는다. 반대로 서버 시각만
 *   쓰면 오프라인이던 노드의 밀린 보고가 실제 수집 순서를 잃는다.
 * 왜 7인가: 에이전트가 지원하는 가장 긴 수집 주기(install-agent.sh 의 daily)의 7배다 —
 *   한 주 내내 끊겼던 노드의 정직한 지연 보고까지는 실제 수집 시각대로 정렬된다.
 * 왜 설정이 아니라 상수인가: 같은 기준이 tb_asset_grade_suggestion_history.effective_at
 *   STORED 생성컬럼 식에도 박혀 있어, 값을 바꾸려면 어차피 마이그레이션으로 테이블을 재구축해야
 *   한다. 설정으로 빼면 DB 와 PHP 가 조용히 어긋날 수 있으므로 한 곳(상수+마이그레이션 주석)에
 *   묶고, tests/assetgrade_history_test.php 가 둘의 일치를 검증한다.
 */
const VG_ASSET_GRADE_RECENCY_CLAMP_DAYS = 7;

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

    // required_stages 는 "이 판정에 필요했던 단계"를 기준으로 채운다 — 아예 안 들어온 단계도
    //   MISSING·0 으로 명시해야, 나중에 스냅샷만 보고 "누락"과 "수집했는데 0건"을 구분할 수 있다.
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
    // 같은 결과 replay 는 유일키로 행이 늘지 않는다. 대신 "마지막으로 다시 본 시각"만 갱신해
    //   "아직도 같은 상태다"라는 정보를 잃지 않는다. 두 시각 모두 **뒤로 가지 않는다** —
    //   늦게 도착한 과거 보고가 마지막 관찰을 과거로 되돌리면 이력 정렬이 뒤집힌다.
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
               THEN VALUES(last_source_collected_at)
             ELSE last_source_collected_at END,
           last_observed_at = GREATEST(last_observed_at, VALUES(last_observed_at))'
    );
    $st->execute([$hostId, $scanId, $grade, $reason, $status, $evidence, $fingerprint,
        $sourceCollectedAt, $sourceCollectedAt]);

    // 수집 불완전은 관찰만 남기고 현재 제안을 지우지 않는다. 지연 도착한 과거 스캔도
    // 이력에는 남기되 현재 호환 컬럼을 과거 상태로 되돌리지 않는다.
    // 확정값(grade/grade_reason/approved_*)은 이 UPDATE 가 절대 건드리지 않는다 — 확정은
    //   vg_asset_grade_confirm() 한 곳의 책임이다.
    if ($status === 'NOT_EVALUATED') { return; }
    // 이 관찰의 effective_at 을 생성컬럼 식과 **똑같이** 계산해 비교한다. 두 식이 어긋나면
    //   "더 최신 판정이 이미 있는가" 판단이 틀린다. 상수는 위 VG_ASSET_GRADE_RECENCY_CLAMP_DAYS.
    $effectiveAtSql = 'LEAST(GREATEST(COALESCE(?, NOW()), DATE_SUB(NOW(), INTERVAL '
        . VG_ASSET_GRADE_RECENCY_CLAMP_DAYS . ' DAY)), NOW())';
    $st = $pdo->prepare(
        'UPDATE tb_host SET grade_suggested = ?, grade_suggested_reason = ?
          WHERE host_id = ?
            AND (
              COALESCE(grade_suggested, \'\') <> COALESCE(?, \'\')
              OR COALESCE(grade_suggested_reason, \'\') <> COALESCE(?, \'\')
            )
            AND NOT EXISTS (
                SELECT 1 FROM tb_asset_grade_suggestion_history newer
                 WHERE newer.host_id = ?
                   -- 판정 불가(NOT_EVALUATED)는 등급을 담지 않는 관찰이라, 유효한 제안의
                   --   반영을 막아서는 안 된다. 수집이 한 번 빠졌다고 제안이 영구 동결된다.
                   AND newer.evaluation_status <> \'NOT_EVALUATED\'
                   AND (newer.effective_at > ' . $effectiveAtSql . '
                        OR (newer.effective_at = ' . $effectiveAtSql . ' AND newer.scan_id > ?))
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
                h.evidence_snapshot, h.source_collected_at, h.observed_at,
                h.effective_at, h.last_observed_at
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
      <p class="why">수집 데이터로 계산한 초안 관찰이며, 사람의 등급 승인·확정 이력이 아닙니다.</p>
      <div class="table-wrap"><table>
        <thead><tr><th>관찰 시각</th><th>수집</th><th>시스템 제안</th><th>판정 상태</th><th>제안 근거</th></tr></thead>
        <tbody>
        <?php foreach ($rows as $row):
            $grade = $row['suggested_grade'] ?? null;
            $reason = (string) ($row['suggested_reason'] ?? '');
            $status = (string) ($row['evaluation_status'] ?? '');
            $statusLabel = ['SUGGESTED' => '제안', 'NO_MATCH' => '근거 없음', 'NOT_EVALUATED' => '판정 불가'][$status] ?? $status;
            // 판정 불가 행은 근거가 비어 있다 — 어느 수집 단계가 빠졌는지 대신 보여준다.
            $evidence = json_decode((string) ($row['evidence_snapshot'] ?? ''), true);
            $missingText = [];
            foreach ((array) ($evidence['missing_stages'] ?? []) as $code) {
                $missingText[] = VG_COLLECTION_STAGE_LABEL[(string) $code] ?? (string) $code;
            }
            $lastObserved = (string) ($row['last_observed_at'] ?? $row['observed_at'] ?? '');
        ?>
          <tr>
            <td><?= vg_h((string) ($row['effective_at'] ?? $row['observed_at'] ?? '')) ?>
              <span class="why">서버 마지막 관찰 <?= vg_h($lastObserved) ?></span></td>
            <td>#<?= (int) ($row['scan_id'] ?? 0) ?></td>
            <td><?= $grade !== null
                ? vg_asset_grade_badge((string) $grade, true, $reason)
                : '<span class="why">제안 없음</span>' ?></td>
            <td><?= vg_badge($statusLabel, $status === 'SUGGESTED' ? 'med' : 'muted') ?></td>
            <td><?= $reason !== '' ? vg_h($reason)
                : ($missingText !== []
                    ? vg_h('수집 누락: ' . implode(', ', $missingText))
                    : '<span class="why">–</span>') ?></td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table></div>
    </section>
    <?php
}
