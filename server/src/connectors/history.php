<?php
declare(strict_types=1);

/**
 * connectors/history.php — ?conn=N 상세(커넥터 하나의 수집 이력 표).
 *   상태 뱃지·실행 계기 어휘는 connectors/vocab.php 가 소유한다.
 */

/** @param array|null $connDetail 부가값(스케줄 라벨·다음 실행)이 얹힌 커넥터 행 */
function vg_connectors_render_history(
    int $connFilter,
    string $connName,
    ?array $connDetail,
    array $logs,
    int $logTotal,
    int $perPage,
    int $page
): void {
    /* 수집 이력 표 — ?conn=N 상세에서 커넥터 하나의 이력을 보여준다. */
    $logHeaders = [
        ['label' => '상태',      'width' => '7rem',  'nowrap' => true],
        ['label' => '실행 계기', 'width' => '7rem'],
        ['label' => '수집/저장', 'width' => '9rem', 'align' => 'right'],
        ['label' => '메시지'],
        ['label' => '시각',      'width' => '11rem', 'nowrap' => true],
    ];
    $logCells = [
        0 => fn($l) => vg_connector_status_badge($l['status'] !== null ? (string) $l['status'] : null),
        1 => fn($l) => '<span class="why">'
            . vg_h(VG_COLLECT_TRIGGER[(string) $l['trigger_by']] ?? (string) $l['trigger_by']) . '</span>',
        2 => fn($l) => '<span class="why">' . ($l['items_fetched'] !== null
                ? number_format((int) $l['items_fetched']) . ' / ' . number_format((int) $l['items_upserted'])
                : '–') . '</span>',
        // 실패 메시지가 이 표의 존재 이유다 — 잘라내되 title 로 원문을 남긴다.
        3 => fn($l) => '<span class="why">' . vg_trunc((string) ($l['message'] ?? ''), 60) . '</span>',
        4 => fn($l) => '<span class="why">' . vg_h((string) $l['started_at']) . '</span>',
    ];
    $logEmpty = [
        'icon'  => '🕘',
        'title' => '아직 실행 이력이 없습니다.',
        'hint'  => '[실행]을 누르거나 예약 시각이 되면 여기에 쌓입니다.',
    ];
    ?>

  <?php if ($connFilter > 0 && $connName !== '' && $connDetail !== null): ?>
    <div class="card" id="collection-history">
      <strong><?= vg_h($connName) ?> · 상세</strong>
      <span class="why"><?= vg_h(VG_CONNECTOR_TYPES[(string) $connDetail['connector_type']]['label'] ?? (string) $connDetail['connector_type']) ?>
        · <?= $connDetail['enabled'] ? '활성' : '중지' ?>
        · <?= vg_h((string) $connDetail['_sched_label']) ?>
        · <a href="?edit=<?= $connFilter ?>">설정 편집</a>
        · <a href="/connectors.php">목록으로</a></span>
      <div class="card__body">
        <div class="sub">최근 실행 <?= vg_h((string) ($connDetail['last_run_at'] ?? '–')) ?> · 다음 실행 <?= vg_h((string) ($connDetail['_next_run'] ?: '–')) ?> · 수집 이력 <?= number_format($logTotal) ?>건</div>
        <?php
        vg_table($logHeaders, $logs, ['card' => false, 'empty' => $logEmpty, 'cell' => $logCells]);
        vg_page_nav($logTotal, $perPage, $page);
        ?>
      </div>
    </div>
  <?php endif;
}
