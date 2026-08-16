<?php
declare(strict_types=1);

/**
 * dashboard/sections/next_feed.php — 다음 수집 예정 한 줄. 예정이 없으면 아무것도 그리지 않는다.
 */
function vg_dash_render_next_feed(?array $nextFeed): void {
  if ($nextFeed !== null):
    $secs = strtotime((string) $nextFeed['next_run_at']) - time();
    $rel  = $secs <= 0 ? '곧'
          : ($secs < 3600 ? (int) round($secs / 60) . '분 후'
          : ($secs < 86400 ? (int) round($secs / 3600) . '시간 후'
          : (int) round($secs / 86400) . '일 후'));
  ?>
  <div class="sub">다음 수집 예정 · <strong><?= vg_h((string) $nextFeed['next_run_at']) ?></strong>
    <span class="why"><?= vg_h($rel) ?> · <?= vg_h($nextFeed['name']) ?> (<?= vg_h(strtoupper((string) $nextFeed['connector_type'])) ?>)</span></div>
  <?php endif;
}
