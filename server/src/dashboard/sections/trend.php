<?php
declare(strict_types=1);

/**
 * dashboard/sections/trend.php — 최근 N일 High 이상 추세 카드.
 *   $days 는 조회층이 쓴 창(窓)과 **같은 값**을 받는다 — 라벨과 데이터가 갈리지 않게.
 */
function vg_dash_render_trend(array $trend, int $days): void {
  ?>
  <div class="card">
    <strong>최근 <?= $days ?>일 추세</strong>
    <div class="card__body"><?php vg_daily_trend($trend); ?></div>
  </div>
<?php
}
