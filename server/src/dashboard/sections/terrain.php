<?php
declare(strict_types=1);

/**
 * dashboard/sections/terrain.php — 상단 왼쪽의 자산 지형도 카드.
 *
 *   "지금 무엇부터" 에 답하는 자리다. 옆의 처리 흐름(퍼널)이 **전체가 얼마나 좁혀지나**를
 *   말한다면, 여기는 **그게 어느 자산에 몰려 있나**를 말한다 — 같은 축(High 이상)을
 *   두 방향에서 보는 한 줄이라 둘이 나란히 선다.
 *
 *   그림은 vg_asset_terrain() 이 그린다(좌표·접힘·접근성 전부). 이 파일은 카드와 어휘만 갖는다.
 */

function vg_dash_render_terrain(array $assets, int $hostCount): void {
  ?>
  <section class="card">
    <strong>자산 지형도</strong>
    <span class="why">블록 높이 = High 이상 건수 · 윗면의 붉은 원 = 악용 확인(KEV) 보유 ·
      자산 <?= vg_h(number_format($hostCount)) ?>대의 최신 수집 기준 ·
      <a href="/assets.php">자산 전체 →</a></span>
    <div class="card__body">
      <?php /* 상위 12대만 세운다 — 자산이 늘면 4열 격자가 카드를 넘는다(dev 실측 53대).
               접힌 자산 수와 그 High 이상 합은 그림 아래 한 줄이 갖는다(조용히 자르지 않는다). */ ?>
      <?php vg_asset_terrain($assets, ['top' => 12, 'rest_href' => '/assets.php']); ?>
    </div>
  </section>
<?php
}
