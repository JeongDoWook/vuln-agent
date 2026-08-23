<?php
declare(strict_types=1);

/**
 * dashboard/sections/rank.php — 상단의 자산 순위 막대 카드.
 *
 *   "지금 무엇부터" 에 답하는 자리다 — **그게 어느 자산에 몰려 있나**를 말한다.
 *   막대 색·겹막대·테두리 원이 무슨 뜻인지는 각 행의 title(hover)이 말한다 — 부제는
 *   되풀이하지 않는다(카드 부제 규칙: 한 줄 20자 이내).
 *
 *   전신은 아이소메트릭 지형도(vg_asset_terrain)였다 — 높이로 비교하는 그림인데 운영
 *   자산 11대의 High 이상이 55~132 로 몰려 있어(중앙 다섯이 75~76) 블록 높이차가 거의
 *   없었고, 이름표가 앞 블록에 가려 잘렸다(#779 운영 실측). 순위 막대는 이름을 그림
 *   밖 한 열에 세워 이 문제를 구조적으로 없앤다.
 *
 *   그림은 vg_asset_rank() 가 그린다(정렬·접힘·겹막대·KEV 표식 전부). 이 파일은 카드와
 *   어휘만 갖는다.
 *
 *   예전엔 오른쪽에 처리 흐름 워터폴을 나란히 세웠다(.dash-top 2열 격자) — 지금은 그
 *   자리가 숫자 4칸(summary.php)으로 바뀌어 섹션 머리로 올라갔으므로, 이 카드는
 *   전체 폭 단독 카드다(높이를 맞출 짝이 없다).
 */

function vg_dash_render_rank(array $assets, int $hostCount): void {
  ?>
  <section class="card">
    <strong>자산 순위</strong>
    <span class="why">자산 <?= vg_h(number_format($hostCount)) ?>대 · 최신 수집 ·
      <a href="/assets.php">자산 전체 →</a></span>
    <div class="card__body">
      <?php /* 상위 12대만 세운다 — 자산이 늘면 목록이 카드를 넘는다(dev 실측 53대).
               접힌 자산 수와 그 High 이상 합은 목록 아래 한 줄이 갖는다(조용히 자르지 않는다). */ ?>
      <?php vg_asset_rank($assets, ['top' => 12, 'rest_href' => '/assets.php']); ?>
    </div>
  </section>
<?php
}
