<?php
declare(strict_types=1);

/**
 * dashboard/sections/trend.php — 최근 N일 High 이상 추세 카드(**자산별 스파크라인 목록**).
 *   $days 는 조회층이 쓴 창(窓)과 **같은 값**을 받는다 — 라벨과 데이터가 갈리지 않게.
 *
 *   합계 한 줄이 아니라 자산별인 이유: 합계는 "전체가 나아지는 중" 만 말해서, 한 자산이
 *   나빠지고 다른 자산이 좋아지면 그 둘이 서로를 지운다. 어느 자산을 손봐야 하는지는
 *   갈려야 보인다. 전체 구성(등급·상태)은 위의 도넛 KPI 가 맡는다.
 *
 *   **한 차트에 겹쳐 그리던 멀티라인(vg_multi_trend)을 줄로 쪼갰다.** 선 5개가 한 차트
 *   안에서 서로를 가려(사용자 지적) 어느 자산이 지금 어떤 방향인지 한눈에 안 들어왔다.
 *   자산마다 한 줄(미니 추세 + 현재값 + N일 전 대비 증감)로 두면 방향은 화살표가,
 *   크기는 숫자가 바로 말한다. **vg_multi_trend() 는 지우지 않는다** — host.php·changes.php
 *   가 그대로 쓴다. 상위 8개만 세우는 것도 같은 이유(PR #137 의 "규모가 다른 계열을 한
 *   그림에 쌓으면 작은 계열이 죽는다" 실측)를 목록 쪽에서 다시 겪지 않으려는 것이다 —
 *   나머지 자산은 아래 [호스트별 현황] 목록에 전수로 있다.
 */
function vg_dash_render_trend(array $trend, int $days): void {
  // x 라벨은 이 카드에서 쓰지 않는다(스파크라인은 축 없이 형태만 보인다) — 점 값만 넘긴다.
  $series = array_map(
      static fn(array $s): array => [
          'name'   => $s['name'],
          'href'   => $s['href'] ?? '',
          'points' => $s['points'],
      ],
      $trend
  );
  ?>
  <div class="card">
    <strong>최근 <?= $days ?>일 자산별 추세</strong>
    <span class="why">High 이상(CRITICAL·HIGH) 건수 · 현재값 기준 상위 8개 자산 · 14일 전 대비 증감</span>
    <div class="card__body">
      <?php vg_asset_sparklines($series, [
          'top'          => 8,
          'unit'         => '건',
          'compare_days' => 14,
      ]); ?>
    </div>
  </div>
<?php
}
