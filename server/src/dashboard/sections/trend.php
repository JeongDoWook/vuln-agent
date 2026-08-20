<?php
declare(strict_types=1);

/**
 * dashboard/sections/trend.php — 최근 N일 High 이상 추세 카드(**자산별 멀티라인**).
 *   $days 는 조회층이 쓴 창(窓)과 **같은 값**을 받는다 — 라벨과 데이터가 갈리지 않게.
 *
 *   합계 한 줄이 아니라 자산별 선인 이유: 합계는 "전체가 나아지는 중" 만 말해서, 한 자산이
 *   나빠지고 다른 자산이 좋아지면 그 둘이 서로를 지운다. 어느 자산을 손봐야 하는지는
 *   선이 갈려야 보인다. 전체 구성(등급·상태)은 위의 도넛 KPI 가 맡는다.
 *
 *   **'기타'로 접지 않고 상위 5개만 그린다(fold=false).** 나머지를 합쳐 한 선으로 얹으면
 *   그 선이 자산 수만큼 커져 정작 상위 5개가 바닥에 눌린다 — dev 실측으로 상위 5개가
 *   각 90건인데 '기타 46개'가 1,258건이라(14배) 다섯 선이 차트 아래 7% 안에 겹쳤다.
 *   규모가 다른 계열을 한 차트에 쌓으면 작은 계열이 1px 실선이 된다는 PR #137 의 실측과
 *   같은 함정이다. **전체 구성은 위의 도넛 KPI 가 맡는다** — 이 차트는 "어느 자산이
 *   나빠지는 중인가" 하나만 답한다. 나머지 자산은 아래 [호스트별 현황] 목록에 전수로 있다.
 */
function vg_dash_render_trend(array $trend, int $days): void {
  // x 라벨은 표시할 모양 그대로 넘긴다(차트가 날짜를 다시 해석하지 않는다).
  $series = array_map(
      static fn(array $s): array => [
          'name'   => $s['name'],
          'points' => array_map(
              static fn(array $p): array => ['d' => date('n/j', strtotime((string) $p['d'])), 'v' => $p['v']],
              $s['points']
          ),
      ],
      $trend
  );
  ?>
  <div class="card">
    <strong>최근 <?= $days ?>일 자산별 추세</strong>
    <span class="why">High 이상(CRITICAL·HIGH) 건수 · 최신 시점 기준 상위 5개 자산</span>
    <div class="card__body">
      <?php vg_multi_trend($series, [
          'unit'       => '건',
          'max_series' => 5,
          'fold'       => false,
          'size'       => 'lg',
          'alt'        => '자산별 최근 ' . $days . '일 High 이상 건수 추세',
          'empty'      => [
              'icon'  => 'chart',
              'title' => '추세를 그리기엔 수집 이력이 부족합니다.',
              'hint'  => '서로 다른 날짜의 수집이 2건 이상 쌓이면 여기에 자산별 추세가 표시됩니다.',
          ],
      ]); ?>
    </div>
  </div>
<?php
}
