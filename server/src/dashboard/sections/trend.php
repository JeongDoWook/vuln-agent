<?php
declare(strict_types=1);

/** 14일 전 대비 |증감| 이 이 값 미만이면 "변화 없음" 으로 접어 그리지 않는다.
 *  스캔은 패키지 하나가 잡히거나 빠지는 정도로 하루 1~2건씩 자연스레 출렁인다 — 그
 *  잡음까지 추세로 그리면 정작 봐야 할 자산이 묻힌다. 3은 시작값이고, 운영 데이터로
 *  체감이 안 맞으면 이 상수만 조정한다(하드코딩 금지 원칙 — 값은 여기 한 곳뿐이다).
 *  **2026-08-23 운영 실측(자산 11대, 이력 있는 전부)으로 그대로 유지하기로 확정**: |증감|
 *  분포가 1·2 대 각 1대, 나머지(5·5·9·9·10·23·30·47·262)는 전부 3 이상이었다 — 1~2 구간과
 *  그 위 구간이 뚜렷이 갈려 있어 "14일 누적 잡음이 3을 넘어 필터가 무력화된다"는 우려의
 *  실측 근거가 없었다. 자산이 늘거나 분포가 달라지면 이 실측을 다시 하고 값을 조정한다. */
const VG_DASH_TREND_MIN_CHANGE = 3;

/** 스파크라인 카드에 세울 자산 수 상한 — 바로 위 자산 순위 카드(rank.php)가 쓰는 12 와
 *  맞춘다. 두 카드가 같은 화면에서 다른 상한을 쓸 이유가 없고(둘 다 옆 도넛 칼럼과 높이를
 *  맞춰야 한다), 예전엔 이 값이 count($shown) 자신이라 상한이 상한 역할을 못 했다(자산이
 *  늘면 카드가 그만큼 길어졌다 — 2026-08-23 리뷰 지적). */
const VG_DASH_TREND_TOP = 12;

/**
 * dashboard/sections/trend.php — 최근 N일 High 이상 추세 카드(**자산별 증감 막대 목록**).
 *   $days 는 조회층이 쓴 창(窓)과 **같은 값**을 받는다 — 라벨과 데이터가 갈리지 않게.
 *
 *   합계 한 줄이 아니라 자산별인 이유: 합계는 "전체가 나아지는 중" 만 말해서, 한 자산이
 *   나빠지고 다른 자산이 좋아지면 그 둘이 서로를 지운다. 어느 자산을 손봐야 하는지는
 *   갈려야 보인다. 전체 구성(등급·상태)은 위의 도넛 KPI 가 맡는다.
 *
 *   **한 차트에 겹쳐 그리던 멀티라인(vg_multi_trend)을 줄로 쪼갰다.** 선 5개가 한 차트
 *   안에서 서로를 가려(사용자 지적) 어느 자산이 지금 어떤 방향인지 한눈에 안 들어왔다.
 *   자산마다 한 줄(증감 막대 + 현재값 + N일 전 대비 증감)로 두면 방향은 막대가, 크기는
 *   숫자가 바로 말한다. **vg_multi_trend() 는 지우지 않는다** — host.php·changes.php 가 그대로 쓴다.
 *
 *   **줄 안의 그림을 스파크라인(선)에서 증감 막대로 바꿨다(2026-08-23).** 선 9개가 죄다
 *   "계단 한 번 오르고 평평"으로 같은 모양이라(사용자 지적) 실제로 다른 두 자산이 안
 *   튀었다 — 이 카드의 질문은 "얼마나·어느 방향으로 움직였나"인데 선은 모양을 그렸다.
 *   자세한 이유·기준선 계산은 vg_asset_delta_bars() 주석 참조.
 *
 *   **"상위 8개" 대신 "변화 있는 자산만".** 예전엔 현재값 기준 상위 8개를 무조건 그렸는데,
 *   그중 절반은 14일간 거의 안 움직였다(사용자 지적 — 세로만 8줄 먹고 절반이 정보가 아니다).
 *   지금은 vg_trend_delta() 로 자산마다 14일 전 대비 증감을 먼저 재고, |증감| 이
 *   VG_DASH_TREND_MIN_CHANGE 미만인 자산은 안 그린다 — **안 그린 사실은 숨기지 않는다**
 *   (vg_asset_rank() 가 접힌 자산 수를 "외 N대는 접었습니다" 한 줄로 남기는 것과 같은 판단).
 *   이력이 짧아 비교 자체가 안 되는 자산(delta=null, '신규')은 변화 판정 대상이 아니라
 *   **그대로 보여준다** — 막 수집을 시작한 자산을 "안 움직였다" 로 접으면 오히려 새 신호를
 *   숨기는 셈이다. 전부 안 움직였으면 카드 자체를 접는다(빈 카드는 자리 낭비다).
 *
 *   **"변화 있는 자산"이 VG_DASH_TREND_TOP(=12) 를 넘어도 상한을 둔다** — 자산 순위 카드
 *   (rank.php)와 같은 이유다: dev DB 에 자산 53대 실측이 있어, 변화 있는 자산만 골라도
 *   그 수가 늘면 카드가 옆 도넛 칼럼보다 훨씬 길어진다. 잘려 나간 수는 "변화 없어 안 그림"
 *   과 다른 사실이라 별도 문구로 남긴다 — 섞으면 "얼마나 잘렸는지"와 "얼마나 조용했는지"가
 *   구분이 안 된다.
 */
function vg_dash_render_trend(array $trend, int $days): void {
  $cmpDays = 14;

  $shown = []; $hiddenCount = 0;
  foreach ($trend as $s) {
      $pts = is_array($s['points'] ?? null) ? $s['points'] : [];
      if (!$pts) { continue; }
      $d = vg_trend_delta($pts, $cmpDays);
      $changed = $d['delta'] === null || abs($d['delta']) >= VG_DASH_TREND_MIN_CHANGE;
      $item = ['name' => $s['name'], 'href' => $s['href'] ?? '', 'points' => $pts];
      if ($changed) { $shown[] = $item; } else { $hiddenCount++; }
  }

  if (!$shown) {
    ?>
    <p class="why dash-trend-flat">최근 <?= $cmpDays ?>일 변화 없음</p>
<?php
    return;
  }

  // vg_asset_delta_bars() 는 "증감 절대값" 내림차순으로 상위 top 만 그린다 — 여기서 잘려
  // 나가는 수는 그 정렬을 다시 하지 않아도 count($shown) 과 top 의 차이로 그대로 안다.
  $top          = VG_DASH_TREND_TOP;
  $trimmedCount = max(0, count($shown) - $top);
  ?>
  <div class="card">
    <strong>최근 <?= $days ?>일 자산별 추세</strong>
    <span class="why">High 이상 · 14일 전 대비</span>
    <div class="card__body">
      <?php vg_asset_delta_bars($shown, [
          'top'          => $top,
          'unit'         => '건',
          'compare_days' => $cmpDays,
      ]); ?>
      <?php if ($hiddenCount > 0): ?>
        <p class="why">변화 없는 자산 <?= number_format($hiddenCount) ?>대는 안 그렸습니다.</p>
      <?php endif; ?>
      <?php if ($trimmedCount > 0): ?>
        <p class="why">변화는 있었지만 상위 <?= number_format($top) ?>대만 그렸습니다
          (<?= number_format($trimmedCount) ?>대 더 있음).</p>
      <?php endif; ?>
    </div>
  </div>
<?php
}
