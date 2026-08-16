<?php
declare(strict_types=1);

/**
 * dashboard/sections/flow.php — 수집 → 매칭 → 판정 → 조치 도식 한 줄.
 */
function vg_dash_render_flow(int $hostCount, array $totals, int $kevOverdue): void {
  /* 이 화면이 무엇을 보여주는지를 문장이 아니라 도식으로 답한다 — 에이전트가 걷은 것이
   *   피드와 매칭돼 판정이 되고, 그 끝에 오늘 할 조치가 남는다. 아래 퍼널은 "얼마나 좁혀지나"
   *   (건수)를 말하고 이 도식은 "그 숫자가 어디서 왔나"(단계)를 말한다 — 같은 값을 두 번
   *   세지 않으려고 칸의 숫자는 이미 계산된 것만 그대로 쓴다.
   *   조회가 실패한 화면에선 그리지 않는다 — 0 만 늘어선 도식은 "아무것도 없다"는 거짓말이 된다. */
  vg_explain_flow([
      ['icon' => 'host',    'label' => '수집', 'value' => number_format($hostCount) . '대', 'state' => 'done'],
      ['icon' => 'feed',    'label' => '매칭', 'state' => 'done'],
      ['icon' => 'shield',  'label' => '판정', 'value' => number_format(array_sum($totals)) . '건', 'state' => 'done'],
      ['icon' => 'warn',    'label' => '조치', 'value' => number_format($kevOverdue) . '건', 'state' => 'active'],
  ], ['label' => '수집에서 조치까지의 흐름']);
}
