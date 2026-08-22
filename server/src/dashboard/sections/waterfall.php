<?php
declare(strict_types=1);

/**
 * dashboard/sections/waterfall.php — 상단 오른쪽의 처리 흐름 카드(줄어드는 사유를 남기는 워터폴).
 *
 *   전신은 퍼널(vg_flow_funnel)이었다 — "좁아진다"만 말했다. 지금은 칸마다 **무엇 때문에
 *   얼마가 빠졌는지**를 사유와 함께 남긴다: LOW 는 관찰 대상으로 빠지고, MEDIUM 은 정기
 *   패치 계획에 반영돼 빠지고, 남은 것 중 밖으로 노출되지 않은 것도 빠진 나머지가 바로
 *   "오늘 할 일"이다.
 *
 *   값은 전부 index.php 가 이미 조회한 것을 받는다 — 섹션이 자기 숫자를 다시 세면 같은
 *   화면에서 값이 갈린다(vg_dash_severity_totals() 의 totals·exposedHighPlus 를 그대로 쓴다).
 */
function vg_dash_render_waterfall(array $totals, int $hostCount, int $exposedHighPlus): void {
  $low    = (int) $totals['LOW'];
  $medium = (int) $totals['MEDIUM'];
  $high   = (int) $totals['HIGH'];
  $crit   = (int) $totals['CRITICAL'];
  $allCount    = array_sum($totals);
  $afterLow    = $allCount - $low;      // CRITICAL+HIGH+MEDIUM — LOW 는 관찰 대상으로 뺀다
  $afterMedium = $afterLow - $medium;   // CRITICAL+HIGH(=High 이상) — MEDIUM 은 계획 반영으로 뺀다
  $today       = $exposedHighPlus;      // High 이상 중 외부 노출 — 이게 오늘 할 일이다
  $notExposed  = $afterMedium - $today;
  ?>
  <section class="card">
    <strong>처리 흐름</strong>
    <span class="why">탐지 전체에서 오늘 할 일까지 · 세로는 로그 척도(선형이면 마지막 칸이 사라진다) ·
      <a href="/findings.php">전체 목록 →</a></span>
    <div class="card__body">
      <?php vg_flow_waterfall([
          ['label' => '탐지 전체', 'value' => $allCount, 'tone' => 'muted', 'href' => '/findings.php',
           'title' => '자산 ' . number_format($hostCount) . '대의 최신 수집 · 탐지 결과 전체'],
          ['label' => 'LOW 제외', 'value' => $afterLow, 'reason' => '관찰 대상', 'tone' => 'low',
           'title' => 'LOW ' . number_format($low) . '건 제외(관찰 대상) · 지금은 조치하지 않고 지켜본다'],
          ['label' => 'MEDIUM 제외', 'value' => $afterMedium, 'reason' => '계획 반영', 'tone' => 'med',
           'href'  => '/findings.php?sev=HIGH%2B',
           'title' => 'MEDIUM ' . number_format($medium) . '건 제외(계획 반영) · 남은 것은 CRITICAL '
                      . number_format($crit) . ' · HIGH ' . number_format($high)],
          ['label' => '노출 안 됨', 'value' => $today, 'tone' => 'ok',
           'title' => 'High 이상 중 외부에서 닿지 않는 ' . number_format($notExposed)
                      . '건 제외 · 밖에서 안 닿으면 급하지 않다'],
          ['label' => '오늘 할 일', 'value' => $today, 'tone' => 'crit',
           'href'  => '/findings.php?sev=HIGH%2B&st=EXTERNAL',
           'title' => 'High 이상이면서 외부에 노출된 것 · 지금 조치해야 한다'],
      ], ['title' => '처리 흐름 워터폴']); ?>
    </div>
  </section>
<?php
}
