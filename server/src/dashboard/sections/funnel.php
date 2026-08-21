<?php
declare(strict_types=1);

/**
 * dashboard/sections/funnel.php — 상단 오른쪽의 처리 흐름 카드(좁혀지는 퍼널).
 *
 *   예전엔 같은 값을 **타일 4칸**으로 늘어놓았다(.funnel__step). 칸을 크기로 키워 좁혀지는
 *   느낌을 냈지만 형태는 여전히 네모 넷의 나열이었고, 이 화면의 다른 그림이 전부 도넛이라
 *   "그림"이라 부를 만한 것이 원 하나뿐이었다(사용자 지적). 지금은 vg_flow_funnel() 이
 *   실제로 좁혀지는 띠를 그리고, 타일이 갖고 있던 것(값·라벨·링크·툴팁)은 그대로 옮겼다.
 *
 *   단계도 넷에서 **다섯**으로 늘렸다 — 전체와 High 이상 사이에 '조치 대상'(LOW 제외)이
 *   빠져 있어서, 이 화면의 다른 그림들이 이미 쓰는 모집단(등급 도넛·위험 막대는 C·H·M 만
 *   그린다)이 퍼널에는 없었다. 값은 전부 index.php 가 이미 조회한 것을 받는다 —
 *   섹션이 자기 숫자를 다시 세면 같은 화면에서 값이 갈린다.
 */
require_once __DIR__ . '/../../format.php';   // vg_sev_actionable() — index.php 의 로드 순서에 우연히 기대지 않는다

function vg_dash_render_funnel(array $totals, int $hostCount, int $kevCount, int $kevOverdue, int $kevSlaDays): void {
  /* 이 숫자들의 실제 관계는 나열이 아니라 **포함**이다 — 전체 안에 조치 대상이 있고, 그 안에
   * High 이상이 있고, 그 안에 악용 확인(KEV)이, 다시 그 안에 기한 초과가 있다. 관계를
   * 형태로 그리면 "가장 먼저 조치할 대상입니다" 라는 배너 문장이 필요 없다(그 배너는 지웠다).
   *
   * 마지막 칸이 "오늘 할 일" 이다. 예전엔 KEV 중 외부 노출을 셌는데, 그건 기한 계산이
   * 이 저장소에 없어서 고른 대체 신호였다. 지금은 finding_sla.php 가 조치 기한을 계산하므로
   * 원래 의도대로 **KEV 중 기한 초과**를 센다 — "언제까지" 를 넘긴 것이 진짜 오늘 할 일이다.
   *
   * 링크: findings.php 에 KEV 필터도, 기한 초과 필터도 없다 — 있는 것은 기한 임박순
   *   정렬(?sort=due)이고, 초과분이 그 목록 맨 위에 선다. 그래서 5번 칸은 그리로 보낸다.
   *   **2번 칸('조치 대상')만 목적지가 없다** — findings.php 의 등급 필터는 한 등급씩이라
   *   C·H·M 묶음을 가리키는 주소가 없다. 없는 필터를 이 화면 때문에 새로 만들지 않고,
   *   무엇을 세는지는 툴팁이 갖는다(값이 갈리는 것보다 못 누르는 편이 낫다).
   */
  $crit = (int) $totals['CRITICAL'];
  $high = (int) $totals['HIGH'];
  $allCount = array_sum($totals);
  ?>
  <section class="card">
    <strong>처리 흐름</strong>
    <span class="why">탐지 전체에서 오늘 할 일까지 · 띠 두께는 로그 척도(선형이면 뒤 칸이 사라진다) ·
      <a href="/findings.php">전체 목록 →</a></span>
    <div class="card__body">
      <?php vg_flow_funnel([
          ['label' => '탐지 전체', 'value' => $allCount, 'tone' => 'muted',
           'href'  => '/findings.php',
           'title' => '자산 ' . number_format($hostCount) . '대의 최신 수집 · 탐지 결과 전체'],
          ['label' => '조치 대상', 'value' => vg_sev_actionable($totals), 'tone' => 'med',
           'href'  => '',
           'title' => '지금 조치할 등급만(CRITICAL·HIGH·MEDIUM) · LOW '
                      . number_format((int) $totals['LOW']) . '건 제외'],
          ['label' => 'High 이상', 'value' => $crit + $high, 'tone' => 'high',
           'href'  => '/findings.php?sev=HIGH%2B',
           'title' => 'CRITICAL ' . number_format($crit) . ' · HIGH ' . number_format($high)],
          ['label' => '악용 확인(KEV)', 'value' => $kevCount, 'tone' => 'crit',
           'href'  => '/findings.php?sev=HIGH%2B&fx=kev',
           'title' => 'High 이상 중 실제 공격에 쓰인 것(KEV 등재)'],
          ['label' => '기한 초과', 'value' => $kevOverdue, 'tone' => 'crit',
           'href'  => '/findings.php?sev=HIGH%2B&fx=overdue&sort=due',
           'title' => 'KEV 조치 기한 ' . number_format($kevSlaDays) . '일을 넘긴 미조치'],
      ], ['title' => '처리 흐름 퍼널']); ?>
    </div>
  </section>
<?php
}
