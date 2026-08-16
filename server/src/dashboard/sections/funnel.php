<?php
declare(strict_types=1);

/**
 * dashboard/sections/funnel.php — 상단의 좁혀지는 퍼널 4칸.
 */
function vg_dash_render_funnel(array $totals, int $hostCount, int $kevCount, int $kevOverdue, int $kevSlaDays): void {
  /* 상단은 결론 문장 + KPI 나열이 아니라 **좁혀지는 퍼널**이다.
   *
   * 이 숫자들의 실제 관계는 나열이 아니라 포함이다 — 전체 안에 High 이상이 있고, 그 안에
   * 악용 확인(KEV)이 있고, 그 안에 외부 노출이 있다. 관계를 형태로 그리면 "가장 먼저
   * 조치할 대상입니다" 라는 배너 문장이 필요 없어져서, 그 배너는 지웠다.
   *
   * 마지막 칸이 "오늘 할 일" 이다. 예전엔 KEV 중 외부 노출을 셌는데, 그건 기한 계산이
   * 이 저장소에 없어서 고른 대체 신호였다. 지금은 finding_sla.php 가 조치 기한을 계산하므로
   * 원래 의도대로 **KEV 중 기한 초과**를 센다 — "언제까지" 를 넘긴 것이 진짜 오늘 할 일이다.
   * (외부 노출 신호는 아래 [주요 취약점 신호] 카드가 정렬 기준으로 계속 보여준다.)
   *
   * 링크: findings.php 에 KEV 필터도, 기한 초과 필터도 없다 — 있는 것은 기한 임박순
   *   정렬(?sort=due)이고, 초과분이 그 목록 맨 위에 선다. 그래서 4번 칸은 그리로 보낸다
   *   (가장 가까운 목적지다). KEV 칸은 KEV 우선 정렬인 아래 카드로 보낸다(#signals) —
   *   숫자만 있고 못 누르는 칸을 만들지 않는다.
   */
  $crit = (int) $totals['CRITICAL'];
  $high = (int) $totals['HIGH'];
  $allCount = array_sum($totals);
  $funnelSteps = [
      ['n' => $allCount, 'label' => '탐지된 전체',
       'cap' => '자산 ' . number_format($hostCount) . '대 · 최신 스캔 기준',
       'href' => '/findings.php', 'title' => '탐지 결과 전체 목록'],
      ['n' => $crit + $high, 'label' => 'High 이상',
       'cap' => 'CRITICAL ' . number_format($crit) . ' · HIGH ' . number_format($high),
       'href' => '/findings.php?sev=HIGH%2B', 'title' => 'CRITICAL과 HIGH 전체 목록'],
      ['n' => $kevCount, 'label' => '악용 확인(KEV)',
       'cap' => 'High 이상 중 · 실제 공격에 쓰임',
       'href' => '/findings.php?sev=HIGH%2B&fx=kev', 'title' => 'High 이상 중 KEV 등재 목록'],
      ['n' => $kevOverdue, 'label' => 'KEV 중 기한 초과',
       'cap' => '조치 기한 ' . number_format($kevSlaDays) . '일 넘김 · 오늘 먼저 조치할 대상',
       'href' => '/findings.php?sev=HIGH%2B&fx=overdue&sort=due', 'title' => 'High 이상 KEV 중 기한을 넘긴 미조치 목록'],
  ];
  ?>
  <div class="funnel">
    <?php foreach ($funnelSteps as $i => $s):
      // 오른쪽으로 갈수록 무게가 커진다(s1 → s4). 다만 **0건이면 색을 걷는다** — 0 은
      //   "지금 볼 것이 없다" 는 뜻이라 위험색을 가져갈 이유가 없다(findings.php 의 등급 카드와 같은 규칙).
      $cls = 'funnel__step funnel__step--s' . ($i + 1) . ((int) $s['n'] === 0 ? ' funnel__step--zero' : '');
    ?>
      <a class="<?= $cls ?>" href="<?= vg_h($s['href']) ?>" title="<?= vg_h($s['title']) ?>">
        <b><?= number_format((int) $s['n']) ?></b>
        <span><?= vg_h($s['label']) ?></span>
        <span class="funnel__cap"><?= vg_h($s['cap']) ?></span>
      </a>
    <?php endforeach; ?>
  </div>
<?php
}
