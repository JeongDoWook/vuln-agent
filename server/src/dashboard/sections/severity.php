<?php
declare(strict_types=1);

/**
 * dashboard/sections/severity.php — 등급별 분포(7일 전 대비 증감 + 도넛). 접힘(details) 안에 둔다.
 */
function vg_dash_render_severity(array $totals, array $delta, int $hostCount, int $kevCount): void {
  ?>
  <?php /* 등급별 전체 분포와 도넛은 지우지 않고 **접어서** 퍼널 아래로 내린다.
   * MEDIUM·LOW 는 "오늘 무엇을 할까" 를 바꾸지 않는 수라(실측 LOW 34,745) 상단에 두면
   * 자릿수만으로 CRITICAL 을 덮는다. 필요할 때 펴 보는 자리가 맞다. */ ?>
  <div class="card">
    <strong>등급별 분포</strong> <span class="why">— 7일 전 대비 증감</span>
    <div class="card__body">
      <?php /* 여는 줄에 카드 제목("등급별 전체 분포 보기")을 다시 적지 않는다 — 바로 위 줄이다. */ ?>
      <details>
        <summary>펼치기</summary>
        <div class="cards cards--grid">
          <div class="kpi"><b><?= number_format($hostCount) ?></b><span>호스트</span></div>
          <?php foreach (['CRITICAL','HIGH','MEDIUM','LOW'] as $s):
      // 증감은 방향을 색만으로 말하지 않는다 — ▲/▼ 기호를 같이 준다(색각 이상·흑백 출력).
      // 변화가 없으면(0) 칩 자체를 안 그린다 — "— 0" 은 알려주는 게 없이 카드만 시끄럽게 했다.
      $d = ($delta[$s] ?? 0) !== 0 ? $delta[$s] : null;
      $dir = $d === null ? '' : ($d > 0 ? 'up' : 'down');
      $dtxt = $d === null ? '' : ($d > 0 ? '▲ ' . number_format($d) : '▼ ' . number_format(abs($d)));
    ?>
          <a class="kpi tone-<?= vg_sev_tone($s) ?>" href="/findings.php?sev=<?= $s ?>">
            <b><?= number_format((int) $totals[$s]) ?></b><span><?= $s ?></span>
            <?php if ($d !== null): ?>
              <span class="kpi__delta <?= $dir ?>"><span class="sr-only">7일 전 대비 </span><?= vg_h($dtxt) ?></span>
            <?php endif; ?>
          </a>
        <?php endforeach; ?>
        </div>
        <div class="donut-wrap">
          <?php vg_sev_donut($totals, 152); ?>
          <?php /* 범례는 색의 뜻만 말한다 — 'n'(건수)은 걷었다. 바로 위 KPI 카드 네 장이 같은
                   네 수를 이미 보여주고 있어, 한 화면에 같은 값이 두 번 있었다. */ ?>
          <?php vg_legend(array_map(
              fn(string $s): array => ['label' => $s, 'tone' => vg_sev_tone($s)],
              ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
          ), ['caption' => '심각도']); ?>
        </div>
        <?php /* 도넛 바닥의 KEV 요약은 걷었다 — 퍼널 3번째 칸이 같은 쿼리의 같은 수를
                 이미 화면 위에서 보여준다($kevCount 는 그래서 이 함수에서 안 쓴다). */ ?>
      </details>
    </div>
  </div>
<?php
}
