<?php
declare(strict_types=1);

/**
 * dashboard/sections/signals.php — 주요 취약점 신호. **표가 아니라 그림**이다.
 *   퍼널 3번 칸이 이 카드로 보내므로 id="signals" 는 계약이다.
 *
 *   예전엔 상위 N건을 표로 나열했다. 나열은 "지금 전체가 어떤 모양인가"에 답하지 못하고,
 *   같은 목록이 /findings.php 에 더 좋은 필터·정렬과 함께 이미 있다. 그래서 이 자리는
 *   **구성**(등급·실행 상태)과 **희소성**(악용 확인)만 맡는다 —
 *   건별 목록으로 가는 문은 카드 머리의 '전체 보기' 가 그대로 갖는다.
 *
 *   세 칸의 성격이 다르다: 앞 둘은 부분/전체(구성)라 도넛이고, KEV 는 **한 조각이 0.3%**라
 *   도넛이 뜻을 못 갖는다(고리가 통째로 한 색이 된다) — 큰 숫자 + 비율 바로 둔다.
 *
 *   'KEV 기한 준수율' 칸은 걷었다 — 바로 위 퍼널 4번 칸이 같은 모집단의 '기한 초과 N' 을
 *   이미 말한다(같은 숫자를 두 번 그리던 자리). 계산(vg_dash_kev_overdue)은 그 퍼널이 계속 쓴다.
 */
function vg_dash_render_signals(array $totals, array $runtime, int $kevCount): void {
  $highPlus  = (int) $totals['CRITICAL'] + (int) $totals['HIGH'];

  // ② 실행 상태 구성 — "깔려만 있는가" 와 "밖에서 닿는가" 는 같은 1건이 아니다.
  //    톤은 findings/tabs/exposure.php 의 범위 색과 같은 서열을 쓴다(화면마다 색이 갈리지 않게).
  //
  //    고리는 **노출·실행 중(EXTERNAL·LISTENING·RUNNING)만** 그린다. 운영 실측이
  //    설치만 됨 38,843 : 외부노출 959 : 수신대기 463 : 실행중 866 : 미상 2,555 라
  //    전부 그리면 고리의 89%가 회색 한 덩어리였다(심각도 도넛의 LOW 와 같은 처방 —
  //    vg_sev_donut 주석). '상태 미상' 도 고리에서 뺀다: 남기면 혼자 53%를 먹어 다시
  //    회색이 절반이 되고, 무엇보다 중앙 숫자가 '노출·실행 중의 합' 이라는 뜻을 잃는다.
  //    **숫자는 지우지 않는다** — 둘 다 오른쪽 목록에 건수로 그대로 남고 링크도 산다.
  $runtimeTone  = ['EXTERNAL' => 'crit', 'LISTENING' => 'high', 'RUNNING' => 'med',
                   'INSTALLED' => 'low', '미상' => 'muted'];
  $runtimeLabel = ['EXTERNAL' => '외부 노출', 'LISTENING' => '수신 대기', 'RUNNING' => '실행 중',
                   'INSTALLED' => '설치만 됨', '미상' => '상태 미상'];
  $runtimeArc   = ['EXTERNAL' => true, 'LISTENING' => true, 'RUNNING' => true,
                   'INSTALLED' => false, '미상' => false];
  $rtSegments = [];
  $rtLive     = 0;
  foreach ($runtimeTone as $key => $tone) {
      $n = (int) ($runtime[$key] ?? 0);
      if ($runtimeArc[$key]) { $rtLive += $n; }
      $rtSegments[] = [
          'label' => $runtimeLabel[$key],
          'value' => $n,
          'tone'  => $tone,
          'arc'   => $runtimeArc[$key],
          'href'  => $key === '미상' ? '' : '/findings.php?st=' . urlencode($key),
      ];
  }

  // ③ 악용 확인(KEV) — 모집단은 퍼널 3번 칸과 **같다**(High 이상 안에서만 센다).
  //    KEV 는 등급과 독립이라 전 등급으로 세면 퍼널의 포함관계가 깨진다(조회층 주석 참조).
  //
  //    여기는 도넛이 아니다. 실측이 KEV 3 : 그 외 High 이상 956 이라 도넛으로 그리면
  //    ㉠ 둘 다 그릴 때는 고리의 99.7%가 회색 한 덩어리고, ㉡ 회색을 arc=false 로 빼면
  //    조각이 하나만 남아 **꽉 찬 원**이 된다 — 어느 쪽도 "부분/전체" 를 말하지 못한다.
  //    희소한 값은 크기가 아니라 **숫자 자체**가 신호다: 큰 숫자 + 얼마나 드문지 보이는 바.
  $kevPct = $highPlus > 0 ? $kevCount / $highPlus * 100 : 0.0;
  ?>
  <section class="card" id="signals">
    <strong>주요 취약점 신호</strong>
    <span class="why">자산 전체의 최신 수집 기준 · <a href="/findings.php">전체 목록 보기 →</a></span>
    <div class="card__body">
      <div class="kpi-donuts">
        <?php /* ① 등급 구성 — 고리는 조치 대상(C·H·M)만 그린다(vg_sev_donut 주석 참조).
                 LOW 는 오른쪽 목록에 건수로 남고, 전체 건수는 위 퍼널의 '탐지된 전체' 가 갖는다.
                 조각을 누르면 그 등급만 걸러 본다(숫자와 목적지가 이어진다). */ ?>
        <?php vg_sev_donut($totals, 132, [
            'title' => '등급 구성',
            'href'  => '/findings.php',
            'seg'   => fn(string $sev): array => ['href' => '/findings.php?sev=' . urlencode($sev)],
        ]); ?>
        <?php vg_donut_kpi('실행 상태 구성', $rtSegments, [
            'center'       => number_format($rtLive),
            'center_label' => '노출·실행 중',
            'href'         => '/findings.php?st=EXTERNAL',
            'none'         => ['label' => '노출·실행 중 없음', 'tone' => 'ok',
                               'title' => '외부 노출·수신 대기·실행 중이 0건이라 고리를 그리지 않습니다'
                                        . ' · 상태별 건수는 오른쪽 목록에 있습니다'],
        ]); ?>
        <div class="kpi-rate tone-<?= $kevCount > 0 ? 'crit' : 'ok' ?>">
          <b><a href="/findings.php?sev=HIGH%2B&amp;fx=kev"><?= number_format($kevCount) ?></a></b>
          <span>악용 확인(KEV)</span>
          <?= vg_meter($kevCount > 0 ? 'crit' : 'ok', $kevPct,
                'High 이상 ' . number_format($highPlus) . '건 중 KEV ' . number_format($kevCount)
                . '건 (' . number_format($kevPct, 1) . '%)') ?>
          <small><a href="/findings.php?sev=HIGH%2B">그 외 High 이상 <?= number_format(max(0, $highPlus - $kevCount)) ?></a>
            · 실제 악용이 확인된 취약점(CISA KEV)</small>
        </div>
      </div>
    </div>
  </section>
<?php
}
