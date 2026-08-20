<?php
declare(strict_types=1);

/**
 * dashboard/sections/signals.php — 주요 취약점 신호. **표가 아니라 그림**이다.
 *   퍼널 3번 칸이 이 카드로 보내므로 id="signals" 는 계약이다.
 *
 *   예전엔 상위 N건을 표로 나열했다. 나열은 "지금 전체가 어떤 모양인가"에 답하지 못하고,
 *   같은 목록이 /findings.php 에 더 좋은 필터·정렬과 함께 이미 있다. 그래서 이 자리는
 *   **구성**(등급·실행 상태·악용 여부)과 **진척**(KEV 기한 준수율)만 맡는다 —
 *   건별 목록으로 가는 문은 카드 머리의 '전체 보기' 가 그대로 갖는다.
 *
 *   네 칸의 성격이 다르다: 앞 셋은 부분/전체(구성)라 도넛이고, 마지막은 "얼마나 왔나"라
 *   도넛이 아니라 **큰 숫자 + 진행바**다. 비율을 도넛으로 그리면 남은 조각이 실제로
 *   존재하는 항목처럼 보인다.
 */
function vg_dash_render_signals(array $totals, array $runtime, int $kevCount,
                                int $kevOverdue, int $kevSlaDays): void {
  $allCount  = array_sum($totals);
  $highPlus  = (int) $totals['CRITICAL'] + (int) $totals['HIGH'];

  // ① 등급 구성 — 조각을 누르면 그 등급만 걸러 본다(숫자와 목적지가 이어진다).
  $sevSegments = [];
  foreach (VG_TONE_SEV as $sev => $tone) {
      $sevSegments[] = [
          'label' => $sev,
          'value' => (int) ($totals[$sev] ?? 0),
          'tone'  => $tone,
          'href'  => '/findings.php?sev=' . urlencode($sev),
      ];
  }

  // ② 실행 상태 구성 — "깔려만 있는가" 와 "밖에서 닿는가" 는 같은 1건이 아니다.
  //    톤은 findings/tabs/exposure.php 의 범위 색과 같은 서열을 쓴다(화면마다 색이 갈리지 않게).
  $runtimeTone  = ['EXTERNAL' => 'crit', 'LISTENING' => 'high', 'RUNNING' => 'med',
                   'INSTALLED' => 'low', '미상' => 'muted'];
  $runtimeLabel = ['EXTERNAL' => '외부 노출', 'LISTENING' => '수신 대기', 'RUNNING' => '실행 중',
                   'INSTALLED' => '설치만 됨', '미상' => '상태 미상'];
  $rtSegments = [];
  foreach ($runtimeTone as $key => $tone) {
      $rtSegments[] = [
          'label' => $runtimeLabel[$key],
          'value' => (int) ($runtime[$key] ?? 0),
          'tone'  => $tone,
          'href'  => $key === '미상' ? '' : '/findings.php?st=' . urlencode($key),
      ];
  }

  // ③ 악용 확인(KEV) — 모집단은 퍼널 3번 칸과 **같다**(High 이상 안에서만 센다).
  //    KEV 는 등급과 독립이라 전 등급으로 세면 퍼널의 포함관계가 깨진다(조회층 주석 참조).
  $kevSegments = [
      ['label' => '악용 확인(KEV)', 'value' => $kevCount, 'tone' => 'crit',
       'href' => '/findings.php?sev=HIGH%2B&fx=kev'],
      ['label' => '그 외 High 이상', 'value' => max(0, $highPlus - $kevCount), 'tone' => 'muted',
       'href' => '/findings.php?sev=HIGH%2B'],
  ];

  // ④ KEV 기한 준수율 — 만들어 낸 지표가 아니라 퍼널 3·4번 칸의 관계 그대로다
  //    (모집단 = KEV, 그중 기한을 안 넘긴 비율). KEV 가 0건이면 비율이 없다.
  $kevInTime = max(0, $kevCount - $kevOverdue);
  $ratePct   = $kevCount > 0 ? $kevInTime / $kevCount * 100 : null;
  $rateTone  = $ratePct === null ? 'muted' : ($ratePct >= 90 ? 'ok' : ($ratePct >= 70 ? 'med' : 'crit'));
  ?>
  <section class="card" id="signals">
    <strong>주요 취약점 신호</strong>
    <span class="why">자산 전체의 최신 스캔 기준 · <a href="/findings.php">전체 목록 보기 →</a></span>
    <div class="card__body">
      <div class="kpi-donuts">
        <?php vg_donut_kpi('등급 구성', $sevSegments, [
            'center'       => number_format($allCount),
            'center_label' => '탐지 전체',
            'href'         => '/findings.php',
        ]); ?>
        <?php vg_donut_kpi('실행 상태 구성', $rtSegments, [
            'center'       => number_format(array_sum($runtime)),
            'center_label' => '탐지 전체',
            'href'         => '/findings.php',
        ]); ?>
        <?php vg_donut_kpi('악용 확인(KEV) 구성', $kevSegments, [
            'center'       => number_format($highPlus),
            'center_label' => 'High 이상',
            'href'         => '/findings.php?sev=HIGH%2B',
        ]); ?>
        <div class="kpi-rate">
          <b><?= $ratePct === null ? '–' : number_format($ratePct, 1) . '%' ?></b>
          <span>KEV 기한 준수율</span>
          <?= vg_meter($rateTone, $ratePct ?? 0.0,
                'KEV 기한 준수율 ' . ($ratePct === null ? '해당 없음' : number_format($ratePct, 1) . '%')) ?>
          <small>기한 내 <?= number_format($kevInTime) ?> ·
            <a href="/findings.php?sev=HIGH%2B&amp;fx=overdue&amp;sort=due">초과 <?= number_format($kevOverdue) ?></a>
            · 기한 <?= number_format($kevSlaDays) ?>일</small>
        </div>
      </div>
    </div>
  </section>
<?php
}
