<?php
declare(strict_types=1);

/**
 * dashboard/sections/summary.php — 상단 현황 요약 숫자 4칸(처리 흐름 워터폴 후신).
 *
 *   전신은 워터폴(vg_flow_waterfall)이었다 — 사유가 있는 5칸을 SVG 로 그렸다. 값 넷과
 *   라벨만 있으면 되는 자리라 그림도 카드도 없앤다: `vg_kpi_strip()`(kisa-u.php·
 *   control_mapping.php 가 이미 쓰는 정본 KPI 줄)로 '현황 요약' 섹션 머리 바로 아래
 *   숫자 4칸을 세운다 — 워터폴 전용 카드가 있던 자리에 두 카드(왼쪽 순위 · 오른쪽 워터폴)를
 *   나란히 세우던 2열 격자(.dash-top)는 걷었다. 숫자 4칸은 한 줄이라 12행짜리 순위
 *   카드와 높이를 맞출 방법이 없고(억지로 맞추면 빈 카드가 된다), 애초에 머리줄로 흡수하면
 *   그 문제 자체가 생기지 않는다.
 *
 *   값은 전부 index.php 가 이미 조회한 것을 받는다 — 섹션이 자기 숫자를 다시 세면 같은
 *   화면에서 값이 갈린다(vg_dash_severity_totals() 의 totals·exposedHighPlus 를 그대로 쓴다).
 *
 *   **바로 아래 '등급 구성' 도넛과 값이 겹치는 칸(조치 대상)이 있다** — 도넛 중앙이
 *   이미 같은 합(CRITICAL+HIGH+MEDIUM)을 보여준다. 숫자 4칸 쪽은 그대로 두고(설계
 *   목업이 요구한 4칸을 유지), 도넛 중앙 쪽을 바꿔 겹침을 없앴다 — signals.php 의
 *   vg_dash_render_severity() 가 중앙을 "전체 중 비중(%)"로 바꾼다(원본은
 *   vg_sev_donut() 의 기본 'center_label'/'center' 를 호출부 opts 로 덮어써 다른
 *   화면(findings.php 등)의 같은 도넛은 그대로 둔다).
 */
function vg_dash_render_summary(array $totals, int $hostCount, int $exposedHighPlus): void {
  $low    = (int) $totals['LOW'];
  $medium = (int) $totals['MEDIUM'];
  $high   = (int) $totals['HIGH'];
  $crit   = (int) $totals['CRITICAL'];
  $allCount    = array_sum($totals);
  $afterLow    = $allCount - $low;      // CRITICAL+HIGH+MEDIUM — LOW 는 관찰 대상으로 뺀다(=조치 대상)
  $afterMedium = $afterLow - $medium;   // CRITICAL+HIGH(=High 이상) — MEDIUM 은 계획 반영으로 뺀다
  $today       = $exposedHighPlus;      // High 이상 중 외부 노출 — 이게 오늘 할 일이다

  vg_kpi_strip([
      ['value' => number_format($allCount), 'label' => '탐지 전체', 'tone' => 'muted',
       'href'  => '/findings.php',
       'title' => '자산 ' . number_format($hostCount) . '대의 최신 수집 · 탐지 결과 전체'],
      ['value' => number_format($afterLow), 'label' => '조치 대상', 'tone' => 'med',
       'title' => 'LOW ' . number_format($low) . '건은 관찰 대상으로 빠졌습니다 · CRITICAL·HIGH·MEDIUM 합'],
      ['value' => number_format($afterMedium), 'label' => 'High 이상', 'tone' => 'high',
       'href'  => '/findings.php?sev=HIGH%2B',
       'title' => 'CRITICAL ' . number_format($crit) . ' · HIGH ' . number_format($high)
                  . ' · MEDIUM ' . number_format($medium) . '건은 계획 반영으로 빠졌습니다'],
      ['value' => number_format($today), 'label' => '오늘 할 일', 'tone' => 'crit',
       'href'  => '/findings.php?sev=HIGH%2B&st=EXTERNAL',
       'title' => 'High 이상이면서 외부에 노출된 것 · 지금 조치해야 합니다'],
  ]);
}
