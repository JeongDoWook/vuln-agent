<?php
declare(strict_types=1);

/**
 * dashboard/sections/signals.php — 주요 취약점 신호. **표가 아니라 그림**이다.
 *   퍼널 3번 칸이 이 카드로 보내므로 id="signals" 는 계약이다.
 *
 *   예전엔 상위 N건을 표로 나열했다. 나열은 "지금 전체가 어떤 모양인가"에 답하지 못하고,
 *   같은 목록이 /findings.php 에 더 좋은 필터·정렬과 함께 이미 있다. 그래서 이 자리는
 *   **구성**(등급 · 노출·실행 상태)만 맡는다 —
 *   건별 목록으로 가는 문은 카드 머리의 '전체 보기' 가 그대로 갖는다.
 *
 *   '악용 확인(KEV)' 칸은 걷었다(그 전에 'KEV 기한 준수율' 칸도 같은 이유로 걷었다).
 *   **바로 위 퍼널이 같은 숫자를 이미 말한다** — 3번 칸 '악용 확인(KEV) N', 4번 칸
 *   'KEV 중 기한 초과 N'. 같은 화면에서 같은 수를 두 번 그리던 자리라, 이 카드는 도넛
 *   두 개(구성)만 남기고 희소한 단일 수치는 퍼널에 맡긴다. 계산(kev)은 그 퍼널이 계속 쓴다.
 */
function vg_dash_render_signals(array $totals, array $runtime): void {
  // ② 노출·실행 상태 구성 — "깔려만 있는가" 와 "밖에서 닿는가" 는 같은 1건이 아니다.
  //    라벨·톤·고리에 그릴지는 vg_runtime_donut() 하나가 갖는다 — 탐지 결과 화면의 같은
  //    도넛과 **같은 함수·같은 어휘**여야 두 화면의 숫자를 이어 읽을 수 있다.
  ?>
  <section class="card" id="signals">
    <strong>주요 취약점 신호</strong>
    <span class="why">자산 전체의 최신 수집 기준 · <a href="/findings.php">전체 목록 보기 →</a></span>
    <div class="card__body">
      <?php /* 도넛 둘만 서는 줄이라 --pair 를 붙인다 — 1fr 칸이면 목록이 화면 절반까지 늘어나
               스와치와 숫자가 손가락 두 마디만큼 벌어진다(app.css 의 .kpi-donuts--pair). */ ?>
      <div class="kpi-donuts kpi-donuts--pair">
        <?php /* ① 등급 구성 — 고리는 조치 대상(C·H·M)만 그린다(vg_sev_donut 주석 참조).
                 LOW 는 오른쪽 목록에 건수로 남고, 전체 건수는 위 퍼널의 '탐지된 전체' 가 갖는다.
                 조각을 누르면 그 등급만 걸러 본다(숫자와 목적지가 이어진다). */ ?>
        <?php vg_sev_donut($totals, 132, [
            'title' => '등급 구성',
            'href'  => '/findings.php',
            'seg'   => fn(string $sev): array => ['href' => '/findings.php?sev=' . urlencode($sev)],
        ]); ?>
        <?php /* 상태별 건수를 누르면 그 상태만 걸러 본다 — '상태 미상' 은 필터 값이 아니라
                 목적지가 없다(툴바의 '노출 상태' 에도 그 항목이 없다). */ ?>
        <?php vg_runtime_donut($runtime, 132, [
            'title' => '노출·실행 상태 구성',
            'href'  => '/findings.php?st=EXTERNAL',
            'seg'   => fn(string $key): array => [
                'href' => $key === '미상' ? '' : '/findings.php?st=' . urlencode($key),
            ],
        ]); ?>
      </div>
    </div>
  </section>
<?php
}
