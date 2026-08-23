<?php
declare(strict_types=1);

/**
 * dashboard/sections/signals.php — 구성 도넛. **카드 한 장이 아니라 두 장이다.**
 *
 *   예전엔 상위 N건을 표로 나열했다. 나열은 "지금 전체가 어떤 모양인가"에 답하지 못하고,
 *   같은 목록이 /findings.php 에 더 좋은 필터·정렬과 함께 이미 있다. 그래서 이 자리는
 *   **구성**(등급 · 노출·실행 상태)만 맡는다.
 *
 *   그 구성 둘을 [주요 취약점 신호] 한 카드에 담고 있었는데, **한 카드에 두 이야기**라
 *   카드가 가로 전체를 쓰면서 내용은 도넛 둘뿐이었다 — 1920px 실측에서 카드 폭 1,643 중
 *   도넛이 쓴 건 822 로 절반(821px)이 통째로 빈 띠였다(1440px 에서도 365px). 카드를 쪼개면
 *   각 카드가 **자기 내용만큼의 폭**을 갖게 되어 그 빈 띠가 구조적으로 사라진다.
 *   묶음("이 둘은 같은 이야기다")은 카드 경계가 아니라 위의 섹션 머리와 격자가 말한다.
 *
 *   '악용 확인(KEV)' 칸은 걷었다(그 전에 'KEV 기한 준수율' 칸도 같은 이유로 걷었다).
 *   **바로 위 퍼널이 같은 숫자를 이미 말한다** — 3번 칸 '악용 확인(KEV) N', 4번 칸
 *   'KEV 중 기한 초과 N'. 계산(kev)은 그 퍼널이 계속 쓴다.
 *
 *   id="signals" 는 남긴다 — 같은 화면 안에서 이 자리를 가리키던 앵커다.
 *
 *   등급 구성 도넛의 중앙 숫자는 바로 위 숫자 4칸(summary.php)의 '조치 대상' 과 같은
 *   합(CRITICAL+HIGH+MEDIUM)이라 **같은 값을 두 번 보여줬다.** 4칸 쪽은 목업이 정한
 *   레이아웃이라 그대로 두고, 여기 중앙만 "전체 중 비중(%)" 으로 바꿔 겹침을 없앤다 —
 *   고리 자체(조각별 절대 건수)는 그대로다. 이 opts 는 vg_sev_donut() 의 기본값
 *   ('조치 대상' 절대값)을 이 호출부만 덮어쓴다 — findings.php 등 다른 화면의 같은
 *   도넛은 그대로 절대값을 보여준다.
 */

/** 등급 구성 — 조치 대상(C·H·M)만 고리로 그리고, 조각을 누르면 그 등급만 걸러 본다. */
function vg_dash_render_severity(array $totals): void {
  $all        = array_sum($totals);
  $actionable = $all - (int) $totals['LOW'];
  $pct        = $all > 0 ? round($actionable / $all * 100) : 0;
  ?>
  <section class="card dash-donut" id="signals">
    <strong>등급 구성</strong>
    <span class="why">최신 수집 기준 · <a href="/findings.php">전체 목록 →</a></span>
    <div class="card__body">
      <?php /* 고리는 조치 대상(C·H·M)만 그린다(vg_sev_donut 주석 참조). LOW 는 오른쪽 목록에
               건수로 남고, 전체 건수는 위 숫자 4칸의 '탐지 전체' 가 갖는다.
               조각을 누르면 그 등급만 걸러 본다(숫자와 목적지가 이어진다). */ ?>
      <?php vg_sev_donut($totals, 132, [
          'title'        => '등급 구성',
          'href'         => '/findings.php',
          'seg'          => fn(string $sev): array => ['href' => '/findings.php?sev=' . urlencode($sev)],
          'center'       => $pct . '%',
          'center_label' => '전체 중 비중',
      ]); ?>
    </div>
  </section>
<?php
}

/** 노출·실행 상태 구성 — "깔려만 있는가" 와 "밖에서 닿는가" 는 같은 1건이 아니다. */
function vg_dash_render_runtime(array $runtime): void {
  ?>
  <section class="card dash-donut">
    <strong>노출·실행 상태</strong>
    <span class="why">최신 수집 기준 · <a href="/findings.php?st=EXTERNAL">외부 노출만 →</a></span>
    <div class="card__body">
      <?php /* 라벨·톤·고리에 그릴지는 vg_runtime_donut() 하나가 갖는다 — 탐지 결과 화면의 같은
               도넛과 **같은 함수·같은 어휘**여야 두 화면의 숫자를 이어 읽을 수 있다.
               상태별 건수를 누르면 그 상태만 걸러 본다 — '상태 미상' 은 필터 값이 아니라
               목적지가 없다(툴바의 '노출 상태' 에도 그 항목이 없다). */ ?>
      <?php vg_runtime_donut($runtime, 132, [
          'title' => '노출·실행 상태 구성',
          'href'  => '/findings.php?st=EXTERNAL',
          'seg'   => fn(string $key): array => [
              'href' => $key === '미상' ? '' : '/findings.php?st=' . urlencode($key),
          ],
      ]); ?>
    </div>
  </section>
<?php
}
