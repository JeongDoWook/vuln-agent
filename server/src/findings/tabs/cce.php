<?php
/**
 * findings/tabs/cce.php — 보안설정(CCE) 탭(판정 구성·위반 등급 구성 카드 · 툴바 · 표).
 *   쓰는 값(findings.php 가 $ctx 로 넘긴다):
 *     $cceResultCounts $cceFailSevCounts $rows $total $page $perPage $scan $hostId $hostOptions
 *     $q $sev $res $sevOptions $type
 */
?>
  <?php // 판정 불가(NA) 해설 배너는 걷었다 — 건수는 바로 아래 결과 카드(NA)와 범례가 갖고,
        //   그 카드를 누르면 NA 만 걸러 볼 수 있다(배너는 같은 수를 문장으로 되풀이했다). ?>
  <?php
  // NA 는 PASS 와 절대 같은 색을 쓰지 않는다 — 회색(판정 불가)과 초록(양호)은 다른 사실이다.
  $cceCardTone  = ['FAIL' => 'high', 'NA' => 'muted', 'PASS' => 'low'];
  $cceCardLabel = ['FAIL' => '위반(FAIL)', 'NA' => '판정 불가(NA)', 'PASS' => '양호(PASS)'];
  $cceSegments = [];
  foreach (['FAIL', 'NA', 'PASS'] as $rk) {
      $cceSegments[] = [
          'label'    => $cceCardLabel[$rk],
          'value'    => (int) $cceResultCounts[$rk],
          'tone'     => $cceCardTone[$rk],
          'href'     => vg_qs(['res' => $res === $rk ? 'ALL' : $rk, 'page' => 1]),
          'selected' => $res === $rk,
      ];
  }
  /* 요약은 **카드 두 장**이다 — 판정 구성(무엇이 얼마나 걸렸나) · 위반 등급 구성(그중 뭐가 급한가).
   *   예전엔 판정 구성 하나뿐이라 도넛 한 개가 화면 한 줄을 통째로 차지했고, 폭 상한
   *   (`.card__body > .donut-kpi:only-child`)이 내용만 34rem 으로 묶어서 **카드 오른쪽 절반이
   *   그대로 비었다**(사용자 지적). CVE 탭처럼 그 탭이 이미 가진 수치를 옆에 세워 그 자리를 채운다.
   * 두 번째 카드의 값은 새 쿼리가 아니다 — 판정 분포를 세던 GROUP BY 에 severity 한 칸을 더해
   *   같이 받은 것이다(queries/cce.php). 모집단은 **위반(FAIL)만**이라 첫 카드와 겹치지 않는다:
   *   첫 카드는 점검 전체가 분모고, 두 번째는 위반이 분모다.
   * vg_sev_donut 을 쓰지 않는 이유: 그 함수는 CVE 등급 어휘(CRITICAL 포함·LOW 는 고리에서 제외)
   *   전용이다. CCE 판정에는 CRITICAL 이 없고 LOW 도 빼면 안 되므로 vg_donut_kpi 를 직접 부른다
   *   (charts.php 주석의 "심각도가 아닌 도넛" 갈래와 같은 판단). */
  ?>
  <div class="card-row card-row--equal">
  <?php
  vg_card('판정 구성', static function () use ($cceSegments): void {
      vg_donut_kpi('판정 구성', $cceSegments, ['center_label' => '점검 전체']);
  }, ['badge' => '점검 ' . number_format(array_sum($cceResultCounts)) . '건']);

  $failTotal = array_sum($cceFailSevCounts);
  $failSegments = [];
  foreach ($cceFailSevCounts as $sevKey => $n) {
      $failSegments[] = [
          'label'    => $sevKey,
          'value'    => (int) $n,
          'tone'     => vg_sev_tone($sevKey),
          // 위반 안에서 등급을 고르는 자리라 res=FAIL 을 함께 건다(res=ALL 로 보던 중에 눌러도
          //   그림과 목록이 같은 모집단을 가리키게). 같은 등급을 다시 누르면 등급만 풀린다.
          'href'     => vg_qs(['res' => 'FAIL', 'sev' => $sev === $sevKey ? '' : $sevKey, 'page' => 1]),
          'selected' => $res === 'FAIL' && $sev === $sevKey,
      ];
  }
  vg_card('위반 등급 구성', static function () use ($failSegments): void {
      vg_donut_kpi('위반 등급 구성', $failSegments, [
          'center_label' => '위반 전체',
          // 위반 0건에 빈 고리를 세우면 "고장난 화면" 으로 읽힌다. 다만 여기서 "안전" 이라고
          //   말하지 않는다 — 점검된 항목 기준이라는 사실은 아래 빈 상태 안내가 갖는다.
          'none' => ['label' => '위반 없음', 'tone' => 'ok',
                     'title' => '점검된 항목 중 위반(FAIL)이 0건이라 고리를 그리지 않습니다'
                              . ' · 판정 불가(NA)는 왼쪽 카드에 있습니다'],
      ]);
  }, [
      'badge'      => '위반 ' . number_format($failTotal) . '건',
      'title_attr' => '분모는 점검 전체가 아니라 위반(FAIL) 전체입니다'
                    . ' — 어느 위반부터 손대야 하는지를 봅니다',
  ]);
  ?>
  </div>

  <?php
  // 툴바 구성은 세 탭이 같다: 자산 → 등급 → (카드로 고른 필터를 hidden 으로) → 검색.
  $toolbar = $scan
      ? [['type' => 'hidden', 'name' => 'scan_id', 'value' => (string) $scan['scan_id']]]
      : [['type' => 'select', 'name' => 'host', 'empty_label' => '전체 호스트',
          'selected' => $hostId > 0 ? (string) $hostId : '', 'options' => $hostOptions]];
  vg_toolbar(array_merge($toolbar, [
      ['type' => 'select', 'name' => 'sev', 'empty_label' => '전체 등급', 'selected' => $sev,
          'options' => array_combine($sevOptions, $sevOptions)],
      // 결과는 바로 위 카드가 토글한다 — 검색을 제출해도 선택이 풀리지 않게 hidden 으로 싣는다.
      ['type' => 'hidden', 'name' => 'res', 'value' => $res === 'FAIL' ? '' : $res, 'reset' => true],
      ['type' => 'search', 'name' => 'q', 'placeholder' => '코드·점검항목·SSG 룰 검색', 'value' => $q],
      ['type' => 'hidden', 'name' => 'type', 'value' => $type],
  ]));

  $hasAnyFilter = $q !== '' || $sev !== '' || $res !== 'FAIL';
  $filterCta = ['href' => vg_qs(['q' => '', 'sev' => '', 'res' => '', 'page' => 1]), 'label' => '필터 초기화'];
  if (!$hostOptions) {
      $emptySpec = [
          'icon'  => 'host',
          'title' => '아직 수집 이력이 없습니다.',
          'hint'  => '에이전트가 자산을 최소 한 번은 수집해야 이 화면에 판정이 뜹니다.',
      ];
  } elseif ($cceResultCounts['FAIL'] + $cceResultCounts['PASS'] + $cceResultCounts['NA'] === 0) {
      // 점검 자체가 없는 것과 "위반이 없는 것" 은 다르다 — 여기서 "안전" 이라고 말하지 않는다.
      $emptySpec = [
          'icon'  => 'shield',
          'title' => '아직 보안설정 점검 결과가 없습니다.',
          'hint'  => '에이전트가 설정값을 수집하고 서버가 판정해야 이 목록이 채워집니다.',
      ];
  } elseif ($res === 'FAIL' && !$hasAnyFilter) {
      $emptySpec = [
          'icon'  => 'search',
          'title' => '위반(FAIL) 0건입니다 — 점검된 항목 기준입니다.',
          'hint'  => '판정 불가(NA) ' . number_format($cceResultCounts['NA']) . '건은 수집이 안 된 항목입니다.',
          'cta'   => ['href' => vg_qs(['res' => 'ALL', 'page' => 1]), 'label' => '전체 결과 보기'],
      ];
  } else {
      $emptySpec = [
          'icon'  => 'search',
          'title' => '조건에 맞는 점검 결과가 없습니다.',
          'hint'  => '등급·결과 필터나 검색어를 넓혀 보세요.',
          'cta'   => $filterCta,
      ];
  }

  // 컬럼 순서는 CVE 탭과 같은 뼈대다 — 자산이 첫 칸, 그 다음이 판정(결과·등급), 마지막이 근거.
  //   노출 축(runtime_status)은 여기 없다: 설정 점검에는 리스닝·외부노출 개념이 없어서
  //   억지로 만들면 없는 걸 있는 척하는 게 된다. 빈 칸을 만들지 않고 컬럼 자체를 두지 않는다.
  // '결과' 열은 **결과가 섞여 있을 때만** 세운다. 이 탭의 기본은 위반(FAIL)만 보는 것이고,
  //   그때 이 열은 전 행이 'FAIL' 이라 폭만 먹었다(dev 실측 기본 뷰 105행 전부 FAIL).
  //   지금 무엇을 보고 있는지는 바로 위 결과 카드의 선택 표시가 말한다 — 카드를 눌러
  //   res=ALL 로 넓히면 값이 섞이므로 열이 다시 선다.
  $showResult = $res === 'ALL';
  $headers = $scan ? [] : [['label' => '호스트', 'key' => 'fqdn', 'width' => '17%', 'class' => 'col-id']];
  if ($showResult) {
      $headers[] = ['label' => '결과', 'key' => 'result', 'width' => '8%', 'nowrap' => true];
  }
  $headers = array_merge($headers, [
      ['label' => '등급',  'key' => 'severity', 'width' => '9%',  'nowrap' => true],
      ['label' => '점검 항목', 'key' => 'title', 'width' => '24%'],
      ['label' => '기준(코드 · SSG 룰)', 'key' => 'code', 'width' => '17%', 'class' => 'col-id'],
      ['label' => '근거', 'key' => 'evidence'],
  ]);

  vg_table(
      $headers,
      $rows,
      [
          'empty' => $emptySpec,
          'row_class' => fn($r) => $r['result'] === 'FAIL' ? vg_sev_row((string) $r['severity']) : '',
          'cell' => [
              'fqdn' => fn($r) => '<a href="/host.php?id=' . (int) $r['host_id'] . '" title="' . vg_h($r['fqdn']) . '">' . vg_h($r['fqdn']) . '</a>',
              // 결과 → 톤: FAIL 은 위험도색, PASS 는 low(초록), NA 는 muted(회색). host.php 와 같은 규칙.
              'result' => fn($r) => vg_badge(
                  (string) $r['result'],
                  $r['result'] === 'FAIL' ? vg_sev_tone((string) $r['severity'])
                      : ($r['result'] === 'PASS' ? 'low' : 'muted')
              ),
              // 등급은 위반일 때만 뜻이 있다 — PASS·NA 에 등급 뱃지를 붙이면 없는 위험을 있는 것처럼
              //   만든다. 그렇다고 '–' 로 칸을 채우지도 않는다(없다는 말은 빈 칸이 이미 한다).
              'severity' => fn($r) => $r['result'] === 'FAIL' ? vg_sev_badge((string) $r['severity']) : '',
              'title' => fn($r) => '<div class="clamp-2">' . vg_h((string) $r['title']) . '</div>',
              // 룰 상세 화면은 이미 compliance_rule.php 가 갖고 있다 — 새로 만들지 않고 링크한다.
              'code' => function ($r) {
                  $code = (string) $r['code'];
                  $html = '<a href="/cce-rule.php?code=' . urlencode($code) . '"><code>'
                        . vg_h($code) . '</code></a>';
                  // 대응 SSG 룰이 없으면 둘째 줄을 아예 만들지 않는다 — '자체 기준(대응 SSG 룰 없음)'
                  //   이라는 문구가 dev 실측 1,092행 중 224행에 같은 모양으로 깔렸고, 그 문장은
                  //   링크가 없다는 사실을 되풀이할 뿐이었다.
                  if (empty($r['ssg_rule_id'])) { return $html; }
                  $ruleId = (string) $r['ssg_rule_id'];
                  $html .= '<div class="why"><a href="/compliance_rule.php?rule=' . urlencode($ruleId) . '">'
                        . vg_h(vg_trunc($ruleId, 28)) . ' →</a></div>';
                  return $html;
              },
              'evidence' => function ($r) {
                  $why = trim((string) ($r['rationale'] ?? ''));
                  $ev  = trim((string) ($r['evidence'] ?? ''));
                  $html = $why !== '' ? '<div class="why clamp-2">' . vg_h($why) . '</div>' : '';
                  if ($ev !== '') {
                      $html .= '<div class="why clamp-2"><code>' . vg_h($ev) . '</code></div>';
                  }
                  return $html;
              },
          ],
      ]
  );
  if ($rows) { vg_page_nav($total, $perPage, $page); }
  ?>
