<?php
/**
 * findings/tabs/cce.php — 보안설정(CCE) 탭(경고 · 결과 카드 · 툴바 · 표).
 *   쓰는 값(findings.php 가 $ctx 로 넘긴다):
 *     $cceResultCounts $rows $total $page $perPage $scan $hostId $hostOptions
 *     $q $sev $res $sevOptions $type
 */
?>
  <?php // 판정 불가(NA) 해설 배너는 걷었다 — 건수는 바로 아래 결과 카드(NA)와 범례가 갖고,
        //   그 카드를 누르면 NA 만 걸러 볼 수 있다(배너는 같은 수를 문장으로 되풀이했다). ?>
  <div class="cards">
    <?php
    // 결과 카드가 res 필터를 토글한다(다시 누르면 전체). CVE 탭의 등급 카드와 같은 조작이다.
    //   NA 는 PASS 와 절대 같은 색을 쓰지 않는다 — 회색(판정 불가)과 초록(양호)은 다른 사실이다.
    $cceCardTone = ['FAIL' => 'high', 'NA' => 'muted', 'PASS' => 'low'];
    $cceCardLabel = ['FAIL' => '위반', 'NA' => '판정 불가', 'PASS' => '양호'];
    foreach (['FAIL', 'NA', 'PASS'] as $rk): ?>
      <a href="<?= vg_h(vg_qs(['res' => $res === $rk ? 'ALL' : $rk, 'page' => 1])) ?>"
         class="kpi kpi--sm tone-<?= $cceCardTone[$rk] ?><?= $res === $rk ? ' is-selected' : '' ?>">
        <b><?= number_format($cceResultCounts[$rk]) ?></b><span><?= $cceCardLabel[$rk] ?>(<?= $rk ?>)</span>
      </a>
    <?php endforeach; ?>
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
          'icon'  => '📭',
          'title' => '아직 수집된 스캔이 없습니다.',
          'hint'  => '에이전트가 자산을 최소 한 번은 수집해야 이 화면에 판정이 뜹니다.',
      ];
  } elseif ($cceResultCounts['FAIL'] + $cceResultCounts['PASS'] + $cceResultCounts['NA'] === 0) {
      // 점검 자체가 없는 것과 "위반이 없는 것" 은 다르다 — 여기서 "안전" 이라고 말하지 않는다.
      $emptySpec = [
          'icon'  => '📭',
          'title' => '아직 보안설정 점검 결과가 없습니다.',
          'hint'  => '에이전트가 설정값을 수집하고 서버가 판정해야 이 목록이 채워집니다.',
      ];
  } elseif ($res === 'FAIL' && !$hasAnyFilter) {
      $emptySpec = [
          'icon'  => '🔍',
          'title' => '위반(FAIL) 0건입니다 — 점검된 항목 기준입니다.',
          'hint'  => '판정 불가(NA) ' . number_format($cceResultCounts['NA']) . '건은 수집이 안 된 항목입니다.',
          'cta'   => ['href' => vg_qs(['res' => 'ALL', 'page' => 1]), 'label' => '전체 결과 보기'],
      ];
  } else {
      $emptySpec = [
          'icon'  => '🔍',
          'title' => '조건에 맞는 점검 결과가 없습니다.',
          'hint'  => '등급·결과 필터나 검색어를 넓혀 보세요.',
          'cta'   => $filterCta,
      ];
  }

  /* 결과 세 갈래(PASS/FAIL/NA)의 색 뜻. FAIL 은 등급색을 그대로 쓰므로 대표로 crit 을 세운다 —
   *   실제 톤 매핑은 아래 'result' 셀이 갖는다(여기서 분류표를 새로 만들지 않는다). */
  vg_legend([
      ['label' => 'FAIL · 위반', 'tone' => 'crit', 'n' => (int) $cceResultCounts['FAIL']],
      ['label' => 'PASS · 양호', 'tone' => 'low',  'n' => (int) $cceResultCounts['PASS']],
      ['label' => 'NA · 판정 불가', 'tone' => 'muted', 'n' => (int) $cceResultCounts['NA']],
  ], ['inline' => true, 'caption' => '점검 결과']);

  // 컬럼 순서는 CVE 탭과 같은 뼈대다 — 자산이 첫 칸, 그 다음이 판정(결과·등급), 마지막이 근거.
  //   노출 축(runtime_status)은 여기 없다: 설정 점검에는 리스닝·외부노출 개념이 없어서
  //   억지로 만들면 없는 걸 있는 척하는 게 된다. 빈 칸을 만들지 않고 컬럼 자체를 두지 않는다.
  $headers = $scan ? [] : [['label' => '호스트', 'key' => 'fqdn', 'width' => '17%', 'class' => 'col-id']];
  $headers = array_merge($headers, [
      ['label' => '결과',  'key' => 'result',   'width' => '8%',  'nowrap' => true],
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
              // 등급은 위반일 때만 뜻이 있다 — PASS·NA 에 등급 뱃지를 붙이면 없는 위험을 있는 것처럼 만든다.
              'severity' => fn($r) => $r['result'] === 'FAIL'
                  ? vg_sev_badge((string) $r['severity'])
                  : '<span class="why">–</span>',
              'title' => fn($r) => '<div class="clamp-2">' . vg_h((string) $r['title']) . '</div>',
              // 룰 상세 화면은 이미 compliance_rule.php 가 갖고 있다 — 새로 만들지 않고 링크한다.
              'code' => function ($r) {
                  $code = (string) $r['code'];
                  $html = '<a href="/cce-rule.php?code=' . urlencode($code) . '"><code>'
                        . vg_h($code) . '</code></a>';
                  if (empty($r['ssg_rule_id'])) {
                      return $html . '<div class="why">자체 기준(대응 SSG 룰 없음)</div>';
                  }
                  $ruleId = (string) $r['ssg_rule_id'];
                  $html .= '<div class="why"><a href="/compliance_rule.php?rule=' . urlencode($ruleId) . '">'
                        . vg_h(vg_trunc($ruleId, 28)) . ' →</a></div>';
                  return $html;
              },
              'evidence' => function ($r) {
                  $why = trim((string) ($r['rationale'] ?? ''));
                  $ev  = trim((string) ($r['evidence'] ?? ''));
                  $html = '<div class="why clamp-2">' . ($why !== '' ? vg_h($why) : '<span class="why">판정 사유 없음</span>') . '</div>';
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
