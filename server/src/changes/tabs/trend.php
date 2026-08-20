<?php
/**
 * changes/tabs/trend.php — '추이' 탭(회차별).
 *   쓰는 값(changes.php 가 $ctx 로 넘긴다):
 *     $trendNeedsHost $trendRounds $trendResolvedAll $trendSummary $page $perPage $pdo
 *
 *   ⚠ $trendNeedsHost 는 "호스트를 안 골랐다" 는 뜻이고, 그때 조회 자체를 **하지 않는다**
 *   (changes.php 의 분기). 전체 호스트 합산은 findings 자기조인급 비용이라 일부러 갈라 둔
 *   것이다(PR #472) — 이 안내 화면을 "일관성" 을 이유로 없애면 그대로 성능 회귀가 된다.
 */
?>
    <?php if ($trendNeedsHost): ?>
      <?php vg_empty([
          'icon'  => 'host',
          'title' => '호스트를 선택하면 추이를 볼 수 있습니다.',
          'hint'  => '전체 자산 합산은 데이터가 많으면 무거워질 수 있어, 위 필터에서 호스트를 먼저 고르세요.',
      ]); ?>
    <?php elseif (!$trendRounds): ?>
      <?php vg_empty([
          'icon'  => 'chart',
          'title' => '아직 비교할 수집 이력이 없습니다.',
          'hint'  => '이 호스트의 수집 이력이 쌓이면 회차별 추이가 표시됩니다.',
      ]); ?>
    <?php else: ?>
      <?php $trendLatest = $trendRounds[count($trendRounds) - 1]; ?>
      <?php /* 0건이면 톤을 뺀다(위 취약점 변화 KPI 와 같은 판단 — 0 은 경고가 아니다). */
      $trendKpi = [
          ['new', '신규', 'crit'], ['up', '등급 상승', 'high'], ['down', '등급 하락', 'low'],
          ['resolved', '해결', 'ok'],
      ]; ?>
      <div class="cards">
        <?php foreach ($trendKpi as [$key, $label, $tone]): ?>
          <div class="kpi kpi--sm<?= $trendSummary[$key] > 0 ? ' tone-' . vg_h($tone) : '' ?>">
            <b><?= number_format($trendSummary[$key]) ?></b><span><?= vg_h($label) ?></span>
          </div>
        <?php endforeach; ?>
        <div class="kpi kpi--sm tone-muted"><b><?= number_format($trendLatest['unresolved']) ?></b><span>현재 잔존</span></div>
      </div>

      <div class="sub">① 미해결 취약점 수 추이</div>
      <div class="card"><div class="card__body">
      <?php
      /* x 라벨은 **회차 번호**다. 같은 날 여러 번 수집하는 자산이 흔해서 날짜를 라벨로 쓰면
       *   두 회차가 한 점으로 합쳐진다(라벨이 곧 x 좌표다). 수집 시각은 아래 ③ 요약표가 갖는다.
       * collected_at 이 NULL/빈값인 회차(에이전트 파싱 실패)는 건너뛴다 — 실제로 없는 시점을
       *   이으면 없는 데이터가 있는 것처럼 보인다. */
      $trendPoints = [];
      foreach ($trendRounds as $r) {
          if ($r['collected_at'] === null || $r['collected_at'] === '') { continue; }
          $trendPoints[] = ['d' => (int) $r['round'] . '회차', 'v' => (int) $r['unresolved']];
      }
      vg_multi_trend([['name' => '미해결', 'points' => $trendPoints]], [
          'unit'  => '건',
          'alt'   => '회차별 미해결 취약점 수 추이',
          'empty' => [
              'icon'  => 'chart',
              'title' => '그래프를 그리기엔 회차 이력이 부족합니다.',
              'hint'  => '수집이 2회차 이상 쌓이면 여기에 추이가 표시됩니다.',
          ],
      ]);
      ?>
      </div></div>

      <div class="sub">② 회차별 신규·해결</div>
      <div class="card"><?php vg_change_bars($trendRounds); ?></div>

      <div class="sub">③ 회차별 요약</div>
      <?php
      vg_table(
          [
              ['label' => '회차', 'width' => '8%', 'align' => 'center'],
              ['label' => '수집일시'],
              ['label' => '신규', 'width' => '10%', 'align' => 'right'],
              ['label' => '해결', 'width' => '10%', 'align' => 'right'],
              ['label' => '잔존', 'width' => '10%', 'align' => 'right'],
              ['label' => '누적 조치율', 'width' => '12%', 'align' => 'right'],
          ],
          array_reverse($trendRounds),   // 최신 회차가 맨 위
          [
              'cell' => [
                  0 => fn($r) => (string) $r['round'],
                  1 => fn($r) => '<span class="why">' . vg_h($r['collected_at'] ?: '–') . '</span>',
                  2 => fn($r) => $r['new'] === null ? '<span class="why">–</span>' : number_format($r['new']),
                  3 => fn($r) => $r['resolved'] === null ? '<span class="why">–</span>' : number_format($r['resolved']),
                  4 => fn($r) => number_format($r['unresolved']),
                  5 => fn($r) => $r['cum_rate'] === null ? '<span class="why">–</span>' : number_format($r['cum_rate'], 1) . '%',
              ],
          ]
      );
      ?>

      <div class="sub">④ 이번 구간 해결된 항목</div>
      <?php
      $trendResolvedTotal = count($trendResolvedAll);
      $trendResolvedPaged = array_slice($trendResolvedAll, ($page - 1) * $perPage, $perPage);
      if ($trendResolvedPaged) {
          try {
              vg_attach_change_reason($pdo, $trendResolvedPaged);
          } catch (Throwable $e) {
              error_log('[changes] trend detail lookup: ' . $e->getMessage());
          }
      }
      vg_table(
          [
              // 위 '취약점 변화' 표와 같은 셀 함수를 쓰므로 열 구성·폭 기준도 그대로 맞춘다.
              ['label' => '회차', 'width' => '4rem', 'align' => 'center'],
              ['label' => '변화 · 사유', 'width' => '15%',
               'title' => '무엇이 달라졌는지와, 왜 그렇게 됐는지(패키지 변경 이력 대조 결과)'],
              ['label' => '호스트'],
              ['label' => 'CVE', 'width' => '11.5rem', 'nowrap' => true],
              ['label' => '패키지'],
              ['label' => '등급 · 노출', 'width' => '11rem'],
              ['label' => '수집 시각', 'width' => '9rem', 'nowrap' => true],
          ],
          $trendResolvedPaged,
          [
              'empty' => [
                  'icon'  => 'check',
                  'title' => '이 구간엔 해결된 항목이 없습니다.',
                  'hint'  => '구간(호스트·최근 N회차)을 넓혀 보세요.',
              ],
              'row_class' => fn($r) => vg_sev_row((string) $r['severity']),
              'cell' => [
                  0 => fn($r) => (string) $r['round'],
                  1 => fn($r) => vg_change_type_cell($r),
                  2 => fn($r) => '<a href="/host.php?id=' . (int) $r['host_id'] . '">' . vg_h($r['fqdn']) . '</a>',
                  3 => fn($r) => '<a href="/cve.php?cve=' . urlencode($r['cve_id']) . '">' . vg_h($r['cve_id']) . '</a>'
                                . ($r['in_kev'] ? ' ' . vg_badge('KEV', 'crit') : ''),
                  4 => fn($r) => vg_change_package_cell($r),
                  5 => fn($r) => vg_change_severity_cell($r),
                  6 => fn($r) => vg_change_when_cell($r),
              ],
          ]
      );
      if ($trendResolvedPaged) { vg_page_nav($trendResolvedTotal, $perPage, $page); }
      ?>
    <?php endif; ?>
