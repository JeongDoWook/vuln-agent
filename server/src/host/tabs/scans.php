<?php
declare(strict_types=1);
/* 수집 이력 탭 — 회차 표 + 같은 회차들의 에이전트 리소스 추이. */ ?>
    <div class="card">
      <strong>수집 이력</strong>
      <div class="card__body">
      <?php
      vg_table(
          [
              ['label' => '실행', 'key' => 'scan_id'],
              ['label' => '수집시각', 'key' => 'collected_at'],
              ['label' => '수신시각', 'key' => 'received_at'],
              ['label' => '패키지', 'key' => 'package_count', 'align' => 'right'],
              ['label' => '노출', 'key' => 'exposure_count', 'align' => 'right'],
              ['label' => '메모리', 'key' => 'peak_rss_mb', 'align' => 'right'],
              ['label' => 'CPU', 'key' => 'cpu_seconds', 'align' => 'right'],
              ['label' => '에이전트', 'key' => 'agent_version'],
              ['label' => '심각도', 'key' => 'sev'],
          ],
          $rows,
          [
              'card' => false,
              'empty' => [
                  'icon'  => '🕘',
                  'title' => '수집 이력이 없습니다.',
              ],
              'cell' => [
                  'scan_id'        => fn($s) => '<a href="/findings.php?scan_id=' . (int) $s['scan_id'] . '">#' . (int) $s['scan_run_id'] . '</a>'
                      . ((int) $s['content_changed'] === 1
                          ? ' <span class="badge">변경</span>'
                          : ' <span class="why">동일</span>'),
                  'collected_at'   => fn($s) => vg_h($s['collected_at']),
                  'received_at'    => fn($s) => '<span class="why">' . vg_h($s['received_at']) . '</span>',
                  'package_count'  => fn($s) => number_format((int) $s['package_count']),
                  'exposure_count' => fn($s) => number_format((int) $s['exposure_count']),
                  'peak_rss_mb'    => fn($s) => vg_resource_mem($s['peak_rss_mb']),
                  'cpu_seconds'    => fn($s) => vg_resource_cpu($s['cpu_seconds']),
                  'agent_version'  => fn($s) => $s['agent_version'] ? '<code>' . vg_h($s['agent_version']) . '</code>' : '<span class="why">–</span>',
                  'sev' => fn($s) => vg_sev_counts($sevByScan[(int) $s['scan_id']] ?? []),
              ],
          ]
      );
      ?>
      </div>
    </div>
    <?php vg_page_nav($total, $perPage, $page); ?>

    <?php
    /* 위 표와 같은 회차들을 추이로 — 표는 회차별 절대치(MB·초), 차트는 호스트 스펙 대비 비율이다.
     *   비율이 필요한 이유: 512MB 짜리 노드의 40MB 와 64GB 노드의 40MB 는 같은 숫자지만 다른 부담이다.
     *   표가 페이지네이션돼도 차트는 최근 구간 전체를 본다(별도 조회). */
    $latestResourceScan = $resourceScans ? end($resourceScans) : null;
    ?>
    <div class="card mt-lg">
      <strong>에이전트 리소스 사용률</strong>
      <?php if ($latestResourceScan): ?>
        <span class="why">현재
          <?= $latestResourceScan['mem_pct'] !== null ? '메모리 ' . vg_resource_pct($latestResourceScan['mem_pct']) : '메모리 –' ?> ·
          <?= $latestResourceScan['cpu_pct'] !== null ? 'CPU ' . vg_resource_pct($latestResourceScan['cpu_pct']) : 'CPU –' ?>
        </span>
      <?php endif; ?>
      <div class="card__body">
      <?php
      /* 메모리와 CPU 를 **한 차트에** 둔다 — 둘 다 단위가 %(호스트 스펙 대비 사용률)라
       *   같은 축에 얹어도 값이 서로 거짓말을 하지 않는다. 단위가 다른 지표였다면 이중축이
       *   아니라 차트를 둘로 갈랐을 것이다(이중축은 눈금 두 개를 겹쳐 놓고 관계가 있는 것처럼
       *   보이게 한다). 축은 0~100 으로 고정한다: 관측 구간으로 자동 확대하면 0.6% 도 차트
       *   꼭대기에 붙어 실제 부하가 큰 것처럼 보인다(예전 SVG 차트가 그래서 절대 축이었다).
       * 값이 없는(구버전 에이전트) 스캔은 그 계열에서 **건너뛴다** — 0 으로 이으면 실제로
       *   없는 급락이 된다. 선은 vg_multi_trend() 가 spanGaps 로 이어 준다. */
      $resLabel = static fn(array $s): string => date('n/j H:i', strtotime((string) $s['collected_at']));
      $resSeries = [];
      foreach (['mem_pct' => '메모리', 'cpu_pct' => 'CPU'] as $field => $name) {
          $pts = [];
          foreach ($resourceScans as $rs) {
              if ($rs[$field] === null || $rs[$field] === '') { continue; }
              $pts[] = ['d' => $resLabel($rs), 'v' => round((float) $rs[$field], 1)];
          }
          if ($pts) { $resSeries[] = ['name' => $name, 'points' => $pts]; }
      }
      vg_multi_trend($resSeries, [
          'unit'  => '%',
          'y_max' => 100,
          'alt'   => '에이전트 메모리·CPU 사용률 추이',
          'empty' => [
              'icon'  => 'chart',
              'title' => '그래프를 그리기엔 수집 이력이 부족합니다.',
              'hint'  => '메모리·CPU 값이 있는 수집이 2건 이상 쌓이면 여기에 추이가 표시됩니다.',
          ],
      ]);
      ?>
      </div>
    </div>
