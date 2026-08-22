<?php
declare(strict_types=1);
/* 수집 이력 탭 — 회차 표 + 같은 회차들의 에이전트 리소스 추이. */ ?>
    <div class="card">
      <strong>수집 이력</strong>
      <div class="card__body">
      <?php
      /* 9열 → 6열. 이 표가 답하는 질문은 "회차마다 무엇이 얼마나 잡혔나" 이고, 나머지는 그
       *   회차에 **딸린 부기**라 각자 열을 세울 값이 아니었다(9열이면 1440px 에서도 값이 눌린다).
       *   ★ '수신시각' → '수집시각' 칸 아랫줄. 둘은 한 회차의 두 시점이라 나란히 읽어야 뜻이
       *     생긴다(수집과 수신 사이가 벌어지면 그게 곧 전송 지연이다) — 떨어진 두 열보다 가깝다.
       *   ★ '메모리'·'CPU' → '에이전트' 칸 아랫줄. 에이전트가 자기 자신을 잰 값이라 버전과 한 몸이고
       *     (버전이 바뀌면 값이 뛴다), 회차별 추이는 바로 아래 '에이전트 리소스 사용률' 카드가
       *     같은 회차들로 이미 그린다. **값은 행마다 그대로 다 남는다.** */
      vg_table(
          [
              ['label' => '실행', 'key' => 'scan_id'],
              ['label' => '수집시각', 'key' => 'collected_at', 'title' => '에이전트가 수집한 시각 · 아랫줄은 서버가 받은 시각'],
              ['label' => '패키지', 'key' => 'package_count', 'align' => 'right'],
              ['label' => '노출', 'key' => 'exposure_count', 'align' => 'right'],
              ['label' => '에이전트', 'key' => 'agent_version', 'title' => '에이전트 버전 · 아랫줄은 그 회차에 에이전트가 쓴 메모리 최대치와 CPU 시간'],
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
                  'collected_at'   => fn($s) => vg_h($s['collected_at'])
                      . '<div class="why">수신 ' . vg_h($s['received_at']) . '</div>',
                  'package_count'  => fn($s) => number_format((int) $s['package_count']),
                  'exposure_count' => fn($s) => number_format((int) $s['exposure_count']),
                  // 버전 + 그 회차의 자기계측(메모리 최대치 · CPU 시간). 값이 없는 구버전
                  //   에이전트는 두 헬퍼가 각자 '–' 를 낸다 — 0 으로 눕히지 않는다.
                  'agent_version'  => fn($s) => ($s['agent_version']
                          ? '<code>' . vg_h($s['agent_version']) . '</code>'
                          : '<span class="why">–</span>')
                      . '<div class="why">메모리 ' . vg_resource_mem($s['peak_rss_mb'])
                      . ' · CPU ' . vg_resource_cpu($s['cpu_seconds']) . '</div>',
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
      /* 메모리·CPU 둘 다 단위가 %(호스트 스펙 대비 사용률)라 같은 축에 얹어도 값이 서로
       *   거짓말을 하지 않는다 — 여기까지는 예전 vg_multi_trend() 와 같은 판단이다.
       *   **선 대신 호라이즌으로 그린다**: 둘 다 0~100 한 축에 겹쳐 그리면 값이 비슷하게
       *   움직일 때 두 선이 서로 가린다(작업지시가 지적한 문제) — 계열마다 제 줄을 갖는
       *   vg_horizon() 은 애초에 겹칠 선이 없다. 상한 100 을 그대로 준다(vg_multi_trend 의
       *   y_max=>100 과 같은 이유 — 관측 구간으로 자동 확대하면 0.6% 도 꼭대기에 붙는다).
       * 값이 없는(구버전 에이전트) 스캔은 그 계열에서 **건너뛴다** — 0 으로 이으면 실제로
       *   없는 급락이 된다(vg_horizon() 도 2점 미만인 계열은 그리지 않는다). */
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
      vg_horizon($resSeries, [
          'unit' => '%',
          'max'  => 100,
          'empty' => [
              'icon'  => 'chart',
              'title' => '그래프를 그리기엔 수집 이력이 부족합니다.',
              'hint'  => '메모리·CPU 값이 있는 수집이 2건 이상 쌓이면 여기에 추이가 표시됩니다.',
          ],
      ]);
      ?>
      </div>
    </div>
