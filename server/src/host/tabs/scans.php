<?php
declare(strict_types=1);
/* 스캔 이력 탭 — 회차 표 + 같은 회차들의 에이전트 리소스 추이. */ ?>
    <div class="card">
      <strong>스캔 이력</strong> <span class="why">— 회차를 눌러 그 시점의 취약점을 본다</span>
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
                  'title' => '스캔 이력이 없습니다.',
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
      <strong>에이전트 메모리 사용률</strong>
      <span class="why">— 회차별 피크 RSS의 호스트 총 메모리 대비 %
        <?php if ($latestResourceScan && $latestResourceScan['mem_pct'] !== null): ?>
          · 현재 <?= vg_resource_pct($latestResourceScan['mem_pct']) ?>
        <?php endif; ?>
      </span>
      <div class="card__body">
      <?php vg_resource_trend($resourceScans, 'mem_pct', '%', 1, 'mem'); ?>
      </div>
    </div>

    <div class="card mt-lg">
      <strong>에이전트 CPU 사용률</strong>
      <span class="why">— 회차별 CPU 시간의 호스트 코어 용량 대비 %
        <?php if ($latestResourceScan && $latestResourceScan['cpu_pct'] !== null): ?>
          · 현재 <?= vg_resource_pct($latestResourceScan['cpu_pct']) ?>
        <?php endif; ?>
      </span>
      <div class="card__body">
      <?php vg_resource_trend($resourceScans, 'cpu_pct', '%', 1, 'cpu'); ?>
      </div>
    </div>

