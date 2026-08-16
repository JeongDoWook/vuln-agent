<?php
declare(strict_types=1);

/**
 * dashboard/sections/hosts.php — 호스트별 현황 목록(위험도 높은 순) + 페이지네이션.
 *   정렬은 이미 SQL 이 했다(조회층 주석 참고) — 이 함수는 순서를 다시 만들지 않는다.
 */
function vg_dash_render_hosts(array $rows, array $sevByScan, int $total, int $perPage, int $page): void {
  ?>
  <div class="card">
    <strong>호스트별 현황</strong> <span class="why">— 위험도 높은 순 · 각 호스트의 최신 스캔 기준</span>
    <?php /* '심각도' 열의 막대는 색으로만 등급을 말한다 — 그 색이 무슨 뜻인지 이 화면 어디에도
             적혀 있지 않았다(접힌 도넛 안에만 있었다). 표 바로 위에 한 줄로 둔다. */ ?>
    <?php vg_legend(array_map(
        fn(string $s): array => ['label' => $s, 'tone' => vg_sev_tone($s)],
        ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
    ), ['inline' => true, 'caption' => '심각도']); ?>
    <div class="card__body">
  <?php
  vg_table(
      [
          ['label' => '호스트'],
          ['label' => 'OS'],
          ['label' => '패키지', 'align' => 'right'],
          ['label' => '노출', 'align' => 'right'],
          ['label' => '심각도'],
          ['label' => '수집시각', 'nowrap' => true],
          ['label' => '', 'nowrap' => true],
      ],
      $rows,
      [
          'card'  => false,
          'empty' => [
              'icon'  => '🖥️',
              'title' => '아직 수집된 스캔이 없습니다.',
              'hint'  => '에이전트를 --send 로 실행하면 여기에 나타납니다.',
          ],
          'cell' => [
              0 => fn($r) => '<strong><a href="/host.php?id=' . (int) $r['host_id'] . '">' . vg_h($r['fqdn']) . '</a></strong>',
              1 => fn($r) => vg_h($r['os_id']) . ' ' . vg_h($r['os_version']),
              2 => fn($r) => vg_h((string) (int) $r['package_count']),
              3 => fn($r) => vg_h((string) (int) $r['exposure_count']),
              // 막대 + 숫자 뱃지 — 막대로 "누가 더 나쁜지" 를 눈이 먼저 잡고, 숫자가 확인해준다.
              4 => function ($r) use ($sevByScan) {
                  $c = $sevByScan[(int) $r['scan_id']] ?? [];
                  return vg_sev_bar($c) . vg_sev_counts($c);
              },
              5 => fn($r) => '<span class="why">' . vg_h($r['collected_at']) . '</span>',
              6 => fn($r) => '<a href="/findings.php?scan_id=' . (int) $r['scan_id'] . '">취약점 →</a>',
          ],
      ]
  );
  if ($rows) { vg_page_nav($total, $perPage, $page); }
  ?>
    </div>
  </div>
<?php
}
