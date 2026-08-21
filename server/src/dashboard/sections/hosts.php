<?php
declare(strict_types=1);

/**
 * dashboard/sections/hosts.php — 호스트별 현황 목록(위험도 높은 순) + 페이지네이션.
 *   정렬은 이미 SQL 이 했다(조회층 주석 참고) — 이 함수는 순서를 다시 만들지 않는다.
 */
function vg_dash_render_hosts(array $rows, array $sevByScan, int $total, int $perPage, int $page): void {
  // 막대의 공통 분모 — 이 목록에서 조치 대상이 가장 많은 호스트. 행마다 자기 합으로 잡으면
  //   HIGH 3뿐인 호스트와 HIGH 300인 호스트의 막대가 똑같아진다.
  $riskScale = vg_sev_bar_scale($sevByScan);
  ?>
  <div class="card">
    <strong>호스트별 현황</strong>
    <?php /* '심각도' 열의 막대는 색으로만 등급을 말한다 — 그 색이 무슨 뜻인지 이 화면 어디에도
             적혀 있지 않다. 표 바로 위에 한 줄로 둔다. */ ?>
    <?php vg_legend(array_map(
        fn(string $s): array => ['label' => $s, 'tone' => vg_sev_tone($s)],
        ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
    ), ['inline' => true, 'caption' => '심각도']); ?>
    <div class="card__body">
  <?php
  vg_table(
      [
          ['label' => '호스트'],
          ['label' => '노출', 'align' => 'right'],
          ['label' => '심각도'],
          ['label' => '수집시각', 'nowrap' => true],
          /* 링크 한 칸짜리 열도 이름을 갖는다 — 빈 머리글은 스크린리더가 읽을 게 없고,
             표에서도 열 하나가 잘려 보인다. 조작(버튼)이 아니라 이동이라 '바로가기' 다. */
          ['label' => '바로가기', 'nowrap' => true],
      ],
      $rows,
      [
          'card'  => false,
          'empty' => [
              'icon'  => 'host',
              'title' => '아직 수집 이력이 없습니다.',
              'hint'  => '에이전트를 --send 로 실행하면 여기에 나타납니다.',
          ],
          'cell' => [
              0 => fn($r) => '<strong><a href="/host.php?id=' . (int) $r['host_id'] . '">' . vg_h($r['fqdn']) . '</a></strong>',
              // OS·패키지 수는 걷었다 — "이 행을 열어볼지" 를 정하지 않는 값이고(docs/dev/ui-design-system.md
              //   §목록과 상세의 분담), 지운 게 아니라 호스트 상세(히어로의 OS · 수집 이력의 패키지 수)에 있다.
              1 => fn($r) => vg_h((string) (int) $r['exposure_count']),
              // 막대 + 숫자 뱃지 — 막대로 "누가 더 나쁜지" 를 눈이 먼저 잡고, 숫자가 확인해준다.
              //   막대는 조치 대상(C·H·M)만 그리고 이 목록에서 가장 많은 호스트를 100%로 잡는다
              //   (LOW 를 같이 쌓으면 나머지가 실오라기가 된다 — vg_sev_bar 주석). LOW 건수는
              //   옆의 등급별 뱃지가 그대로 갖는다.
              2 => function ($r) use ($sevByScan, $riskScale) {
                  $c = $sevByScan[(int) $r['scan_id']] ?? [];
                  return vg_sev_bar($c, $riskScale) . vg_sev_counts($c);
              },
              3 => fn($r) => '<span class="why">' . vg_h($r['collected_at']) . '</span>',
              4 => fn($r) => '<a href="/findings.php?scan_id=' . (int) $r['scan_id'] . '">취약점 →</a>',
          ],
      ]
  );
  if ($rows) { vg_page_nav($total, $perPage, $page); }
  ?>
    </div>
  </div>
<?php
}
