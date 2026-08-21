<?php
/**
 * findings/tabs/exposure.php — 노출 탭(범위 카드 · 툴바 · 표).
 *   쓰는 값(findings.php 가 $ctx 로 넘긴다):
 *     $scopeCounts $scopeOptions $scope $expCveCounts $rows $total $page $perPage
 *     $scan $hostId $hostOptions $q $type
 */
?>
  <?php
  // 톤은 host.php 의 $scopeTone 과 같은 매핑이다(같은 값이 화면마다 다른 색이 되지 않게).
  $scopeTone = ['EXTERNAL' => 'crit', 'LAN' => 'med', 'BOUND' => 'med',
                'FILTERED' => 'muted', 'LOCAL' => 'muted', '-' => 'muted'];
  $scopeSegments = [];
  foreach ($scopeOptions as $sc) {
      $scopeSegments[] = [
          'label'    => vg_scope_label($sc),
          'value'    => (int) ($scopeCounts[$sc] ?? 0),
          'tone'     => $scopeTone[$sc] ?? 'muted',
          'href'     => vg_qs(['scope' => $scope === $sc ? '' : $sc, 'page' => 1]),
          'selected' => $scope === $sc,
      ];
  }
  /* CCE 탭과 같은 이유로 카드 하나 · vg_card() 하나다(탭마다 카드 문법이 갈리지 않게). */
  vg_card('노출 범위 구성', static function () use ($scopeSegments): void {
      vg_donut_kpi('노출 범위 구성', $scopeSegments, ['center_label' => '노출 전체']);
  }, ['badge' => '노출 ' . number_format(array_sum(array_column($scopeSegments, 'value'))) . '건']);
  ?>

  <?php
  $toolbar = $scan
      ? [['type' => 'hidden', 'name' => 'scan_id', 'value' => (string) $scan['scan_id']]]
      : [['type' => 'select', 'name' => 'host', 'empty_label' => '전체 호스트',
          'selected' => $hostId > 0 ? (string) $hostId : '', 'options' => $hostOptions]];
  vg_toolbar(array_merge($toolbar, [
      // 범위는 위 카드가 토글한다(같은 필터에 컨트롤을 둘 두지 않는다) — 검색 제출 시 유지되게 hidden.
      ['type' => 'hidden', 'name' => 'scope', 'value' => $scope, 'reset' => true],
      ['type' => 'search', 'name' => 'q', 'placeholder' => '프로세스 또는 실행 패키지 검색', 'value' => $q],
      ['type' => 'hidden', 'name' => 'type', 'value' => $type],
  ]));

  $hasAnyFilter = $q !== '' || $scope !== '';
  if (!$hostOptions) {
      $emptySpec = [
          'icon'  => 'host',
          'title' => '아직 수집 이력이 없습니다.',
          'hint'  => '에이전트가 자산을 최소 한 번은 수집해야 이 화면에 노출이 뜹니다.',
      ];
  } elseif ($hasAnyFilter) {
      $emptySpec = [
          'icon'  => 'search',
          'title' => '조건에 맞는 리스닝 소켓이 없습니다.',
          'hint'  => '범위 필터나 검색어를 넓혀 보세요.',
          'cta'   => ['href' => vg_qs(['q' => '', 'scope' => '', 'page' => 1]), 'label' => '필터 초기화'],
      ];
  } else {
      // 0건을 "안전" 으로 말하지 않는다 — 구버전 에이전트·수집 실패면 열린 포트가 있어도 0건이다.
      $emptySpec = [
          'icon'  => 'port',
          'title' => '수집된 네트워크 노출이 없습니다.',
          'hint'  => '에이전트가 리스닝 소켓을 수집해야 이 목록이 채워집니다 — 0건이 "열린 포트 없음"을 보장하지 않습니다.',
      ];
  }

  $headers = $scan ? [] : [['label' => '호스트', 'key' => 'fqdn', 'width' => '17%', 'class' => 'col-id']];
  // 노출 근거(범위)가 이 탭의 판정 축이다 — CVE 탭의 '상태' 칸과 같은 자리다. 다만 카드로
  //   한 범위를 고른 뷰에서는 전 행이 그 값이라 열을 세우지 않는다(무엇을 골랐는지는 카드의
  //   선택 표시가 말한다). 카드를 다시 눌러 선택을 풀면 값이 섞이므로 열이 돌아온다.
  if ($scope === '') {
      $headers[] = ['label' => '범위', 'key' => 'scope', 'width' => '11%', 'nowrap' => true];
  }
  $headers = array_merge($headers, [
      ['label' => '프로세스', 'key' => 'proc',  'width' => '16%', 'class' => 'col-id'],
      ['label' => '포트',   'key' => 'port',    'width' => '11%', 'nowrap' => true],
      ['label' => '실행 패키지', 'key' => 'exe_pkg', 'width' => '18%', 'class' => 'col-id'],
      ['label' => '로드한 패키지', 'key' => 'loaded_pkgs'],
  ]);

  vg_table(
      $headers,
      $rows,
      [
          'empty' => $emptySpec,
          // 외부노출 행은 CVE 표의 CRITICAL 행과 같은 강조를 준다(같은 화면에서 같은 뜻의 색).
          'row_class' => fn($r) => $r['scope'] === 'EXTERNAL' ? vg_sev_row('CRITICAL') : '',
          // 범위는 NULL 도 '-'(범위 미상)로 접어 카드·필터와 같은 값으로 다룬다.
          'cell' => [
              'fqdn' => fn($r) => '<a href="/host.php?id=' . (int) $r['host_id'] . '" title="' . vg_h($r['fqdn']) . '">' . vg_h($r['fqdn']) . '</a>',
              // 톤 매핑은 위 카드와 같은 $scopeTone 하나를 쓴다(같은 값이 카드와 표에서 다른 색이면 안 된다).
              'scope' => function ($r) use ($scopeTone) {
                  $sc = ((string) ($r['scope'] ?? '')) !== '' ? (string) $r['scope'] : '-';
                  return vg_badge(vg_scope_label($sc), $scopeTone[$sc] ?? 'muted');
              },
              // 컨테이너의 nginx 를 호스트의 nginx 로 착각하지 않게, **컨테이너일 때만** 위치를 적는다.
              //   예전엔 호스트 소켓에도 '호스트' 를 적어 dev 실측 66행 중 55행에 같은 두 글자가
              //   깔렸다 — 빈 줄이 곧 호스트다(CVE 탭의 패키지 칸이 이미 쓰는 규칙).
              'proc' => fn($r) => vg_h((string) ($r['proc'] ?? ''))
                  . ($r['ctr'] !== '' ? '<div class="why">컨테이너 ' . vg_h((string) $r['ctr']) . '</div>' : ''),
              'port' => fn($r) => vg_h((string) ($r['proto'] ?? '')) . '/' . (int) $r['port']
                  . '<div class="why">' . vg_h((string) ($r['bind_addr'] ?? '')) . '</div>',
              // 이 리스너에 걸린 CVE 건수 — 누르면 CVE 탭에서 같은 자산·같은 패키지로 좁혀 본다.
              //   노출과 취약점을 잇는 자리라 이 제품의 축이 한 줄에서 완성된다.
              'exe_pkg' => function ($r) use ($expCveCounts) {
                  $pkg = (string) ($r['exe_pkg'] ?? '');
                  if ($pkg === '') { return ''; }   // 없는 값은 '–' 로 채우지 않는다
                  $html = vg_h($pkg);
                  $n = $expCveCounts[$r['scan_id'] . '|' . $r['container_id'] . '|' . $pkg] ?? 0;
                  if ($n > 0) {
                      $href = '/findings.php?host=' . (int) $r['host_id'] . '&amp;q=' . urlencode($pkg);
                      $html .= '<div class="why"><a href="' . $href . '">CVE ' . number_format($n) . '건 →</a></div>';
                  }
                  return $html;
              },
              'loaded_pkgs' => fn($r) => '<span class="why">' . vg_trunc($r['loaded_pkgs'], 80) . '</span>',
          ],
      ]
  );
  if ($rows) { vg_page_nav($total, $perPage, $page); }
  ?>
