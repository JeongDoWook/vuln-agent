<?php
declare(strict_types=1);
/* 런타임 탭 — 재시작 필요(억제 취소 신호) + 노출 소켓 + 실행 프로세스. */ ?>
    <?php vg_toolbar([
        ['type' => 'search', 'name' => 'q', 'placeholder' => '프로세스명·사용자·실행패키지 검색', 'value' => $q],
        ['type' => 'hidden', 'name' => 'tab', 'value' => $tab],
        ['type' => 'hidden', 'name' => 'id', 'value' => (string) $hostId],
    ]); ?>
    <?php
    // ── 재시작 필요(억제 취소 신호) ────────────────────────────────────────
    //   패치는 끝났는데 프로세스가 옛 .so 를 메모리에 물고 있으면 **여전히 취약**하다.
    //   오탐이 아니라 미탐 쪽이라(대시보드엔 "패치됨"으로 보인다) 억제 근거보다 세게 말한다.
    //   0건을 '깨끗함'으로 쓰지 않는다 — 이 목록은 실행 프로세스 수집에서 나오므로,
    //   그 단계가 없으면 "재시작 필요 없음"이 아니라 "알 수 없음"이다(NA ≠ PASS).
    $staleCollected = !in_array('runtime_processes', $missingStageCodes, true);
    $staleTotal = (int) ($staleLibs['total'] ?? 0);
    if (!$staleCollected) {
        $staleTone = 'muted';
        $staleText = '실행 프로세스를 수집하지 못해 재시작 필요 여부를 판정할 수 없습니다(0건이 "없음"이 아닙니다).';
        $staleLabel = '판정 불가';
    } elseif ($staleTotal === 0) {
        $staleTone = 'ok';
        $staleText = '옛 라이브러리를 물고 있는 프로세스가 관측되지 않았습니다.';
        $staleLabel = '해당 없음';
    } else {
        $staleTone = 'high';
        $staleText = '패치는 적용됐지만 아래 프로세스가 교체 전 라이브러리를 아직 메모리에 물고 있습니다. '
            . '조치는 업데이트가 아니라 재시작이며, 그동안 이 취약점은 억제되지 않습니다.';
        $staleLabel = '재시작 필요 ' . number_format($staleTotal) . '건';
    }
    ?>
    <div class="card">
      <strong>재시작 필요 (억제 취소 신호)</strong>
      <?= vg_badge($staleLabel, $staleTone) ?>
      <span class="why"> · <?= vg_h($staleText) ?></span>
      <?php if ($staleLibs['rows']): ?>
        <div class="card__body">
        <?php
        vg_table(
            [
                ['label' => '프로세스', 'key' => 'comm', 'class' => 'col-id'],
                ['label' => '패키지', 'key' => 'package_name'],
                ['label' => '옛 라이브러리'],
                ['label' => '조치'],
            ],
            $staleLibs['rows'],
            [
                'card' => false,
                'cell' => [
                    'comm' => fn($s) => '<strong>' . vg_h((string) ($s['comm'] ?? '?')) . '</strong>'
                        . ' <span class="why">PID ' . (int) $s['sample_pid']
                        . ((int) $s['procs'] > 1 ? ' 외 ' . ((int) $s['procs'] - 1) . '개' : '') . '</span>',
                    2 => fn($s) => '<code>' . vg_trunc((string) ($s['sample_lib'] ?? ''), 60) . '</code>'
                        . ((int) $s['libs'] > 1 ? ' <span class="why">외 ' . ((int) $s['libs'] - 1) . '개</span>' : ''),
                    3 => fn($s) => '<span class="why">해당 서비스 재시작(또는 재부팅)</span>',
                ],
            ]
        );
        ?>
        </div>
        <?php if ($staleTotal > count($staleLibs['rows'])): ?>
          <span class="why">상위 <?= count($staleLibs['rows']) ?>건만 표시합니다(전체 <?= number_format($staleTotal) ?>건).</span>
        <?php endif; ?>
        <span class="why"> · 해당 취약점은 <a href="<?= vg_h(vg_qs(['tab' => 'vuln', 'page' => null, 'q' => null])) ?>">취약점 탭의 "재시작·재부팅" 표</a>에 그대로 남아 있습니다.</span>
      <?php endif; ?>
    </div>

    <div class="card mt-lg">
      <strong>런타임 노출</strong>
      <div class="card__body">
      <?php
      vg_table(
          [
              ['label' => '범위'],
              ['label' => '위치'],
              ['label' => '프로세스', 'key' => 'proc'],
              ['label' => '포트'],
              ['label' => '실행패키지', 'key' => 'exe_pkg'],
              ['label' => '로드한 패키지'],
          ],
          $exposures,
          [
              'card' => false,
              'empty' => $hasFilter
                  ? [
                      'title' => '검색 결과가 없습니다.',
                      'cta'   => ['href' => vg_qs(['q' => null, 'page' => null, 'epage' => null]), 'label' => '검색 초기화'],
                  ]
                  : '리스닝 소켓이 없습니다(외부·내부 포함).',
              'cell' => [
                  0 => fn($e) => vg_badge(vg_scope_label((string) $e['scope']), $scopeTone[$e['scope']] ?? 'muted'),
                  1 => fn($e) => $e['ctr'] !== ''
                        ? '<span class="why">컨테이너 ' . vg_h($e['ctr']) . '</span>'
                        : '<span class="why">호스트</span>',
                  3 => fn($e) => vg_h($e['proto']) . '/' . (int) $e['port'],
                  5 => fn($e) => '<span class="why">' . vg_trunc($e['loaded_pkgs'], 60) . '</span>',
              ],
          ]
      );
      ?>
      </div>
    </div>
    <?php vg_page_nav($exposureTotal, $perPage, $ePage, 'epage'); ?>

    <div class="card mt-lg">
      <strong>실행 프로세스</strong>
      <div class="card__body">
      <?php
      vg_table(
          [
              ['label' => 'PID'],
              ['label' => '위치'],
              ['label' => '프로세스', 'key' => 'comm'],
              ['label' => '사용자'],
              ['label' => '실행 패키지', 'key' => 'exe_pkg'],
              ['label' => '로드한 패키지'],
          ],
          $rows,
          [
              'card' => false,
              'empty' => $hasFilter
                  ? [
                      'title' => '검색 결과가 없습니다.',
                      'cta'   => ['href' => vg_qs(['q' => null, 'page' => null, 'epage' => null]), 'label' => '검색 초기화'],
                  ]
                  : [
                      'icon'  => '🗂️',
                      'title' => '실행 프로세스 데이터가 없습니다.',
                      'hint'  => '구버전 에이전트로 수집된 스캔입니다.',
                  ],
              'cell' => [
                  0 => fn($pr) => '<span class="why">' . (int) $pr['pid'] . '</span>',
                  1 => fn($pr) => $pr['ctr'] !== ''
                        ? '<span class="why">컨테이너 ' . vg_h($pr['ctr']) . '</span>'
                        : '<span class="why">호스트</span>',
                  3 => fn($pr) => '<span class="why">' . vg_h($pr['username']) . '</span>',
                  5 => fn($pr) => '<span class="why">' . vg_trunc($pr['loaded_pkgs'], 60) . '</span>',
              ],
          ]
      );
      ?>
      </div>
    </div>
    <?php vg_page_nav($total, $perPage, $page); ?>

