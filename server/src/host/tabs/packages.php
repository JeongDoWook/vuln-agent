<?php
declare(strict_types=1);
/* 설치 패키지 탭 — 패키지 무결성(관측) + 호스트 OS 패키지 목록. */ ?>
    <?php /* SBOM 은 더 이상 자기 카드를 갖지 않는다 — '부품표 보기' 버튼 하나 때문에 카드가
             탭 맨 위를 차지했다. 이 탭이 보여주는 패키지 목록 자체를 표준 포맷으로 내보내는
             것이라, 그 목록의 액션 줄(아래 '설치 패키지')이 제자리다.
             CycloneDX/SPDX 다운로드 버튼은 화면에서 내렸다(감사 제출 같은 실사용 요구가 없다).
             엔드포인트 sbom.php?format=… 는 그대로 살아 있다 — 화면만 정리한 것이다. */ ?>
    <?php vg_toolbar([
        ['type' => 'search', 'name' => 'q', 'placeholder' => '패키지명·소스·출처 검색', 'value' => $q],
        ['type' => 'hidden', 'name' => 'tab', 'value' => $tab],
        ['type' => 'hidden', 'name' => 'id', 'value' => (string) $hostId],
    ]); ?>
    <?php
    // ── 패키지 무결성(관측) ─────────────────────────────────────────────
    //   "미수행"과 "0건"을 절대 합치지 않는다 — 합치면 검사도 안 한 자산이 "정상"으로 보인다.
    //   어휘도 단정하지 않는다: 운영자가 직접 고친 파일일 수 있으므로 "변조됨"이 아니라
    //   "패키지 원본과 다름(관측)" 이다(nofix.php 의 EOL 표현과 같은 원칙).
    $integChecked = !empty($scan['integrity_checked']);
    $integTotal   = (int) ($scan['integrity_total'] ?? 0);
    $integPartial = !empty($scan['integrity_partial']);
    if (!$integChecked) {
        // 미수행일 때는 설명 대신 켜는 자리로 데려간다 — 이 탭의 단독 버튼은 없앴다(무결성은
        //   별도 스캔이 아니라 수집 실행 안의 한 단계라, 진입점이 수집 제어 하나로 모였다).
        $integTone = 'muted';
        $integText = '';
    } elseif ($integTotal === 0) {
        $integTone = 'ok';
        $integText = '패키지 원본과 다른 파일이 관측되지 않았습니다.';
    } else {
        $integTone = 'high';
        $integText = '패키지 원본과 다른 파일 ' . number_format($integTotal) . '건이 관측되었습니다. '
            . '운영자가 직접 바꾼 파일일 수도 있어 변조로 단정하지 않습니다.';
    }
    // 이미 무결성 포함 명령이 큐에 있으면 그 사실을 알린다 — 수 분짜리 부하를 거는 동작이라
    //   같은 자산에 두 번 걸지 않게 한다(중복 등록 자체는 서버가 막지 않는다).
    $verifyQueued = false;
    foreach ($pendingCommands as $pc) {
        if (!empty($pc['verify_files'])) { $verifyQueued = true; break; }
    }
    // 검사 결과에는 "언제 것인지"가 붙어야 한다 — 무결성 값은 최신 스캔(tb_scan)에 실려 오므로
    //   그 수집 시각이 곧 검사 시각이다. 없는 값을 만들지 않는다(미수행이면 붙일 시각도 없다).
    $integAt = $integChecked ? (string) ($scan['collected_at'] ?? '') : '';
    ?>
    <div class="card">
      <strong>패키지 무결성</strong>
      <?= vg_badge($integChecked ? ($integTotal === 0 ? '정상' : '원본과 다름 ' . number_format($integTotal) . '건') : '미수행', $integTone) ?>
      <?php if ($integPartial): ?><?= vg_badge('부분 결과', 'med', '제한시간·줄수 상한으로 잘렸습니다. 0건이 "깨끗함"을 뜻하지 않습니다.') ?><?php endif; ?>
      <?php if ($integAt !== ''): ?><span class="why" title="<?= vg_h($integAt) ?>"> · <?= vg_h(substr($integAt, 0, 16)) ?> 검사</span><?php endif; ?>
      <?php if ($integText !== ''): ?><span class="why"> · <?= vg_h($integText) ?></span><?php endif; ?>
      <?php if ($integPartial): ?>
        <span class="why"> · 검사가 도중에 잘렸습니다 — 아래 목록과 건수는 전수가 아닙니다.</span>
      <?php endif; ?>
      <?php /* 실행 진입점은 이 탭이 아니라 이 페이지 위쪽의 수집 제어다 — '지금 스캔' 의
               '무결성 검사 포함' 체크박스 하나로 합쳤다. 여기서는 상태만 말하고, 어디서
               켜는지 모르는 상태로 두지 않도록 그 카드로 가는 앵커만 남긴다(버튼 아님).
               앵커 대상(#agent-control)은 assets 권한이 있을 때만 그려지므로 같은 조건을 쓴다. */ ?>
      <?php if ($verifyQueued): ?>
        <span class="why"> · 무결성 검사 대기 중 — 다음 수집 결과에 반영됩니다.</span>
      <?php elseif (!$integChecked && vg_can('assets')): ?>
        <span class="why"> · <a href="#agent-control">수집 제어</a> 의 '지금 스캔' 에서 '무결성 검사 포함' 을 켜면 다음 수집에 함께 돕니다.</span>
      <?php endif; ?>
      <?php if ($integrityRows): ?>
        <div class="card__body">
        <?php
        vg_table(
            [
                ['label' => '파일', 'key' => 'file_path', 'class' => 'col-id'],
                ['label' => '관측된 차이', 'key' => 'flags'],
                ['label' => '패키지', 'key' => 'package_name'],
            ],
            $integrityRows,
            [
                'card' => false,
                'cell' => [
                    'file_path' => fn($r) => '<code>' . vg_h((string) $r['file_path']) . '</code>',
                    'flags' => fn($r) => vg_h(vg_integrity_flag_label((string) $r['flags']))
                        . ' <span class="why">' . vg_h((string) $r['flags']) . '</span>',
                    'package_name' => fn($r) => ($r['package_name'] ?? '') !== ''
                        ? vg_h((string) $r['package_name'])
                        : '<span class="why">미상</span>',
                ],
            ]
        );
        ?>
        </div>
        <?php if ($integTotal > count($integrityRows)): ?>
          <span class="why">상위 <?= count($integrityRows) ?>건만 표시합니다(전체 <?= number_format($integTotal) ?>건).</span>
        <?php endif; ?>
      <?php endif; ?>
    </div>

    <div class="card">
      <strong>설치 패키지</strong>
      <span class="why"> · 최신 수집 기준 호스트 운영체제 패키지 <?= number_format($packageTotal) ?>개</span>
      <div class="actions">
      <?php vg_sbom_view_button((string) $host['fqdn']); ?>
      <?php if ($depEdgeTotal > 0): ?>
        <?php /* 이제 '의존성' 탭이 있으므로 전용 화면이 아니라 그 탭으로 보낸다 — 자산 상세를
                 벗어나지 않는다. 버튼은 늘리지 않고 **라벨에 엣지 수를 담아** "이 자산엔 볼 게
                 있다"를 여기서 알린다(엣지가 0인 자산에는 탭도 이 버튼도 서지 않는다). */ ?>
        <a class="btn btn--sm btn--ghost" href="<?= vg_h(vg_qs(['tab' => 'depgraph', 'page' => null, 'q' => null])) ?>"
           title="이 자산의 패키지 의존성 트리"><?= vg_icon('chart') ?>의존성 엣지 <?= number_format($depEdgeTotal) ?>개</a>
      <?php endif; ?>
      <?php /* 전체 설치 패키지(asset-packages.php)는 자산을 고르지 않으면 함대 전체가 한 표에 쏟아진다 —
               이 자산으로 필터한 링크를 주 진입점으로 둔다(화면 자체는 전역 검색용으로 남는다). */ ?>
        <a class="btn btn--sm btn--ghost" href="/asset-packages.php?host=<?= (int) $hostId ?>" title="다른 자산과 나란히 보기(전체 설치 패키지)"><?= vg_icon('host') ?>다른 자산과 비교</a>
      </div>
      <div class="card__body">
      <?php
      vg_table(
          [
              ['label' => '패키지', 'key' => 'name', 'class' => 'col-id'],
              ['label' => '설치 버전', 'key' => 'version'],
              ['label' => '아키텍처', 'key' => 'arch'],
              ['label' => '관리자', 'key' => 'manager'],
              ['label' => '소스 패키지', 'key' => 'source_pkg'],
              ['label' => '출처', 'key' => 'origin'],
          ],
          $rows,
          [
              'card' => false,
              'empty' => $hasFilter
                  ? [
                      'icon' => 'search',
                      'title' => '검색 조건에 맞는 설치 패키지가 없습니다.',
                      'cta' => ['href' => vg_qs(['q' => null, 'page' => null]), 'label' => '검색 초기화'],
                  ]
                  : [
                      'icon' => 'package',
                      'title' => '수집된 운영체제 패키지가 없습니다.',
                  ],
              'cell' => [
                  'name' => fn($p) => '<strong>' . vg_h((string)$p['name']) . '</strong>',
                  'version' => fn($p) => '<code>' . vg_h((string)($p['version'] ?? '')) . '</code>',
                  'arch' => fn($p) => $p['arch'] ? vg_h((string)$p['arch']) : '<span class="why">–</span>',
                  'manager' => fn($p) => '<code>' . vg_h((string)$p['manager']) . '</code>',
                  'source_pkg' => function ($p) {
                      if (empty($p['source_pkg'])) { return '<span class="why">–</span>'; }
                      return vg_h((string)$p['source_pkg'])
                          . (!empty($p['source_version']) ? ' <span class="why">' . vg_h((string)$p['source_version']) . '</span>' : '');
                  },
                  'origin' => fn($p) => $p['origin']
                      ? vg_h((string)$p['origin'])
                      : (!empty($p['vendor']) ? vg_h((string)$p['vendor']) : '<span class="why">–</span>'),
              ],
          ]
      );
      ?>
      </div>
    </div>
    <?php vg_page_nav($total, $perPage, $page); ?>
