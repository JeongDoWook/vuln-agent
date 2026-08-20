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
        // 미수행일 때는 설명 대신 실행 버튼을 준다 — 예전엔 "에이전트를 --verify-files 로
        //   실행해야 합니다"라고 안내만 하고, 중앙에서 켤 방법이 없었다.
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
    // 이미 무결성 포함 명령이 큐에 있으면 버튼 대신 상태만 보여준다 — 수 분짜리 부하를 거는
    //   동작이라 같은 자산에 두 번 쌓이지 않게 한다(중복 등록 자체는 서버가 막지 않는다).
    $verifyQueued = false;
    foreach ($pendingCommands as $pc) {
        if (!empty($pc['verify_files'])) { $verifyQueued = true; break; }
    }
    ?>
    <div class="card">
      <strong>패키지 무결성</strong>
      <?= vg_badge($integChecked ? ($integTotal === 0 ? '정상' : '원본과 다름 ' . number_format($integTotal) . '건') : '미수행', $integTone) ?>
      <?php if ($integPartial): ?><?= vg_badge('부분 결과', 'med', '제한시간·줄수 상한으로 잘렸습니다. 0건이 "깨끗함"을 뜻하지 않습니다.') ?><?php endif; ?>
      <?php if ($integText !== ''): ?><span class="why"> · <?= vg_h($integText) ?></span><?php endif; ?>
      <?php if ($integPartial): ?>
        <span class="why"> · 검사가 도중에 잘렸습니다 — 아래 목록과 건수는 전수가 아닙니다.</span>
      <?php endif; ?>
      <div class="actions">
      <?php if ($verifyQueued): ?>
        <span class="why">무결성 검사 대기 중 · 다음 수집에 반영</span>
      <?php elseif (vg_can('assets')): ?>
        <?php /* 되돌리기 어려운(대상 서버에 수 분간 부하) 동작이라 확인을 붙인다 — 설명문이
                 아니라 확인이다. 인가는 화면 숨김이 아니라 host/agent_control.php 의 POST
                 분기에서 vg_can('assets') 로 서버측 확정된다. */ ?>
        <form method="post" data-confirm="무결성 검사는 모든 패키지 파일을 해시합니다. 대상 서버에 수 분간 부하가 걸립니다. 실행할까요?">
          <input type="hidden" name="csrf" value="<?= vg_h($agentCsrf) ?>">
          <input type="hidden" name="action" value="agent_run_verify">
          <input type="hidden" name="id" value="<?= (int) $hostId ?>">
          <button class="btn btn--sm btn--ghost" type="submit"><?= vg_icon('shield') ?>무결성 검사</button>
        </form>
      <?php endif; ?>
      </div>
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
        <a class="btn btn--sm btn--ghost" href="/depgraph.php?id=<?= (int) $hostId ?>" title="무엇이 이 패키지를 끌어왔나(의존성 그래프)"><?= vg_icon('chart') ?>의존성 그래프</a>
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
