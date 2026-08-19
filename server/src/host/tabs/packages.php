<?php
declare(strict_types=1);
/* 설치 패키지 탭 — 패키지 무결성(관측) + 호스트 OS 패키지 목록. */ ?>
    <?php /* SBOM 진입점 — 탭 맨 위. 예전엔 패키지 목록 페이지네이션보다도 아래에 있어
             찾으려면 목록을 끝까지 스크롤해야 했다. 부품표는 이 탭이 보여주는 패키지
             목록 자체를 표준 포맷으로 내보내는 것이라 탭 상단이 제자리다. */ ?>
    <?php vg_sbom_links((string) $host['fqdn']); ?>
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
        $integTone = 'muted';
        $integText = '미수행 — 에이전트를 --verify-files 로 실행해야 검사합니다(비용 때문에 기본 꺼짐).';
    } elseif ($integTotal === 0) {
        $integTone = 'ok';
        $integText = '패키지 원본과 다른 파일이 관측되지 않았습니다.';
    } else {
        $integTone = 'high';
        $integText = '패키지 원본과 다른 파일 ' . number_format($integTotal) . '건이 관측되었습니다. '
            . '운영자가 직접 바꾼 파일일 수도 있어 변조로 단정하지 않습니다.';
    }
    ?>
    <div class="card">
      <strong>패키지 무결성</strong>
      <?= vg_badge($integChecked ? ($integTotal === 0 ? '정상' : '원본과 다름 ' . number_format($integTotal) . '건') : '미수행', $integTone) ?>
      <?php if ($integPartial): ?><?= vg_badge('부분 결과', 'med', '제한시간·줄수 상한으로 잘렸습니다. 0건이 "깨끗함"을 뜻하지 않습니다.') ?><?php endif; ?>
      <span class="why"> · <?= vg_h($integText) ?></span>
      <?php if ($integPartial): ?>
        <span class="why"> · 검사가 도중에 잘렸습니다 — 아래 목록과 건수는 전수가 아닙니다.</span>
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
