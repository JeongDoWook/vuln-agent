<?php
declare(strict_types=1);
/* 억제 보기 — 백포트 등으로 억제된 취약점과 그 근거 원 데이터.
   탭이 아니라 '취약점' 탭의 두 번째 보기다(?tab=suppressed 는 URL 하위호환으로 살아 있다). */ ?>
    <?php vg_host_render_risk_views($tab, $vulnTotal, $suppressedCount); ?>
    <?php vg_toolbar([
        ['type' => 'search', 'name' => 'q', 'placeholder' => 'CVE 또는 패키지명 검색', 'value' => $q],
        ['type' => 'hidden', 'name' => 'tab', 'value' => $tab],
        ['type' => 'hidden', 'name' => 'id', 'value' => (string) $hostId],
    ]); ?>
    <div class="card">
      <strong>백포트로 억제된 취약점</strong>
      <?php if ($suppLayers): ?>
        <div class="card__body">
          <?php /* 어느 겹이 얼마나 걷어냈나 — 표를 읽기 전에 "왜 이만큼이 빠졌는지"가 먼저 보여야 한다. */ ?>
          <div class="badge-set">
            <?php foreach ($suppLayers as $lk => $lc):
                $meta = vg_suppress_layer_meta($lk); ?>
              <?= vg_badge($meta['label'] . ' ' . number_format($lc) . '건', $meta['tone'], $meta['desc']) ?>
            <?php endforeach; ?>
          </div>
          <p class="why">근거가 사라지면 다음 수집에서 다시 위험으로 올라옵니다.</p>
        </div>
      <?php endif; ?>
      <div class="card__body">
      <?php
      vg_table(
          [
              ['label' => '원래등급', 'key' => 'base_severity'],
              ['label' => 'CVE'],
              ['label' => '대상', 'key' => 'target'],
              ['label' => '패키지'],
              ['label' => '억제 근거'],
          ],
          $rows,
          [
              'card' => false,
              'empty' => $hasFilter
                  ? [
                      'title' => '검색 결과가 없습니다.',
                      'cta'   => ['href' => vg_qs(['q' => null, 'page' => null]), 'label' => '검색 초기화'],
                  ]
                  : '억제된 취약점이 없습니다.',
              'row_class' => fn($r) => vg_sev_row((string) $r['base_severity']),
              'cell' => [
                  'base_severity' => fn($r) => vg_sev_badge((string) $r['base_severity'])
                      . ((int) $r['in_kev'] === 1 ? ' ' . vg_badge('KEV', 'crit') : ''),
                  1 => fn($r) => '<strong><a href="/cve.php?cve=' . urlencode($r['cve_id']) . '">' . vg_h($r['cve_id']) . '</a></strong>',
                  3 => fn($r) => vg_h($r['package_name']) . ' <span class="why">' . vg_h($r['installed_version']) . '</span>',
                  /* 근거 칸은 세 층이다: 어느 겹인가(뱃지) → 그 겹이 왜 억제하나(한 줄) →
                   *   접으면 그 겹의 **원 데이터**(errata·changelog 행, 트래커에 남은 CVE 수).
                   *   원 데이터가 있어야 "이 판정을 믿을지" 를 사람이 스스로 확인할 수 있다. */
                  4 => function ($r) use ($suppEvidence) {
                      $meta = vg_suppress_layer_meta((string) $r['layer']);
                      $key = (string) $r['package_name'] . '|' . (string) $r['cve_id'];
                      $raw = [];
                      if (isset($suppEvidence['errata'][$key])) {
                          $raw[] = 'tb_applied_errata · ' . ($suppEvidence['errata'][$key] !== ''
                              ? (string) $suppEvidence['errata'][$key] : '권고가 이 빌드를 지목함');
                      }
                      if (isset($suppEvidence['changelog'][$key])) {
                          $raw[] = 'tb_pkg_changelog_cve · ' . ($suppEvidence['changelog'][$key] !== ''
                              ? (string) $suppEvidence['changelog'][$key] : 'changelog 에 CVE 기록');
                      }
                      if (($r['layer'] ?? '') === 'tracker' && !empty($suppEvidence['debsecan'][$r['package_name']])) {
                          $raw[] = 'tb_debsecan · 같은 패키지에 아직 취약으로 남은 CVE '
                              . (int) $suppEvidence['debsecan'][$r['package_name']] . '건'
                              . ' — 판정이 실제로 수집됐다는 뜻입니다(이 CVE 만 해당 없음).';
                      }
                      $out = vg_badge($meta['label'], $meta['tone'], $meta['desc'])
                          . ' <span class="why">' . vg_trunc($r['suppress_reason'], 90) . '</span>';
                      $out .= '<details><summary>근거 상세</summary><div class="why">'
                          . vg_h($meta['desc']) . '<br>' . vg_h((string) $r['suppress_reason']);
                      foreach ($raw as $line) { $out .= '<br>' . vg_h($line); }
                      if (!$raw) {
                          $out .= '<br>' . vg_h('원 근거 행 없음 — 이 겹은 벤더 판정(' . $meta['source'] . ')으로만 성립합니다.');
                      }
                      return $out . '</div></details>';
                  },
              ],
          ]
      );
      ?>
      </div>
    </div>
    <?php vg_page_nav($total, $perPage, $page); ?>

