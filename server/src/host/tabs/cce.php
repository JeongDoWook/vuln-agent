<?php
declare(strict_types=1);
/* 보안 설정 탭 — CCE 점검 결과와 그 기준(SSG 룰 · CIS/NIST/STIG). */ ?>
    <?php vg_toolbar([
        ['type' => 'search', 'name' => 'q', 'placeholder' => '코드·점검항목·SSG 룰 검색', 'value' => $q],
        ['type' => 'hidden', 'name' => 'tab', 'value' => $tab],
        ['type' => 'hidden', 'name' => 'id', 'value' => (string) $hostId],
    ]); ?>
    <div class="card">
      <strong>보안 설정 점검 (CCE)</strong>
      <div class="card__body">
      <?php
      // 결과 → 톤: FAIL 은 위험도색, PASS 는 low(초록), NA 는 muted.
      $cceBadge = function (array $r): string {
          $tone = $r['result'] === 'FAIL' ? vg_sev_tone($r['severity'])
                : ($r['result'] === 'PASS' ? 'low' : 'muted');
          return vg_badge($r['result'], $tone);
      };
      // 기준 배지 — 이 점검이 **어느 룰셋의 어느 항목**에 근거하는지 보여준다.
      //   예전엔 우리가 정한 코드(CCE-SSH-ROOT)만 있어서 "왜 이게 기준인가" 를 답할 수 없었다.
      //   이제 SSG 룰에 묶여 있고, 그 룰이 CIS·NIST·STIG 참조를 들고 있다.
      $refBadges = static function (array $r): string {
          if (empty($r['ssg_rule_id'])) {
              return '<span class="why">자체 기준(대응 SSG 룰 없음)</span>';
          }
          $refs = vg_json_col($r['refs_json'] ?? '');
          $html = '';
          foreach ($refs as $k => $v) {
              // 기관 기준만 보여준다 — cis-csc 같은 상위 카테고리는 항목 번호가 아니라 생략.
              if (strncmp((string) $k, 'cis@', 4) === 0) {
                  $html .= ' ' . vg_badge('CIS ' . $v, 'info', 'CIS 벤치마크 ' . $k . ' 항목 ' . $v);
              } elseif ($k === 'nist') {
                  $html .= ' ' . vg_badge('NIST ' . vg_trunc((string) $v, 14), 'muted', 'NIST 800-53: ' . $v);
              } elseif ($k === 'stigid') {
                  $html .= ' ' . vg_badge('STIG', 'muted', 'DISA STIG: ' . $v);
              }
          }
          $ruleId = (string) $r['ssg_rule_id'];
          $rule = '<a href="/compliance_rule.php?rule=' . urlencode($ruleId) . '">'
              . '<code class="why">' . vg_h($ruleId) . '</code></a>';
          return $rule . ($html !== '' ? '<br>' . $html : '');
      };

      vg_table(
          [
              ['label' => '결과', 'key' => 'result'],
              ['label' => '점검 항목', 'key' => 'title'],
              ['label' => '코드', 'key' => 'code'],
              ['label' => '기준(SSG 룰 · CIS/NIST)'],
              ['label' => '근거'],
              ['label' => '사유'],
          ],
          $rows,
          [
              'card' => false,
              'empty' => $hasFilter
                  ? [
                      'title' => '검색 결과가 없습니다.',
                      'cta'   => ['href' => vg_qs(['q' => null, 'page' => null]), 'label' => '검색 초기화'],
                  ]
                  : [
                      'icon'  => '🗂️',
                      'title' => 'CCE 점검 데이터가 없습니다.',
                      'hint'  => '구버전 에이전트 또는 security/users 미수집입니다.',
                  ],
              'cell' => [
                  'result' => $cceBadge,
                  'code'   => fn($r) => '<code>' . vg_h($r['code']) . '</code>',
                  3 => $refBadges,
                  4 => fn($r) => '<span class="why">' . vg_trunc($r['evidence'], 40) . '</span>',
                  5 => fn($r) => '<span class="why">' . vg_trunc($r['rationale']) . '</span>',
              ],
          ]
      );
      ?>
      </div>
    </div>
    <?php vg_page_nav($total, $perPage, $page); ?>

