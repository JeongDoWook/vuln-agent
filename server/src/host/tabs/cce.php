<?php
declare(strict_types=1);
/* 보안 설정 탭 — CCE 점검 결과 목록. 결과·점검 항목·코드 세 열만 세운다.
 *
 *   여섯 열(결과·점검 항목·코드·참조 매핑·근거·사유)이던 자리다. 걷어낸 셋은 **목록에서
 *   읽을 값이 아니다** — 한 행이 세 줄씩 차지해 정작 "무엇이 FAIL 인가" 가 안 읽혔다.
 *   지우는 게 아니라 제자리로 내린다:
 *     · 참조 매핑(SSG 룰 · CIS/NIST/STIG) → 코드 링크가 여는 **점검 항목 상세**(cce-rule.php).
 *       그 화면이 기준 매핑의 정본이고, 목록은 같은 값을 배지로 다시 늘어놓고 있었다.
 *     · 근거(evidence) · 사유(rationale) → 점검 항목 칸의 **툴팁**. 이 둘은 자산·회차마다
 *       다른 값이라 점검 항목 상세가 가질 수 없다(그 화면은 룰 하나를 설명한다).
 *
 *   ⚠ 참조 매핑 열은 **HTML 이 그대로 새고 있었다** — vg_badge() 는 라벨을 이스케이프하는데
 *     거기에 vg_trunc()(말줄임 <span> 을 돌려주는 함수)를 넣어서, 화면에
 *     `NIST <span class="trunc" title=…>` 문자열이 글자로 보였다. 그 열을 걷어내며 함께
 *     사라졌다 — 두 함수를 겹쳐 쓰지 않는다(하나는 텍스트를, 하나는 마크업을 돌려준다). */ ?>
    <?php vg_toolbar([
        ['type' => 'search', 'name' => 'q', 'placeholder' => '코드·점검항목·SSG 룰 검색', 'value' => $q],
        ['type' => 'hidden', 'name' => 'tab', 'value' => $tab],
        ['type' => 'hidden', 'name' => 'id', 'value' => (string) $hostId],
    ]); ?>
    <div class="card">
      <strong>보안 설정 점검 (CCE)</strong>
      <span class="why"> · 코드를 누르면 그 점검의 기준 매핑(CIS·NIST·STIG)을 봅니다</span>
      <div class="card__body">
      <?php
      // 결과 → 톤: FAIL 은 위험도색, PASS 는 low(초록), NA 는 muted.
      $cceBadge = function (array $r): string {
          $tone = $r['result'] === 'FAIL' ? vg_sev_tone($r['severity'])
                : ($r['result'] === 'PASS' ? 'low' : 'muted');
          return vg_badge($r['result'], $tone);
      };
      /* 점검 항목 — 이 자산에서 나온 근거·사유를 툴팁으로 달고 다닌다(원문 그대로, 안 자른다).
       *   목록에 펼치면 한 행이 세 줄이 되고, 버리면 "왜 이 결과인가" 를 어디서도 못 읽는다. */
      $cceTitle = static function (array $r): string {
          $tip = [];
          if (($r['evidence'] ?? '') !== '')  { $tip[] = '근거 · ' . (string) $r['evidence']; }
          if (($r['rationale'] ?? '') !== '') { $tip[] = '사유 · ' . (string) $r['rationale']; }
          $title = (string) $r['title'];
          return $tip
              ? '<span class="trunc" title="' . vg_h(implode("\n", $tip)) . '">' . vg_h($title) . '</span>'
              : vg_h($title);
      };

      vg_table(
          [
              ['label' => '결과', 'width' => '6rem', 'nowrap' => true],
              ['label' => '점검 항목', 'key' => 'title'],
              ['label' => '코드', 'key' => 'code', 'width' => '30%', 'class' => 'col-id'],
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
                  0 => $cceBadge,
                  1 => $cceTitle,
                  // 코드가 곧 상세로 가는 문이다 — 참조 매핑·조치 안내는 그 화면이 갖는다.
                  2 => fn(array $r): string => '<a href="/cce-rule.php?code=' . urlencode((string) $r['code'])
                      . '"><code>' . vg_h((string) $r['code']) . '</code></a>',
              ],
          ]
      );
      ?>
      </div>
    </div>
    <?php vg_page_nav($total, $perPage, $page); ?>
