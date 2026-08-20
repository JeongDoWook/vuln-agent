<?php
declare(strict_types=1);
/* 계정 탭 — 계정 컴플라이언스 판정 + 계정 목록.
 *   host.php: vg_require_menu_any('assets','findings') 라 findings 만 있는 계정도 이 탭
 *   URL(?tab=accounts) 에 닿는다. 계정명·sudo·잠금 상태는 findings 권한 밖의 자산 인벤토리라
 *   manage.php 의 등급 카드와 같은 방식으로 여기서 한 번 더 좁힌다. */
if (!vg_can('assets')) {
    vg_alert('이 탭을 볼 권한이 없습니다.');
    return;
}
    // 판정 결과 → 톤. NA 는 회색이다 — 정상(초록)과 절대 같은 색을 쓰지 않는다.
    $accTone = ['FAIL' => 'high', 'REVIEW' => 'warn', 'PASS' => 'ok', 'NA' => 'muted'];
    $accLabel = ['FAIL' => '위반', 'REVIEW' => '검토 필요', 'PASS' => '양호', 'NA' => '판정 불가'];
    // 값이 없다(NULL)는 것과 "아니다"(0)는 다르다 — 화면에서도 구분한다.
    $accNa = '<span class="why">판정 불가</span>';
    ?>
    <div class="card">
      <strong>계정 컴플라이언스 판정</strong>
      <div class="card__body">
      <?php
      vg_table(
          [
              ['label' => '결과', 'width' => '92px'],
              ['label' => '판정 항목', 'key' => 'title'],
              ['label' => '설명'],
              ['label' => '해당 계정'],
              ['label' => '기준', 'nowrap' => true],
          ],
          $accountJudgments,
          [
              'card'  => false,
              'empty' => ['icon' => 'user', 'title' => '계정 인벤토리가 없습니다.',
                          'hint' => '구버전 에이전트가 보낸 수집입니다. 다시 수집하면 채워집니다.'],
              'cell'  => [
                  0 => fn($j) => vg_badge($accLabel[$j['result']] ?? $j['result'], $accTone[$j['result']] ?? 'muted'),
                  2 => fn($j) => '<span class="why">' . vg_h((string) $j['detail']) . '</span>',
                  3 => fn($j) => $j['names']
                        ? vg_h(vg_trunc(implode(', ', $j['names']), 90))
                        : '<span class="why">–</span>',
                  4 => fn($j) => '<span class="why">ISMS-P ' . vg_h((string) $j['isms'])
                        . '<br>N2SF ' . vg_h((string) $j['n2sf']) . '</span>',
              ],
          ]
      );
      ?>
      </div>
    </div>

    <?php vg_toolbar([
        ['type' => 'search', 'name' => 'q', 'placeholder' => '계정명·셸·홈 디렉토리 검색', 'value' => $q],
        ['type' => 'select', 'name' => 'acc', 'selected' => $accFilter, 'empty_label' => '전체 계정',
         'options' => [
             'human'  => '사람 계정(시스템 제외)',
             'sudo'   => 'sudo 권한 보유',
             'locked' => '잠긴 계정',
             'stale'  => vg_account_stale_login_days() . '일 이상 미로그인',
         ]],
        ['type' => 'hidden', 'name' => 'tab', 'value' => $tab],
        ['type' => 'hidden', 'name' => 'id', 'value' => (string) $hostId],
    ]); ?>
    <div class="card mt-lg">
      <strong>계정 목록</strong>
      <span class="why"><?= number_format($accountTotal) ?>개 · 패스워드 해시는 수집하지 않습니다</span>
      <div class="card__body">
      <?php
      vg_table(
          [
              ['label' => '계정', 'key' => 'username', 'class' => 'col-id'],
              ['label' => 'UID / GID', 'nowrap' => true],
              ['label' => '구분'],
              ['label' => '셸', 'key' => 'shell'],
              ['label' => '홈', 'key' => 'home'],
              ['label' => '마지막 로그인', 'nowrap' => true],
              ['label' => '패스워드 변경', 'nowrap' => true],
              ['label' => '만료일', 'nowrap' => true],
          ],
          $rows,
          [
              'card'  => false,
              'empty' => $hasFilter
                  ? ['icon' => 'search', 'title' => '조건에 맞는 계정이 없습니다.',
                     'cta' => ['href' => vg_qs(['q' => null, 'acc' => null, 'page' => null]), 'label' => '검색 초기화']]
                  : ['icon' => 'user', 'title' => '수집된 계정이 없습니다.',
                     'hint' => '/etc/passwd 를 수집하지 못했습니다 — 0건은 "계정 없음"이 아니라 "판정 불가"입니다.'],
              'cell' => [
                  'username' => fn($a) => '<strong>' . vg_h((string) $a['username']) . '</strong>',
                  1 => fn($a) => '<span class="why">' . vg_h((string) ($a['uid'] ?? '–'))
                        . ' / ' . vg_h((string) ($a['gid'] ?? '–')) . '</span>',
                  2 => function ($a) {
                      $b = [];
                      $b[] = (int) $a['is_system'] === 1 ? vg_badge('시스템', 'muted') : vg_badge('사용자', 'info');
                      if ($a['is_sudoer'] === null) { $b[] = vg_badge('sudo?', 'muted', 'sudoers 미수집 — 판정 불가'); }
                      elseif ((int) $a['is_sudoer'] === 1) { $b[] = vg_badge('sudo', 'warn', 'sudo 관리자 권한 보유'); }
                      if ($a['is_locked'] === null) { $b[] = vg_badge('잠금?', 'muted', '/etc/shadow 미수집 — 판정 불가'); }
                      elseif ((int) $a['is_locked'] === 1) { $b[] = vg_badge('잠김', 'low', '패스워드 로그인 불가'); }
                      return implode(' ', $b);
                  },
                  'shell' => fn($a) => '<code class="why">' . vg_h((string) ($a['shell'] ?? '')) . '</code>',
                  'home'  => fn($a) => '<span class="why">' . vg_h(vg_trunc((string) ($a['home'] ?? ''), 28)) . '</span>',
                  5 => function ($a) use ($accNa) {
                      if ($a['never_logged_in'] === null) { return $accNa; }
                      if ((int) $a['never_logged_in'] === 1) { return '<span class="why">이력 없음</span>'; }
                      $ts = strtotime((string) $a['last_login_at']);
                      $age = $ts ? (int) floor((time() - $ts) / 86400) : null;
                      $txt = vg_h(substr((string) $a['last_login_at'], 0, 16));
                      return $age !== null && $age >= vg_account_stale_login_days()
                          ? $txt . ' ' . vg_badge($age . '일', 'warn', vg_account_stale_login_days() . '일 이상 미로그인')
                          : $txt;
                  },
                  // shadow 를 못 읽었으면(is_locked 가 NULL) 정책 필드 전체가 NA 다.
                  //   읽었는데 값이 없는 것(–)과 못 읽은 것(판정 불가)은 다르다.
                  6 => function ($a) use ($accNa) {
                      if ($a['is_locked'] === null) { return $accNa; }
                      if (empty($a['pw_last_change'])) { return '<span class="why">–</span>'; }
                      return vg_h((string) $a['pw_last_change'])
                          . ($a['pw_max_days'] ? ' <span class="why">/ 최대 ' . (int) $a['pw_max_days'] . '일</span>' : '');
                  },
                  7 => function ($a) use ($accNa) {
                      if ($a['is_locked'] === null) { return $accNa; }
                      return $a['expire_date'] ? vg_h((string) $a['expire_date']) : '<span class="why">없음</span>';
                  },
              ],
          ]
      );
      ?>
      </div>
    </div>
    <?php vg_page_nav($total, $perPage, $page); ?>

