<?php
declare(strict_types=1);

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
vg_require_menu('dashboard');

vg_header('UI 디자인 시스템', 'dashboard');
vg_page_title('UI 디자인 시스템', 'SYSTEM');
?>
<section class="styleguide-section">
  <h2>아이콘</h2>
  <div class="icon-grid">
    <?php foreach (array_keys(VG_ICON_PATHS) as $name): ?>
      <span class="icon-cell"><?= vg_icon($name) ?><?= vg_h($name) ?></span>
    <?php endforeach; ?>
  </div>
</section>

<section class="styleguide-section">
  <h2>범례</h2>
  <?php vg_legend([
      ['label' => 'CRITICAL', 'tone' => 'crit', 'n' => 1],
      ['label' => 'HIGH', 'tone' => 'high', 'n' => 12],
      ['label' => 'MEDIUM', 'tone' => 'med', 'n' => 40],
      ['label' => 'LOW', 'tone' => 'low', 'n' => 1204],
  ], ['inline' => true, 'caption' => '심각도']); ?>
  <?php vg_legend([
      ['label' => vg_scope_label('EXTERNAL'), 'tone' => 'crit'],
      ['label' => vg_scope_label('LAN'), 'tone' => 'med'],
      ['label' => vg_scope_label('BOUND'), 'tone' => 'purple'],
      ['label' => vg_scope_label('FILTERED'), 'tone' => 'muted'],
      ['label' => vg_scope_label('LOCAL'), 'tone' => 'ok'],
  ], ['inline' => true, 'caption' => '노출 범위']); ?>
</section>

<section class="styleguide-section">
  <h2>게이지</h2>
  <?php /* vg_meter() 는 format.php 에 이미 있고 6개 화면이 공유한다 — 여기서는 전시만 한다. */ ?>
  <div class="token-grid">
    <?= vg_meter('crit', 98, 'CVSS 기본점수 9.8 / 10') ?>
    <?= vg_meter('high', 72, 'EPSS 72%') ?>
    <?= vg_meter('med', 41, '조치 완료율 41%') ?>
    <?= vg_meter('low', 12, '조치 완료율 12%') ?>
  </div>
</section>

<section class="styleguide-section">
  <h2>표면과 심각도</h2>
  <div class="token-grid" aria-label="색상 토큰">
    <span class="token-swatch token-swatch--surface">기본 표면</span>
    <span class="token-swatch token-swatch--raised">상승 표면</span>
    <span class="token-swatch token-swatch--sunken">내려간 표면</span>
    <span class="token-swatch tone-crit">CRITICAL</span>
    <span class="token-swatch tone-high">HIGH</span>
    <span class="token-swatch tone-med">MEDIUM</span>
    <span class="token-swatch tone-low">LOW</span>
  </div>
</section>

<section class="styleguide-section">
  <h2>숫자 스케일</h2>
  <?php /* 화면의 주인공 숫자는 이 세 단만 쓴다. rem 을 직접 쓰는 자리가 생기면 여기 표에서 고른다. */ ?>
  <div class="scale-grid">
    <div class="scale-cell scale-cell--sm">
      <b>1,204</b>
      <code>--fs-num-sm</code>
      <span>1.3rem · 보조 숫자 — 목록 위 KPI, 요약 블록</span>
    </div>
    <div class="scale-cell scale-cell--md">
      <b>1,204</b>
      <code>--fs-num</code>
      <span>1.6rem · 기본 숫자 — 대시보드 KPI, 도넛 가운데, 통계 격자</span>
    </div>
    <div class="scale-cell scale-cell--lg">
      <b>1,204</b>
      <code>--fs-num-lg</code>
      <span>2rem · 가장 큰 숫자 — 상세 사이드바 점수, 퍼널 마지막 칸</span>
    </div>
  </div>
</section>

<section class="styleguide-section">
  <h2>버튼 규격</h2>
  <?php /* 색 계열은 서열을, 크기 클래스는 자리를 말한다. 자리가 같으면 크기도 같다. */ ?>
  <?php vg_table(
      [['label' => '자리', 'key' => 'place'], ['label' => '규격', 'key' => 'spec'], ['label' => '보기', 'key' => 'demo']],
      [
          ['place' => '페이지 머리글의 주 동작', 'spec' => 'btn btn--sm btn--primary',
           'demo' => '<button type="button" class="btn btn--sm btn--primary">+ 사용자 추가</button>'],
          ['place' => '툴바의 보조 동작', 'spec' => 'btn btn--sm btn--ghost',
           'demo' => '<button type="button" class="btn btn--sm btn--ghost">초기화</button>'],
          ['place' => '중간 서열(눌러 보라고 권하는 것)', 'spec' => 'btn btn--sm btn--secondary',
           'demo' => '<button type="button" class="btn btn--sm btn--secondary">미리보기</button>'],
          ['place' => '표 행 안의 인라인 동작', 'spec' => 'btn btn--xs btn--ghost',
           'demo' => '<button type="button" class="btn btn--xs btn--ghost">이력</button>'
                   . ' <button type="button" class="btn btn--xs btn--danger">삭제</button>'],
          ['place' => '모달 푸터 · 폼 하나가 화면인 제출', 'spec' => 'btn btn--primary (크기 없음)',
           'demo' => '<button type="button" class="btn btn--ghost">취소</button>'
                   . ' <button type="button" class="btn btn--primary">저장</button>'],
      ],
      ['cell' => [
          'spec' => static fn(array $row): string => '<code>' . vg_h((string) $row['spec']) . '</code>',
          'demo' => static fn(array $row): string => (string) $row['demo'],
      ]]
  ); ?>
</section>

<section class="styleguide-section">
  <h2>카드</h2>
  <?php /* 카드 문법의 전시장 — 규약 본문은 vg_card() 주석이 갖는다(여기서 되풀이하지 않는다).
           화면마다 카드 머리를 손으로 짜던 것이 갈라짐의 원인이었으므로, 새 카드는 이 함수로 만든다. */ ?>
  <ul class="why">
    <li>한 카드 = 한 이야기. 성격이 다른 덩어리는 카드를 나누고 <code>.card-row</code> 로 한 줄에 세운다.</li>
    <li>카드에는 제목이 있다. 제목을 못 붙일 덩어리는 카드가 아니다(다른 카드 안의 요소이거나 지울 것).</li>
    <li>제목 오른쪽은 보조 수치(배지)나 조작부 자리다.</li>
    <li>예외는 하나 — <strong>화면의 주 목록 표</strong>. 그 카드의 제목은 화면 제목(h1)·탭이 이미 갖는다.</li>
  </ul>
  <div class="card-row">
    <?php vg_card('제목만', '<p class="why">가장 단순한 카드. 본문은 이야기 하나만 담는다.</p>'); ?>
    <?php vg_card('제목 + 보조 수치', '<p class="why">배지는 그 카드가 세는 모집단의 크기를 말한다.</p>',
        ['badge' => '전체 1,234건']); ?>
  </div>
</section>

<section class="styleguide-section">
  <h2>KPI</h2>
  <?php // 결론 배너(vg_verdict)는 없앴다 — 화면의 결론은 KPI·뱃지 같은 값이 말한다. ?>
  <?php vg_kpi_strip([
      ['label' => '전체 자산', 'value' => 11, 'href' => '/assets.php'],
      ['label' => 'CRITICAL', 'value' => 1, 'tone' => 'crit'],
      ['label' => 'HIGH', 'value' => '1,000', 'tone' => 'high'],
      ['label' => '미조치', 'value' => 0, 'tone' => 'crit'],
  ], ['compact' => true]); ?>
</section>

<section class="styleguide-section">
  <h2>배지와 판단 신호</h2>
  <div class="badge-set">
    <?= vg_sev_badge('CRITICAL') ?> <?= vg_sev_badge('HIGH') ?> <?= vg_sev_badge('MEDIUM') ?> <?= vg_sev_badge('LOW') ?>
    <?= vg_badge('외부 노출', 'high') ?> <?= vg_badge('KEV', 'crit') ?> <?= vg_badge('재시작', 'med') ?>
    <?= vg_badge('정상', 'ok') ?> <?= vg_badge('미제공', 'muted') ?>
  </div>
  <?php vg_signal_slots([
      'exposure' => ['value' => '외부 노출', 'tone' => 'high'],
      'exploit' => ['value' => 'KEV 등재', 'tone' => 'crit'],
      'severity' => ['value' => 'CRITICAL', 'tone' => 'crit'],
      'action' => ['value' => '재시작', 'tone' => 'med'],
  ]); ?>
  <?php vg_signal_slots([
      'exposure' => ['state' => 'na'],
      'exploit' => ['state' => 'na'],
      'severity' => ['value' => 'HIGH', 'tone' => 'high'],
      'action' => ['value' => '설정 변경', 'tone' => 'med'],
  ]); ?>
</section>

<section class="styleguide-section">
  <h2>표와 빈 상태</h2>
  <?php vg_table(
      [['label' => '대상', 'key' => 'target', 'class' => 'col-id'], ['label' => '판단 신호', 'key' => 'signals']],
      [['target' => 'web-01', 'signals' => '']],
      ['cell' => ['signals' => static fn(array $row): string => vg_capture(static function (): void {
          vg_signal_slots([
              'exposure' => ['value' => '외부 노출', 'tone' => 'high'],
              'exploit' => ['value' => 'KEV 등재', 'tone' => 'crit'],
              'severity' => ['value' => 'CRITICAL', 'tone' => 'crit'],
              'action' => ['value' => '업그레이드', 'tone' => 'med'],
          ]);
      })]]
  ); ?>
  <div class="card styleguide-empty"><?php vg_empty([
      'icon' => 'search', 'title' => '조건에 맞는 결과가 없습니다.',
      'hint' => '필터를 초기화하거나 수집 상태를 확인하세요.',
      'cta' => ['href' => '/findings.php', 'label' => '전체 결과'],
  ]); ?></div>
</section>
<?php vg_footer(); ?>
