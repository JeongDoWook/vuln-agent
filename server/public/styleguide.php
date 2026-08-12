<?php
declare(strict_types=1);

require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
vg_require_menu('dashboard');

vg_header('UI 디자인 시스템', 'dashboard');
vg_page_title('UI 디자인 시스템', 'SYSTEM', '공통 토큰과 판단 신호를 한 화면에서 비교합니다.');
?>
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
  <h2>KPI와 결론</h2>
  <?php vg_kpi_strip([
      ['label' => '전체 자산', 'value' => 11, 'href' => '/assets.php'],
      ['label' => 'CRITICAL', 'value' => 1, 'tone' => 'crit'],
      ['label' => 'HIGH', 'value' => '1,000', 'tone' => 'high'],
      ['label' => '미조치', 'value' => 0, 'tone' => 'crit'],
  ], ['compact' => true]); ?>
  <?php vg_verdict('crit', '외부 노출된 CRITICAL 1건을 먼저 조치하세요.', [
      ['label' => '대상 자산', 'value' => 1, 'tone' => 'crit'],
      ['label' => 'KEV', 'value' => 1, 'tone' => 'crit'],
      ['label' => '재시작', 'value' => 1, 'tone' => 'warn'],
  ]); ?>
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
      [['target' => 'deskmini-x300', 'signals' => '']],
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
      'icon' => '◇', 'title' => '조건에 맞는 결과가 없습니다.',
      'hint' => '필터를 초기화하거나 수집 상태를 확인하세요.',
      'cta' => ['href' => '/findings.php', 'label' => '전체 결과'],
  ]); ?></div>
</section>
<?php vg_footer(); ?>
