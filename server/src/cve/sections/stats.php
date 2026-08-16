<?php
declare(strict_types=1);
/* 핵심 지표 — CVSS·EPSS·KEV·CWE·공개일·영향 자산. CVE 자체가 아직 수집되지 않았으면
   지표 대신 그 사실만 알린다(빈 칸 일곱 개는 잡음이다). */
?>
<?php if ($cve === null): ?>
  <div class="card">
    <?php vg_empty([
        'icon'  => '📭',
        'title' => '이 CVE 는 아직 수집되지 않았습니다.',
        'hint'  => 'NVD 커넥터가 수집한 뒤 다시 확인하세요.',
    ]); ?>
  </div>
<?php else: ?>
<div class="card">
  <strong>핵심 지표</strong>
  <div class="card__body stat-grid">
    <div class="stat">
      <?php if ($cvss !== null): ?>
        <div class="score tone-<?= vg_h($tone) ?>"><?= vg_h((string) $cvss) ?><small> / 10</small></div>
        <?= vg_meter($tone, (float) $cvss * 10, 'CVSS 기본점수 ' . $cvss . ' / 10') ?>
      <?php else: ?>
        <span class="stat__val"><span class="why">–</span></span>
      <?php endif; ?>
      <div class="why">CVSS 기본점수</div>
    </div>

    <div class="stat">
      <span class="stat__val"><?= vg_epss_cell($cve['epss'] ?? null, $cve['epss_percentile'] ?? null) ?></span>
      <div class="why">EPSS(악용확률)</div>
    </div>

    <div class="stat">
      <span class="stat__val">
        <?= $kev ? vg_badge('등재됨', 'crit', '실제 악용이 확인된 취약점') : vg_badge('미등재', 'muted') ?>
      </span>
      <div class="why">CISA KEV</div>
    </div>

    <?php if ($kev && $due !== null && $due !== ''): ?>
      <div class="stat">
        <span class="stat__val <?= $overdue ? 'is-danger' : '' ?>"><?= vg_h((string) $due) ?></span>
        <div class="why"><?= $overdue ? vg_h(abs($dLeft) . '일 초과') : vg_h('D-' . $dLeft) ?> · CISA 연방기관 조치 기준일</div>
      </div>
    <?php endif; ?>

    <div class="stat">
      <span class="stat__val"><?= !empty($cve['cwe']) ? vg_h((string) $cve['cwe']) : '<span class="why">–</span>' ?></span>
      <div class="why">CWE 유형</div>
    </div>

    <div class="stat">
      <span class="stat__val"><?= $cve['published'] ? vg_h((string) $cve['published']) : '<span class="why">–</span>' ?></span>
      <div class="why">공개일</div>
    </div>

    <div class="stat">
      <span class="stat__val"><?= number_format($assetTotal) ?>대</span>
      <div class="why">영향 자산<?= $locTotal > $assetTotal ? ' · 발견 ' . number_format($locTotal) . '건' : '' ?></div>
    </div>
  </div>
</div>
<?php endif; ?>
