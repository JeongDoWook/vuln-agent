<?php
declare(strict_types=1);
/* 요약 섹션 — 설명 · 식별과 출처(값이 언제 어디서 왔나) · (등재됐으면) CISA KEV. */
?>
<section id="summary">
  <div class="card">
    <strong>요약</strong>
    <p class="why prose"><?= $cve && $cve['summary'] ? vg_h($cve['summary']) : '수집된 설명이 없습니다.' ?></p>
  </div>

  <?php if ($cve !== null): ?>
    <div class="card">
      <strong>식별과 출처</strong>
      <span class="why">— 이 화면의 값이 언제 어디서 온 것인가</span>
      <div class="card__body">
        <dl class="kv">
          <dt>CVE ID</dt><dd><code><?= vg_h($cveId) ?></code></dd>
          <dt>CWE 유형</dt>
          <dd><?= !empty($cve['cwe']) ? vg_h((string) $cve['cwe']) : '<span class="why">미수집</span>' ?></dd>
          <dt>공개일(NVD)</dt>
          <dd><?= !empty($cve['published']) ? vg_h((string) $cve['published']) : '<span class="why">–</span>' ?></dd>
          <dt>최초 수집</dt><dd><?= vg_h((string) ($cve['created_at'] ?? '–')) ?></dd>
          <dt>마지막 갱신</dt><dd><?= vg_h((string) ($cve['updated_at'] ?? '–')) ?></dd>
          <dt>EPSS 백분위</dt>
          <dd><?= $cve['epss_percentile'] !== null
              ? vg_h(number_format((float) $cve['epss_percentile'] * 100, 1)) . '% — 전체 CVE 중 이만큼보다 악용확률이 높다'
              : '<span class="why">미수집</span>' ?></dd>
          <dt>벤더 판정</dt>
          <dd><?= $vendorTotal > 0
              ? '<a href="#vendor">' . number_format($vendorTotal) . '건</a>'
              : '<span class="why">없음 — 벤더 피드에 이 CVE 가 없습니다</span>' ?></dd>
          <dt>영향 패키지</dt>
          <dd><a href="#affected"><?= number_format($affectedTotal) ?>건</a></dd>
          <dt>내 자산 노출</dt>
          <dd><?= $locTotal > 0
              ? '<a href="#locations">' . number_format($assetTotal) . '대 · 발견 ' . number_format($locTotal) . '건</a>'
              : '<span class="why">없음(최신 스캔 기준)</span>' ?></dd>
        </dl>
        <div class="actions mt">
          <?php vg_copy_btn($cveId, 'CVE ID 복사'); ?>
          <a class="btn btn--sm btn--ghost" href="/findings.php?q=<?= urlencode($cveId) ?>">취약점 현황에서 보기</a>
        </div>
      </div>
    </div>
  <?php endif; ?>

  <?php if ($kev): ?>
    <div class="card">
      <strong>CISA KEV</strong>
      <span class="why">— 실제 악용 확인 · 최우선 대응 대상</span>
      <div class="card__body">
        <dl class="kv">
          <dt>등재일</dt>
          <dd><?= !empty($kev['date_added']) ? vg_h((string) $kev['date_added']) : '<span class="why">–</span>' ?></dd>
          <dt>조치 기한</dt>
          <dd class="<?= $overdue ? 'is-danger' : '' ?>"><?= $due
              ? vg_h((string) $due) . ' · ' . vg_h($overdue ? abs($dLeft) . '일 초과' : 'D-' . $dLeft)
              : '<span class="why">–</span>' ?></dd>
          <dt>랜섬웨어 사용</dt>
          <dd><?= !empty($kev['ransomware'])
              ? vg_badge('확인됨', 'crit', '랜섬웨어 캠페인에 실제로 사용된 취약점')
              : vg_badge('알려진 바 없음', 'muted') ?></dd>
        </dl>
        <?php if (!empty($kev['note'])): ?>
          <p class="why prose"><?= vg_h((string) $kev['note']) ?></p>
        <?php endif; ?>
      </div>
    </div>
  <?php endif; ?>
</section>
