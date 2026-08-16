<?php
declare(strict_types=1);
/* 공격 벡터 섹션 — CVSS 벡터를 사람 말로 분해한다. */
?>
<section id="vector">
  <?php
  // CVSS 벡터 분해 — 점수 하나로는 "원격인지 로컬인지, 인증이 필요한지" 를 알 수 없다.
  $parts  = vg_cvss_vector_parts($cve['cvss_vector'] ?? null);
  $vecRaw = $cve['cvss_vector'] ?? null;
  ?>
  <?php if ($parts): ?>
    <div class="card">
      <strong>공격 벡터</strong>
      <span class="why">— 붉은 값이 공격자에게 유리한 조건이다</span>
      <div class="card__body">
        <dl class="kv">
          <?php foreach ($parts as $p): ?>
            <dt><?= vg_h($p['label']) ?></dt>
            <dd class="<?= $p['danger'] ? 'is-danger' : '' ?>"><?= vg_h($p['value']) ?></dd>
          <?php endforeach; ?>
        </dl>
        <div class="why mt"><code><?= vg_h((string) $vecRaw) ?></code></div>
      </div>
    </div>
  <?php elseif (!empty($vecRaw)): ?>
    <div class="card">
      <strong>공격 벡터</strong>
      <div class="card__body">
        <code><?= vg_h((string) $vecRaw) ?></code>
        <div class="why">해독할 수 없는 형식입니다(CVSS v2 벡터일 수 있음).</div>
      </div>
    </div>
  <?php else: ?>
    <div class="card">
      <strong>공격 벡터</strong>
      <div class="card__body">
        <div class="why">벡터 정보가 없습니다. NVD 커넥터가 다시 돌면 채워집니다.</div>
      </div>
    </div>
  <?php endif; ?>
</section>
