<?php
declare(strict_types=1);
/* 영향받는 버전 맵 — "패키지 @ 설치 버전" 별 전체 자산 수를 세그먼트 맵(segment-map.php)과
 *   같은 카드 나열 구조로 보여준다. $verMap 은 vg_cve_load_version_map() 이 페이지와 무관하게
 *   이 CVE 전체를 GROUP BY 해 준 집계 결과라 — 발견 위치 표(#locations, page/per_page)의
 *   현재 페이지만 보고 세면 같은 카드가 페이지마다 쪼개지거나 중복 등장한다.
 *   개별 자산 목록은 카드에 나열하지 않는다 — 아래 '발견 위치' 섹션이 그 상세다. */
?>
<section id="assetmap">
  <div class="card">
    <strong>영향받는 버전 맵</strong>
    <?php if ($locTotal > 0): ?>
    <div class="card__body">
      <?php foreach ($verMap as $g): ?>
        <div class="ctree">
          <div class="ctree__root">
            <span class="ctree__icon" aria-hidden="true"><?= vg_icon('package') ?></span>
            <div class="ctree__rootid">
              <strong><?= vg_h((string) $g['package_name']) ?></strong>
              <span class="why"><?= $g['installed_version'] !== '' ? '설치 버전 ' . vg_h((string) $g['installed_version']) : '버전 미상' ?></span>
            </div>
            <a class="badge tone-muted" href="#locations"><?= number_format((int) $g['host_count']) ?>대 →</a>
          </div>
        </div>
      <?php endforeach; ?>
    </div>
    <?php endif; ?>
  </div>
</section>
