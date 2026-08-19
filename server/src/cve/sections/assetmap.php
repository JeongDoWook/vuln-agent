<?php
declare(strict_types=1);
/* 영향받는 버전 맵 — "발견 위치" 섹션과 같은 조회 결과(page/per_page 공유, #278)를
 *   세그먼트 맵(segment-map.php)과 같은 카드 나열 구조로 다시 그린다.
 *   대역(ctree__root) = 이 CVE 의 영향을 받는 "패키지 @ 설치 버전", 그 안의 카드(ctrcard) =
 *   그 버전을 설치한 자산. 새 쿼리·새 페이저 파라미터를 만들지 않고 locations 섹션이 이미
 *   불러온 $locations 를 그대로 재사용한다(기존 렌더링 흐름을 바꾸지 않는 확장). */

$verGroups = []; // "패키지@버전" => ['package'=>, 'version'=>, 'rows'=>[...]]
foreach ($locations as $l) {
    $pkg = (string) ($l['package_name'] ?? '');
    $ver = (string) ($l['installed_version'] ?? '');
    $key = $pkg . '@' . $ver;
    if (!isset($verGroups[$key])) {
        $verGroups[$key] = ['package' => $pkg, 'version' => $ver, 'rows' => []];
    }
    $verGroups[$key]['rows'][] = $l;
}
?>
<section id="assetmap">
  <div class="card">
    <strong>영향받는 버전 맵</strong>
    <span class="why"> · 이 CVE 의 영향 버전을 설치한 자산을 버전별 카드로 묶어 보여줍니다(발견 위치와 같은 목록)</span>
    <div class="card__body">
    <?php if (!$locations): ?>
      <?php vg_empty([
          'icon'  => '✅',
          'title' => '이 CVE 에 노출된 자산이 없습니다.',
          'hint'  => '최신 스캔 기준으로 영향받는 호스트가 없습니다.',
      ]); ?>
    <?php else: ?>
      <?php foreach ($verGroups as $g): ?>
        <div class="ctree">
          <div class="ctree__root">
            <span class="ctree__icon" aria-hidden="true">📦</span>
            <div class="ctree__rootid">
              <strong><?= vg_h($g['package']) ?></strong>
              <span class="why"><?= $g['version'] !== '' ? '설치 버전 ' . vg_h($g['version']) : '버전 미상' ?></span>
            </div>
            <span class="badge tone-muted"><?= number_format(count($g['rows'])) ?>대</span>
          </div>
          <ul class="ctree__list">
            <?php foreach ($g['rows'] as $l): ?>
              <li class="ctrcard tone-<?= vg_h(vg_sev_tone((string) $l['severity'])) ?>">
                <div class="ctrcard__head">
                  <a class="ctrcard__name" href="/host.php?id=<?= (int) $l['host_id'] ?>"><?= vg_h((string) $l['fqdn']) ?></a>
                  <?= vg_sev_badge((string) $l['severity']) ?>
                </div>
                <div class="ctrcard__facts">
                  <span><?= $l['ctr'] !== '' ? '컨테이너 ' . vg_h((string) $l['ctr']) : '호스트' ?></span>
                  <?= vg_status_badge($l['runtime_status']) ?>
                </div>
                <div class="links"><a href="/host.php?id=<?= (int) $l['host_id'] ?>">자산 상세 →</a></div>
              </li>
            <?php endforeach; ?>
          </ul>
        </div>
      <?php endforeach; ?>
      <?php vg_page_nav($locTotal, $perPage, $page); ?>
    <?php endif; ?>
    </div>
  </div>
</section>
