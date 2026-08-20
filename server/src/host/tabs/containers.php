<?php
declare(strict_types=1);
/* 컨테이너 탭 — 호스트 아래 컨테이너를 계층 카드로. */ ?>
    <?php vg_toolbar([
        ['type' => 'search', 'name' => 'q', 'placeholder' => '컨테이너·이미지·네임스페이스 검색', 'value' => $q],
        ['type' => 'hidden', 'name' => 'tab', 'value' => $tab],
        ['type' => 'hidden', 'name' => 'id', 'value' => (string) $hostId],
    ]); ?>
    <?php
    /* 표가 아니라 **계층**으로 그린다.
     *   컨테이너는 "호스트에 딸린 행 6개"가 아니라 그 안에 자기 OS·패키지·프로세스·취약점을
     *   가진 별개 자산이다. 표 6열로는 그게 안 보여서, 운영자가 컨테이너 안을 볼 수 있다는
     *   사실 자체를 몰랐다(드릴다운 링크가 아예 없었다).
     *   루트(호스트) 한 줄 아래에 컨테이너 카드를 늘어놓고, 카드마다 이미지·OS·패키지 수와
     *   **심각도 분포 미니 게이지**를 얹어 "어느 컨테이너부터 열어야 하나"를 한눈에 준다.
     *   표에 있던 값(k8s 위치·다이제스트·SBOM 해시·상태)은 하나도 버리지 않고 카드로 옮겼다 —
     *   같은 행을 표와 카드로 두 번 그리지 않기 위해 표를 대체한다.
     *   JS·차트 라이브러리는 쓰지 않는다(CSP·오프라인 배포). 전부 CSS 와 게이지 폭 계산뿐이다. */
    // 런타임 상태 톤 — dead 만 위험으로 올린다(멈춘 컨테이너는 위험이 아니라 사실).
    $stateTone = ['running' => 'ok', 'restarting' => 'med', 'dead' => 'high'];
    // 심각도 높은 컨테이너부터 보여준다 — 정렬은 SQL 단(vg_host_load_containers_tab, LIMIT/OFFSET 전)
    // 에서 전수 기준으로 이미 끝났다. 여기서 다시 정렬하면 이 페이지 안에서만 재배열되어
    // 뒷페이지에 남은 CRITICAL 을 못 끌어오므로, 이 뷰는 받은 순서를 그대로 그린다.
    ?>
    <div class="card">
      <strong>컨테이너</strong>
      <span class="why"> · 최신 수집 기준 <?= number_format($containerTotal) ?>개 · 컨테이너는 호스트와 OS 가 다를 수 있습니다</span>
      <div class="card__body">
        <?php if (!$rows): ?>
          <?php vg_empty($hasFilter
              ? [
                  'icon' => 'search',
                  'title' => '검색 조건에 맞는 컨테이너가 없습니다.',
                  'cta' => ['href' => vg_qs(['q' => null, 'page' => null]), 'label' => '검색 초기화'],
              ]
              : '수집된 컨테이너가 없습니다.'); ?>
        <?php else: ?>
        <div class="ctree">
          <?php /* 루트 = 호스트 자신. 컨테이너가 "무엇 위에 떠 있는지"를 화면에서 잃지 않게 한다. */ ?>
          <div class="ctree__root">
            <span class="ctree__icon" aria-hidden="true">🖥️</span>
            <div class="ctree__rootid">
              <strong><?= vg_h((string) $host['fqdn']) ?></strong>
              <span class="why"><?= vg_h(trim($host['os_id'] . ' ' . $host['os_version'])) ?: 'OS 미상' ?>
                · 호스트 패키지 <?= number_format($packageTotal) ?>개</span>
            </div>
            <span class="badge tone-muted">컨테이너 <?= number_format($containerTotal) ?></span>
          </div>
          <ul class="ctree__list">
          <?php foreach ($rows as $c):
              $ctrId  = (int) $c['container_id'];
              $sev    = $sevByContainer[$ctrId] ?? [];
              $sevSum = array_sum($sev);
              // 카드 톤은 그 컨테이너의 최고 등급이다 — 취약점이 없으면 색을 가져가지 않는다.
              $ctrWorst = null;
              foreach (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as $s) {
                  if (($sev[$s] ?? 0) > 0) { $ctrWorst = $s; break; }
              }
              $href = '/container.php?id=' . (int) $hostId . '&cid=' . urlencode((string) $c['cid']);
              $os   = trim((string) ($c['os_id'] ?? '') . ' ' . (string) ($c['os_version'] ?? ''));
              $rState = (string) ($c['runtime_state'] ?? '');
              $k8s  = array_filter(
                  [$c['k8s_namespace'] ?? null, $c['k8s_pod'] ?? null, $c['k8s_container'] ?? null],
                  fn($v) => (string) $v !== ''
              );
          ?>
            <li class="ctrcard tone-<?= $ctrWorst !== null ? vg_h(vg_sev_tone($ctrWorst)) : 'muted' ?>">
              <div class="ctrcard__head">
                <div class="ctrcard__title">
                  <a class="ctrcard__name" href="<?= vg_h($href) ?>"><?= vg_h((string) $c['cid']) ?></a>
                  <?php if (!empty($c['name']) && (string) $c['name'] !== (string) $c['cid']): ?>
                    <span class="why"><?= vg_h((string) $c['name']) ?></span>
                  <?php endif; ?>
                </div>
                <div class="ctrcard__badges">
                  <?php if ($rState !== ''): ?><?= vg_badge($rState, $stateTone[$rState] ?? 'muted') ?><?php endif; ?>
                </div>
              </div>

              <?php /* 1차 정보: 이 카드에서 가장 먼저 봐야 하는 한 가지 — 심각도.
               * 게이지 폭(width:N%)은 vg_sev_bar() 가 계산한다(인라인 style 예외). */ ?>
              <div class="ctrcard__risk">
                <?php if ($sevSum > 0): ?>
                  <?= vg_sev_bar($sev) ?>
                  <div class="legend--inline">
                    <?php foreach (['CRITICAL' => 'crit', 'HIGH' => 'high', 'MEDIUM' => 'med', 'LOW' => 'low'] as $s => $tone): ?>
                      <?php if (($sev[$s] ?? 0) > 0): ?>
                        <span class="why"><?= vg_h($s) ?><span class="n"><?= number_format($sev[$s]) ?></span></span>
                      <?php endif; ?>
                    <?php endforeach; ?>
                  </div>
                <?php else: ?>
                  <span class="why">판정된 취약점 없음</span>
                <?php endif; ?>
              </div>

              <?php /* 2차 정보: 이미지·OS·k8s·다이제스트·SBOM — 카드 정체성엔 필요하지만
               * 심각도만큼 매번 볼 필요는 없다. 기본 접힘, 지우지 않고 펼치면 그대로 다 보인다. */ ?>
              <details class="ctrcard__detail">
                <summary>이미지 · 패키지 <?= number_format((int) $c['pkg_count']) ?>개</summary>
                <div class="ctrcard__image">
                  <?= ((string) ($c['image'] ?? '')) !== ''
                        ? '<code>' . vg_h((string) $c['image']) . '</code>'
                        : '<span class="why">이미지 미상</span>' ?>
                </div>

                <div class="ctrcard__facts">
                  <span><?= $os !== '' ? vg_h($os) : '<span class="why">OS 미상</span>' ?></span>
                  <span><?= !empty($c['manager'])
                          ? '<code>' . vg_h((string) $c['manager']) . '</code>'
                          : '<span class="why">패키지 DB 없음</span>' ?></span>
                </div>

                <?php if ($k8s || !empty($c['workload_ref']) || !empty($c['image_digest']) || !empty($c['sbom_hash'])): ?>
                  <div class="ctrcard__more">
                    <?php if ($k8s): ?><span class="why">k8s <?= vg_h(implode(' / ', $k8s)) ?></span><?php endif; ?>
                    <?php if (!empty($c['workload_ref'])): ?><span class="why">워크로드 <?= vg_h((string) $c['workload_ref']) ?></span><?php endif; ?>
                    <?php if (!empty($c['image_digest'])): ?><span class="why"><?= vg_trunc((string) $c['image_digest'], 24) ?></span><?php endif; ?>
                    <?php if (!empty($c['sbom_format']) || !empty($c['sbom_hash'])): ?>
                      <span class="why">SBOM <?= vg_h((string) ($c['sbom_format'] ?? '')) ?> <?= vg_trunc((string) ($c['sbom_hash'] ?? ''), 20) ?></span>
                    <?php endif; ?>
                  </div>
                <?php endif; ?>
              </details>

              <div class="links">
                <a href="<?= vg_h($href) ?>">상세 열기 →</a>
                <a href="<?= vg_h($href . '&tab=packages') ?>">패키지</a>
                <a href="<?= vg_h($href . '&tab=runtime') ?>">런타임</a>
              </div>
            </li>
          <?php endforeach; ?>
          </ul>
        </div>
        <?php endif; ?>
      </div>
    </div>
    <?php vg_page_nav($total, $perPage, $page); ?>

