<?php
declare(strict_types=1);

/**
 * container/overview.php — 컨테이너 상세의 머리 — "이것이 무엇이고 얼마나 위험한가".
 *   히어로(최고 위험도) → 자리 도식 → 심각도 범례 → 이미지 식별 → SBOM 링크 → 판정 불가
 *   경고 → KPI 카드. 탭 아래(표)는 container/tabs/*.php 의 몫이다.
 *
 *   여기 값은 전부 호출부가 $ctx 로 넘긴 것만 쓴다(전역을 주워 쓰지 않는다).
 */
function vg_container_render_overview(array $ctx): void {
    extract($ctx, EXTR_SKIP);

    // 최고 위험도 → 히어로 톤. 하나도 없으면 '양호'(ok) — host.php 와 같은 규칙.
    $worst = null;
    foreach (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as $s) { if ($counts[$s] > 0) { $worst = $s; break; } }
    $heroTone = $worst ? vg_sev_tone($worst) : 'ok';

    $image   = (string) ($container['image'] ?? '');
    $state   = (string) ($container['runtime_state'] ?? '');
    // 런타임 상태 톤 — dead 만 위험으로 올린다(멈춘 컨테이너는 위험이 아니라 사실).
    $stateTone = ['running' => 'ok', 'restarting' => 'med', 'dead' => 'high'];

    $meta = ['<a href="/host.php?id=' . (int) $hostId . '&amp;tab=containers">← ' . vg_h((string) $host['fqdn']) . '</a>'];
    if ($image !== '')   { $meta[] = '<code>' . vg_h($image) . '</code>'; }
    if ($state !== '')   { $meta[] = vg_badge($state, $stateTone[$state] ?? 'muted'); }
    $meta[] = $ctrOs !== '' ? vg_h($ctrOs) : 'OS 미상';
    $meta[] = !empty($container['manager'])
        ? '<code>' . vg_h((string) $container['manager']) . '</code>'
        : '<span class="why">패키지 관리자 미상</span>';
    $meta[] = '패키지 ' . number_format($packageTotal) . '개';
    $k8s = array_filter(
        [$container['k8s_namespace'] ?? null, $container['k8s_pod'] ?? null, $container['k8s_container'] ?? null],
        static fn($v) => (string) $v !== ''
    );
    if ($k8s) { $meta[] = 'k8s ' . vg_h(implode(' / ', $k8s)); }
    if (!empty($container['workload_ref'])) { $meta[] = '워크로드 ' . vg_h((string) $container['workload_ref']); }
    $meta[] = '최신 수집 ' . vg_h((string) $scan['collected_at']);

    vg_hero(vg_h((string) $container['cid']), $meta, $worst ?? '양호', $heroTone, '최고 위험도');

    ?>

<?php /* 이미지 다이제스트·SBOM 해시는 길어서 히어로 한 줄에 못 넣는다 — "이 이미지가 정확히
         무엇인가" 를 증명하는 값이라 접지 않고 자기 자리에서 통째로 보여준다(선택·복사 대상). */ ?>
<?php if (!empty($container['image_digest']) || !empty($container['sbom_hash']) || !empty($container['name'])): ?>
  <div class="card">
    <strong>이미지 식별</strong>
    <div class="card__body">
      <dl class="kv">
        <?php if (!empty($container['name']) && (string) $container['name'] !== (string) $container['cid']): ?>
          <dt>컨테이너 이름</dt><dd><?= vg_h((string) $container['name']) ?></dd>
        <?php endif; ?>
        <?php if ($image !== ''): ?>
          <dt>이미지</dt><dd class="selectable"><?= vg_h($image) ?></dd>
        <?php endif; ?>
        <?php if (!empty($container['image_digest'])): ?>
          <dt>다이제스트</dt><dd class="selectable"><?= vg_h((string) $container['image_digest']) ?></dd>
        <?php endif; ?>
        <?php if (!empty($container['sbom_format']) || !empty($container['sbom_hash'])): ?>
          <dt>수집 SBOM</dt>
          <dd class="selectable">
            <?= vg_h(trim((string) ($container['sbom_format'] ?? '') . ' ' . (string) ($container['sbom_hash'] ?? ''))) ?>
          </dd>
        <?php endif; ?>
      </dl>
    </div>
  </div>
<?php endif; ?>

<?php
    // 이 컨테이너의 부품표. 호스트 SBOM 과 범위를 섞지 않는다(sbom.php 머리주석).
    vg_sbom_links((string) $host['fqdn'], (string) $container['cid']);

    // 취약점 0건이 "안전"으로 읽히면 안 되는 컨테이너는 그 이유를 화면에 적는다.
    if ($unjudgeable !== null) {
        vg_alert([
            'type'  => 'warn',
            'title' => '이 컨테이너는 취약점 매칭이 수행되지 않습니다 — 0건은 "안전함"이 아니라 "판정 불가"입니다',
            'hints' => [$unjudgeable],
        ]);
    }

    /* 지표 줄은 카드 격자를 손으로 짜지 않고 vg_kpi_strip() 에 맡긴다 — 같은 KPI 를 그리는
     *   화면(kisa-u.php 등)과 간격·톤·0값 처리(kpi--zero) 규칙을 한 곳에서 공유한다.
     *   여기는 항목을 나열하는 격자가 아니라 이 컨테이너의 **요약 지표**라 표로 바꾸지 않는다. */
    $kpis = [];
    foreach (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as $s) {
        $kpis[] = ['value' => number_format((int) $counts[$s]), 'label' => $s, 'tone' => vg_sev_tone($s)];
    }
    $kpis[] = ['value' => number_format($kevCount), 'label' => 'KEV 악용확인',
               'tone'  => $kevCount > 0 ? 'crit' : 'muted',
               'title' => 'KEV — 실제 악용이 확인된 취약점(CISA Known Exploited Vulnerabilities)'];
    $kpis[] = ['value' => number_format($externalFindings), 'label' => '외부노출 취약점',
               'tone'  => $externalFindings > 0 ? 'crit' : 'ok',
               'title' => '이 컨테이너에서 밖으로 열린 포트를 통해 닿는 취약점'];
    $kpis[] = ['value' => number_format($packageTotal), 'label' => '설치 패키지'];
    $kpis[] = ['value' => number_format($exposureCount), 'label' => '노출 소켓'];
    vg_kpi_strip($kpis, ['compact' => true]);
}
