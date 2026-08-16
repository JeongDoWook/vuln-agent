<?php
declare(strict_types=1);

/**
 * dashboard/sections/signals.php — 주요 취약점 신호 카드(KEV·노출·심각도 순 상위 N건).
 *   퍼널 3번 칸(#signals)이 이 카드로 보내므로 id 는 계약이다.
 */
function vg_dash_render_signals(array $urgent, int $urgentTotal): void {
  ?>
  <div class="card" id="signals">
    <strong>주요 취약점 신호</strong>
    <?php /* 정렬 기준과 "몇 건 중 몇 건" 이 각각 다른 why 로 붙어 제목 옆이 두 줄로 흘렀다 — 한 줄로 합친다.
             정렬 기준의 근거(KEV·노출·심각도)는 아래 [탐지 신호] 열이 행마다 다시 보여준다. */ ?>
    <span class="why">— KEV·노출·심각도 순<?php if ($urgentTotal > count($urgent)): ?>
      · 상위 <?= count($urgent) ?>건 / 총 <?= number_format($urgentTotal) ?>건 ·
      <a href="/findings.php">전체 보기 →</a><?php endif; ?></span>
    <div class="card__body">
    <?php
    vg_table(
        [
            ['label' => '등급', 'key' => 'severity', 'width' => '6rem', 'nowrap' => true],
            ['label' => 'CVE', 'width' => '13rem', 'nowrap' => true],
            ['label' => '호스트'],
            ['label' => '패키지'],
            ['label' => '탐지 신호', 'width' => '15rem'],
        ],
        $urgent,
        [
            'card'  => false,
            'empty' => [
                'icon'  => '✅',
                'title' => '급한 항목이 없습니다.',
                'hint'  => '악용이 확인됐거나 외부에 노출된 취약점이 없습니다.',
            ],
            'row_class' => fn($u) => vg_sev_row((string) $u['severity']),
            'cell' => [
                'severity' => fn($u) => vg_sev_badge((string) $u['severity']),
                1 => function ($u) {
                    $html = '<strong><a href="/cve.php?cve=' . urlencode((string) $u['cve_id']) . '">'
                          . vg_h((string) $u['cve_id']) . '</a></strong>';
                    if ($u['in_kev']) { $html .= ' ' . vg_badge('KEV', 'crit'); }
                    return $html;
                },
                2 => fn($u) => '<a href="/host.php?id=' . (int) $u['host_id'] . '">' . vg_h((string) $u['fqdn']) . '</a>',
                3 => fn($u) => vg_h((string) $u['package_name']),
                4 => function ($u) {
                    if ($u['in_kev'] && $u['runtime_status'] === 'EXTERNAL') {
                        return vg_badge('악용확인 + 외부노출', 'crit');
                    }
                    if ($u['in_kev']) {
                        return vg_badge('악용확인', 'warn') . ' ' . vg_status_badge($u['runtime_status']);
                    }
                    return vg_status_badge($u['runtime_status']);
                },
            ],
        ]
    );
    ?>
    </div>
  </div>
<?php
}
