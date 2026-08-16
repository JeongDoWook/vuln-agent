<?php
declare(strict_types=1);
/* 취약점 탭 — 이 컨테이너 안 패키지 기준 판정 결과. 페이저는 page/per_page. */
?>
  <div class="card">
    <strong>취약점</strong>
    <span class="why"> · 이 컨테이너 안에 설치된 패키지 기준 <?= number_format($vulnTotal) ?>건</span>
    <div class="card__body">
    <?php
    vg_table(
        [
            ['label' => '등급·상태', 'key' => 'severity', 'width' => '13%'],
            ['label' => 'CVE', 'nowrap' => true, 'width' => '13%'],
            ['label' => 'EPSS', 'align' => 'right', 'nowrap' => true, 'width' => '10%'],
            ['label' => '패키지', 'width' => '16%'],
            ['label' => '근거', 'width' => '28%'],
            ['label' => '조치', 'width' => '20%'],
        ],
        $rows,
        [
            'card' => false,
            // 행 강조는 등급 문자열을 받는다 — 행 배열을 그대로 넘기면 안 된다(vg_table 은 행을 준다).
            'row_class' => fn($f) => vg_sev_row((string) $f['severity']),
            'empty' => $hasFilter
                ? [
                    'icon'  => '🔍',
                    'title' => '검색 조건에 맞는 취약점이 없습니다.',
                    'cta'   => ['href' => vg_qs(['q' => null, 'page' => null]), 'label' => '검색 초기화'],
                ]
                : [
                    'icon'  => '✅',
                    'title' => '이 컨테이너에서 판정된 취약점이 없습니다.',
                    'hint'  => '설치 패키지 탭에서 실제로 무엇이 깔렸는지 확인할 수 있습니다.',
                ],
            'cell' => [
                'severity' => fn($f) => vg_sev_badge((string) $f['severity'])
                    . ' ' . vg_status_badge($f['runtime_status'])
                    . (!empty($f['in_kev']) ? ' ' . vg_badge('KEV', 'crit', '실제 악용이 확인된 취약점') : ''),
                1 => fn($f) => '<strong><a href="/cve.php?cve=' . urlencode((string) $f['cve_id']) . '">'
                    . vg_h((string) $f['cve_id']) . '</a></strong>',
                2 => fn($f) => vg_epss_cell($f['epss'], $f['epss_percentile']),
                3 => fn($f) => '<strong>' . vg_h((string) $f['package_name']) . '</strong> <code>'
                    . vg_h((string) $f['installed_version']) . '</code>'
                    . (!empty($f['needs_restart']) ? ' ' . vg_badge('재시작 필요', 'high') : ''),
                4 => fn($f) => '<span class="why">' . vg_h((string) ($f['rationale'] ?? '')) . '</span>',
                // 컨테이너의 조치는 대개 "이미지를 다시 빌드" 다 — 그래도 목표 버전은 알려준다.
                5 => fn($f) => vg_fix_cell($f['fixed_version'] ?? null, $f['ref_urls_json'] ?? null,
                                           $f['installed_version'] ?? null),
            ],
        ]
    );
    ?>
    </div>
  </div>
  <?php vg_page_nav($total, $perPage, $page); ?>
