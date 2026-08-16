<?php
declare(strict_types=1);
/* 영향 패키지 섹션 — 이 CVE 의 전역 영향 범위. 페이저는 apage/aper_page 다(#278). */
?>
<section id="affected">
  <div class="card">
    <strong>영향 패키지</strong>
    <span class="why">— 이 CVE 의 전역 영향 범위(설치 여부 무관)</span>
    <div class="card__body">
    <?php
    vg_table(
        [
            ['label' => '생태계', 'key' => 'ecosystem', 'width' => '10rem'],
            ['label' => '패키지', 'key' => 'package_name'],
            ['label' => '수정 버전', 'width' => '16rem'],
        ],
        $affected,
        [
            'card'  => false,
            'empty' => [
                'icon'  => '📦',
                'title' => '영향 패키지 정보가 없습니다.',
                'hint'  => '피드(OSV·NVD)가 이 CVE 의 패키지 범위를 아직 안 알려준 경우입니다.',
            ],
            'cell' => [
                'package_name' => function ($a) {
                    $name = (string) ($a['package_name'] ?? '');
                    $eco = (string) ($a['ecosystem'] ?? '');
                    if ($name === '' || $eco === '') { return vg_h($name); }
                    return '<a href="/package.php?name=' . urlencode($name) . '&amp;eco=' . urlencode($eco) . '">'
                         . vg_h($name) . '</a>';
                },
                2 => fn($a) => !empty($a['fixed_version'])
                    ? vg_badge((string) $a['fixed_version'] . ' 이상', 'muted')
                    : '<span class="why">수정 버전 미공개</span>',
            ],
        ]
    );
    if ($affected) { vg_page_nav($affectedTotal, $aPerPage, $aPage, 'apage', 'aper_page'); }
    ?>
    </div>
  </div>
</section>
