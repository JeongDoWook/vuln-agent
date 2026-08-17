<?php
/**
 * changes/tabs/pkg.php — '패키지 변경' 탭의 표.
 *   쓰는 값(changes.php 가 $ctx 로 넘긴다): $pkgChanges $pkgTotal $page $perPage
 */
?>
<?php /* "직전 수집과 비교" 는 화면 부제가 이미 말한다(changes.php) — 탭마다 다시 적지 않는다. */ ?>
    <?php
    vg_table(
        [
            // 변화유형 뱃지는 고정 크기다 — 9%(1110px 표에서 100px)는 '다운그레이드' 뱃지(실측
            //   136px)를 못 담아 말줄임으로 잘렸다("다운그레이…"). 값 136 + 여백 → 8.5rem.
            ['label' => '변화', 'width' => '8.5rem', 'nowrap' => true],
            ['label' => '호스트'],
            ['label' => '패키지'],
            ['label' => '버전'],
            // 취약점 변화 표와 같은 기준 — 분까지만 보이고(vg_change_when_cell) 폭은 그 값에 맞춘다.
            ['label' => '시각', 'width' => '9rem', 'nowrap' => true],
        ],
        $pkgChanges,
        [
            'empty' => [
                'icon'  => '📦',
                'title' => '아직 패키지 변경이 없습니다.',
                'hint'  => '첫 수집 이후 실제로 달라진 것이 생기면 여기에 남습니다.',
            ],
            'cell' => [
                0 => fn($r) => vg_badge(VG_PKG_CHANGE_TYPES[$r['change_type']] ?? $r['change_type'],
                                        vg_pkgchg_tone((string) $r['change_type'])),
                1 => fn($r) => '<a href="/host.php?id=' . (int) $r['host_id'] . '">' . vg_h($r['fqdn']) . '</a>',
                2 => fn($r) => vg_package_detail_link($r)
                              . ' <span class="why">' . vg_h((string) $r['manager']) . '</span>',
                3 => fn($r) => $r['old_version'] !== null && $r['new_version'] !== null
                              ? '<span class="why">' . vg_h($r['old_version']) . ' →</span> ' . vg_h($r['new_version'])
                              : vg_h((string) ($r['new_version'] ?? $r['old_version'])),
                4 => fn($r) => vg_change_when_cell($r),
            ],
        ]
    );
    if ($pkgChanges) { vg_page_nav($pkgTotal, $perPage, $page); }
