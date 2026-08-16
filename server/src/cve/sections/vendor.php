<?php
declare(strict_types=1);
/* 벤더 판정 섹션 — 5개 소스의 패치 여부 원본. 이 섹션의 페이저는 vpage/vper_page 다
   (발견 위치의 page/per_page·영향 패키지의 apage/aper_page 와 섞이면 서로를 밀어낸다 — #278).
   그 이름은 cve.php 가 정해 $vPage/$vPerPage 로 넘긴다. */
?>
<?php if ($vendorTotal > 0): ?>
<section id="vendor">
  <div class="card">
    <strong>벤더 판정</strong>
    <span class="why">— 벤더별 패치 여부 원본(5개 소스)</span>
    <div class="card__body">
    <?php
    vg_table(
        [
            ['label' => '소스', 'width' => '11rem'],
            ['label' => '벤더/릴리스', 'width' => '12rem'],
            ['label' => '패키지'],
            ['label' => '고친 버전 / 상태'],
        ],
        $vendorRows,
        [
            'card' => false,
            'empty' => [
                'icon'  => '🏷️',
                'title' => '이 페이지에 표시할 벤더 판정이 없습니다.',
                'hint'  => '앞 페이지로 돌아가 보세요.',
            ],
            'cell' => [
                0 => function ($r) {
                    $d = VG_CVE_VENDOR_SRC[$r['src']] ?? null;
                    $label = $d !== null ? $d['label'] : (string) $r['src'];
                    // 알약(.pill)은 파란 배경 + 강조색 글자라 링크로 보인다 — 이 값들은 링크가
                    //   아니므로 중립 뱃지로 낮춘다(이 파일의 다른 세 자리도 같은 이유로 바꿨다).
                    return vg_badge($label, 'muted');
                },
                1 => fn($r) => vg_h((string) $r['vendor']) . '<span class="why">/</span>' . vg_h((string) $r['rel']),
                2 => fn($r) => '<a href="/packages.php?q=' . urlencode((string) $r['pkg']) . '">'
                             . vg_trunc((string) $r['pkg'], 32) . '</a>',
                3 => function ($r) use ($cveId) {
                    // vendor.php 와 같은 벤더 링크·툴팁 규칙(작업 1·2) — 한쪽만 반영되면 사용자가 헷갈린다.
                    $src = (string) $r['src'];
                    $tipParts = [];
                    if ($src === 'debtracker') {
                        $tipParts[] = ((int) $r['extra2']) === 1 ? '바이너리 패키지' : '소스 패키지';
                        $ov = trim((string) ($r['extra1'] ?? ''));
                        if ($ov !== '') { $tipParts[] = '예외 버전 ' . $ov; }
                    } elseif ($src === 'rhunfixed') {
                        $cvss = trim((string) ($r['extra1'] ?? ''));
                        if ($cvss !== '') { $tipParts[] = 'CVSS ' . $cvss; }
                        $checkedAt = trim((string) ($r['extra2'] ?? ''));
                        if ($checkedAt !== '') { $tipParts[] = '확인일 ' . substr($checkedAt, 0, 10); }
                    }
                    if (!empty($r['fixed'])) {
                        $body = vg_badge((string) $r['fixed'] . ' 이상', 'muted');
                    } else {
                        $state = trim((string) ($r['state'] ?? ''));
                        $body = $state !== ''
                            ? '<span class="why">' . vg_h($state) . '</span>'
                            : '<span class="why">–</span>';
                    }
                    if ($tipParts) {
                        $body .= '<div class="why">' . vg_h(implode(' · ', $tipParts)) . '</div>';
                    }

                    $link = $src === 'rhoval'
                        ? vg_vendor_advisory_url((string) $r['vendor'], (string) ($r['extra1'] ?? ''), (string) $r['rel'])
                        : (in_array($src, ['debtracker', 'ubuntuoval', 'rhunfixed'], true) ? vg_vendor_cve_url($src, $cveId) : null);
                    if ($link !== null) {
                        $body .= ' <a class="why" href="' . vg_h($link) . '" target="_blank" rel="noopener">원문 ↗</a>';
                    }
                    return $body;
                },
            ],
        ]
    );
    if ($vendorRows) { vg_page_nav($vendorTotal, $vPerPage, $vPage, 'vpage', 'vper_page'); }
    ?>
    </div>
    <div class="why mt">
      <a href="/vendor.php?q=<?= urlencode($cveId) ?>">벤더 판정 전체 보기(필터·상세) →</a>
    </div>
  </div>
</section>
<?php endif; ?>
