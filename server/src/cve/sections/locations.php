<?php
declare(strict_types=1);
/* 발견 위치 섹션 — 실제 설치가 확인된 자리(호스트별 최신 스캔 기준).
   이 섹션만 기본 이름(page/per_page)을 쓴다 — 셋 중 먼저 있었고, 기존 호출부 20여 개가
   그 이름으로 들어온다(#278). 다른 두 섹션이 vpage/apage 로 비켜난 이유가 이것이다. */
?>
<section id="locations">
  <div class="card">
    <strong>이 CVE 가 발견된 위치</strong>
    <div class="card__body">
    <?php
    vg_table(
        [
            ['label' => '호스트'],
            // nowrap 이 없으면 '호스트' 석 자가 '호스'/'트' 로 접힌다 — 이 표는 폭이 고정된
            //   목록 표와 달리 auto 레이아웃이라, 옆의 긴 열들이 폭을 가져가면 이 칸이 두 글자까지
            //   눌린다(실측 1440px). 세 글자짜리 값이 두 줄이 되면 행 높이만 늘고 읽히지도 않는다.
            ['label' => '위치', 'nowrap' => true],
            ['label' => '등급', 'key' => 'severity', 'width' => '6rem'],
            ['label' => '상태', 'key' => 'runtime_status', 'width' => '7rem'],
            ['label' => '패키지', 'key' => 'package_name'],
            ['label' => '현재 → 권장 조치', 'width' => '19rem'],
            ['label' => '수집일', 'nowrap' => true],
        ],
        $locations,
        [
            'card'  => false,
            'empty' => [
                'icon'  => '✅',
                'title' => '이 CVE 에 노출된 자산이 없습니다.',
                'hint'  => '최신 스캔 기준으로 영향받는 호스트가 없습니다.',
            ],
            'row_class' => fn($l) => vg_sev_row((string) $l['severity']),
            'cell' => [
                0 => fn($l) => '<a href="/host.php?id=' . (int) $l['host_id'] . '">' . vg_h($l['fqdn']) . '</a>',
                // 같은 호스트가 여러 줄로 반복되는 이유를 밝힌다 — 호스트냐 그 안의 컨테이너냐.
                1 => fn($l) => $l['ctr'] !== ''
                      ? '<span class="why">컨테이너 ' . vg_h($l['ctr']) . '</span>'
                      : '<span class="why">호스트</span>',
                'severity'       => fn($l) => vg_sev_badge((string) $l['severity']),
                'runtime_status' => fn($l) => vg_status_badge($l['runtime_status']),
                5 => function ($l) use ($cve) {
                    $installed = (string) ($l['installed_version'] ?? '');
                    if (!empty($l['needs_restart'])) {
                        $action = vg_is_kernel_code_pkg((string) ($l['package_name'] ?? ''))
                            ? '재부팅'
                            : (!empty($l['ctr']) ? '컨테이너 재시작' : '프로세스 재시작');
                        // 이건 "해야 할 일" 이라 중립이 아니라 주의 톤을 준다 — 그래도 링크는 아니다.
                        return vg_badge($action, 'warn')
                            . '<div class="why">패키지는 수정됨 · 현재 <code>' . vg_h($installed) . '</code></div>';
                    }
                    if (!empty($l['no_fix'])) {
                        return '<span class="why">수정본 미공개</span>'
                            . '<div class="why">완화·격리·제거 검토 · 현재 <code>' . vg_h($installed) . '</code></div>';
                    }
                    // 고친 버전이 있으면 여기서 그린다 — vg_fix_cell 은 그 경우에만 알약(.pill)을
                    //   쓰는데, 링크가 아닌 값이 파랗게 뜬다. 대신 조치 버전을 중립 뱃지로 두고
                    //   현재 버전을 아랫줄에 붙여 이 칸의 다른 두 갈래(재시작·미공개)와 모양을 맞춘다.
                    //   나머지 갈래(참조 링크·평문)는 알약을 만들지 않으므로 공용 헬퍼에 그대로 맡긴다.
                    $fixedVer = (string) ($l['fixed_version'] ?? '');
                    if ($fixedVer !== '') {
                        // '설치 → 고침' 한 줄은 이 칸의 계약이다(tests/smoke.sh 가 이 문자열을
                        //   그대로 확인한다) — 문구는 그대로 두고 톤만 낮춘다.
                        $plain = ($installed !== '' ? $installed . ' → ' : '') . $fixedVer . ' 이상';
                        return vg_badge($plain, 'muted', $plain);
                    }
                    return vg_fix_cell(null, $cve['ref_urls_json'] ?? null, $installed);
                },
                6 => fn($l) => '<span class="why">' . vg_h($l['collected_at']) . '</span>',
            ],
        ]
    );
    if ($locations) { vg_page_nav($locTotal, $perPage, $page); }
    ?>
    </div>
  </div>
</section>
