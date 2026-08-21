<?php
declare(strict_types=1);
/* 발견 위치 섹션 — 실제 설치가 확인된 자리(호스트별 최신 수집 기준).
   이 섹션만 기본 이름(page/per_page)을 쓴다 — 셋 중 먼저 있었고, 기존 호출부 20여 개가
   그 이름으로 들어온다(#278). 다른 두 섹션이 vpage/apage 로 비켜난 이유가 이것이다.

   ★ 이 표가 답하는 질문은 "이 CVE 가 우리 자산 중 **어디**에 있나 · 무엇으로 올려야 하나" 다.
     '수집일' 열을 걷은 이유가 그것이다 — 날짜는 그 판단에 안 쓰이는데 열 하나를 통째로 먹었다.
     지운 게 아니라 호스트 링크의 툴팁으로 내렸고, 회차별 정본은 그 호스트 상세의 '수집 이력'
     탭이 갖는다. '위치' 열은 값이 섞였을 때만 세운다(전 행이 같은 값이면 정보량이 0이다). */
$locNote = '호스트별 최신 수집 기준';
if ($locations) {
    $placeNote = vg_place_note((bool) $locMixed, (string) $locations[0]['ctr']);
    if ($placeNote !== '') { $locNote .= ' · ' . $placeNote; }
}
$locHeaders = [['label' => '호스트', 'key' => 'fqdn']];
if ($locMixed) {
    // nowrap 이 없으면 '호스트' 석 자가 '호스'/'트' 로 접힌다 — 이 표는 폭이 고정된
    //   목록 표와 달리 auto 레이아웃이라, 옆의 긴 열들이 폭을 가져가면 이 칸이 두 글자까지
    //   눌린다(실측 1440px). 세 글자짜리 값이 두 줄이 되면 행 높이만 늘고 읽히지도 않는다.
    $locHeaders[] = ['label' => '위치', 'key' => 'ctr', 'nowrap' => true];
}
// 열이 조건부라 칸 콜백은 **인덱스가 아니라 key** 로 건다 — 인덱스로 걸면 '위치' 열이 빠지는
//   순간 그 뒤 칸이 통째로 한 칸씩 밀린다.
$locHeaders = array_merge($locHeaders, [
    ['label' => '등급', 'key' => 'severity', 'width' => '6rem'],
    ['label' => '상태', 'key' => 'runtime_status', 'width' => '7rem'],
    ['label' => '패키지', 'key' => 'package_name'],
    ['label' => '현재 → 권장 조치', 'key' => 'fix', 'width' => '19rem'],
]);
?>
<section id="locations">
  <div class="card">
    <strong>이 CVE 가 발견된 위치</strong>
    <span class="why"> · <?= vg_h($locNote) ?></span>
    <div class="card__body">
    <?php
    vg_table(
        $locHeaders,
        $locations,
        [
            'card'  => false,
            'empty' => [
                'icon'  => '✅',
                'title' => '이 CVE 에 노출된 자산이 없습니다.',
                'hint'  => '최신 수집 기준으로 영향받는 호스트가 없습니다.',
            ],
            'row_class' => fn($l) => vg_sev_row((string) $l['severity']),
            'cell' => [
                // 걷어낸 '수집일' 이 여기로 온다 — 이 행이 어느 회차 수집인지는 호스트에 붙은 사실이다.
                'fqdn' => fn($l) => '<a href="/host.php?id=' . (int) $l['host_id']
                    . '" title="' . vg_h('수집 ' . (string) $l['collected_at']) . '">'
                    . vg_h($l['fqdn']) . '</a>',
                // 같은 호스트가 여러 줄로 반복되는 이유를 밝힌다 — 호스트냐 그 안의 컨테이너냐.
                'ctr'            => fn($l) => vg_place_cell((string) $l['ctr']),
                'severity'       => fn($l) => vg_sev_badge((string) $l['severity']),
                'runtime_status' => fn($l) => vg_status_badge($l['runtime_status']),
                'fix' => function ($l) use ($cve) {
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
            ],
        ]
    );
    if ($locations) { vg_page_nav($locTotal, $perPage, $page); }
    ?>
    </div>
  </div>
</section>
