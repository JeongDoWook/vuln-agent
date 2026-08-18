<?php
declare(strict_types=1);
/* 취약점 탭 — 먼저 올릴 대상·같은 패키지 묶음·우선순위 표·재시작 표·상세 모달. */
    require_once __DIR__ . '/../rationale.php';   // 표에 실을 때만 근거 문장의 중복을 접는다
    // 두 표(CRITICAL·HIGH / 재시작·재부팅)는 열 구성이 같다 — 스펙을 한 번만 만들어 나눠 쓴다.
    /* 열 구성의 기준: 식별자는 절대 접지 않고(CVE-2023-6780 이 세 줄로 쪼개지던 자리),
     *   문장은 접되 뜻이 끊기지 않게 한다.
     *   - '등급'·'상태' 를 한 칸에 겹쳤다 — 둘 다 뱃지 하나짜리라 열을 따로 세울 값이 아니었고,
     *     열이 하나 줄어야 '근거' 가 문장으로 읽히는 폭을 갖는다. KEV 도 여기 붙는다.
     *   - 'width' 는 %로 준다. rem 으로 주면 나머지 한 칸(근거)이 "남은 자리"만 받아
     *     실측 1568px 에서 90px 까지 눌렸다 — 문장이 두 글자에서 끊긴다. 비율로 나누면
     *     화면이 좁아져도 근거가 문장 폭을 유지한다.
     *   - 근거는 **자르지 않고 접는다**(줄바꿈). vg_trunc(.trunc = 한 줄 nowrap · 최대 46vw)를
     *     쓰면 그 칸이 46vw 를 요구해 표가 가로로 넘치고, 밀려난 CVE 열이 하이픈마다 접혔다.
     *     .clamp-2 도 안 쓴다 — overflow:hidden 이라 이 칸의 최소폭이 0 이 되어(auto 레이아웃에서
     *     항상 지는 칸이 된다) 실측 90px 까지 눌려 두 글자에서 끊겼다. 그냥 접히게 두면
     *     max-content 가 가장 커서 남는 폭을 이 칸이 가장 많이 받는다 — 행은 높아지고 문장은 산다.
     *     (전체 문장은 행을 눌러 여는 상세 모달에도 그대로 있다.) */
    /*   - 열 키는 **문자열**로 준다(0,1,2… 가 아니라). 값이 한 종류뿐인 열('등급·상태')을 표에서
     *     빼려면 헤더 하나를 지워야 하는데, 인덱스로 묶어 두면 그 순간 나머지 칸이 한 칸씩
     *     밀린다(vg_table 은 위치로 콜백을 찾는다). 키로 묶으면 빼도 제자리에 그려진다. */
    $vulnHeaders = [
        'severity' => ['label' => '등급·상태', 'key' => 'severity', 'width' => '11%'],
        'cve'      => ['label' => 'CVE', 'key' => 'cve', 'nowrap' => true, 'width' => '12%'],
        'epss'     => ['label' => 'EPSS', 'key' => 'epss', 'align' => 'right', 'nowrap' => true, 'width' => '9%'],   // 확률(%) — advisory·package·cves 화면과 같은 정렬
        'package'  => ['label' => '패키지', 'key' => 'package', 'width' => '14%'],
        // 출처 부기(어느 피드가 그렇게 판정했나)는 46행이 통째로 반복하던 문구다 — 열 머리글에서
        //   한 번만 말하고, 원문 전체는 행을 눌러 여는 상세 모달의 '판정 근거'가 갖는다.
        'why'      => ['label' => '근거', 'key' => 'why', 'width' => '34%',
                       'title' => '등급·KEV·출처는 다른 칸과 상세 모달이 말한다 — 여기엔 이 행에만 해당하는 사실만 남긴다'],
        'fix'      => ['label' => '조치', 'key' => 'fix', 'width' => '20%'],
    ];
    $vulnCells = [
        // 등급·노출상태·KEV — 이 행이 얼마나 급한지를 한 칸에서 읽는다.
        'severity' => fn($f) => vg_sev_badge((string) $f['severity'])
                       . ' ' . vg_status_badge($f['runtime_status'])
                       . (!empty($f['in_kev']) ? ' ' . vg_badge('KEV', 'crit', '실제 악용이 확인된 취약점') : ''),
        // 이력은 열을 따로 세우지 않는다 — 뱃지 하나짜리 열이 근거 문장에서 폭을 가져갔다.
        //   같은 CVE 를 가리키는 링크라 식별자 아래가 제자리다.
        //   '이력' 글자는 걷었다(시계 아이콘이 곧 그 뜻이다). 화면에 안 보이는 사람을 위해
        //   aria-label 은 남긴다 — 아이콘만 남은 링크는 라벨이 없으면 읽히지 않는다.
        'cve' => fn($f) => '<strong><a href="/cve.php?cve=' . urlencode($f['cve_id']) . '">' . vg_h($f['cve_id']) . '</a></strong>'
                       . '<div><a class="pill" href="'
                       . vg_h(vg_finding_history_url($hostId, (int) $f['container_id'], (string) $f['cve_id'], (string) $f['package_name']))
                       . '" title="스캔별 이력 보기" aria-label="스캔별 이력 보기">🕘</a></div>',
        'epss' => fn($f) => vg_epss_cell($f['epss'], $f['epss_percentile']),
        // 패키지명과 버전은 한 줄로 눕힌다(예전엔 'libc6 2.39-' / '0ubuntu8.8' 로 접혔다).
        //   커널은 재부팅해야 새 코드가 올라온다 — 프로세스 재시작으로는 안 고쳐진다.
        'package' => fn($f) => '<strong>' . vg_h($f['package_name']) . '</strong> <code>' . vg_h($f['installed_version']) . '</code>'
                       . (!empty($f['needs_restart'])
                          ? ' ' . vg_badge(vg_is_kernel_code_pkg((string) ($f['package_name'] ?? '')) ? '재부팅 필요' : '재시작 필요', 'high')
                          : ''),
        // 등급·KEV·출처 부기는 같은 행의 다른 칸이 이미 말한다 — 표에서는 접는다(원문은 모달).
        'why' => fn($f) => '<span class="why">' . vg_h(vg_host_rationale_brief($f['rationale'] ?? null)) . '</span>',
        // 재시작/재부팅이 필요하면 조치는 "업그레이드"가 아니다(이미 패치돼 있다).
        //   전이 의존성이면 "이 버전으로 올려라"도 틀린다 — 부모가 끌어오는 것이라 혼자 못 바꾼다.
        'fix' => function ($f) use ($depOrigins, $hostId) {
            if (!empty($f['needs_restart'])) {
                return '<span class="pill">' . (vg_is_kernel_code_pkg((string) ($f['package_name'] ?? '')) ? '재부팅' : '프로세스 재시작') . '</span>';
            }
            $o = $depOrigins['origins'][vg_host_dep_key($f)] ?? null;
            if ($o !== null) { return vg_host_dep_origin_cell($o, $hostId); }
            /* 버전 조치는 이 화면에서만 평문으로 눕힌다. vg_fix_cell 의 .pill 은 nowrap 이고
             *   (app.css 소유 — 목록 화면들은 거기서 white-space:normal 로 풀어 준다)
             *   이 표는 table-layout:auto 라, 접히지 않는 한 칸이 "0:2.34-60.el9_2.3 →
             *   0:2.28-225.0.4.el8_8.6 이상" 만으로 표 폭의 38%(실측 466px)를 가져가
             *   근거 문장이 100px 로 눌렸다. 조치 문구가 접히면 그 폭이 근거로 돌아온다.
             *   조치버전이 없는 경우(참조 링크·평문)는 짧으므로 공용 헬퍼를 그대로 쓴다. */
            $fixed = (string) ($f['fixed_version'] ?? '');
            if ($fixed !== '') {
                // 목표 버전만 쓴다. '현재 <버전>' 은 같은 행의 '패키지' 칸이 이미 글자까지 똑같이
                //   갖고 있던 값이라 걷었다(설치 버전은 상세 모달에도 항목으로 있다).
                return '<strong>→ ' . vg_h($fixed) . ' 이상</strong>';
            }
            return vg_fix_cell(null, $f['ref_urls_json'] ?? null, $f['installed_version'] ?? null);
        },
    ];
    $findingRowAttrs = function (array $f) use ($hostId, $depOrigins, $findingStatuses): array {
        /* 표의 EPSS 칸과 **같은 헬퍼**를 쓴다. 예전엔 여기서만 확률+백분위를 따로 조립해
         *   같은 값이 표와 모달에서 다른 문장으로 나왔다(표는 vg_epss_cell, 여기는 인라인). */
        $epss = vg_epss_pct($f['epss'] ?? null);
        $isKernel = vg_is_kernel_code_pkg((string) ($f['package_name'] ?? ''));
        $depOrigin = $depOrigins['origins'][vg_host_dep_key($f)] ?? null;
        if (!empty($f['needs_restart'])) {
            $action = $isKernel ? '패치된 커널을 적용하려면 호스트를 재부팅하세요.' : '패치된 라이브러리를 적용하려면 관련 프로세스를 재시작하세요.';
        } elseif ($depOrigin !== null) {
            // 전이 의존성 — 이 패키지만 갈아끼우면 부모가 깨진다. 부모를 올리는 것이 조치다.
            $action = '직접 조치 불가 — ' . vg_host_dep_parent_label($depOrigin)
                    . '. 이 패키지만 바꾸면 부모가 깨집니다. 부모를 올려 안전한 자식을 끌어오게 하세요.';
        } elseif (!empty($f['fixed_version'])) {
            $action = (string) ($f['installed_version'] ?? '') . ' → ' . (string) $f['fixed_version'] . ' 이상으로 업데이트';
        } else {
            $action = '공식 패치 또는 벤더 권고를 확인하세요.';
        }
        $historyUrl = vg_finding_history_url($hostId, (int) $f['container_id'], (string) $f['cve_id'], (string) $f['package_name']);
        /* 조치 상태 — 모달의 상태 폼이 이 값으로 셀렉트를 맞추고, 저장 대상을 식별할 자연키
         *   (컨테이너 이름·CVE·패키지)를 hidden 으로 채운다. 기록이 없으면 미조치(OPEN)다. */
        $cref = (string) ($f['container_cid'] ?? '');
        $fs = $findingStatuses[vg_finding_status_key($hostId, $cref, (string) $f['cve_id'], (string) $f['package_name'])] ?? null;
        $detail = [
            'severity' => (string) $f['severity'],
            'status' => vg_status_label($f['runtime_status'] ?? null),
            'fix_status' => (string) ($fs['status'] ?? 'OPEN'),
            'fix_status_label' => vg_finding_status_label($fs['status'] ?? null),
            'fix_note' => (string) ($fs['note'] ?? ''),
            'container_ref' => $cref,
            'cve' => (string) $f['cve_id'],
            'epss' => $epss,
            'package' => (string) $f['package_name'],
            'installed' => (string) ($f['installed_version'] ?? '–'),
            'fixed' => (string) ($f['fixed_version'] ?? '–'),
            'rationale' => (string) ($f['rationale'] ?? '근거 정보가 없습니다.'),
            'action' => $action,
            'cve_url' => '/cve.php?cve=' . urlencode((string) $f['cve_id']),
            'history_url' => $historyUrl,
        ];
        return [
            'data-finding-detail' => json_encode($detail, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
            'tabindex' => '0',
            'role' => 'button',
            'aria-label' => (string) $f['cve_id'] . ' 상세 보기',
        ];
    };
    $vulnOpts = [
        'card'      => false,
        'row_class' => fn($f) => vg_sev_row((string) $f['severity']),
        'row_attrs' => $findingRowAttrs,
        'cell'      => $vulnCells,
    ];
    /* 값이 한 종류뿐인 열은 열이 아니라 한 줄이다.
     *   '우선순위 취약점' 표는 CRITICAL·HIGH 만 담는데, 실측 자산에서 46행이 전부
     *   'HIGH 외부노출' 이라 '등급·상태' 칸이 46번 같은 뱃지를 반복했다 — 열 하나가 통째로
     *   상수면 읽을 것이 없고, 그 폭은 행마다 다른 값(근거·조치)에서 가져온 것이다.
     *   **값이 섞이는 순간 다시 열로 선다**(한 종류일 때만 접는다) — 두 표에 같은 규칙을 쓴다. */
    $renderVulnTable = function (array $rows, array $opts) use ($vulnHeaders, $vulnOpts, $vulnCells): void {
        $headers  = $vulnHeaders;
        $constant = null;
        if ($rows) {
            $sev   = $vulnCells['severity'];
            $first = $sev($rows[0]);
            $same  = true;
            foreach ($rows as $r) { if ($sev($r) !== $first) { $same = false; break; } }
            if ($same) { $constant = $first; unset($headers['severity']); }
        }
        if ($constant !== null) {
            // 뱃지 HTML 은 콜백이 이미 이스케이프한 값이다(vg_table 의 셀 규약과 같다).
            echo '<div class="why">이 표 ' . number_format(count($rows)) . '행이 모두 ' . $constant . '</div>';
        }
        vg_table($headers, $rows, $vulnOpts + $opts);
    };
    // 그래프가 상한에서 잘렸으면 밝힌다 — 조용히 자르면 "전이 아님"이 사실처럼 보인다.
    if ($depOrigins['edge_truncated'] || $depOrigins['path_truncated'] || $depOrigins['finding_truncated']) {
        $depHints = [];
        if ($depOrigins['finding_truncated']) {
            $depHints[] = '집계에 쓴 취약점이 상한(' . number_format(VG_PKGDEP_ROLLUP_FINDING_MAX)
                . '건)에서 잘렸습니다 — 아래 "먼저 올릴 대상"의 건수는 전수가 아닙니다.';
        }
        if ($depOrigins['edge_truncated']) {
            $depHints[] = '엣지가 상한(' . number_format(VG_PKGDEP_EDGE_MAX) . '개)에서 잘렸습니다 — 그 뒤의 의존성은 보지 않았습니다.';
        }
        if ($depOrigins['path_truncated']) {
            $depHints[] = '경로가 상한(깊이 ' . VG_PKGDEP_DEPTH_MAX . ' · ' . VG_PKGDEP_PATH_MAX . '개)에서 끊겼습니다 — 손댈 대상이 더 있을 수 있습니다.';
        }
        $depHints[] = '전체 구조는 의존성 그래프 화면에서 확인하세요.';
        vg_alert(['type' => 'warn', 'title' => '의존성 판정이 일부만 반영됐습니다', 'hints' => $depHints]);
    }
  ?>
    <?php
    /* ── 손댈 대상(부모)별 묶음 — "이 하나를 올리면 N건" ────────────────────────
     *   행 단위로만 보면 "그래서 뭐부터 올리지?" 에 답이 안 나온다. 같은 부모가 여러
     *   취약점을 끌어오는 건 흔해서, 그 묶음을 먼저 보여주는 것이 조치 순서를 바꾼다.
     *   집계는 **스캔 전체** 기준이라 페이지를 넘겨도 값이 변하지 않는다.
     *   전이 취약점이 없으면 이 요약 자체를 그리지 않는다 — 빈 카드는 잡음이다. */
    if ($depOrigins['parents']):
        $rollupAll = $depOrigins['parents'];
        $rollupTop = array_slice($rollupAll, 0, VG_PKGDEP_ROLLUP_TOP);
        $rollupHeaders = [
            ['label' => '먼저 올릴 대상'],
            ['label' => '최고 등급', 'key' => 'severity'],
            ['label' => '해결 건수', 'align' => 'right', 'nowrap' => true],
            ['label' => '끌어오는 취약 패키지'],
        ];
        $rollupOpts = [
            'card'      => false,
            'row_class' => fn($p) => vg_sev_row((string) $p['severity']),
            'cell'      => [
                0 => fn($p) => vg_host_dep_rollup_target($p, $hostId),
                'severity' => fn($p) => vg_sev_badge((string) $p['severity']),
                2 => fn($p) => '<strong>' . number_format((int) $p['count']) . '</strong>건',
                3 => function ($p) {
                    $shown = array_slice($p['packages'], 0, VG_PKGDEP_ROLLUP_PKG_TOP);
                    $more  = count($p['packages']) - count($shown);
                    return '<span class="why">' . vg_h(implode(', ', $shown))
                        . ($more > 0 ? ' 외 ' . $more . '개' : '') . '</span>';
                },
            ],
        ];
    ?>
    <div class="card">
      <strong>먼저 올릴 대상 <span class="hint">(<?= number_format(count($rollupAll)) ?>개)</span></strong>
      <?php /* 집계 범위 같은 해설은 걷었다 — 남는 건 절단 고지(상위 몇 개만 보여주는가)뿐이다. */ ?>
      <span class="why">
        <?php if (count($rollupAll) > count($rollupTop)): ?>
          · <?= number_format(count($rollupAll)) ?>개 중 상위 <?= count($rollupTop) ?>개
        <?php endif; ?>
        · 올릴 버전은 제시하지 않는다(부모의 다른 버전이 무엇을 끌어오는지 수집된 정보로 알 수 없다)
      </span>
      <div class="card__body">
      <?php vg_table($rollupHeaders, $rollupTop, $rollupOpts); ?>
      </div>
    </div>
    <?php endif; ?>
    <?php
    /* ── 같은 패키지에서 나온 묶음 ────────────────────────────────────────────
     *   위 "먼저 올릴 대상" 은 전이 의존성이 있는 자산에만 나온다. dpkg/rpm 만 있는 자산에서는
     *   libc6 하나가 만든 CVE 다섯 건이 근거까지 사실상 같은 다섯 행으로 화면을 채운다 —
     *   같은 질문("무엇부터 올리나")에 같은 형태로 답한다.
     *   묶임이 없으면(전부 1건씩) 이 카드는 아예 그리지 않는다 — 빈 요약은 잡음이다. */
    if ($pkgRollup['rows']):
        /* '비고' 는 KEV·재시작이 섞였을 때만 값을 갖는다 — 실측에선 8행 전부 '–' 였다.
         *   빈 열은 표의 폭만 먹으므로, 붙일 뱃지가 한 행도 없으면 열 자체를 세우지 않는다. */
        $pkgRollupNote = function (array $p): string {
            $b = [];
            if (!empty($p['kev'])) { $b[] = vg_badge('KEV 포함', 'crit', '실제 악용이 확인된 취약점이 섞여 있습니다.'); }
            if (!empty($p['needs_restart'])) {
                $b[] = vg_badge(vg_is_kernel_code_pkg((string) $p['package_name']) ? '재부팅 필요 포함' : '재시작 필요 포함', 'high');
            }
            return implode(' ', $b);
        };
        $pkgRollupHasNote = false;
        foreach ($pkgRollup['rows'] as $p) {
            if ($pkgRollupNote($p) !== '') { $pkgRollupHasNote = true; break; }
        }
        $pkgRollupHeaders = [
            'pkg'      => ['label' => '먼저 올릴 패키지', 'key' => 'pkg'],
            'severity' => ['label' => '최고 등급', 'key' => 'severity', 'nowrap' => true, 'width' => '8rem'],
            'cnt'      => ['label' => '해결 건수', 'key' => 'cnt', 'align' => 'right', 'nowrap' => true, 'width' => '7rem'],
        ];
        if ($pkgRollupHasNote) { $pkgRollupHeaders['note'] = ['label' => '비고', 'key' => 'note']; }
        $pkgRollupOpts = [
            'card'      => false,
            'row_class' => fn($p) => vg_sev_row((string) $p['severity']),
            'cell'      => [
                // 패키지명 자체가 '이 패키지만 보기' 링크다 — 8행이 같은 문구를 반복할 이유가 없다.
                'pkg' => fn($p) => '<strong><a href="' . vg_h(vg_qs(['q' => (string) $p['package_name'], 'page' => null]))
                    . '" title="이 패키지의 취약점만 보기">' . vg_h((string) $p['package_name']) . '</a></strong> '
                    . '<code>' . vg_h((string) $p['installed_version']) . '</code>',
                'severity' => fn($p) => vg_sev_badge((string) $p['severity']),
                'cnt'  => fn($p) => '<strong>' . number_format((int) $p['cnt']) . '</strong>건',
                'note' => $pkgRollupNote,
            ],
        ];
    ?>
    <div class="card">
      <strong>같은 패키지에서 나온 취약점 <span class="hint">(<?= count($pkgRollup['rows']) ?>개 패키지)</span></strong>
      <span class="why">
        <?php if ($pkgRollup['truncated']): ?>
          · 묶음이 더 있습니다 — 많이 묶인 순으로 <?= count($pkgRollup['rows']) ?>개만 보여줍니다.
        <?php endif; ?>
      </span>
      <div class="card__body">
      <?php vg_table($pkgRollupHeaders, $pkgRollup['rows'], $pkgRollupOpts); ?>
      </div>
    </div>
    <?php endif; ?>
    <?php /* 억제됨은 탭이 아니라 이 탭의 보기 하나다 — 억제가 0건이면 그리지 않는다. */ ?>
    <?php vg_host_render_risk_views($tab, $vulnTotal, $suppressedCount); ?>
    <?php vg_toolbar([
        ['type' => 'search', 'name' => 'q', 'placeholder' => 'CVE 또는 패키지명 검색', 'value' => $q],
        ['type' => 'hidden', 'name' => 'tab', 'value' => $tab],
        ['type' => 'hidden', 'name' => 'id', 'value' => (string) $hostId],
    ]); ?>
    <?php
    /* 판단 신호 네 칸(노출·악용·등급·조치)은 여기서 걷었다 — 네 값 중 셋이 이 페이지가
     *   이미 말하고 있던 것과 글자까지 같았다: 노출=머리 KPI '외부노출 취약점', 악용=KPI 'KEV
     *   악용확인', 등급=히어로의 '최고 위험도'. 남은 조치 축(재시작 N건 / 업데이트 N건)도
     *   아래 두 표의 제목이 건수로 말한다. 축 자체를 없앤 게 아니라(vg_signal_slots 는
     *   cve.php 가 그대로 쓴다) 같은 화면에서 두 번 그리던 것을 한 번으로 줄인 것이다.
     *   판정 순서(노출→악용→등급→조치)는 상세 모달의 vg_decision_flow 가 계속 세운다. */
    ?>
    <?php vg_legend(array_map(
        fn(string $s): array => ['label' => $s, 'tone' => vg_sev_tone($s), 'n' => (int) $counts[$s]],
        ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
    ), ['inline' => true, 'caption' => '심각도']); ?>
    <div class="card">
      <strong>우선순위 취약점 (CRITICAL·HIGH)</strong>
      <span class="why"><a href="/findings.php?scan_id=<?= (int) $scan['scan_id'] ?>">전체 취약점 보기 →</a></span>
      <div class="card__body">
      <?php
      /* 빈 상태는 한 줄이다. 0건을 아이콘·제목·해설 세 줄로 설명하면 "없다"는 사실보다
       *   설명이 길어진다 — 다음 행동이 있는 경우(검색 초기화)만 버튼을 남긴다. */
      $renderVulnTable($rows, [
          'empty' => $hasFilter
              ? [
                  'title' => '검색 결과가 없습니다.',
                  'cta'   => ['href' => vg_qs(['q' => null, 'page' => null]), 'label' => '검색 초기화'],
              ]
              : 'CRITICAL·HIGH 가 없습니다.',
      ]);
      ?>
      </div>
    </div>
    <?php vg_page_nav($total, $perPage, $page); ?>

    <div class="card mt-lg">
      <strong>재시작·재부팅 필요 <span class="hint">(<?= number_format($restartTotal) ?>건)</span></strong>
      <span class="why">
        <?php if ($restartTotal > count($restartRows)): ?>
          · 상위 <?= count($restartRows) ?>건 ·
          <a href="/findings.php?scan_id=<?= (int) $scan['scan_id'] ?>&amp;fx=restart">전체 보기 →</a>
        <?php endif; ?>
      </span>
      <div class="card__body">
      <?php
      $renderVulnTable($restartRows, ['empty' => '재시작·재부팅이 필요한 항목이 없습니다.']);
      ?>
      </div>
    </div>

    <?php
    /* 조치 상태 변경은 **쓰기 작업**이다 — 조회(findings 메뉴)만으로는 못 한다. 자산 등급 확정이
     *   관리자 전용인 것과 같은 기준으로, 상태는 실제 조치를 굴리는 운영자까지 허용한다
     *   (자산 삭제·속도 티어와 동일). 인가는 아래 POST 분기에서 서버측으로 다시 확정한다 —
     *   여기서 폼을 숨기는 것은 화면 정리일 뿐 통제가 아니다. */
    $canFixStatus = vg_has_role('admin', 'operator');
    vg_modal_open('findingDetailModal', '취약점 상세', 'modal--wide finding-detail-modal');
    if ($canFixStatus) {
        // 폼이 모달 본문 전체를 감싼다 — 저장 버튼이 모달 푸터(오른쪽 아래)에 서야 하기 때문
        //   (vg_modal_foot 은 본문 안에서 그려진다). 대상 식별자는 JS 가 행에서 받아 채운다.
        echo '<form method="post">'
           . '<input type="hidden" name="csrf" value="' . vg_h($agentCsrf) . '">'
           . '<input type="hidden" name="action" value="finding_set_status">'
           . '<input type="hidden" name="id" value="' . (int) $hostId . '">'
           . '<input type="hidden" name="container_ref" data-finding-fix-ref value="">'
           . '<input type="hidden" name="cve_id" data-finding-fix-cve value="">'
           . '<input type="hidden" name="package_name" data-finding-fix-package value="">';
    }
    ?>
      <div class="finding-detail__summary">
        <span class="badge" data-finding-severity></span>
        <span class="badge tone-muted" data-finding-status></span>
        <strong data-finding-cve></strong>
      </div>
      <?php
      /* 판정이 어떤 순서로 이뤄졌는지를 문장 대신 네 칸으로 세운다. 각 칸은 그 근거를 직접
       *   확인할 수 있는 자리로 간다 — 상세가 "이렇게 판정했다"고 말만 하고 끝나지 않게.
       *   칸의 대상은 이 자산 단위로 고정한다(건별 링크는 아래 푸터의 [이력 보기]·[CVE 상세]가
       *   맡는다 — 그쪽은 열린 행에 맞춰 JS 가 주소를 채운다).
       *   vg_decision_flow() 자체는 건드리지 않았다. */
      vg_decision_flow([
          ['label' => '노출', 'hint' => '어느 범위로 열려 있나',
           'href' => vg_qs(['tab' => 'runtime', 'page' => null, 'q' => null])],
          ['label' => '악용', 'hint' => 'KEV 등재 · EPSS',
           'href' => '/findings.php?scan_id=' . (int) $scan['scan_id'] . '&fx=kev'],
          ['label' => '등급', 'hint' => '심각도와 판정 근거',
           'href' => vg_qs(['tab' => 'vuln', 'page' => null, 'q' => null])],
          ['label' => '조치', 'hint' => '올릴 버전 · 재시작 여부',
           'href' => '/findings.php?scan_id=' . (int) $scan['scan_id'] . '&fx=restart'],
      ]);
      ?>
      <dl class="finding-detail__grid">
        <div><dt>패키지</dt><dd data-finding-package></dd></div>
        <div><dt>설치 버전</dt><dd data-finding-installed></dd></div>
        <div><dt>조치 버전</dt><dd data-finding-fixed></dd></div>
        <div><dt>EPSS</dt><dd data-finding-epss></dd></div>
      </dl>
      <section class="finding-detail__section">
        <strong>판정 근거</strong>
        <p data-finding-rationale></p>
      </section>
      <section class="finding-detail__section">
        <strong>권장 조치</strong>
        <p data-finding-action></p>
      </section>
      <section class="finding-detail__section">
        <strong>조치 상태</strong>
        <?php if ($canFixStatus): ?>
          <div class="form-grid">
            <label class="field" for="findingFixStatus">상태
              <select id="findingFixStatus" name="status" data-finding-fix-status>
                <?php foreach (vg_finding_status_labels() as $code => $label): ?>
                  <option value="<?= vg_h($code) ?>"><?= vg_h($label . ($code === 'EXCEPTED' ? ' (메모 필수)' : '')) ?></option>
                <?php endforeach; ?>
              </select>
            </label>
            <label class="field" for="findingFixNote">메모 (예외 선택 시 필수)
              <input type="text" id="findingFixNote" name="note" data-finding-fix-note
                     maxlength="<?= VG_FINDING_STATUS_NOTE_MAX ?>" autocomplete="off"
                     placeholder="예: 다음 정기 점검 때 반영">
            </label>
          </div>
          <?php /* 남길 값은 감사 고지 한 줄뿐이다 — "담당자·결재선이 없다" 는 폼이 이미 보여준다. */ ?>
          <span class="why">저장하면 접속기록에 남습니다.</span>
        <?php else: ?>
          <p data-finding-fix-status-label></p>
          <span class="why">상태 변경은 관리자·운영자만 할 수 있습니다.</span>
        <?php endif; ?>
      </section>
    <?php
    vg_modal_foot($canFixStatus ? '상태 저장' : null, [
        'extra' => '<a class="btn btn--ghost" data-finding-history href="#">이력 보기</a>'
                 . '<a class="btn btn--primary" data-finding-cve-link href="#">CVE 상세</a>',
        'cancel' => '닫기',
        'loading' => '저장 중…',
    ]);
    if ($canFixStatus) { echo '</form>'; }
    vg_modal_close();
    ?>
