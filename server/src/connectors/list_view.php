<?php
declare(strict_types=1);

/**
 * connectors/list_view.php — 데이터 수집 화면의 **소스 목록**(역할별 그룹 카드 + 표).
 *   상태 어휘·뱃지는 connectors/vocab.php, 조회는 connectors/queries.php 가 갖는다.
 */

/**
 * 표시용 부가값(스케줄 라벨/다음 실행)을 각 행에 얹는다. 값을 얹은 행은 상세 카드도 그대로
 *   쓰므로($connDetail), 여기서 함께 되돌려 준다 — 두 번 계산하면 목록과 상세가 갈린다.
 *
 * @param array|null $connDetail ?conn=N 의 커넥터 행(부가값이 얹힌 것)으로 채워진다
 */
function vg_connectors_decorate(array $connectors, int $connFilter, ?array &$connDetail): array
{
    // 표시용 부가값(스케줄 라벨/다음 실행) 을 미리 계산해 각 행에 얹는다.
    foreach ($connectors as &$c) {
        $sc = vg_json_col($c['schedule_json']);
        $mode = $sc['mode'] ?? 'manual';
        switch ($mode) {
            case 'interval':
                // 분으로만 적으면 "매 10080분" 처럼 사람이 계산해야 읽힌다 — 나누어떨어지는 단위로 올린다.
                $m = (int) ($sc['interval_minutes'] ?? 0);
                if ($m >= 1440 && $m % 1440 === 0) {
                    $d = intdiv($m, 1440);
                    $c['_sched_label'] = $d === 1 ? '매일' : '매 ' . $d . '일';
                } elseif ($m >= 60 && $m % 60 === 0) {
                    $c['_sched_label'] = '매 ' . intdiv($m, 60) . '시간';
                } else {
                    $c['_sched_label'] = '매 ' . $m . '분';
                }
                break;
            case 'daily':    $c['_sched_label'] = '매일 ' . ($sc['time'] ?? '?'); break;
            case 'cron':     $c['_sched_label'] = 'cron: ' . ($sc['expr'] ?? '?'); break;
            default:         $c['_sched_label'] = '수동';
        }
        $c['_next_run'] = ($c['enabled'] && $mode !== 'manual') ? ($c['next_run_at'] ?: vg_schedule_next($sc)) : '–';
        if ((int) $c['feed_connector_id'] === $connFilter) { $connDetail = $c; }
    }
    unset($c);
    return $connectors;
}

/** 소스 목록 — 역할 그룹 카드마다 표 하나. 등록된 게 하나도 없으면 그룹 없이 안내만. */
function vg_connectors_render_list(array $connectors, string $csrf, array $logCountByConn): void
{
    // 커넥터를 역할별로 나눠 보여준다. 11종이 한 표에 평평하게 있으면 "무엇이 취약점을
    // 가져오고 무엇이 벤더 패치버전을 가져오는지" 가 안 보인다. 분류 기준은 docs/dev/피드소스-역할.md.
    //   타입 → 그룹 매핑은 아래 목록이 유일한 근거다(새 타입은 여기 한 줄 추가). 목록에 없는
    //   타입은 맨 아래 '기타' 로 떨어져 화면에서 사라지지 않는다.
    $roleGroups = [
        ['title' => '취약점 정보', 'types' => ['nvd', 'osv', 'kisa']],
        ['title' => '위험 신호', 'types' => ['kev', 'epss']],
        ['title' => '벤더 판정', 'types' => ['debtracker', 'rhoval', 'rhunfixed', 'ubuntuoval', 'kcve']],
        ['title' => '보안 기준', 'types' => ['ssg']],
    ];

    $tableHeaders = [
        ['label' => '소스'], ['label' => '주기'], ['label' => '실행 시각', 'nowrap' => true],
        ['label' => '상태'], ['label' => '작업', 'align' => 'right'],
    ];
    $tableCells = [
        0 => fn($c) => '<strong><a href="?conn=' . (int) $c['feed_connector_id']
            . '#collection-history">' . vg_h($c['name']) . '</a></strong>',
        1 => fn($c) => '<span class="why">' . vg_h($c['_sched_label']) . '</span>',
        // 없는 시각은 '–' 로 채우지 않는다 — 한 번도 안 돈 수동 소스가 '최근 – / 다음 –' 두 줄을
        //   차지했는데, 그 사실은 '주기: 수동' 과 상태 칸의 '미실행' 이 이미 말한다.
        2 => function ($c) {
            $parts = [];
            if (($c['last_run_at'] ?? '') !== '') { $parts[] = '최근 ' . vg_h((string) $c['last_run_at']); }
            if (($c['_next_run'] ?? '–') !== '–' && ($c['_next_run'] ?? '') !== '') {
                $parts[] = '다음 ' . vg_h((string) $c['_next_run']);
            }
            return $parts ? '<span class="why">' . implode('<br>', $parts) . '</span>' : '';
        },
        // 상태 칸은 "지금 어떤 상태인가" 만 보여준다 — 켜기/끄기는 편집 폼의 '활성' 체크박스 하나로
        //   한다(전엔 여기 토글 버튼이 하나 더 있어 같은 일을 하는 경로가 둘이었다).
        //   꺼진 커넥터는 수집 결과 뱃지만 보면 "왜 안 도는지" 를 알 수 없으므로 '중지' 를 앞에 붙인다.
        3 => function ($c) {
            return '<div class="stack-sm">'
            . ($c['enabled'] ? '' : vg_badge('중지', 'muted'))
            . vg_connector_status_badge($c['last_status'] !== null ? (string) $c['last_status'] : null) . '</div>';
        },
        4 => function ($c) use ($csrf, $logCountByConn) {
            $html = '';
            if ($c['last_message']) {
                $html .= '<span class="sr-only">' . vg_h($c['last_message']) . '</span>';
            }
            $id = (int) $c['feed_connector_id'];
            $n  = $logCountByConn[$id] ?? 0;
            /* 버튼 서열: 주작업(실행)만 채운 색, 그 다음이 편집(btn--secondary — 강조색 외곽선),
             * 나머지는 중립 외곽선(ghost). 크기는 표 안이라 전부 btn--xs 로 맞춘다 —
             * btn--sm 은 행 높이를 키워 한 화면에 보이는 소스 수를 줄인다. 파괴작업(삭제)은 색을 빼고
             * 구분점 뒤로 밀어 자주 쓰는 것(실행·상세·편집)과 눈으로 갈리게 한다 — 확인창은
             * data-confirm 으로 그대로 살아 있다. 예전엔 삭제가 화면에서 가장 강한 요소였고,
             * 소스가 늘수록 빨간 점이 표를 덮었다.
             * 개수는 <span> 으로 감싸지 않는다 — .btn 은 display:flex 라 별개 항목이 되어
             * gap 만큼 '상세 149' 가 벌어져 이 버튼만 폭이 달라 보였다(assets.php 와 같은 함정). */
            return $html . '<div class="actions">'
                . '<form method="post"><input type="hidden" name="csrf" value="' . vg_h($csrf) . '"><input type="hidden" name="action" value="run"><input type="hidden" name="id" value="' . $id . '">'
                . '<button class="btn btn--xs btn--primary" data-loading="수집 중…">실행</button></form>'
                . '<a class="btn btn--xs btn--ghost" href="?conn=' . $id . '#collection-history">'
                . '상세 ' . number_format($n) . '</a>'
                . '<a class="btn btn--xs btn--secondary" href="?edit=' . $id . '">편집</a>'
                . '<span class="why" aria-hidden="true">·</span>'
                . '<form method="post" data-confirm="이 데이터 소스를 삭제할까요? 예약 수집은 중단되며 기존 이력은 남습니다."><input type="hidden" name="csrf" value="' . vg_h($csrf) . '"><input type="hidden" name="action" value="delete"><input type="hidden" name="id" value="' . $id . '">'
                . '<button class="btn btn--xs btn--ghost">삭제</button></form>'
                . '</div>';
        },
    ];

    if (!$connectors) {
        // 등록된 게 하나도 없으면 그룹 헤딩 없이 안내만.
        vg_table($tableHeaders, [], ['empty' => [
            'icon'  => '🔌',
            'title' => '등록된 데이터 소스가 없습니다.',
            'hint'  => '[+ 데이터 소스 추가]에서 수집 대상을 등록합니다.',
        ]]);
    } else {
        // 타입 → 그룹 인덱스. 그룹에 담고, 매핑에 없는 타입은 '기타' 로.
        $typeGroup = [];
        foreach ($roleGroups as $gi => $g) { foreach ($g['types'] as $t) { $typeGroup[$t] = $gi; } }
        // generic_api 는 타입이 하나뿐이라 위 표로 그룹을 못 정한다 — connection_json.role 로 정한다
        // (VG_GENERIC_ROLES 순서와 앞의 세 roleGroups 카드가 그대로 대응: identity/priority/vendor).
        $genericRoleGroup = ['identity' => 0, 'priority' => 1, 'vendor' => 2];
        $grouped = []; $others = [];
        foreach ($connectors as $c) {
            if ($c['connector_type'] === 'generic_api') {
                $gc = vg_json_col($c['connection_json']);
                $gi = $genericRoleGroup[$gc['role'] ?? ''] ?? null;
            } else {
                $gi = $typeGroup[$c['connector_type']] ?? null;
            }
            if ($gi === null) { $others[] = $c; } else { $grouped[$gi][] = $c; }
        }
        foreach ($roleGroups as $gi => $g) {
            if (empty($grouped[$gi])) { continue; }
            echo '<div class="card"><strong>' . vg_h($g['title']) . '</strong>'
               . '<div class="card__body">';
            vg_table($tableHeaders, $grouped[$gi], ['card' => false, 'cell' => $tableCells]);
            echo '</div></div>';
        }
        if ($others) {
            echo '<div class="card"><strong>기타</strong><div class="card__body">';
            vg_table($tableHeaders, $others, ['card' => false, 'cell' => $tableCells]);
            echo '</div></div>';
        }
    }
}
