<?php
declare(strict_types=1);

/**
 * view/charts_arc.php — segment-map.php·connectors.php 하단/상단을 채우는 SVG 두 벌.
 *   charts.php 에 함께 넣지 않고 새 파일로 뗀 이유는 코드 성격이 아니라 **동시성** 이다 —
 *   이 시점에 여러 워커가 charts.php 를 각자 건드리고 있어, 같은 파일에 얹으면 병합 충돌만
 *   늘어난다. 규약은 charts.php 와 동일: 좌표는 PHP 가 계산하고 SVG 만 내보낸다(CSP
 *   default-src 'self' 라 인라인 <script> 불가), 색은 전부 class(app.css 소유)로만 준다.
 *   쿼리는 이 파일에 없다 — 호출부(segment-map.php·connectors.php)가 이미 정렬·집계까지
 *   끝낸 배열을 넘긴다(charts.php 의 다른 함수들과 같은 분리).
 */

/* ── 공유 패키지 아크(vg_shared_arc) ─────────────────────────────────────────
 *   가로 한 줄에 패키지 노드, 같은 자산에 함께 있는 패키지끼리 반원 호로 잇는다.
 *   호의 반지름 = 두 노드 x 거리의 절반 → 이웃한 노드는 낮은 호, 먼 노드는 높은 호로
 *   자연스럽게 겹치지 않고 포갠다(고전적인 arc diagram 배치, 새 좌표계를 만들 필요가 없다). */
const VG_ARC_R_MIN        = 9.0;
const VG_ARC_R_MAX        = 24.0;
const VG_ARC_SPACING      = 156.0;  // 노드 사이 x 간격 — 이름·수치 두 줄 라벨이 겹치지 않는 최소값
const VG_ARC_PAD          = 16.0;
const VG_ARC_LABEL_GAP    = 10.0;
const VG_ARC_LABEL_LINE_H = 14.0;
const VG_ARC_CHAR_W       = 6.1;

function vg_arc_tone(string $severity): string {
    return $severity === 'CRITICAL' ? 'crit' : 'high';
}

/**
 * $items: [['label'=>string,'count'=>int,'hosts'=>int,'severity'=>'CRITICAL'|'HIGH','href'=>string], ...]
 *   순서가 곧 배치 순서다 — 호출부가 이미 건수 내림차순 상위 6~8종만 추려 넘긴다(더 넣으면
 *   호가 엉킨다 — 정본 지시).
 * $edges: [['a'=>int, 'b'=>int, 'shared'=>int], ...] — a/b 는 $items 의 인덱스.
 *   **실제로 같은 자산에 공존하는 쌍만** 넣는다 — 호출부가 호스트 집합 교집합으로 확인한
 *   관계다. 상위 N종을 무조건 다 이어 놓으면 "공유"가 거짓말이 된다(정본 지시 4번).
 * $opts: ['total_hosts'=>int(전체 자산 수 — 캡션 계산용), 'empty'=>vg_empty() 스펙]
 */
function vg_shared_arc(array $items, array $edges, array $opts = []): void {
    $items = array_values($items);
    $n = count($items);
    if ($n < 2) {
        vg_empty($opts['empty'] ?? ['icon' => 'package', 'title' => '공유 패키지를 그릴 데이터가 부족합니다.',
            'hint' => '최신 스캔에서 High 이상 판정이 2종 이상 쌓이면 공유 관계가 표시됩니다.']);
        return;
    }

    $maxCount = 1;
    foreach ($items as $it) { $maxCount = max($maxCount, (int) $it['count']); }
    $maxShared = 1;
    foreach ($edges as $e) { $maxShared = max($maxShared, (int) $e['shared']); }

    $x0 = VG_ARC_PAD + VG_ARC_R_MAX;
    $pos = [];
    foreach ($items as $i => $it) {
        $r = VG_ARC_R_MIN + (VG_ARC_R_MAX - VG_ARC_R_MIN) * sqrt((int) $it['count'] / $maxCount);
        $pos[$i] = ['x' => $x0 + $i * VG_ARC_SPACING, 'r' => round($r, 1)];
    }

    // 위쪽 여유 = 실제로 그리는 호 중 가장 반지름이 큰 것(연결이 없으면 노드 반지름만큼만).
    $topSpace = VG_ARC_R_MAX;
    foreach ($edges as $e) {
        $dx = abs($pos[$e['b']]['x'] - $pos[$e['a']]['x']);
        $topSpace = max($topSpace, $dx / 2);
    }
    $baseline = VG_ARC_PAD + $topSpace;
    $bottomSpace = VG_ARC_R_MAX + VG_ARC_LABEL_GAP + VG_ARC_LABEL_LINE_H * 2; // 이름 줄 + 수치 줄
    $H = $baseline + $bottomSpace + VG_ARC_PAD;
    $W = $pos[$n - 1]['x'] + VG_ARC_R_MAX + VG_ARC_PAD;

    // 캡션은 데이터에서 계산한다 — 상위 종 전부가 전체 자산에 걸려 있는지부터 본다.
    $totalHosts = max(0, (int) ($opts['total_hosts'] ?? 0));
    $allCovered = 0;
    foreach ($items as $it) { if ($totalHosts > 0 && (int) $it['hosts'] === $totalHosts) { $allCovered++; } }
    if ($totalHosts > 0 && $allCovered === $n) {
        $caption = '상위 ' . $n . '종이 자산 ' . number_format($totalHosts) . '대 전부에 걸려 있습니다.';
    } elseif ($allCovered > 0) {
        $caption = '상위 ' . $n . '종 가운데 ' . $allCovered . '종이 자산 ' . number_format($totalHosts) . '대 전부에 걸려 있습니다.';
    } else {
        $maxHostCov = 0;
        foreach ($items as $it) { $maxHostCov = max($maxHostCov, (int) $it['hosts']); }
        $caption = '상위 ' . $n . '종 중 가장 널리 퍼진 패키지가 자산 ' . number_format($maxHostCov) . '대에 걸쳐 있습니다.';
    }
    $alt = '공유 패키지 아크 · 노드 ' . $n . '개 · ' . $caption;

    echo '<div class="arc">';
    echo '<svg viewBox="0 0 ' . round($W, 1) . ' ' . round($H, 1) . '" role="img" aria-label="' . vg_h($alt) . '">';

    // 호를 먼저 그려 노드 아래 깔리게 한다(segmap 의 엣지-먼저 순서와 동일).
    foreach ($edges as $e) {
        $a = $pos[(int) $e['a']]; $b = $pos[(int) $e['b']];
        [$l, $rr] = $a['x'] <= $b['x'] ? [$a, $b] : [$b, $a];
        $rad = round(($rr['x'] - $l['x']) / 2, 1);
        if ($rad <= 0) { continue; }
        $sw = round(0.9 + 2.2 * ((int) $e['shared'] / $maxShared), 2);
        echo '<path class="arc__edge" stroke-width="' . $sw . '" d="M' . $l['x'] . ',' . $baseline
            . ' A' . $rad . ',' . $rad . ' 0 0 1 ' . $rr['x'] . ',' . $baseline . '">'
            . '<title>' . vg_h($items[(int) $e['a']]['label'] . ' + ' . $items[(int) $e['b']]['label']
                . ' · 함께 있는 자산 ' . number_format((int) $e['shared']) . '대') . '</title>'
            . '</path>';
    }

    foreach ($items as $i => $it) {
        $p     = $pos[$i];
        $tone  = vg_arc_tone((string) ($it['severity'] ?? 'HIGH'));
        $href  = (string) ($it['href'] ?? '');
        $tag   = $href !== '' ? 'a' : 'g';
        $label = mb_strimwidth((string) $it['label'], 0, max(4, (int) (VG_ARC_SPACING / VG_ARC_CHAR_W)), '…');
        $meta  = number_format((int) $it['count']) . '건 · ' . number_format((int) $it['hosts']) . '대';

        echo '<' . $tag . ' class="arc__node"' . ($href !== '' ? ' href="' . vg_h($href) . '"' : '') . '>';
        echo '<title>' . vg_h((string) $it['label'] . ' · High 이상 ' . number_format((int) $it['count'])
            . '건 · 자산 ' . number_format((int) $it['hosts']) . '대') . '</title>';
        echo '<circle class="arc__circle tone-' . vg_h($tone) . '" cx="' . $p['x'] . '" cy="' . $baseline . '" r="' . $p['r'] . '"/>';
        echo '<text class="arc__name" x="' . $p['x'] . '" y="' . round($baseline + VG_ARC_R_MAX + VG_ARC_LABEL_GAP, 1) . '">'
            . vg_h($label) . '</text>';
        echo '<text class="arc__meta" x="' . $p['x'] . '" y="' . round($baseline + VG_ARC_R_MAX + VG_ARC_LABEL_GAP + VG_ARC_LABEL_LINE_H, 1) . '">'
            . vg_h($meta) . '</text>';
        echo '</' . $tag . '>';
    }

    echo '</svg></div>';
    echo '<p class="why">' . vg_h($caption) . '</p>';
}

/* ── 수집 타임라인(vg_collect_timeline) ──────────────────────────────────────
 *   가로축은 시간(왼쪽 = 윈도우 분 전, 오른쪽 = 지금). 커넥터·자산을 같은 축 위에 이름별
 *   한 행씩 놓고, 마지막 실행/수신 시각을 점으로 찍는다. 창 밖(윈도우보다 오래됨 또는
 *   기록 없음)은 잘라내지 않고 **왼쪽 끝에 화살표로 눌러 붙여 빨갛게** 표시한다 — 잘라내면
 *   가장 봐야 할 신호(오래 멈춘 것)가 사라진다(정본 지시 5번). 실제 경과시간은 각 행의
 *   글자·<title> 로 그대로 남는다.
 */
const VG_CTL_ROW_H         = 22.0;
const VG_CTL_GROUP_H       = 24.0;
const VG_CTL_AXIS_H        = 20.0;
const VG_CTL_LABEL_W       = 176.0;
const VG_CTL_TRACK_W       = 300.0;
const VG_CTL_META_W        = 84.0;
const VG_CTL_GAP           = 10.0;
const VG_CTL_PAD           = 14.0;
const VG_CTL_CHAR_W        = 6.2;
const VG_CTL_TOP_PER_GROUP = 24;

/** 분 단위 경과시간을 사람이 읽는 짧은 문구로. null = 한 번도 기록이 없음. */
function vg_collect_age_label(?int $ageMin): string {
    if ($ageMin === null) { return '기록 없음'; }
    if ($ageMin < 0) { $ageMin = 0; }
    if ($ageMin < 60) { return $ageMin . '분 전'; }
    if ($ageMin < 1440) { return intdiv($ageMin, 60) . '시간 전'; }
    return intdiv($ageMin, 1440) . '일 전';
}

/**
 * $items: [['group'=>string, 'label'=>string, 'age_min'=>?int, 'href'=>string], ...]
 *   age_min 은 "마지막 실행/수신으로부터 몇 분 지났는가"(SQL TIMESTAMPDIFF 로 계산해서
 *   넘긴다 — PHP 시계와 DB 시계가 다를 수 있어 나이 계산 자체를 앱 서버에서 하지 않는다).
 *   null = 한 번도 기록이 없음(커넥터 미실행/자산 미수신).
 * $opts: ['window_min'=>60, 'top'=>그룹당 표시 상한]
 */
function vg_collect_timeline(array $items, array $opts = []): void {
    $windowMin = max(1, (int) ($opts['window_min'] ?? 60));
    $top = max(1, (int) ($opts['top'] ?? VG_CTL_TOP_PER_GROUP));

    // 처음 등장한 순서를 그룹 표시 순서로 삼는다.
    $groups = [];
    foreach ($items as $it) { $groups[(string) ($it['group'] ?? '')][] = $it; }
    if (!$groups) {
        vg_empty(['icon' => 'clock', 'title' => '표시할 수집 이력이 없습니다.']);
        return;
    }

    $skippedTotal = 0;
    foreach ($groups as $g => &$list) {
        // 창 밖(오래 멈춘 것)이 위로 오게 정렬 — 문제부터 보인다. 기록 없음은 가장 위.
        usort($list, static function (array $a, array $b): int {
            $av = $a['age_min'] ?? null; $bv = $b['age_min'] ?? null;
            return ($bv ?? PHP_INT_MAX) <=> ($av ?? PHP_INT_MAX);
        });
        if (count($list) > $top) {
            $skippedTotal += count($list) - $top;
            $list = array_slice($list, 0, $top);
        }
    }
    unset($list);

    $trackL = VG_CTL_PAD + VG_CTL_LABEL_W + VG_CTL_GAP;
    $trackR = $trackL + VG_CTL_TRACK_W;
    $metaX  = $trackR + VG_CTL_GAP;
    $W = $metaX + VG_CTL_META_W + VG_CTL_PAD;

    $rows = 0; foreach ($groups as $list) { $rows += count($list); }
    $H = VG_CTL_PAD + VG_CTL_AXIS_H + count($groups) * VG_CTL_GROUP_H + $rows * VG_CTL_ROW_H + VG_CTL_PAD;

    $outCount = 0;
    foreach ($items as $it) {
        $age = $it['age_min'] ?? null;
        if ($age === null || $age > $windowMin) { $outCount++; }
    }
    $alt = '수집 타임라인 · 최근 ' . $windowMin . '분 창 · 항목 ' . $rows . '개 · 창 밖 ' . $outCount . '개';

    echo '<div class="colltl">';
    echo '<svg viewBox="0 0 ' . round($W, 1) . ' ' . round($H, 1) . '" role="img" aria-label="' . vg_h($alt) . '">';

    $gridTop = VG_CTL_PAD + VG_CTL_AXIS_H;
    $gridBottom = round($H - VG_CTL_PAD, 1);
    echo '<line class="colltl__grid" x1="' . $trackL . '" y1="' . $gridTop . '" x2="' . $trackL . '" y2="' . $gridBottom . '"/>';
    echo '<line class="colltl__grid" x1="' . $trackR . '" y1="' . $gridTop . '" x2="' . $trackR . '" y2="' . $gridBottom . '"/>';
    echo '<text class="colltl__axis" x="' . $trackL . '" y="' . (VG_CTL_PAD + 10) . '">' . vg_h($windowMin . '분 전') . '</text>';
    echo '<text class="colltl__axis colltl__axis--end" x="' . $trackR . '" y="' . (VG_CTL_PAD + 10) . '">지금</text>';

    $y = $gridTop;
    foreach ($groups as $g => $list) {
        $y += VG_CTL_GROUP_H;
        echo '<text class="colltl__group" x="' . VG_CTL_PAD . '" y="' . round($y - VG_CTL_GROUP_H / 2, 1) . '">'
            . vg_h($g . ' · ' . count($list) . '개') . '</text>';

        foreach ($list as $it) {
            $rowY  = $y + VG_CTL_ROW_H / 2;
            $age   = $it['age_min'] ?? null;
            $href  = (string) ($it['href'] ?? '');
            $label = mb_strimwidth((string) $it['label'], 0, max(4, (int) (VG_CTL_LABEL_W / VG_CTL_CHAR_W)), '…');
            $ageLabel = vg_collect_age_label($age !== null ? (int) $age : null);
            $tag   = $href !== '' ? 'a' : 'g';

            echo '<' . $tag . ' class="colltl__row"' . ($href !== '' ? ' href="' . vg_h($href) . '"' : '') . '>';
            echo '<title>' . vg_h((string) $it['label'] . ' · ' . $ageLabel) . '</title>';
            echo '<rect class="colltl__hit" x="0" y="' . round($rowY - VG_CTL_ROW_H / 2, 1)
                . '" width="' . round($W, 1) . '" height="' . VG_CTL_ROW_H . '"/>';
            echo '<line class="colltl__track" x1="' . $trackL . '" y1="' . $rowY . '" x2="' . $trackR . '" y2="' . $rowY . '"/>';
            echo '<text class="colltl__label" x="' . VG_CTL_PAD . '" y="' . $rowY . '">' . vg_h($label) . '</text>';

            if ($age !== null && (int) $age <= $windowMin) {
                $frac = max(0, (int) $age) / $windowMin;
                $x = round($trackR - $frac * VG_CTL_TRACK_W, 1);
                echo '<circle class="colltl__dot tone-ok" cx="' . $x . '" cy="' . $rowY . '" r="4"/>';
            } else {
                // 창 밖 — 왼쪽 끝에 눌러 붙인 화살표(더 왼쪽/더 오래됐다는 뜻)로 표시.
                echo '<path class="colltl__arrow tone-crit" d="M' . round($trackL - 1, 1) . ',' . $rowY
                    . ' L' . round($trackL + 8, 1) . ',' . round($rowY - 5, 1)
                    . ' L' . round($trackL + 8, 1) . ',' . round($rowY + 5, 1) . ' Z"/>';
            }
            echo '<text class="colltl__meta" x="' . $metaX . '" y="' . $rowY . '">' . vg_h($ageLabel) . '</text>';
            echo '</' . $tag . '>';
            $y += VG_CTL_ROW_H;
        }
    }

    echo '</svg></div>';
    if ($skippedTotal > 0) {
        echo '<p class="why">표시 상한(그룹당 ' . number_format($top) . '개)에서 잘림 · 미표시 '
            . number_format($skippedTotal) . '개(오래된 순으로 우선 표시했습니다)</p>';
    }
}
