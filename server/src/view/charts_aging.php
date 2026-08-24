<?php
declare(strict_types=1);

/**
 * charts_aging.php — 방치 기간 타임라인(vg_age_timeline).
 *
 *   charts.php 와 파일을 가른 이유는 성격이 아니라 **동시 작업**이다 — 이 작업이 뜬 시점에
 *   charts.php 를 같이 건드리는 워커가 여럿이라 한 파일에 보태면 병합 충돌이 난다. vg_nice_max()·
 *   vg_empty() 등은 charts.php 를 그대로 require 해서 재사용한다(그 파일 자체는 수정하지 않는다).
 */

require_once __DIR__ . '/charts.php';

/** 방치 기간 타임라인 한 카드가 그리는 최대 항목 수 — "12건만 보여준다" 는 캡션의 근거이자
 *  이 값을 쓰는 모든 SQL LIMIT 의 단일 출처다(매직 넘버 금지). */
const VG_AGE_TIMELINE_TOP = 12;

/** 방치 기간 타임라인에서 라벨을 몇 자까지 보여줄지(그 이상은 …로 접고 <title> 전체를 남긴다). */
const VG_AGE_LABEL_MAX = 22;

/**
 * 방치 기간 타임라인(프리스틀리 형식) — 취약점/공지 하나가 막대 하나. 왼쪽 끝 = 공개일,
 *   오른쪽 끝 = 오늘, 길이가 곧 방치 기간이다. **색은 등급이 아니라 방치 연수가 정한다**
 *   (10년↑ 빨강 · 5년↑ 주황 · 그 아래 노랑) — 심각도 도넛과 같은 --crit/--high/--med 토큰을
 *   재사용하지만 이 차트에서는 나이의 어휘라는 점에 주의(호출부가 severity 를 넘기지 않는다).
 *
 *   $items: [['label'=>…, 'published'=>'YYYY-MM-DD', 'count'=>int, 'href'=>'', 'title'=>''], …]
 *           'published' 가 없는 항목은 여기서 걸러진다(그릴 근거가 없다) — 호출부가 NULL 공개일을
 *           걸러 캡션에 적는 것과는 다른 방어선이다. **정렬도 여기서 다시 한다**(오래된 것 →
 *           최근 것, vg_rank_bars 가 값 내림차순으로 다시 정렬하는 것과 같은 태도).
 *   $opts:  'title'(접근성 이름) · 'note'(그림 아래 붙는 캡션 한 줄 — "상위 N건 표시" · "공개일
 *           미상 N건 제외" 같은 안내는 호출부가 문장으로 조립해 넘긴다) · 'empty'(vg_empty 스펙)
 */
function vg_age_timeline(array $items, array $opts = []): void {
    $rows = [];
    foreach ($items as $it) {
        if (!is_array($it) || empty($it['published'])) { continue; }
        $rows[] = [
            'label'     => (string) ($it['label'] ?? ''),
            'published' => (string) $it['published'],
            'count'     => max(0, (int) ($it['count'] ?? 0)),
            'href'      => (string) ($it['href'] ?? ''),
            'title'     => (string) ($it['title'] ?? ''),
        ];
    }
    if (!$rows) {
        vg_empty($opts['empty'] ?? ['icon' => 'chart', 'title' => '방치 기간을 그릴 데이터가 없습니다.',
                                    'hint'  => '공개일이 있는 CVE 가 쌓이면 여기에 표시됩니다.']);
        return;
    }

    $today = new DateTimeImmutable('today');
    foreach ($rows as &$r) {
        $pub  = new DateTimeImmutable($r['published']);
        $days = $pub <= $today ? $today->diff($pub)->days : 0;
        $r['pub']   = $pub;
        $r['years'] = $days / 365.25;
        $r['tone']  = $r['years'] >= 10 ? 'crit' : ($r['years'] >= 5 ? 'high' : 'med');
    }
    unset($r);

    // 오래된 것이 위로 — 가장 방치된 항목을 먼저 본다.
    usort($rows, static fn(array $a, array $b): int => $a['pub'] <=> $b['pub']);

    $n = count($rows);
    $minPub = $rows[0]['pub'];
    $spanDays = max(1, $today->diff($minPub)->days);

    $hasLabel = false;
    foreach ($rows as $r) { if ($r['label'] !== '') { $hasLabel = true; break; } }

    $RH = 28; $padTop = 10; $padAxis = 26;
    $labelW = $hasLabel ? 152 : 0;
    $labelGap = $hasLabel ? 8 : 0;
    $trackW = 380;
    $statGap = 10; $statW = 96;
    $padLeft = 8; $padRight = 8;

    $x0   = $padLeft + $labelW + $labelGap;
    $xEnd = $x0 + $trackW;
    $W = $xEnd + $statGap + $statW + $padRight;
    $H = $padTop + $n * $RH + $padAxis;

    $xAt = static function (DateTimeImmutable $d) use ($x0, $trackW, $minPub, $spanDays, $today): float {
        if ($d <= $minPub) { return (float) $x0; }
        if ($d >= $today) { return (float) ($x0 + $trackW); }
        return $x0 + $trackW * ($minPub->diff($d)->days / $spanDays);
    };

    $alt = (string) ($opts['title'] ?? '방치 기간 타임라인') . ' · 항목 ' . $n . '개';

    echo '<div class="age">';
    echo '<svg viewBox="0 0 ' . $W . ' ' . $H . '" role="img" aria-label="' . vg_h($alt) . '">';

    // 연 단위 격자 — 구간이 넓으면(15년↑) 라벨을 전부 달면 겹치므로 라벨은 성기게, 격자선은 매년.
    $minYear = (int) $minPub->format('Y');
    $maxYear = (int) $today->format('Y');
    $yearSpan = max(1, $maxYear - $minYear);
    $labelEvery = max(1, (int) ceil($yearSpan / 8));
    $gridTop = $padTop; $gridBot = $padTop + $n * $RH;
    for ($y = $minYear; $y <= $maxYear; $y++) {
        $d = new DateTimeImmutable($y . '-01-01');
        if ($d < $minPub || $d > $today) { continue; }
        $gx = round($xAt($d), 1);
        echo '<line class="chart__grid" x1="' . $gx . '" y1="' . $gridTop . '" x2="' . $gx . '" y2="' . $gridBot . '"></line>';
        if (($y - $minYear) % $labelEvery === 0 || $y === $maxYear) {
            echo '<text class="age__tick" x="' . $gx . '" y="' . ($gridBot + 14) . '">' . $y . '</text>';
        }
    }

    foreach ($rows as $i => $r) {
        $cy = $padTop + $i * $RH + $RH / 2;
        $barH = $RH - 12;
        $barY = $cy - $barH / 2;
        $barX = $xAt($r['pub']);
        $barW = max(2.0, $xEnd - $barX);

        $label = $r['label'];
        if (mb_strlen($label) > VG_AGE_LABEL_MAX) { $label = mb_substr($label, 0, VG_AGE_LABEL_MAX - 1) . '…'; }

        $yearsTxt = number_format($r['years'], 1) . '년';
        $tip = $r['title'] !== '' ? $r['title']
             : ($r['label'] !== '' ? $r['label'] . ' · ' : '') . '공개 ' . $r['published']
               . ' · ' . $yearsTxt . ' 방치 · ' . number_format($r['count']) . '대';

        $tag = $r['href'] !== '' ? 'a' : 'g';
        echo '<' . $tag . ' class="age__row tone-' . vg_h($r['tone']) . '"'
            . ($r['href'] !== '' ? ' href="' . vg_h($r['href']) . '"' : '') . '>';
        echo '<title>' . vg_h($tip) . '</title>';
        if ($hasLabel) {
            echo '<text class="age__label" x="' . round($x0 - $labelGap, 1) . '" y="' . round($cy + 3.5, 1) . '">'
                . vg_h($label) . '</text>';
        }
        echo '<rect class="age__bar tone-' . vg_h($r['tone']) . '" x="' . round($barX, 1) . '" y="' . round($barY, 1) . '"'
            . ' width="' . round($barW, 1) . '" height="' . round($barH, 1) . '" rx="2.5"></rect>';
        echo '<text class="age__stat" x="' . round($xEnd + $statGap, 1) . '" y="' . round($cy + 3.5, 1) . '">'
            . vg_h($yearsTxt . ' · ' . number_format($r['count']) . '대') . '</text>';
        echo '</' . $tag . '>';
    }

    echo '</svg></div>';

    $note = (string) ($opts['note'] ?? '');
    if ($note !== '') { echo '<p class="why">' . vg_h($note) . '</p>'; }
}
