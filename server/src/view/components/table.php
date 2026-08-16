<?php
declare(strict_types=1);

/**
 * components/table.php — 목록 렌더: 카드+테이블과 GET 검색·필터 툴바.
 *   페이저와 갈라 둔 건 이쪽만 표 마크업을 안다는 뜻이다 — URL 상태 계산은 paging.php 몫이다.
 */

require_once __DIR__ . '/../../format.php';
require_once __DIR__ . '/../../ui_config.php';
require_once __DIR__ . '/paging.php';   // vg_toolbar() 의 vg_perpage()·vg_qs()
require_once __DIR__ . '/notice.php';   // vg_table() 의 빈 목록이 vg_empty() 를 부른다.

/**
 * 카드+테이블 렌더 (DRY — 각 페이지가 반복하던 <div class="card"><table>… 마크업 통합).
 *   $headers: [['label'=>'등급','align'=>'left'|'right'|'center','width'=>'80px','key'=>'severity'], ...]
 *     'key' 는 콜백이 없을 때 $row[key] 를 자동 이스케이프해서 출력하는 데 쓰인다(없으면 빈칸).
 *   $opts['cell']: 컬럼 인덱스(0,1,2…) 또는 header 의 'key' → function($row): string.
 *     콜백 반환값은 이미 이스케이프된 HTML 이라는 규약(콜백 안에서 vg_h 책임).
 *   $opts['empty']: 빈 목록 메시지(문자열) 또는 vg_empty() 의 배열 스펙.
 *   $opts['row_class']: function($row): string — <tr> 에 붙일 클래스.
 *     심각도 행 강조는 vg_sev_row() 를 그대로 넘기면 된다: 'row_class' => 'vg_sev_row'.
 *   $opts['card']: 카드 래핑 여부(기본 true). $opts['class']: <table> 에 추가할 클래스.
 */
function vg_table(array $headers, array $rows, array $opts = []): void {
    $card     = $opts['card'] ?? true;
    $class    = trim('data-table ' . ($opts['class'] ?? ''));
    $cell     = $opts['cell'] ?? [];
    $empty    = $opts['empty'] ?? '데이터가 없습니다.';
    $rowClass = $opts['row_class'] ?? null;
    $rowAttrs = $opts['row_attrs'] ?? null;

    if ($card) { echo '<div class="card">'; }

    if (!$rows) {
        vg_empty($empty);
        if ($card) { echo '</div>'; }
        return;
    }

    echo '<table class="' . vg_h($class) . '">';
    echo '<thead><tr>';
    foreach ($headers as $h) {
        $label = is_array($h) ? (string) ($h['label'] ?? '') : (string) $h;
        $align = is_array($h) ? ($h['align'] ?? null) : null;
        $width = is_array($h) ? ($h['width'] ?? null) : null;
        $style = $width ? ' style="width:' . vg_h($width) . ';"' : '';
        $thClasses = [];
        if ($align === 'right') { $thClasses[] = 'right'; }
        elseif ($align === 'center') { $thClasses[] = 'center'; }
        if (is_array($h) && !empty($h['class'])) { $thClasses[] = (string) $h['class']; }
        $thClass = $thClasses ? ' class="' . vg_h(implode(' ', $thClasses)) . '"' : '';
        // 'title' — 열 이름만으로 뜻이 안 잡히는 열(약어·등급 기호)의 짧은 범례 자리. 한 줄로 끝낸다.
        $thTitle = is_array($h) && !empty($h['title']) ? ' title="' . vg_h((string) $h['title']) . '"' : '';
        // 'label_html' — 머리글이 글자가 아니라 조작부인 열(선택 열의 전체선택 체크박스).
        //   이미 이스케이프된 HTML 을 그대로 넣는다. 'label' 은 그대로 두어야 한다(칸의 data-label).
        $thHtml = is_array($h) && isset($h['label_html']) ? (string) $h['label_html'] : vg_h($label);
        echo '<th' . $thClass . $style . $thTitle . '>' . $thHtml . '</th>';
    }
    echo '</tr></thead><tbody>';
    foreach ($rows as $row) {
        $rc = $rowClass !== null ? (string) $rowClass($row) : '';
        $attrs = $rowAttrs !== null ? (array) $rowAttrs($row) : [];
        $attrHtml = $rc !== '' ? ' class="' . vg_h($rc) . '"' : '';
        foreach ($attrs as $name => $value) {
            $name = (string) $name;
            if ($value === null || $value === false || preg_match('/^[a-zA-Z_:][a-zA-Z0-9:._-]*$/', $name) !== 1) { continue; }
            $attrHtml .= $value === true ? ' ' . $name : ' ' . $name . '="' . vg_h((string) $value) . '"';
        }
        echo '<tr' . $attrHtml . '>';
        foreach (array_values($headers) as $i => $h) {
            $key   = is_array($h) ? ($h['key'] ?? null) : null;
            $align = is_array($h) ? ($h['align'] ?? null) : null;
            $cb    = $cell[$i] ?? ($key !== null ? ($cell[$key] ?? null) : null);
            if ($cb) {
                $html = $cb($row);
            } elseif ($key !== null) {
                $html = vg_h((string) ($row[$key] ?? ''));
            } else {
                $html = '';
            }
            $nowrap = is_array($h) && !empty($h['nowrap']);
            $tdClasses = [];
            if ($nowrap) { $tdClasses[] = 'nowrap'; }
            if (is_array($h) && !empty($h['class'])) { $tdClasses[] = (string) $h['class']; }
            if ($align === 'right') { $tdClasses[] = 'right'; }
            elseif ($align === 'center') { $tdClasses[] = 'center'; }
            $tdClass = $tdClasses ? ' class="' . vg_h(implode(' ', $tdClasses)) . '"' : '';
            $cellLabel = is_array($h) ? (string) ($h['label'] ?? '') : (string) $h;
            $labelAttr = $cellLabel !== '' ? ' data-label="' . vg_h($cellLabel) . '"' : '';
            echo '<td' . $tdClass . $labelAttr . '>' . $html . '</td>';
        }
        echo '</tr>';
    }
    echo '</tbody></table>';
    if ($card) { echo '</div>'; }
}

/**
 * GET 검색/필터 툴바(class="toolbar"). 값이 있으면 제출버튼 옆에 초기화 링크 자동 표시.
 *   $fields 각 항목: ['type'=>'search'|'date'|'select'|'hidden', 'name'=>, 'value'=>, 'placeholder'=>,
 *                     'options'=>['값'=>'라벨'], 'selected'=>, 'empty_label'=>'전체', 'reset'=>bool]
 *   per_page 는 이 폼의 입력이 아니므로 hidden 으로 실어 보낸다 —
 *   안 그러면 "100개씩 보기" 상태에서 검색할 때마다 기본값으로 돌아간다.
 *   hidden 타입은 두 가지 의미로 쓰인다: (1) 컨텍스트 유지용(scan_id, per_page 등 — 'reset' 생략,
 *   초기화해도 남는다) (2) 폼 밖 필터 운반용(KPI 카드·탭으로 고른 sev/src 등 — 'reset'=>true 를
 *   켜야 초기화 링크가 이 값도 지운다). 새로 hidden 필드를 추가할 때 어느 쪽인지 판단해서 넣는다.
 */
function vg_toolbar(array $fields): void {
    $resetOverrides = ['page' => null];
    $hasValue = false;

    echo '<form class="toolbar" method="get">';

    $perPage = vg_perpage();
    if ($perPage !== vg_ui_per_page_default()) {
        echo '<input type="hidden" name="per_page" value="' . $perPage . '">';
    }

    foreach ($fields as $f) {
        $type = $f['type'] ?? 'search';
        $name = (string) ($f['name'] ?? '');
        $value = (string) ($f['value'] ?? '');

        if ($type === 'hidden') {
            $isReset = !empty($f['reset']);
            $resetAttr = $isReset ? ' data-reset="1"' : '';
            echo '<input type="hidden" name="' . vg_h($name) . '" value="' . vg_h($value) . '"' . $resetAttr . '>';
            if ($isReset) {
                $resetOverrides[$name] = null;
                if ($value !== '') { $hasValue = true; }
            }
            continue;
        }

        if ($type === 'search') {
            $ph = (string) ($f['placeholder'] ?? '');
            echo '<input type="search" name="' . vg_h($name) . '" placeholder="' . vg_h($ph) . '" value="' . vg_h($value) . '">';
            if ($value !== '') { $hasValue = true; }
            $resetOverrides[$name] = null;
        } elseif ($type === 'date') {
            // 기간 필터(감사로그의 접속일시). 브라우저 기본 날짜 선택기를 그대로 쓴다 —
            // 달력 위젯을 직접 만들 이유가 없다(KISS). aria-label 은 값이 비었을 때
            // 이 칸이 '시작'인지 '종료'인지 알려준다(placeholder 가 안 먹는 입력이라).
            $ph = (string) ($f['placeholder'] ?? '');
            echo '<input type="date" name="' . vg_h($name) . '" value="' . vg_h($value) . '"'
                . ($ph !== '' ? ' aria-label="' . vg_h($ph) . '" title="' . vg_h($ph) . '"' : '') . '>';
            if ($value !== '') { $hasValue = true; }
            $resetOverrides[$name] = null;
        } elseif ($type === 'select') {
            $options  = $f['options'] ?? [];
            $selected = (string) ($f['selected'] ?? '');
            $emptyLabel = (string) ($f['empty_label'] ?? '전체');
            // data-autosubmit: 고르는 즉시 폼 제출(app.js). JS 가 없으면 검색 버튼이 그대로 동작한다.
            echo '<select name="' . vg_h($name) . '" data-autosubmit>';
            echo '<option value="">' . vg_h($emptyLabel) . '</option>';
            foreach ($options as $val => $label) {
                $val = (string) $val;
                echo '<option value="' . vg_h($val) . '"' . ($selected === $val ? ' selected' : '') . '>' . vg_h((string) $label) . '</option>';
            }
            echo '</select>';
            if ($selected !== '') { $hasValue = true; }
            $resetOverrides[$name] = null;
        }
    }
    echo '<button type="submit" class="btn btn--sm btn--primary" data-loading="검색 중…">검색</button>';
    if ($hasValue) {
        echo '<a class="btn btn--sm btn--ghost" href="' . vg_h(vg_qs($resetOverrides)) . '">초기화</a>';
    }
    echo '</form>';
}
