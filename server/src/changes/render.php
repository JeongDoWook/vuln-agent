<?php
declare(strict_types=1);

/**
 * changes/render.php — 변화 추적 화면의 렌더 헬퍼 모음.
 *
 *   '취약점 변화' 탭과 '추이' 탭의 "해결된 항목" 표가 **같은 셀 함수**를 쓴다(같은 값이 두 표에서
 *   다른 모양이면 안 된다). 그래서 탭 파일마다 복사하지 않고 여기 한 곳에 둔다 — 탭 파일은
 *   이 함수들을 호출만 한다.
 *
 *   여기 있는 것은 전부 changes.php 에 있던 것을 이름·시그니처·반환 형태 그대로 옮긴 것이다.
 */

// 변화유형: 정렬·필터·배지에 공유
const VG_CHANGE_TYPES = ['new' => '신규', 'up' => '등급 상승', 'down' => '등급 하락', 'resolved' => '해결'];
// 패키지 변경유형(tb_pkg_change.change_type)
const VG_PKG_CHANGE_TYPES = [
    'installed'   => '설치',
    'removed'     => '제거',
    'upgraded'    => '업그레이드',
    'downgraded'  => '다운그레이드',
];
// 다운그레이드는 되돌아간 것이라 눈에 띄어야 한다(취약 버전으로 회귀했을 수 있다).
function vg_pkgchg_tone(string $t): string {
    return ['upgraded' => 'ok', 'installed' => 'med', 'removed' => 'muted', 'downgraded' => 'high'][$t] ?? 'muted';
}

function vg_change_tone(string $type): string {
    return ['new' => 'crit', 'up' => 'high', 'down' => 'muted', 'resolved' => 'ok'][$type] ?? 'muted';
}

/**
 * 이 화면 안의 갈래(취약점 변화 · 패키지 변경 · 추이).
 *   위의 '탐지 결과' 줄(vg_findings_subtabs → .subtabs, 밑줄형)은 **화면을 바꾸는** 내비이고,
 *   이 줄은 **같은 화면 안에서 무엇을 볼지** 고르는 것이다. 둘 다 vg_subtabs() 로 그리던 동안엔
 *   탭 줄이 두 개 똑같이 생겨 어느 쪽이 상위인지 화면에서 안 읽혔다 — 그래서 이 줄만
 *   알약형(.tabs/.pill, cves.php·vendor.php 의 화면 내 선택과 같은 컴포넌트)으로 내려 그린다.
 *   ?tab= 키 이름은 그대로 둔다(다른 화면에서 들어오는 링크가 깨지지 않게).
 */
function vg_change_tabs(array $tabs, string $active): void {
    echo '<div class="tabs">';
    foreach ($tabs as $key => $def) {
        $on = $active === (string) $key;
        echo '<a class="pill' . ($on ? ' pill--on' : '') . '"'
            . ' href="' . vg_h(vg_qs(['tab' => $key, 'page' => null])) . '">'
            . vg_h((string) $def['label'])
            . (isset($def['n']) ? ' ' . number_format((int) $def['n']) : '')
            . '</a>';
    }
    echo '</div>';
}

/** 실제 스캔 대상의 OS 생태계가 식별되는 패키지만 상세 링크로 만든다. */
function vg_package_detail_link(array $row): string {
    $name = (string) $row['package_name'];
    $ecosystem = vg_osv_ecosystem($row['package_os_id'] ?? null, $row['package_os_version'] ?? null);
    if ($ecosystem === null) { return vg_h($name); }
    return '<a href="/package.php?name=' . urlencode($name) . '&amp;eco=' . urlencode($ecosystem) . '">'
         . vg_h($name) . '</a>';
}

/**
 * 취약점 변화·추이의 패키지 셀. 두 목록이 같은 모양이 되게 한곳에서 렌더한다.
 *   판정 근거 문장은 접이식(details)으로 여기 달려 있었다 — 목록에서 펴 보는 사람은 드문데
 *   행마다 접이식이 하나씩 서서 표가 시끄러웠고, 쿼리는 행마다 문장 하나를 더 실어 왔다.
 *   근거는 상세가 정본이다: finding_history.php 의 '현재 상태 · 판정 근거' 와
 *   '스캔별 상태 타임라인'(회차별 근거 — 해결된 항목의 **직전** 근거도 여기서 보인다).
 *   그래서 문장을 빼는 대신 **그리로 가는 링크를 이 칸에 남긴다**(정보를 없애지 않는다).
 */
function vg_change_package_cell(array $row): string {
    $out = vg_package_detail_link($row);
    if (($row['installed_version'] ?? '') !== '') {
        $out .= ' <span class="why">' . vg_h((string) $row['installed_version']) . '</span>';
    }
    $href = vg_finding_history_url(
        (int) $row['host_id'], (int) ($row['container_id'] ?? 0),
        (string) $row['cve_id'], (string) $row['package_name']
    );
    $out .= '<div class="why"><a href="' . vg_h($href) . '">이 자산 판정 →</a></div>';
    return $out;
}

/**
 * 취약점 변화·추이의 등급 셀 — 등급(+이전 등급)과 외부노출까지. **가로로** 눕힌다.
 *   예전엔 여기에 변화 사유까지 얹혀 6.5rem 칸 안에서 세 값이 세로로 쌓였고(한 행이 3줄),
 *   사유는 그 좁은 칸에서 잘려 문장이 끊겼다. 사유는 '변화' 칸으로 옮겼다(변화와 그 이유는
 *   같이 읽는 값이다). 이 칸의 폭(10rem)은 'MEDIUM → [HIGH] [외부노출]' 이 한 줄에 들어가는 값.
 */
function vg_change_severity_cell(array $row): string {
    $severity = vg_sev_badge((string) $row['severity']);
    if (!empty($row['from_sev'])) {
        $severity = '<span class="why">' . vg_h((string) $row['from_sev']) . ' →</span> ' . $severity;
    }
    if (!empty($row['exposed'])) { $severity .= ' ' . vg_badge('외부노출', 'high'); }
    return $severity;
}

/** 수집 시각 셀 — 분까지만 보이고 전체 값은 title 로 남긴다(좁은 칸에서 잘리지 않게). */
function vg_change_when_cell(array $row): string {
    $when = (string) ($row['when'] ?? '');
    if ($when === '') { return ''; }   // 없는 시각은 '–' 로 채우지 않는다 — 빈 칸이 같은 말을 한다
    return '<span class="why" title="' . vg_h($when) . '">' . vg_h(substr($when, 0, 16)) . '</span>';
}

/** 변화 유형 + 그렇게 된 이유. 사유는 문장이라 이 칸에서 접히게 둔다(잘리지 않는다). */
function vg_change_type_cell(array $row): string {
    $out = vg_badge(VG_CHANGE_TYPES[$row['type']], vg_change_tone((string) $row['type']));
    // 사유는 문장이라 셀에 그대로 깔면 행 높이가 제각각이 된다(실측: '업그레이드로 신규 노출
    //   (1.2.3 → 1.2.4)' 는 이 칸에서 세 줄로 접혔다). **짧은 라벨 뱃지로 접고 원문은 툴팁으로**
    //   넘긴다 — title 은 app.js 가 CSS 툴팁(.info-tooltip)으로 승격하므로 브라우저 기본
    //   툴팁의 1초 지연·OS 기본 모양을 타지 않는다(PR#225 와 같은 경로).
    if (($row['reason'] ?? '') !== '') {
        $short = (string) ($row['reason_short'] ?? '');
        $out .= ' ' . vg_badge($short !== '' ? $short : '사유', 'muted', (string) $row['reason']);
    }
    return $out;
}

/**
 * 사유의 **짧은 라벨**(표 셀의 뱃지용). 원문은 vg_change_reason() 이 그대로 만들고 툴팁으로 붙는다.
 *   두 함수는 같은 판정(type + tb_pkg_change 대조)을 보므로 분기를 나란히 둔다 — 한쪽만 고치면
 *   뱃지와 툴팁이 서로 다른 말을 하게 된다.
 */
function vg_change_reason_short(string $type, ?array $pc): string {
    if ($type === 'new') {
        if ($pc && $pc['change_type'] === 'installed') { return '새 설치'; }
        if ($pc && $pc['change_type'] === 'upgraded')  { return '버전 변경'; }
        return '신규 공표';
    }
    if ($type === 'resolved') {
        if ($pc && $pc['change_type'] === 'removed')  { return '제거됨'; }
        if ($pc && $pc['change_type'] === 'upgraded') { return '패치 적용'; }
        return '재판정';
    }
    return $pc && in_array($pc['change_type'], ['upgraded', 'downgraded'], true) ? '버전 변경' : '';
}

/** tb_pkg_change 대조 결과(없으면 null)로 변화 사유 문구를 만든다. 추측성 사유는 만들지 않는다. */
function vg_change_reason(string $type, ?array $pc): string {
    if ($type === 'new') {
        if ($pc && in_array($pc['change_type'], ['installed', 'upgraded'], true)) {
            return $pc['change_type'] === 'installed'
                ? '새 설치 (' . $pc['new_version'] . ')'
                : '업그레이드로 신규 노출 (' . $pc['old_version'] . ' → ' . $pc['new_version'] . ')';
        }
        return '기존 패키지·신규 CVE 공표';
    }
    if ($type === 'resolved') {
        if ($pc && in_array($pc['change_type'], ['removed', 'upgraded'], true)) {
            return $pc['change_type'] === 'removed'
                ? '패키지 제거됨'
                : '패치 적용 (' . $pc['new_version'] . ')';
        }
        return '재판정으로 해결';
    }
    // up | down: 등급 변화는 이미 배지로 보이므로, 버전도 같이 바뀐 경우에만 부가 정보를 붙인다.
    if ($pc && in_array($pc['change_type'], ['upgraded', 'downgraded'], true)) {
        return '패키지 버전도 ' . $pc['old_version'] . ' → ' . $pc['new_version'] . ' 변경됨';
    }
    return '';
}
