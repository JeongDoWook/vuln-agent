<?php
declare(strict_types=1);

/**
 * assetgrade/vocab.php — 자산 중요도·N2SF 등급의 **어휘와 그 표시**.
 *   등급 문자열(C/S/O)·중요도 어휘·보호수준 순위, 그리고 그 어휘로 만드는 범례·뱃지가 여기 있다.
 *   화면마다 분류표를 다시 적지 않도록 이 파일이 단일 출처다.
 *   신호 수집(signals.php)·제안(suggest.php)·확정(confirm.php)은 각자 자기 파일이 맡는다.
 */

/** N2SF 등급 어휘. 화면 라벨·검증 허용값의 단일 출처(하드코딩 분류표를 늘리지 않는다). */
const VG_ASSET_GRADES = [
    'C' => 'C · 기밀',
    'S' => 'S · 민감',
    'O' => 'O · 공개',
];

/**
 * 등급의 보호수준 순위(높을수록 강한 보호). 여러 업무정보 등급이 한 정보시스템에 있으면
 * **가장 높은 등급을 승계**한다 — vg_asset_grade_max() 가 이 순위만 본다.
 */
const VG_ASSET_GRADE_RANK = ['O' => 1, 'S' => 2, 'C' => 3];

/** 자산 중요도 어휘(DB 는 ENUM('HIGH','MEDIUM','LOW'), 화면은 상/중/하). */
const VG_ASSET_CRITICALITY = ['HIGH' => '상', 'MEDIUM' => '중', 'LOW' => '하'];

/**
 * 정보시스템 등급 = 그 시스템에 포함된 업무정보 등급의 **최고값 승계**.
 *   리포트가 "표 2-9 가 완전한 결정 규칙이라 100% 자동 계산된다"고 한 부분이다. 표 원문의
 *   세부 조합까지는 확인하지 못했으므로, 여기서는 **단순 최고등급 승계**만 구현하고 근거 문구를
 *   함께 돌려준다(과설계 금지 — 규칙이 확인되면 이 함수 하나만 고치면 된다).
 *
 * @param string[] $grades 확정 등급 목록(빈 값·모르는 값은 무시)
 * @return array{grade:string,reason:string}|null 유효한 등급이 하나도 없으면 null
 */
function vg_asset_grade_max(array $grades): ?array
{
    $best = null;
    $count = 0;
    foreach ($grades as $g) {
        $g = (string) $g;
        if (!isset(VG_ASSET_GRADE_RANK[$g])) { continue; }
        $count++;
        if ($best === null || VG_ASSET_GRADE_RANK[$g] > VG_ASSET_GRADE_RANK[$best]) { $best = $g; }
    }
    if ($best === null) { return null; }

    return [
        'grade'  => $best,
        'reason' => '포함된 업무정보 등급 ' . $count . '건 중 최고등급 ' . $best . ' 를 승계했습니다.',
    ];
}

/**
 * 등급 범례 한 줄("C · 기밀 / S · 민감 / O · 공개").
 *   화면에 C/S/O 라는 글자만 뜨면 처음 보는 사람은 뜻을 알 수 없다. 어휘를 화면마다 다시 적지 않도록
 *   VG_ASSET_GRADES 에서 만들어 쓴다(하드코딩 분류표를 늘리지 않는다).
 */
function vg_asset_grade_legend(): string
{
    return implode(' / ', VG_ASSET_GRADES);
}

/** 등급 뱃지. 확정값과 제안값을 눈으로 구분해야 하므로 제안값은 '제안' 꼬리표를 단다. */
function vg_asset_grade_badge(?string $grade, bool $suggested = false, string $reason = ''): string
{
    $grade = (string) $grade;
    if (!isset(VG_ASSET_GRADES[$grade])) { return '<span class="why">–</span>'; }

    // 톤: 보호수준이 높을수록 강한 색(색 자체는 app.css 의 .tone-* 이 정한다).
    $tone = ['C' => 'crit', 'S' => 'high', 'O' => 'low'][$grade];
    $label = $suggested ? $grade . ' 제안' : VG_ASSET_GRADES[$grade];
    $title = $suggested
        ? '시스템 초안 제안(확정 아님) — ' . $reason
        : ($reason !== '' ? '확정 근거 — ' . $reason : '');

    return vg_badge($label, $suggested ? 'muted' : $tone, $title);
}
