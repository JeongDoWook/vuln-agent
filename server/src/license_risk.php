<?php
declare(strict_types=1);

/**
 * license_risk.php — SPDX 라이선스 식별자 → 위험도(permissive/copyleft/unknown) 판정.
 *   language-packages.php(목록)·language-package.php(상세, 있다면)가 공유하는 단일 헬퍼(DRY).
 *   목록은 바뀔 일이 거의 없는 알려진 SPDX 어휘라 하드코딩을 허용한다(CLAUDE.md 예외 조항).
 */

// 대표적인 permissive 라이선스 — 재배포·수정에 카피레프트 의무가 없다.
const VG_LICENSE_PERMISSIVE = [
    'MIT', 'MIT-0', 'Apache-2.0', 'Apache-1.1', 'BSD-2-Clause', 'BSD-3-Clause', 'BSD-4-Clause',
    'ISC', '0BSD', 'Unlicense', 'Zlib', 'BSL-1.0', 'PSF-2.0', 'X11', 'WTFPL', 'CC0-1.0', 'Python-2.0',
];

// 대표적인 copyleft 라이선스 — 재배포 시 소스 공개·동일 라이선스 의무가 붙어 조직 정책 검토가 필요하다.
const VG_LICENSE_COPYLEFT = [
    'GPL-2.0', 'GPL-2.0-only', 'GPL-2.0-or-later', 'GPL-3.0', 'GPL-3.0-only', 'GPL-3.0-or-later',
    'LGPL-2.0', 'LGPL-2.0-only', 'LGPL-2.0-or-later', 'LGPL-2.1', 'LGPL-2.1-only', 'LGPL-2.1-or-later',
    'LGPL-3.0', 'LGPL-3.0-only', 'LGPL-3.0-or-later',
    'AGPL-1.0', 'AGPL-3.0', 'AGPL-3.0-only', 'AGPL-3.0-or-later',
    'MPL-1.1', 'MPL-2.0', 'EPL-1.0', 'EPL-2.0', 'CDDL-1.0', 'CDDL-1.1', 'CPL-1.0',
];

/**
 * SPDX 식별자(또는 "MIT OR Apache-2.0" 같은 SPDX 표현식) → permissive|copyleft|unknown.
 *   복합 표현식은 토큰(OR/AND/WITH 로 분리) 중 하나라도 copyleft 면 보수적으로 copyleft 로 본다 —
 *   라이선스 위험 판정은 놓치는 것(미탐)이 잘못 띄우는 것(과탐)보다 훨씬 나쁘다.
 */
function vg_license_classify(?string $license): string
{
    $s = trim((string) $license);
    if ($s === '') { return 'unknown'; }
    if (in_array($s, VG_LICENSE_COPYLEFT, true)) { return 'copyleft'; }
    if (in_array($s, VG_LICENSE_PERMISSIVE, true)) { return 'permissive'; }

    $tokens = preg_split('/\s+(?:OR|AND|WITH)\s+/i', $s) ?: [$s];
    $hasCopyleft = false;
    $hasPermissive = false;
    foreach ($tokens as $t) {
        $t = trim($t);
        if (in_array($t, VG_LICENSE_COPYLEFT, true)) { $hasCopyleft = true; }
        elseif (in_array($t, VG_LICENSE_PERMISSIVE, true)) { $hasPermissive = true; }
    }
    if ($hasCopyleft) { return 'copyleft'; }
    if ($hasPermissive) { return 'permissive'; }
    return 'unknown';
}

// 위험도 → 한글 라벨.
function vg_license_risk_label(string $risk): string
{
    return ['permissive' => '허용적', 'copyleft' => '카피레프트', 'unknown' => '미상'][$risk] ?? '미상';
}

// 위험도 → 뱃지 톤(vg_badge 와 함께 쓴다). 카피레프트=위험(high), 허용적=안전(low), 미상=muted.
function vg_license_risk_tone(string $risk): string
{
    return ['permissive' => 'low', 'copyleft' => 'high', 'unknown' => 'muted'][$risk] ?? 'muted';
}
